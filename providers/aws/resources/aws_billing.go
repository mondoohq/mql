// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/budgets"
	budgetstypes "github.com/aws/aws-sdk-go-v2/service/budgets/types"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// --- aws.billing -------------------------------------------------------------

type mqlAwsBillingInternal struct {
	// month-to-date GetCostAndUsage(GroupBy=SERVICE)
	mtdLock      sync.Mutex
	mtdFetched   bool
	mtdTotal     float64
	mtdByService map[string]any
	mtdCurrency  string
	mtdErr       error

	// previous full calendar month GetCostAndUsage(GroupBy=SERVICE)
	lastMonthLock      sync.Mutex
	lastMonthFetched   bool
	lastMonthTotal     float64
	lastMonthByService map[string]any
	lastMonthErr       error

	// trailing 30 days GetCostAndUsage (no GroupBy)
	last30Lock    sync.Mutex
	last30Fetched bool
	last30Total   float64
	last30Err     error

	// month-end forecast = mtdTotal + GetCostForecast(tomorrow..first-of-next-month)
	forecastLock        sync.Mutex
	forecastFetched     bool
	forecastAmount      float64
	forecastUnavailable bool
	forecastErr         error
}

func (a *mqlAwsBilling) id() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return "aws.billing/" + conn.AccountId(), nil
}

// monthRange returns Start (1st of current month) and End (today + 1d, exclusive).
func monthRange(now time.Time) (string, string) {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := now.AddDate(0, 0, 1)
	return start.Format("2006-01-02"), end.Format("2006-01-02")
}

// lastMonthRange returns Start (1st of previous month) and End (1st of current month, exclusive).
func lastMonthRange(now time.Time) (string, string) {
	now = now.UTC()
	first := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	start := first.AddDate(0, -1, 0)
	return start.Format("2006-01-02"), first.Format("2006-01-02")
}

// trailing30Range returns Start and End (exclusive) for a 30-day window
// ending today (inclusive): [today-29, today+1).
func trailing30Range(now time.Time) (string, string) {
	end := now.UTC().AddDate(0, 0, 1)
	start := end.AddDate(0, 0, -30)
	return start.Format("2006-01-02"), end.Format("2006-01-02")
}

// forecastRange returns Start (tomorrow) and End (first of next month). Returns
// empty strings on the last day of the month (no future days remain).
func forecastRange(now time.Time) (string, string) {
	now = now.UTC()
	tomorrow := now.AddDate(0, 0, 1)
	firstOfNext := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	if !tomorrow.Before(firstOfNext) {
		return "", ""
	}
	return tomorrow.Format("2006-01-02"), firstOfNext.Format("2006-01-02")
}

func parseCEAmount(s *string) float64 {
	if s == nil {
		return 0
	}
	v, err := strconv.ParseFloat(*s, 64)
	if err != nil {
		return 0
	}
	return v
}

// costByServiceResult accumulates an unblended cost total and per-service
// breakdown across all pages of a GetCostAndUsage(GroupBy=SERVICE) call.
type costByServiceResult struct {
	total     float64
	byService map[string]any
	currency  string
}

// fetchCostByService runs GetCostAndUsage(GroupBy=SERVICE) for the given
// window, paginating via NextPageToken so accounts with many services
// don't get truncated.
func fetchCostByService(svc *costexplorer.Client, start, end string) (*costByServiceResult, error) {
	out := &costByServiceResult{byService: map[string]any{}}

	var pageToken *string
	for {
		resp, err := svc.GetCostAndUsage(context.TODO(), &costexplorer.GetCostAndUsageInput{
			TimePeriod:    &cetypes.DateInterval{Start: aws.String(start), End: aws.String(end)},
			Granularity:   cetypes.GranularityMonthly,
			Metrics:       []string{"UnblendedCost"},
			GroupBy:       []cetypes.GroupDefinition{{Type: cetypes.GroupDefinitionTypeDimension, Key: aws.String("SERVICE")}},
			NextPageToken: pageToken,
		})
		if err != nil {
			return nil, classifyAwsError(err, "ce:GetCostAndUsage")
		}

		for _, r := range resp.ResultsByTime {
			for _, g := range r.Groups {
				if len(g.Keys) == 0 {
					continue
				}
				metric, ok := g.Metrics["UnblendedCost"]
				if !ok {
					continue
				}
				amt := parseCEAmount(metric.Amount)
				out.byService[g.Keys[0]] = amt
				out.total += amt
				if out.currency == "" && metric.Unit != nil {
					out.currency = *metric.Unit
				}
			}
			if len(r.Groups) == 0 {
				if metric, ok := r.Total["UnblendedCost"]; ok {
					out.total = parseCEAmount(metric.Amount)
					if out.currency == "" && metric.Unit != nil {
						out.currency = *metric.Unit
					}
				}
			}
		}

		if resp.NextPageToken == nil || *resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return out, nil
}

// fetchMonthToDate populates the mtd* fields. Safe to call repeatedly.
func (a *mqlAwsBilling) fetchMonthToDate() error {
	a.mtdLock.Lock()
	defer a.mtdLock.Unlock()
	if a.mtdFetched {
		return a.mtdErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	start, end := monthRange(time.Now())
	res, err := fetchCostByService(conn.CostExplorer(), start, end)
	if err != nil {
		a.mtdErr = err
		a.mtdFetched = true
		return err
	}
	a.mtdTotal = res.total
	a.mtdByService = res.byService
	a.mtdCurrency = res.currency
	a.mtdFetched = true
	return nil
}

func (a *mqlAwsBilling) fetchLastMonth() error {
	a.lastMonthLock.Lock()
	defer a.lastMonthLock.Unlock()
	if a.lastMonthFetched {
		return a.lastMonthErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	start, end := lastMonthRange(time.Now())
	res, err := fetchCostByService(conn.CostExplorer(), start, end)
	if err != nil {
		a.lastMonthErr = err
		a.lastMonthFetched = true
		return err
	}
	a.lastMonthTotal = res.total
	a.lastMonthByService = res.byService
	a.lastMonthFetched = true
	return nil
}

func (a *mqlAwsBilling) fetchLast30Days() error {
	a.last30Lock.Lock()
	defer a.last30Lock.Unlock()
	if a.last30Fetched {
		return a.last30Err
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CostExplorer()
	start, end := trailing30Range(time.Now())

	resp, err := svc.GetCostAndUsage(context.TODO(), &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &cetypes.DateInterval{Start: aws.String(start), End: aws.String(end)},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{"UnblendedCost"},
	})
	if err != nil {
		a.last30Err = classifyAwsError(err, "ce:GetCostAndUsage")
		a.last30Fetched = true
		return a.last30Err
	}

	for _, r := range resp.ResultsByTime {
		if metric, ok := r.Total["UnblendedCost"]; ok {
			a.last30Total += parseCEAmount(metric.Amount)
		}
	}

	a.last30Fetched = true
	return nil
}

// fetchForecast populates forecastAmount as mtdTotal + future-forecast.
func (a *mqlAwsBilling) fetchForecast() error {
	a.forecastLock.Lock()
	defer a.forecastLock.Unlock()
	if a.forecastFetched {
		return a.forecastErr
	}

	if err := a.fetchMonthToDate(); err != nil {
		return err
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CostExplorer()
	start, end := forecastRange(time.Now())
	if start == "" {
		a.forecastAmount = a.mtdTotal
		a.forecastFetched = true
		return nil
	}

	resp, err := svc.GetCostForecast(context.TODO(), &costexplorer.GetCostForecastInput{
		TimePeriod:  &cetypes.DateInterval{Start: aws.String(start), End: aws.String(end)},
		Metric:      cetypes.MetricUnblendedCost,
		Granularity: cetypes.GranularityMonthly,
	})
	if err != nil {
		if classified := classifyAwsError(err, "ce:GetCostForecast"); llx.KindOf(classified) != llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
			a.forecastErr = classified
			a.forecastFetched = true
			return classified
		}
		// CE returns "unable to produce a meaningful forecast" for accounts
		// with little history; treat as zero future-forecast.
		log.Debug().Err(err).Msg("aws.billing: cost forecast unavailable")
		a.forecastUnavailable = true
		a.forecastAmount = a.mtdTotal
		a.forecastFetched = true
		return nil
	}

	if resp.Total != nil {
		a.forecastAmount = a.mtdTotal + parseCEAmount(resp.Total.Amount)
	} else {
		a.forecastAmount = a.mtdTotal
	}
	a.forecastFetched = true
	return nil
}

func (a *mqlAwsBilling) currency() (string, error) {
	if err := a.fetchMonthToDate(); err != nil {
		return "", err
	}
	if a.mtdCurrency == "" {
		return "USD", nil
	}
	return a.mtdCurrency, nil
}

func (a *mqlAwsBilling) monthToDateCost() (float64, error) {
	if err := a.fetchMonthToDate(); err != nil {
		return 0, err
	}
	return a.mtdTotal, nil
}

func (a *mqlAwsBilling) costsByService() (map[string]any, error) {
	if err := a.fetchMonthToDate(); err != nil {
		return nil, err
	}
	if a.mtdByService == nil {
		return map[string]any{}, nil
	}
	return a.mtdByService, nil
}

func (a *mqlAwsBilling) lastMonthCost() (float64, error) {
	if err := a.fetchLastMonth(); err != nil {
		return 0, err
	}
	return a.lastMonthTotal, nil
}

func (a *mqlAwsBilling) costsByServiceLastMonth() (map[string]any, error) {
	if err := a.fetchLastMonth(); err != nil {
		return nil, err
	}
	if a.lastMonthByService == nil {
		return map[string]any{}, nil
	}
	return a.lastMonthByService, nil
}

func (a *mqlAwsBilling) last30DaysCost() (float64, error) {
	if err := a.fetchLast30Days(); err != nil {
		return 0, err
	}
	return a.last30Total, nil
}

func (a *mqlAwsBilling) forecastedMonthCost() (float64, error) {
	if err := a.fetchForecast(); err != nil {
		return 0, err
	}
	if a.forecastUnavailable {
		a.ForecastedMonthCost.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return a.forecastAmount, nil
}

// --- aws.billing.budgets -----------------------------------------------------

func (a *mqlAwsBilling) budgets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Budgets()
	accountId := conn.AccountId()

	res := []any{}
	paginator := budgets.NewDescribeBudgetsPaginator(svc, &budgets.DescribeBudgetsInput{
		AccountId: aws.String(accountId),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, classifyAwsError(err, "budgets:ViewBudget")
		}
		for i := range page.Budgets {
			b := page.Budgets[i]
			if b.BudgetName == nil {
				continue
			}

			limit, limitUnit := budgetSpend(b.BudgetLimit)

			var actualSpendVal, forecastSpendVal *budgetstypes.Spend
			if b.CalculatedSpend != nil {
				actualSpendVal = b.CalculatedSpend.ActualSpend
				forecastSpendVal = b.CalculatedSpend.ForecastedSpend
			}
			actual, _ := budgetSpend(actualSpendVal)
			forecast, _ := budgetSpend(forecastSpendVal)

			var periodStart, periodEnd *time.Time
			if b.TimePeriod != nil {
				periodStart = b.TimePeriod.Start
				periodEnd = b.TimePeriod.End
			}

			args := map[string]*llx.RawData{
				"__id":            llx.StringData(accountId + "/" + *b.BudgetName),
				"name":            llx.StringDataPtr(b.BudgetName),
				"accountId":       llx.StringData(accountId),
				"budgetType":      llx.StringData(string(b.BudgetType)),
				"timeUnit":        llx.StringData(string(b.TimeUnit)),
				"budgetLimit":     llx.FloatData(limit),
				"budgetLimitUnit": llx.StringData(limitUnit),
				"actualSpend":     llx.FloatData(actual),
				"forecastedSpend": llx.FloatData(forecast),
				"costFilters":     llx.MapData(budgetCostFiltersToAny(b.CostFilters), types.Array(types.String)),
				"periodStart":     llx.TimeDataPtr(periodStart),
				"periodEnd":       llx.TimeDataPtr(periodEnd),
				"lastUpdatedTime": llx.TimeDataPtr(b.LastUpdatedTime),
			}

			mqlBudget, err := CreateResource(a.MqlRuntime, "aws.billing.budget", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlBudget)
		}
	}
	return res, nil
}

// budgetSpend extracts (amount, unit) from a Spend struct, treating nil as
// zero / empty.
func budgetSpend(s *budgetstypes.Spend) (float64, string) {
	if s == nil {
		return 0, ""
	}
	var amt float64
	if s.Amount != nil {
		v, err := strconv.ParseFloat(*s.Amount, 64)
		if err == nil {
			amt = v
		}
	}
	unit := ""
	if s.Unit != nil {
		unit = *s.Unit
	}
	return amt, unit
}

// budgetCostFiltersToAny converts the SDK's map[string][]string into the
// map[string]any (with []any values) layout llx.MapData expects.
func budgetCostFiltersToAny(in map[string][]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		entries := make([]any, len(v))
		for i, s := range v {
			entries[i] = s
		}
		out[k] = entries
	}
	return out
}

// --- aws.billing.budget ------------------------------------------------------

func (a *mqlAwsBillingBudget) id() (string, error) {
	return a.AccountId.Data + "/" + a.Name.Data, nil
}

func (a *mqlAwsBillingBudget) notifications() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Budgets()

	res := []any{}
	notifPaginator := budgets.NewDescribeNotificationsForBudgetPaginator(svc,
		&budgets.DescribeNotificationsForBudgetInput{
			AccountId:  aws.String(a.AccountId.Data),
			BudgetName: aws.String(a.Name.Data),
		})

	for notifPaginator.HasMorePages() {
		page, err := notifPaginator.NextPage(context.TODO())
		if err != nil {
			return nil, classifyAwsError(err, "budgets:ViewBudget")
		}
		for _, n := range page.Notifications {
			entry := map[string]any{
				"notificationType":   string(n.NotificationType),
				"comparisonOperator": string(n.ComparisonOperator),
				"threshold":          n.Threshold,
				"thresholdType":      string(n.ThresholdType),
				"notificationState":  string(n.NotificationState),
			}

			subs, err := fetchBudgetSubscribers(svc, a.AccountId.Data, a.Name.Data, n)
			if err != nil {
				return nil, err
			}
			entry["subscribers"] = subs
			res = append(res, entry)
		}
	}
	return res, nil
}

func fetchBudgetSubscribers(svc *budgets.Client, accountId, budgetName string, n budgetstypes.Notification) ([]any, error) {
	out := []any{}
	notifCopy := n
	subPaginator := budgets.NewDescribeSubscribersForNotificationPaginator(svc,
		&budgets.DescribeSubscribersForNotificationInput{
			AccountId:    aws.String(accountId),
			BudgetName:   aws.String(budgetName),
			Notification: &notifCopy,
		})
	for subPaginator.HasMorePages() {
		page, err := subPaginator.NextPage(context.TODO())
		if err != nil {
			if Is400AccessDeniedError(err) {
				return out, nil
			}
			return nil, err
		}
		for _, s := range page.Subscribers {
			entry := map[string]any{
				"type": string(s.SubscriptionType),
			}
			if s.Address != nil {
				entry["address"] = *s.Address
			}
			out = append(out, entry)
		}
	}
	return out, nil
}
