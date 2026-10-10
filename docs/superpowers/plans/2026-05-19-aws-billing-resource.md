# AWS Billing Resource Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new `aws.billing` MQL resource family (with `aws.billing.budget` sub-resource) that surfaces month-to-date and historical spend from AWS Cost Explorer plus the inventory of configured AWS Budgets.

**Architecture:** Two resources defined in `providers/aws/resources/aws.lr`, implementation in a new file `providers/aws/resources/aws_billing.go`. Both AWS APIs (Cost Explorer and Budgets) are pinned to `us-east-1`. Cost Explorer calls are minimized — one `GetCostAndUsage` call (group-by `SERVICE`) yields both the period total and the per-service breakdown, cached in an `mqlAwsBillingInternal` struct so multiple field accesses share fetches. Cost Explorer requires opt-in per account; the implementation degrades gracefully (returns zeros) when CE access is denied or the service isn't opted in.

**Tech Stack:** Go 1.25; AWS SDK Go v2 services `costexplorer` and `budgets`; mql provider SDK; `mqlr` codegen.

**Reference spec:** `docs/superpowers/specs/2026-05-19-aws-billing-resource-design.md`.

---

### Task 1: Add Cost Explorer + Budgets SDK dependencies

**Files:**
- Modify: `providers/aws/go.mod`
- Modify: `providers/aws/go.sum`

- [ ] **Step 1: Add the two SDK modules**

Run from the repo root:

```bash
cd providers/aws && go get \
  github.com/aws/aws-sdk-go-v2/service/costexplorer \
  github.com/aws/aws-sdk-go-v2/service/budgets && cd -
```

Expected: `go.mod` gains two new `require` lines, `go.sum` gains corresponding entries. No code change yet.

- [ ] **Step 2: Tidy**

Run:

```bash
(cd providers/aws && go mod tidy)
```

Expected: no errors. Verify the two new modules are still listed in `providers/aws/go.mod` (running `tidy` after `get` without any importers can drop them; the import will be added in Task 3, so it's fine if `tidy` shows them as indirect for now — re-tidy at end of Task 3 will promote them).

Skip the commit for now — we'll bundle these dep changes with the rest of the work in one commit at the end of Task 8.

---

### Task 2: Add `aws.billing` and `aws.billing.budget` to the schema

**Files:**
- Modify: `providers/aws/resources/aws.lr` (insert near the top, after `aws.account`/`aws.organization` block)
- Modify: `providers/aws/resources/aws.lr.versions` (one new line per field, version `13.26.2`)

- [ ] **Step 1: Locate the insertion point**

`aws.account` ends around line 100 of `providers/aws/resources/aws.lr` (after the `aws.account.alternateContact` definition). The next block is `aws.organization` starting at line 126. Insert the new resources between them, right after the closing `}` of `aws.account.alternateContact` and before the `// AWS Organizations organization` comment that opens `aws.organization`.

- [ ] **Step 2: Add the two resource definitions**

Insert this exact block:

```
// AWS Billing
//
// Examine the AWS account's billing posture: month-to-date and recent
// historical spend (from AWS Cost Explorer), service-level breakdowns,
// forecasts for the current month, and the inventory of configured
// AWS Budgets. Cost Explorer must be enabled in the account; if not,
// cost fields return zero. Each Cost Explorer API call is billed by
// AWS at $0.01, so cost-related fields are fetched lazily and cached.
aws.billing @defaults("monthToDateCost currency budgets.length") {
  // Currency the account is billed in (e.g., USD)
  currency() string
  // Month-to-date unblended cost in `currency`
  monthToDateCost() float
  // Total unblended cost for the previous full calendar month
  lastMonthCost() float
  // Total unblended cost for the trailing 30 days
  last30DaysCost() float
  // Forecasted total unblended cost for the current calendar month:
  // month-to-date actuals plus a Cost Explorer forecast for the
  // remainder of the month
  forecastedMonthCost() float
  // Month-to-date unblended cost broken down by AWS service name
  costsByService() map[string]float
  // Previous full calendar month unblended cost broken down by AWS service name
  costsByServiceLastMonth() map[string]float
  // All AWS Budgets configured on the account
  budgets() []aws.billing.budget
}

// AWS Budget
//
// Examine a single AWS Budgets entry. The `name` field selects the budget
// (unique per account), e.g. `aws.billing.budgets.where(name == "monthly-cap")`.
// Surfaces the budget's type, time unit, limit, actual and forecasted
// spend, cost filters, and the configured notifications and subscribers.
private aws.billing.budget @defaults("name budgetType budgetLimit actualSpend") {
  // Budget name (unique within an account)
  name string
  // Account ID that owns the budget
  accountId string
  // Budget type: COST, USAGE, RI_UTILIZATION, RI_COVERAGE,
  // SAVINGS_PLANS_UTILIZATION, or SAVINGS_PLANS_COVERAGE
  budgetType string
  // Reporting period: DAILY, MONTHLY, QUARTERLY, or ANNUALLY
  timeUnit string
  // Configured budget ceiling
  budgetLimit float
  // Unit of `budgetLimit` (e.g., USD, GB, hours)
  budgetLimitUnit string
  // Actual spend/usage in the current period
  actualSpend float
  // Forecasted spend/usage for the current period
  forecastedSpend float
  // Cost filter dimensions applied to the budget
  // (e.g., "Service" -> ["Amazon EC2"], "LinkedAccount" -> ["123..."])
  costFilters map[string][]string
  // Start time of the current budget period
  periodStart time
  // End time of the current budget period
  periodEnd time
  // Last time the budget definition was updated
  lastUpdatedTime time
  // Notifications configured on the budget. Each entry has keys:
  // notificationType (ACTUAL|FORECASTED), comparisonOperator, threshold,
  // thresholdType (PERCENTAGE|ABSOLUTE_VALUE), notificationState
  // (OK|ALARM), and subscribers ([{type, address}])
  notifications() []dict
}

```

- [ ] **Step 3: Add `aws.lr.versions` entries at `13.26.2`**

The `.lr.versions` file is sorted alphabetically. Run this to splice in the new entries in the right place:

```bash
sort -o providers/aws/resources/aws.lr.versions <(cat providers/aws/resources/aws.lr.versions; cat <<'EOF'
aws.billing 13.26.2
aws.billing.budgets 13.26.2
aws.billing.currency 13.26.2
aws.billing.monthToDateCost 13.26.2
aws.billing.lastMonthCost 13.26.2
aws.billing.last30DaysCost 13.26.2
aws.billing.forecastedMonthCost 13.26.2
aws.billing.costsByService 13.26.2
aws.billing.costsByServiceLastMonth 13.26.2
aws.billing.budget 13.26.2
aws.billing.budget.name 13.26.2
aws.billing.budget.accountId 13.26.2
aws.billing.budget.budgetType 13.26.2
aws.billing.budget.timeUnit 13.26.2
aws.billing.budget.budgetLimit 13.26.2
aws.billing.budget.budgetLimitUnit 13.26.2
aws.billing.budget.actualSpend 13.26.2
aws.billing.budget.forecastedSpend 13.26.2
aws.billing.budget.costFilters 13.26.2
aws.billing.budget.periodStart 13.26.2
aws.billing.budget.periodEnd 13.26.2
aws.billing.budget.lastUpdatedTime 13.26.2
aws.billing.budget.notifications 13.26.2
EOF
)
```

Verify with:

```bash
grep "^aws.billing" providers/aws/resources/aws.lr.versions
```

Expected: 23 lines (1 namespace + 8 fields on `aws.billing`, 1 sub-resource + 13 fields on `aws.billing.budget`), all at version `13.26.2`.

No commit yet — the build is broken until Task 4 lands.

---

### Task 3: Add the AWS connection client constructors

**Files:**
- Modify: `providers/aws/connection/clients.go` (append two new methods at the end of the file)

Both Cost Explorer and Budgets are us-east-1-only services. The constructor ignores any passed-in region and pins to us-east-1.

- [ ] **Step 1: Add the imports**

In the `import (` block at the top of `providers/aws/connection/clients.go`, add (keep the block sorted):

```go
	"github.com/aws/aws-sdk-go-v2/service/budgets"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
```

- [ ] **Step 2: Append the two constructors at the end of `clients.go`**

```go
// CostExplorer returns a Cost Explorer client. Cost Explorer is a global
// service whose endpoint lives only in us-east-1, so the region argument
// is ignored.
func (t *AwsConnection) CostExplorer() *costexplorer.Client {
	cacheVal := "_costexplorer_"

	c, ok := t.clientcache.Load(cacheVal)
	if ok {
		return c.Data.(*costexplorer.Client)
	}

	cfg := t.cfg.Copy()
	cfg.Region = "us-east-1"
	client := costexplorer.NewFromConfig(cfg)

	t.clientcache.Store(cacheVal, &CacheEntry{Data: client})
	return client
}

// Budgets returns an AWS Budgets client. Budgets is a global service whose
// endpoint lives only in us-east-1, so the region argument is ignored.
func (t *AwsConnection) Budgets() *budgets.Client {
	cacheVal := "_budgets_"

	c, ok := t.clientcache.Load(cacheVal)
	if ok {
		return c.Data.(*budgets.Client)
	}

	cfg := t.cfg.Copy()
	cfg.Region = "us-east-1"
	client := budgets.NewFromConfig(cfg)

	t.clientcache.Store(cacheVal, &CacheEntry{Data: client})
	return client
}
```

- [ ] **Step 3: Re-tidy provider deps**

Run:

```bash
(cd providers/aws && go mod tidy)
```

Expected: the two new modules promote from indirect to direct `require` lines in `providers/aws/go.mod`.

- [ ] **Step 4: Verify the connection package builds**

```bash
(cd providers/aws && go build ./connection/...)
```

Expected: clean exit.

---

### Task 4: Generate scaffolding (first codegen pass)

**Files:**
- Modify (auto-generated): `providers/aws/resources/aws.lr.go`
- Modify (auto-generated): `providers/aws/resources/aws.resources.json`

- [ ] **Step 1: Build `mqlr` if needed**

```bash
[ -x ./mqlr ] || make providers/mqlr
```

Expected: `mqlr` binary exists at repo root.

- [ ] **Step 2: Run codegen**

```bash
./mqlr generate providers/aws/resources/aws.lr --dist providers/aws/resources
```

Expected: clean exit. `git status` shows modifications to `aws.lr.go` (and `aws.resources.json`).

- [ ] **Step 3: Confirm the new types exist in the generated file**

```bash
grep -E "mqlAwsBilling\b|mqlAwsBillingBudget\b" providers/aws/resources/aws.lr.go | head
```

Expected: at least four lines, including the struct declarations for `mqlAwsBilling` and `mqlAwsBillingBudget`.

Build will still fail until Task 5 adds the Go implementation — proceed directly to Task 5.

---

### Task 5: Implement `providers/aws/resources/aws_billing.go`

**Files:**
- Create: `providers/aws/resources/aws_billing.go`

This file implements `id()` accessors, lazy-loaders for all the cost methods, and `budgets()`. It also declares the `mqlAwsBillingInternal` struct that the codegen will embed in a second pass (Task 6).

- [ ] **Step 1: Create the file**

Create `providers/aws/resources/aws_billing.go` with this content:

```go
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
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// --- aws.billing -------------------------------------------------------------

type mqlAwsBillingInternal struct {
	// month-to-date GetCostAndUsage(GroupBy=SERVICE)
	mtdLock        sync.Mutex
	mtdFetched     bool
	mtdTotal       float64
	mtdByService   map[string]any // map[string]float64 stored as any for llx
	mtdCurrency    string
	mtdUnavailable bool // true when Cost Explorer is not opted in / access denied

	// previous full calendar month GetCostAndUsage(GroupBy=SERVICE)
	lastMonthLock        sync.Mutex
	lastMonthFetched     bool
	lastMonthTotal       float64
	lastMonthByService   map[string]any
	lastMonthUnavailable bool

	// trailing 30 days GetCostAndUsage (no groupBy)
	last30Lock        sync.Mutex
	last30Fetched     bool
	last30Total       float64
	last30Unavailable bool

	// month-end forecast = mtd + GetCostForecast(tomorrow..first-of-next-month)
	forecastLock        sync.Mutex
	forecastFetched     bool
	forecastAmount      float64
	forecastUnavailable bool
}

func (a *mqlAwsBilling) id() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return "aws.billing/" + conn.AccountId(), nil
}

// monthRange returns ISO yyyy-MM-dd Start/End strings for the current
// calendar month, where Start is the first day of the month and End is
// "today + 1 day" (Cost Explorer End is exclusive).
func monthRange(now time.Time) (string, string) {
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := now.UTC().AddDate(0, 0, 1)
	return start.Format("2006-01-02"), end.Format("2006-01-02")
}

// lastMonthRange returns Start (1st of previous month) and End (1st of current
// month, exclusive) ISO yyyy-MM-dd strings.
func lastMonthRange(now time.Time) (string, string) {
	first := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	start := first.AddDate(0, -1, 0)
	return start.Format("2006-01-02"), first.Format("2006-01-02")
}

// trailing30Range returns ISO Start = now-30d, End = now+1d (exclusive).
func trailing30Range(now time.Time) (string, string) {
	end := now.UTC().AddDate(0, 0, 1)
	start := end.AddDate(0, 0, -31) // 30 full days back from end
	return start.Format("2006-01-02"), end.Format("2006-01-02")
}

// forecastRange returns ISO Start = tomorrow, End = first day of next month.
// Returns empty strings if today is the last day of the month (no future days
// in the current month to forecast).
func forecastRange(now time.Time) (string, string) {
	tomorrow := now.UTC().AddDate(0, 0, 1)
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

// fetchMonthToDate populates the mtd* fields. Safe to call repeatedly; only
// the first call hits the API.
func (a *mqlAwsBilling) fetchMonthToDate() error {
	if a.mtdFetched {
		return nil
	}
	a.mtdLock.Lock()
	defer a.mtdLock.Unlock()
	if a.mtdFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CostExplorer()
	start, end := monthRange(time.Now())

	a.mtdByService = map[string]any{}
	resp, err := svc.GetCostAndUsage(context.TODO(), &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &cetypes.DateInterval{Start: aws.String(start), End: aws.String(end)},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{"UnblendedCost"},
		GroupBy: []cetypes.GroupDefinition{
			{Type: cetypes.GroupDefinitionTypeDimension, Key: aws.String("SERVICE")},
		},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Debug().Msg("aws.billing: Cost Explorer access denied for month-to-date")
			a.mtdUnavailable = true
			a.mtdFetched = true
			return nil
		}
		return err
	}

	for _, r := range resp.ResultsByTime {
		for _, g := range r.Groups {
			if len(g.Keys) == 0 {
				continue
			}
			service := g.Keys[0]
			metric, ok := g.Metrics["UnblendedCost"]
			if !ok {
				continue
			}
			amt := parseCEAmount(metric.Amount)
			a.mtdByService[service] = amt
			a.mtdTotal += amt
			if a.mtdCurrency == "" && metric.Unit != nil {
				a.mtdCurrency = *metric.Unit
			}
		}
		// Fall back to top-level Total when no groups (rare).
		if len(r.Groups) == 0 {
			if metric, ok := r.Total["UnblendedCost"]; ok {
				a.mtdTotal = parseCEAmount(metric.Amount)
				if a.mtdCurrency == "" && metric.Unit != nil {
					a.mtdCurrency = *metric.Unit
				}
			}
		}
	}

	a.mtdFetched = true
	return nil
}

// fetchLastMonth populates the lastMonth* fields. Same pattern as fetchMonthToDate.
func (a *mqlAwsBilling) fetchLastMonth() error {
	if a.lastMonthFetched {
		return nil
	}
	a.lastMonthLock.Lock()
	defer a.lastMonthLock.Unlock()
	if a.lastMonthFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CostExplorer()
	start, end := lastMonthRange(time.Now())

	a.lastMonthByService = map[string]any{}
	resp, err := svc.GetCostAndUsage(context.TODO(), &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &cetypes.DateInterval{Start: aws.String(start), End: aws.String(end)},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{"UnblendedCost"},
		GroupBy: []cetypes.GroupDefinition{
			{Type: cetypes.GroupDefinitionTypeDimension, Key: aws.String("SERVICE")},
		},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Debug().Msg("aws.billing: Cost Explorer access denied for last month")
			a.lastMonthUnavailable = true
			a.lastMonthFetched = true
			return nil
		}
		return err
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
			a.lastMonthByService[g.Keys[0]] = amt
			a.lastMonthTotal += amt
		}
		if len(r.Groups) == 0 {
			if metric, ok := r.Total["UnblendedCost"]; ok {
				a.lastMonthTotal = parseCEAmount(metric.Amount)
			}
		}
	}

	a.lastMonthFetched = true
	return nil
}

func (a *mqlAwsBilling) fetchLast30Days() error {
	if a.last30Fetched {
		return nil
	}
	a.last30Lock.Lock()
	defer a.last30Lock.Unlock()
	if a.last30Fetched {
		return nil
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
		if Is400AccessDeniedError(err) {
			log.Debug().Msg("aws.billing: Cost Explorer access denied for last 30 days")
			a.last30Unavailable = true
			a.last30Fetched = true
			return nil
		}
		return err
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
// Depends on fetchMonthToDate succeeding (or being unavailable).
func (a *mqlAwsBilling) fetchForecast() error {
	if a.forecastFetched {
		return nil
	}
	a.forecastLock.Lock()
	defer a.forecastLock.Unlock()
	if a.forecastFetched {
		return nil
	}

	if err := a.fetchMonthToDate(); err != nil {
		return err
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CostExplorer()
	start, end := forecastRange(time.Now())
	if start == "" {
		// On the last day of the month there are no future days to forecast.
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
		if Is400AccessDeniedError(err) {
			log.Debug().Msg("aws.billing: Cost Explorer access denied for forecast")
			a.forecastUnavailable = true
			a.forecastFetched = true
			return nil
		}
		// CE returns "Cost Explorer is unable to produce a meaningful forecast"
		// for accounts with little usage history; treat as zero forecast.
		log.Debug().Err(err).Msg("aws.billing: cost forecast unavailable")
		a.forecastUnavailable = true
		a.forecastFetched = true
		return nil
	}

	a.forecastAmount = a.mtdTotal + parseCEAmount(resp.Total.Amount)
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
			if Is400AccessDeniedError(err) {
				log.Debug().Msg("aws.billing: Budgets access denied")
				return res, nil
			}
			return nil, err
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

// budgetSpend extracts (amount, unit) from a Budgets Spend struct, treating
// nil pointers as zero / empty.
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
// map[string]any layout llx.MapData expects.
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
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
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

```

- [ ] **Step 2: Verify it parses**

```bash
(cd providers/aws && go vet ./resources/...)
```

Expected: vet passes. If you see "method has wrong signature" errors, the codegen expectations don't match — re-check method names/types against the generated `aws.lr.go`.

Do NOT commit yet — Task 6 regenerates with the Internal struct.

---

### Task 6: Second codegen pass (embed `mqlAwsBillingInternal`)

**Files:**
- Modify (auto-generated): `providers/aws/resources/aws.lr.go`

- [ ] **Step 1: Re-run codegen**

```bash
./mqlr generate providers/aws/resources/aws.lr --dist providers/aws/resources
```

Expected: clean exit. `git diff providers/aws/resources/aws.lr.go` should show `mqlAwsBillingInternal` now embedded into the generated `mqlAwsBilling` struct.

- [ ] **Step 2: Verify embedding**

```bash
grep -A 3 "^type mqlAwsBilling struct" providers/aws/resources/aws.lr.go
```

Expected output includes a line like `mqlAwsBillingInternal` inside the struct body.

---

### Task 7: Build, install, regenerate permissions

**Files:**
- Modify (auto-generated): `providers/aws/resources/aws.permissions.json`

- [ ] **Step 1: Build the provider**

```bash
make providers/build/aws
```

Expected: clean exit, no compile errors. This step regenerates `providers/aws/resources/aws.permissions.json`. If the build fails with a missing-method or wrong-signature error against `mqlAwsBilling` or `mqlAwsBillingBudget`, return to Task 5 and fix the signature mismatch.

- [ ] **Step 2: Confirm `aws.permissions.json` picked up the new perms**

```bash
grep -E "ce:Get(CostAndUsage|CostForecast)|budgets:Describe" providers/aws/resources/aws.permissions.json
```

Expected: at least these five lines:

```
ce:GetCostAndUsage
ce:GetCostForecast
budgets:DescribeBudgets
budgets:DescribeNotificationsForBudget
budgets:DescribeSubscribersForNotification
```

If the permissions file doesn't include them, the build's permissions scan didn't see the SDK calls. Verify that `aws_billing.go` calls them by exact method name (`svc.GetCostAndUsage`, `svc.GetCostForecast`, paginators `DescribeBudgetsPaginator` etc.).

- [ ] **Step 3: Install the provider locally**

```bash
make providers/install/aws
```

Expected: `~/.config/mondoo/providers/aws/aws` is updated.

---

### Task 8: Interactive verification

**Files:** none modified.

- [ ] **Step 1: Sanity-check the schema is queryable**

```bash
mql run aws -c "aws.billing { currency }"
```

Expected: either a numeric/string result or — if the test account has CE disabled — `currency` returns `"USD"` and no scan error. Either outcome is acceptable; the failure mode is "scan aborts with an error".

- [ ] **Step 2: Cost fields**

```bash
mql run aws -c "aws.billing { monthToDateCost lastMonthCost last30DaysCost forecastedMonthCost }"
```

Expected: four floats (possibly all `0` on a CE-disabled account; non-zero on an active account). No error.

- [ ] **Step 3: Service breakdown**

```bash
mql run aws -c "aws.billing.costsByService"
```

Expected: a `{service: cost}` map. May be empty if CE is unavailable.

- [ ] **Step 4: Budgets**

```bash
mql run aws -c "aws.billing.budgets { name budgetType budgetLimit actualSpend notifications.length }"
```

Expected: a list (possibly empty if no budgets configured). Each entry has the expected fields. No scan error.

- [ ] **Step 5: Notifications and subscribers (only if at least one budget exists)**

```bash
mql run aws -c "aws.billing.budgets.first.notifications"
```

Expected: a list of dicts each with keys `notificationType`, `comparisonOperator`, `threshold`, `thresholdType`, `notificationState`, `subscribers`.

If any of these steps fail with a scan error (rather than empty/zero data), investigate before continuing.

---

### Task 9: Pre-PR checks + commit + PR

**Files:** all from previous tasks.

- [ ] **Step 1: gofmt**

```bash
gofmt -w providers/aws/resources/aws_billing.go providers/aws/connection/clients.go
```

- [ ] **Step 2: Confirm codegen is up to date**

```bash
./mqlr generate providers/aws/resources/aws.lr --dist providers/aws/resources
git diff --stat providers/aws/resources/aws.lr.go providers/aws/resources/aws.resources.json
```

Expected: no diff after the regenerate (already up to date from Task 6).

- [ ] **Step 3: Confirm `go mod tidy` is clean**

```bash
(cd providers/aws && go mod tidy)
git diff providers/aws/go.mod providers/aws/go.sum
```

Expected: no diff.

- [ ] **Step 4: Lint the provider**

```bash
(cd providers/aws && go vet ./...)
```

Expected: clean exit.

- [ ] **Step 5: Stage and commit**

```bash
git add \
  providers/aws/go.mod providers/aws/go.sum \
  providers/aws/connection/clients.go \
  providers/aws/resources/aws.lr \
  providers/aws/resources/aws.lr.versions \
  providers/aws/resources/aws.lr.go \
  providers/aws/resources/aws.resources.json \
  providers/aws/resources/aws.permissions.json \
  providers/aws/resources/aws_billing.go

git commit -m "$(cat <<'EOF'
✨ aws: add aws.billing resource for Cost Explorer and Budgets

Adds an `aws.billing` namespace surfacing month-to-date, last-month, and
trailing-30-day unblended spend plus a Cost Explorer forecast for the
current month, with a per-service breakdown. Adds `aws.billing.budget` for
configured AWS Budgets, including thresholds, actuals, forecasts, cost
filters, and notification subscribers.

Cost Explorer charges $0.01 per request, so a single GetCostAndUsage call
per window backs both the total and the service breakdown, cached on first
access.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 6: Push and open a PR**

```bash
git push -u origin HEAD
gh pr create --title "✨ aws: add aws.billing resource for Cost Explorer and Budgets" --body "$(cat <<'EOF'
## Summary
- New `aws.billing` MQL resource exposing month-to-date, last-month, last-30-day spend, current-month forecast, and per-service cost breakdowns via AWS Cost Explorer
- New `aws.billing.budget` sub-resource exposing each configured AWS Budget (type, limit, actuals, forecast, cost filters, notifications + subscribers)
- Cost Explorer and Budgets are both us-east-1-only; both clients are pinned in `providers/aws/connection/clients.go`
- Cost Explorer charges $0.01 per request — one `GetCostAndUsage` call per window backs both totals and per-service breakdowns, cached via `mqlAwsBillingInternal` with double-check locking
- Graceful degradation when Cost Explorer is not opted in (`AccessDenied` → zero values, debug log, scan continues)

Design: `docs/superpowers/specs/2026-05-19-aws-billing-resource-design.md`

## Test plan
- [ ] `mql run aws -c "aws.billing { currency monthToDateCost lastMonthCost last30DaysCost forecastedMonthCost }"` against an account with Cost Explorer enabled
- [ ] `mql run aws -c "aws.billing.costsByService"` returns a non-empty map on an active account
- [ ] `mql run aws -c "aws.billing.budgets { name budgetType budgetLimit actualSpend forecastedSpend notifications }"` returns configured budgets
- [ ] Same queries against a CE-disabled account return zero / empty without aborting the scan

🤖 Generated with [Claude Code](https://claude.com/product/claude-code)
EOF
)"
```

Expected: PR URL printed to stdout; share it with the user.
