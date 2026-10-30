// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// usageReportDays is how many whole UTC days before today the usage and cost
// reports cover. Today's partial day is always included on top.
const usageReportDays = 7

// usageBucketLimit asks for enough daily buckets to cover the window in one
// page: seven whole days plus today.
const usageBucketLimit = usageReportDays + 1

// usageGroupBy splits each usage report by who used the API and from where.
// Every usage type the report covers accepts these four dimensions, and the
// API leaves a dimension null in every row unless the request groups by it.
var usageGroupBy = []string{"project_id", "user_id", "api_key_id", "model"}

// costGroupBy splits the cost report by project and line item.
var costGroupBy = []string{"project_id", "line_item"}

// usageWindowStart returns the Unix time of midnight UTC usageReportDays days
// before now, the start of the usage and cost report window.
func usageWindowStart(now time.Time) int64 {
	y, m, d := now.UTC().AddDate(0, 0, -usageReportDays).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Unix()
}

// usageRow is one row of a usage report, whatever usage type it came from.
type usageRow struct {
	usageType         string
	startTime         int64
	endTime           int64
	projectID         string
	userID            string
	apiKeyID          string
	model             string
	requests          int64
	inputTokens       *int64
	cachedInputTokens *int64
	outputTokens      *int64
}

// id keys a usage row. The report is grouped by every dimension below, so
// together they identify a row. A null dimension reads as the empty string,
// which no real identifier equals.
func (u usageRow) id() string {
	return fmt.Sprintf("usage/%s/%d/%s/%s/%s/%s", u.usageType, u.startTime, u.projectID, u.userID, u.apiKeyID, u.model)
}

// reportPage fetches one page of a usage or cost report. An empty cursor asks
// for the first page.
type reportPage[T any] func(cursor string) (rows []T, hasMore bool, next string, err error)

// walkReport collects every page of a usage or cost report. It stops when the
// API says there is no more, and also when a cursor repeats, since an
// endpoint that keeps handing back the same cursor would otherwise be asked
// for the same page forever.
func walkReport[T any](fetch reportPage[T]) ([]T, error) {
	var all []T
	seen := map[string]struct{}{}
	cursor := ""
	for {
		rows, hasMore, next, err := fetch(cursor)
		if err != nil {
			return nil, err
		}
		all = append(all, rows...)
		if !hasMore || next == "" {
			return all, nil
		}
		if _, repeated := seen[next]; repeated {
			return all, nil
		}
		seen[next] = struct{}{}
		cursor = next
	}
}

// usageEndpoints returns one page fetcher per usage type the usage report
// covers. Each usage type is its own endpoint with its own response type,
// so each maps its rows onto usageRow here.
func usageEndpoints(ctx context.Context, client *openai.Client, start int64) []reportPage[usageRow] {
	usage := client.Admin.Organization.Usage
	return []reportPage[usageRow]{
		func(cursor string) ([]usageRow, bool, string, error) {
			params := openai.AdminOrganizationUsageCompletionsParams{
				StartTime: start, Limit: openai.Int(usageBucketLimit), GroupBy: usageGroupBy,
				BucketWidth: openai.AdminOrganizationUsageCompletionsParamsBucketWidth1d,
			}
			if cursor != "" {
				params.Page = openai.String(cursor)
			}
			resp, err := usage.Completions(ctx, params)
			if err != nil {
				return nil, false, "", err
			}
			var rows []usageRow
			for _, b := range resp.Data {
				for _, r := range b.Results {
					rows = append(rows, usageRow{
						usageType: "completions", startTime: b.StartTime, endTime: b.EndTime,
						projectID: r.ProjectID, userID: r.UserID, apiKeyID: r.APIKeyID, model: r.Model,
						requests:          r.NumModelRequests,
						inputTokens:       &r.InputTokens,
						cachedInputTokens: &r.InputCachedTokens,
						outputTokens:      &r.OutputTokens,
					})
				}
			}
			return rows, resp.HasMore, resp.NextPage, nil
		},
		func(cursor string) ([]usageRow, bool, string, error) {
			params := openai.AdminOrganizationUsageEmbeddingsParams{
				StartTime: start, Limit: openai.Int(usageBucketLimit), GroupBy: usageGroupBy,
				BucketWidth: openai.AdminOrganizationUsageEmbeddingsParamsBucketWidth1d,
			}
			if cursor != "" {
				params.Page = openai.String(cursor)
			}
			resp, err := usage.Embeddings(ctx, params)
			if err != nil {
				return nil, false, "", err
			}
			var rows []usageRow
			for _, b := range resp.Data {
				for _, r := range b.Results {
					rows = append(rows, usageRow{
						usageType: "embeddings", startTime: b.StartTime, endTime: b.EndTime,
						projectID: r.ProjectID, userID: r.UserID, apiKeyID: r.APIKeyID, model: r.Model,
						requests:    r.NumModelRequests,
						inputTokens: &r.InputTokens,
					})
				}
			}
			return rows, resp.HasMore, resp.NextPage, nil
		},
		func(cursor string) ([]usageRow, bool, string, error) {
			params := openai.AdminOrganizationUsageModerationsParams{
				StartTime: start, Limit: openai.Int(usageBucketLimit), GroupBy: usageGroupBy,
				BucketWidth: openai.AdminOrganizationUsageModerationsParamsBucketWidth1d,
			}
			if cursor != "" {
				params.Page = openai.String(cursor)
			}
			resp, err := usage.Moderations(ctx, params)
			if err != nil {
				return nil, false, "", err
			}
			var rows []usageRow
			for _, b := range resp.Data {
				for _, r := range b.Results {
					rows = append(rows, usageRow{
						usageType: "moderations", startTime: b.StartTime, endTime: b.EndTime,
						projectID: r.ProjectID, userID: r.UserID, apiKeyID: r.APIKeyID, model: r.Model,
						requests:    r.NumModelRequests,
						inputTokens: &r.InputTokens,
					})
				}
			}
			return rows, resp.HasMore, resp.NextPage, nil
		},
		func(cursor string) ([]usageRow, bool, string, error) {
			params := openai.AdminOrganizationUsageImagesParams{
				StartTime: start, Limit: openai.Int(usageBucketLimit), GroupBy: usageGroupBy,
				BucketWidth: openai.AdminOrganizationUsageImagesParamsBucketWidth1d,
			}
			if cursor != "" {
				params.Page = openai.String(cursor)
			}
			resp, err := usage.Images(ctx, params)
			if err != nil {
				return nil, false, "", err
			}
			var rows []usageRow
			for _, b := range resp.Data {
				for _, r := range b.Results {
					rows = append(rows, usageRow{
						usageType: "images", startTime: b.StartTime, endTime: b.EndTime,
						projectID: r.ProjectID, userID: r.UserID, apiKeyID: r.APIKeyID, model: r.Model,
						requests: r.NumModelRequests,
					})
				}
			}
			return rows, resp.HasMore, resp.NextPage, nil
		},
		func(cursor string) ([]usageRow, bool, string, error) {
			params := openai.AdminOrganizationUsageAudioSpeechesParams{
				StartTime: start, Limit: openai.Int(usageBucketLimit), GroupBy: usageGroupBy,
				BucketWidth: openai.AdminOrganizationUsageAudioSpeechesParamsBucketWidth1d,
			}
			if cursor != "" {
				params.Page = openai.String(cursor)
			}
			resp, err := usage.AudioSpeeches(ctx, params)
			if err != nil {
				return nil, false, "", err
			}
			var rows []usageRow
			for _, b := range resp.Data {
				for _, r := range b.Results {
					rows = append(rows, usageRow{
						usageType: "audio_speeches", startTime: b.StartTime, endTime: b.EndTime,
						projectID: r.ProjectID, userID: r.UserID, apiKeyID: r.APIKeyID, model: r.Model,
						requests: r.NumModelRequests,
					})
				}
			}
			return rows, resp.HasMore, resp.NextPage, nil
		},
		func(cursor string) ([]usageRow, bool, string, error) {
			params := openai.AdminOrganizationUsageAudioTranscriptionsParams{
				StartTime: start, Limit: openai.Int(usageBucketLimit), GroupBy: usageGroupBy,
				BucketWidth: openai.AdminOrganizationUsageAudioTranscriptionsParamsBucketWidth1d,
			}
			if cursor != "" {
				params.Page = openai.String(cursor)
			}
			resp, err := usage.AudioTranscriptions(ctx, params)
			if err != nil {
				return nil, false, "", err
			}
			var rows []usageRow
			for _, b := range resp.Data {
				for _, r := range b.Results {
					rows = append(rows, usageRow{
						usageType: "audio_transcriptions", startTime: b.StartTime, endTime: b.EndTime,
						projectID: r.ProjectID, userID: r.UserID, apiKeyID: r.APIKeyID, model: r.Model,
						requests: r.NumModelRequests,
					})
				}
			}
			return rows, resp.HasMore, resp.NextPage, nil
		},
	}
}

// fetchUsageRows reads every usage type the usage report covers.
func fetchUsageRows(ctx context.Context, client *openai.Client, start int64) ([]usageRow, error) {
	var all []usageRow
	for _, fetch := range usageEndpoints(ctx, client, start) {
		rows, err := walkReport(fetch)
		if err != nil {
			return nil, err
		}
		all = append(all, rows...)
	}
	return all, nil
}

// costRow is one row of the cost report.
type costRow struct {
	startTime    int64
	endTime      int64
	projectID    string
	lineItem     string
	amount       float64
	currency     string
	quantity     *float64
	quantityUnit *string
}

// id keys a cost row. The report is grouped by project and line item, so
// those two identify a row within a bucket.
func (c costRow) id() string {
	return fmt.Sprintf("cost/%d/%s/%s", c.startTime, c.projectID, c.lineItem)
}

func costPages(ctx context.Context, client *openai.Client, start int64) reportPage[costRow] {
	return func(cursor string) ([]costRow, bool, string, error) {
		params := openai.AdminOrganizationUsageCostsParams{
			StartTime: start, Limit: openai.Int(usageBucketLimit), GroupBy: costGroupBy,
			BucketWidth: openai.AdminOrganizationUsageCostsParamsBucketWidth1d,
		}
		if cursor != "" {
			params.Page = openai.String(cursor)
		}
		resp, err := client.Admin.Organization.Usage.Costs(ctx, params)
		if err != nil {
			return nil, false, "", err
		}
		var rows []costRow
		for _, b := range resp.Data {
			for _, r := range b.Results {
				row := costRow{
					startTime: b.StartTime, endTime: b.EndTime,
					projectID: r.ProjectID, lineItem: r.LineItem,
					amount: r.Amount.Value, currency: r.Amount.Currency,
					quantityUnit: emptyToNil(string(r.QuantityUnit)),
				}
				if r.JSON.Quantity.Valid() {
					q := r.Quantity
					row.quantity = &q
				}
				rows = append(rows, row)
			}
		}
		return rows, resp.HasMore, resp.NextPage, nil
	}
}

// classifyReportError turns a refusal of an admin read (the usage or cost
// report, the external key list) into a classified error. Anything else is
// returned with context and no kind.
func classifyReportError(err error, report string) error {
	wrapped := fmt.Errorf("failed to read the %s: %w", report, err)
	if apiErr, ok := errors.AsType[*openai.Error](err); ok {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized:
			return llx.Unauthenticated(wrapped)
		case http.StatusForbidden:
			return llx.Forbidden(wrapped)
		}
	}
	return wrapped
}

// openai.usageEntry

type mqlOpenaiUsageEntryInternal struct {
	cacheProjectId string
	cacheUserId    string
	cacheApiKeyId  string
}

func (r *mqlOpenai) usageReport() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.usageReport")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}

	rows, err := fetchUsageRows(context.Background(), client, usageWindowStart(time.Now()))
	if err != nil {
		return nil, classifyReportError(err, "usage report")
	}

	res := make([]any, 0, len(rows))
	for _, row := range rows {
		mqlEntry, err := CreateResource(r.MqlRuntime, "openai.usageEntry", usageEntryArgs(row))
		if err != nil {
			return nil, err
		}
		entry := mqlEntry.(*mqlOpenaiUsageEntry)
		entry.cacheProjectId = row.projectID
		entry.cacheUserId = row.userID
		entry.cacheApiKeyId = row.apiKeyID
		res = append(res, mqlEntry)
	}
	return res, nil
}

// usageEntryArgs maps a usage row onto resource arguments. A token count the
// usage type does not measure reads as null rather than as zero, which would
// claim a measurement the report never made.
func usageEntryArgs(row usageRow) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":              llx.StringData(row.id()),
		"startingAt":        llx.TimeDataPtr(unixToNullableTime(row.startTime)),
		"endingAt":          llx.TimeDataPtr(unixToNullableTime(row.endTime)),
		"usageType":         llx.StringData(row.usageType),
		"model":             llx.StringData(row.model),
		"requests":          llx.IntData(row.requests),
		"inputTokens":       llx.IntDataPtr(row.inputTokens),
		"cachedInputTokens": llx.IntDataPtr(row.cachedInputTokens),
		"outputTokens":      llx.IntDataPtr(row.outputTokens),
	}
}

func (r *mqlOpenaiUsageEntry) project() (*mqlOpenaiProject, error) {
	if r.cacheProjectId == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	project, err := resolveProject(r.MqlRuntime, r.cacheProjectId)
	if err != nil {
		return nil, err
	}
	if project == nil {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

func (r *mqlOpenaiUsageEntry) user() (*mqlOpenaiOrganizationUser, error) {
	if r.cacheUserId == "" {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	user, err := findOrganizationUser(r.MqlRuntime, r.cacheUserId)
	if err != nil {
		return nil, err
	}
	if user == nil {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return user, nil
}

// apiKey resolves the key through its project's cached key list, so every
// row of a project shares one key listing.
func (r *mqlOpenaiUsageEntry) apiKey() (*mqlOpenaiProjectApiKey, error) {
	if r.cacheApiKeyId == "" || r.cacheProjectId == "" {
		r.ApiKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	project, err := resolveProject(r.MqlRuntime, r.cacheProjectId)
	if err != nil {
		return nil, err
	}
	if project == nil {
		r.ApiKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	keys := project.GetApiKeys()
	if keys.Error != nil {
		return nil, keys.Error
	}
	for i := range keys.Data {
		if k, ok := keys.Data[i].(*mqlOpenaiProjectApiKey); ok && k.Id.Data == r.cacheApiKeyId {
			return k, nil
		}
	}
	r.ApiKey.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// organizationUsageFor returns the organization's usage report entries whose
// caller, as picked by callerID, is id. It reads the organization's cached
// report, so every key and member shares one report fetch.
func organizationUsageFor(runtime *plugin.Runtime, id string, callerID func(*mqlOpenaiUsageEntry) string) ([]any, error) {
	obj, err := CreateResource(runtime, "openai", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	report := obj.(*mqlOpenai).GetUsageReport()
	if report.Error != nil {
		return nil, report.Error
	}
	return usageEntriesFor(report.Data, id, callerID), nil
}

// usageEntriesFor filters usage report entries down to those whose caller, as
// picked by callerID, is id. An empty id matches nothing, so usage the report
// attributes to no key or member is never attributed to one.
func usageEntriesFor(entries []any, id string, callerID func(*mqlOpenaiUsageEntry) string) []any {
	res := []any{}
	if id == "" {
		return res
	}
	for _, e := range entries {
		if entry, ok := e.(*mqlOpenaiUsageEntry); ok && callerID(entry) == id {
			res = append(res, entry)
		}
	}
	return res
}

func (r *mqlOpenaiProjectApiKey) usageReport() ([]any, error) {
	return organizationUsageFor(r.MqlRuntime, r.Id.Data,
		func(e *mqlOpenaiUsageEntry) string { return e.cacheApiKeyId })
}

func (r *mqlOpenaiOrganizationUser) usageReport() ([]any, error) {
	return organizationUsageFor(r.MqlRuntime, r.Id.Data,
		func(e *mqlOpenaiUsageEntry) string { return e.cacheUserId })
}

// openai.costEntry

type mqlOpenaiCostEntryInternal struct {
	cacheProjectId string
}

func (r *mqlOpenai) costReport() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.costReport")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}

	rows, err := walkReport(costPages(context.Background(), client, usageWindowStart(time.Now())))
	if err != nil {
		return nil, classifyReportError(err, "cost report")
	}

	res := make([]any, 0, len(rows))
	for _, row := range rows {
		mqlEntry, err := CreateResource(r.MqlRuntime, "openai.costEntry", costEntryArgs(row))
		if err != nil {
			return nil, err
		}
		mqlEntry.(*mqlOpenaiCostEntry).cacheProjectId = row.projectID
		res = append(res, mqlEntry)
	}
	return res, nil
}

func costEntryArgs(row costRow) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":         llx.StringData(row.id()),
		"startingAt":   llx.TimeDataPtr(unixToNullableTime(row.startTime)),
		"endingAt":     llx.TimeDataPtr(unixToNullableTime(row.endTime)),
		"amount":       llx.FloatData(row.amount),
		"currency":     llx.StringData(row.currency),
		"lineItem":     llx.StringData(row.lineItem),
		"quantity":     llx.FloatDataPtr(row.quantity),
		"quantityUnit": llx.StringDataPtr(row.quantityUnit),
	}
}

func (r *mqlOpenaiCostEntry) project() (*mqlOpenaiProject, error) {
	if r.cacheProjectId == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	project, err := resolveProject(r.MqlRuntime, r.cacheProjectId)
	if err != nil {
		return nil, err
	}
	if project == nil {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}
