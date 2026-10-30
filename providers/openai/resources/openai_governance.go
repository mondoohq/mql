// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// isNotFound reports whether the API answered "this is not configured". The
// spend limit and model policy endpoints return 404 when nothing has been set,
// which is a legitimate absence rather than a failure, and the resulting fields
// have to read as null instead of zero.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if apiErr, ok := errors.AsType[*openai.Error](err); ok {
		return apiErr.StatusCode == 404
	}
	return false
}

// nullableInt returns a pointer to v when the API actually sent the field, and
// nil when it did not. Rate limit allowances that do not apply to a model are
// absent from the response rather than zero, so reporting them as 0 would
// invent a ceiling of zero.
func nullableInt(v int64, present bool) *int64 {
	if !present {
		return nil
	}
	return &v
}

type mqlOpenaiInternal struct {
	spendLimitFetched atomic.Bool
	spendLimitLock    sync.Mutex
	spendLimit        *openai.OrganizationSpendLimit
}

// fetchSpendLimit reads the organization hard spend limit once and shares it
// across the four fields derived from it. A nil result with a nil error means
// no limit is configured.
func (r *mqlOpenai) fetchSpendLimit() (*openai.OrganizationSpendLimit, error) {
	if r.spendLimitFetched.Load() {
		return r.spendLimit, nil
	}
	r.spendLimitLock.Lock()
	defer r.spendLimitLock.Unlock()
	if r.spendLimitFetched.Load() {
		return r.spendLimit, nil
	}

	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.spendLimit")
	if err != nil {
		return nil, err
	}
	if client == nil {
		r.spendLimitFetched.Store(true)
		return nil, nil
	}

	limit, err := client.Admin.Organization.SpendLimit.Get(context.Background())
	if err != nil {
		if isNotFound(err) || isAccessDenied(err) {
			r.spendLimitFetched.Store(true)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get organization spend limit: %w", err)
	}
	r.spendLimit = limit
	r.spendLimitFetched.Store(true)
	return limit, nil
}

func (r *mqlOpenai) spendLimitAmount() (int64, error) {
	limit, err := r.fetchSpendLimit()
	if err != nil {
		return 0, err
	}
	if limit == nil {
		r.SpendLimitAmount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return limit.ThresholdAmount, nil
}

func (r *mqlOpenai) spendLimitCurrency() (string, error) {
	limit, err := r.fetchSpendLimit()
	if err != nil {
		return "", err
	}
	if limit == nil {
		r.SpendLimitCurrency.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(limit.Currency), nil
}

func (r *mqlOpenai) spendLimitInterval() (string, error) {
	limit, err := r.fetchSpendLimit()
	if err != nil {
		return "", err
	}
	if limit == nil {
		r.SpendLimitInterval.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(limit.Interval), nil
}

func (r *mqlOpenai) spendLimitEnforcement() (string, error) {
	limit, err := r.fetchSpendLimit()
	if err != nil {
		return "", err
	}
	if limit == nil {
		r.SpendLimitEnforcement.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return limit.Enforcement.Status, nil
}

func (r *mqlOpenai) dataRetentionType() (string, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.dataRetentionType")
	if err != nil {
		return "", err
	}
	if client == nil {
		r.DataRetentionType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	retention, err := client.Admin.Organization.DataRetention.Get(context.Background())
	if err != nil {
		if isNotFound(err) || isAccessDenied(err) {
			r.DataRetentionType.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		return "", fmt.Errorf("failed to get organization data retention: %w", err)
	}
	return string(retention.Type), nil
}

// spendAlertArgs builds the resource args for an openai.spendAlert. The same
// alert shape is returned for the organization and for a project, so the scope
// prefix keeps the two apart in the resource cache.
func spendAlertArgs(scope, id string, threshold int64, currency, interval, notificationType string, recipients []string, subjectPrefix string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                      llx.StringData(scope + "/" + id),
		"id":                        llx.StringData(id),
		"thresholdAmount":           llx.IntData(threshold),
		"currency":                  llx.StringData(currency),
		"interval":                  llx.StringData(interval),
		"notificationType":          llx.StringData(notificationType),
		"notificationRecipients":    llx.ArrayData(convertStringSlice(recipients), "string"),
		"notificationSubjectPrefix": llx.StringData(subjectPrefix),
	}
}

func (r *mqlOpenai) spendAlerts() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.spendAlerts")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.SpendAlerts.ListAutoPaging(ctx, openai.AdminOrganizationSpendAlertListParams{})
	var res []any
	for iter.Next() {
		a := iter.Current()
		mqlAlert, err := CreateResource(r.MqlRuntime, "openai.spendAlert", spendAlertArgs(
			"org", a.ID, a.ThresholdAmount, string(a.Currency), string(a.Interval),
			string(a.NotificationChannel.Type), a.NotificationChannel.Recipients, a.NotificationChannel.SubjectPrefix))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAlert)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list organization spend alerts: %w", err)
	}
	return res, nil
}

type mqlOpenaiProjectInternal struct {
	hostedToolsFetched atomic.Bool
	hostedToolsLock    sync.Mutex
	hostedTools        *openai.ProjectHostedToolPermissions

	modelPermsFetched atomic.Bool
	modelPermsLock    sync.Mutex
	modelPerms        *openai.ProjectModelPermissions

	spendLimitFetched atomic.Bool
	spendLimitLock    sync.Mutex
	spendLimit        *openai.ProjectSpendLimit
}

// fetchHostedToolPermissions reads the project hosted tool policy once and
// shares it across the five per-tool fields.
func (r *mqlOpenaiProject) fetchHostedToolPermissions() (*openai.ProjectHostedToolPermissions, error) {
	if r.hostedToolsFetched.Load() {
		return r.hostedTools, nil
	}
	r.hostedToolsLock.Lock()
	defer r.hostedToolsLock.Unlock()
	if r.hostedToolsFetched.Load() {
		return r.hostedTools, nil
	}

	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.hostedToolPermissions")
	if err != nil {
		return nil, err
	}
	if client == nil {
		r.hostedToolsFetched.Store(true)
		return nil, nil
	}

	perms, err := client.Admin.Organization.Projects.HostedToolPermissions.Get(context.Background(), r.Id.Data)
	if err != nil {
		if isNotFound(err) || isAccessDenied(err) {
			r.hostedToolsFetched.Store(true)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get hosted tool permissions for project %s: %w", r.Id.Data, err)
	}
	r.hostedTools = perms
	r.hostedToolsFetched.Store(true)
	return perms, nil
}

// hostedToolEnabled resolves one hosted tool flag, marking the field null when
// the project has no hosted tool policy to report.
func (r *mqlOpenaiProject) hostedToolEnabled(field *plugin.TValue[bool], pick func(*openai.ProjectHostedToolPermissions) bool) (bool, error) {
	perms, err := r.fetchHostedToolPermissions()
	if err != nil {
		return false, err
	}
	if perms == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return pick(perms), nil
}

func (r *mqlOpenaiProject) codeInterpreterEnabled() (bool, error) {
	return r.hostedToolEnabled(&r.CodeInterpreterEnabled, func(p *openai.ProjectHostedToolPermissions) bool {
		return p.CodeInterpreter.Enabled
	})
}

func (r *mqlOpenaiProject) fileSearchEnabled() (bool, error) {
	return r.hostedToolEnabled(&r.FileSearchEnabled, func(p *openai.ProjectHostedToolPermissions) bool {
		return p.FileSearch.Enabled
	})
}

func (r *mqlOpenaiProject) imageGenerationEnabled() (bool, error) {
	return r.hostedToolEnabled(&r.ImageGenerationEnabled, func(p *openai.ProjectHostedToolPermissions) bool {
		return p.ImageGeneration.Enabled
	})
}

func (r *mqlOpenaiProject) mcpEnabled() (bool, error) {
	return r.hostedToolEnabled(&r.McpEnabled, func(p *openai.ProjectHostedToolPermissions) bool {
		return p.Mcp.Enabled
	})
}

func (r *mqlOpenaiProject) webSearchEnabled() (bool, error) {
	return r.hostedToolEnabled(&r.WebSearchEnabled, func(p *openai.ProjectHostedToolPermissions) bool {
		return p.WebSearch.Enabled
	})
}

// fetchModelPermissions reads the project model policy once and shares it
// across the mode and model-id fields. A nil result with a nil error means no
// policy is configured, which leaves every model reachable.
func (r *mqlOpenaiProject) fetchModelPermissions() (*openai.ProjectModelPermissions, error) {
	if r.modelPermsFetched.Load() {
		return r.modelPerms, nil
	}
	r.modelPermsLock.Lock()
	defer r.modelPermsLock.Unlock()
	if r.modelPermsFetched.Load() {
		return r.modelPerms, nil
	}

	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.modelPermissions")
	if err != nil {
		return nil, err
	}
	if client == nil {
		r.modelPermsFetched.Store(true)
		return nil, nil
	}

	perms, err := client.Admin.Organization.Projects.ModelPermissions.Get(context.Background(), r.Id.Data)
	if err != nil {
		if isNotFound(err) || isAccessDenied(err) {
			r.modelPermsFetched.Store(true)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get model permissions for project %s: %w", r.Id.Data, err)
	}
	r.modelPerms = perms
	r.modelPermsFetched.Store(true)
	return perms, nil
}

func (r *mqlOpenaiProject) modelPermissionMode() (string, error) {
	perms, err := r.fetchModelPermissions()
	if err != nil {
		return "", err
	}
	if perms == nil {
		r.ModelPermissionMode.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(perms.Mode), nil
}

func (r *mqlOpenaiProject) modelPermissionModelIds() ([]any, error) {
	perms, err := r.fetchModelPermissions()
	if err != nil {
		return nil, err
	}
	if perms == nil {
		r.ModelPermissionModelIds.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convertStringSlice(perms.ModelIDs), nil
}

func (r *mqlOpenaiProject) dataRetentionType() (string, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.dataRetentionType")
	if err != nil {
		return "", err
	}
	if client == nil {
		r.DataRetentionType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	retention, err := client.Admin.Organization.Projects.DataRetention.Get(context.Background(), r.Id.Data)
	if err != nil {
		if isNotFound(err) || isAccessDenied(err) {
			r.DataRetentionType.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		return "", fmt.Errorf("failed to get data retention for project %s: %w", r.Id.Data, err)
	}
	return string(retention.Type), nil
}

func (r *mqlOpenaiProject) rateLimits() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.rateLimits")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Projects.RateLimits.ListRateLimitsAutoPaging(ctx, r.Id.Data,
		openai.AdminOrganizationProjectRateLimitListRateLimitsParams{})
	var res []any
	for iter.Next() {
		rl := iter.Current()

		mqlRateLimit, err := CreateResource(r.MqlRuntime, "openai.project.rateLimit", map[string]*llx.RawData{
			"__id":                       llx.StringData(rl.ID),
			"id":                         llx.StringData(rl.ID),
			"model":                      llx.StringData(rl.Model),
			"maxRequestsPerMinute":       llx.IntData(rl.MaxRequestsPer1Minute),
			"maxTokensPerMinute":         llx.IntData(rl.MaxTokensPer1Minute),
			"maxImagesPerMinute":         llx.IntDataPtr(nullableInt(rl.MaxImagesPer1Minute, rl.JSON.MaxImagesPer1Minute.Valid())),
			"maxAudioMegabytesPerMinute": llx.IntDataPtr(nullableInt(rl.MaxAudioMegabytesPer1Minute, rl.JSON.MaxAudioMegabytesPer1Minute.Valid())),
			"maxRequestsPerDay":          llx.IntDataPtr(nullableInt(rl.MaxRequestsPer1Day, rl.JSON.MaxRequestsPer1Day.Valid())),
			"batchMaxInputTokensPerDay":  llx.IntDataPtr(nullableInt(rl.Batch1DayMaxInputTokens, rl.JSON.Batch1DayMaxInputTokens.Valid())),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRateLimit)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list rate limits for project %s: %w", r.Id.Data, err)
	}
	return res, nil
}

// fetchProjectSpendLimit reads the project hard spend limit once and shares it
// across the four fields derived from it. A nil result with a nil error means
// no limit is configured for the project.
func (r *mqlOpenaiProject) fetchProjectSpendLimit() (*openai.ProjectSpendLimit, error) {
	if r.spendLimitFetched.Load() {
		return r.spendLimit, nil
	}
	r.spendLimitLock.Lock()
	defer r.spendLimitLock.Unlock()
	if r.spendLimitFetched.Load() {
		return r.spendLimit, nil
	}

	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.spendLimit")
	if err != nil {
		return nil, err
	}
	if client == nil {
		r.spendLimitFetched.Store(true)
		return nil, nil
	}

	limit, err := client.Admin.Organization.Projects.SpendLimit.Get(context.Background(), r.Id.Data)
	if err != nil {
		if isNotFound(err) || isAccessDenied(err) {
			r.spendLimitFetched.Store(true)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get spend limit for project %s: %w", r.Id.Data, err)
	}
	r.spendLimit = limit
	r.spendLimitFetched.Store(true)
	return limit, nil
}

func (r *mqlOpenaiProject) spendLimitAmount() (int64, error) {
	limit, err := r.fetchProjectSpendLimit()
	if err != nil {
		return 0, err
	}
	if limit == nil {
		r.SpendLimitAmount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return limit.ThresholdAmount, nil
}

func (r *mqlOpenaiProject) spendLimitCurrency() (string, error) {
	limit, err := r.fetchProjectSpendLimit()
	if err != nil {
		return "", err
	}
	if limit == nil {
		r.SpendLimitCurrency.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(limit.Currency), nil
}

func (r *mqlOpenaiProject) spendLimitInterval() (string, error) {
	limit, err := r.fetchProjectSpendLimit()
	if err != nil {
		return "", err
	}
	if limit == nil {
		r.SpendLimitInterval.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(limit.Interval), nil
}

func (r *mqlOpenaiProject) spendLimitEnforcement() (string, error) {
	limit, err := r.fetchProjectSpendLimit()
	if err != nil {
		return "", err
	}
	if limit == nil {
		r.SpendLimitEnforcement.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return limit.Enforcement.Status, nil
}

func (r *mqlOpenaiProject) spendAlerts() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.spendAlerts")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Projects.SpendAlerts.ListAutoPaging(ctx, r.Id.Data,
		openai.AdminOrganizationProjectSpendAlertListParams{})
	var res []any
	for iter.Next() {
		a := iter.Current()
		mqlAlert, err := CreateResource(r.MqlRuntime, "openai.spendAlert", spendAlertArgs(
			"project/"+r.Id.Data, a.ID, a.ThresholdAmount, string(a.Currency), string(a.Interval),
			string(a.NotificationChannel.Type), a.NotificationChannel.Recipients, a.NotificationChannel.SubjectPrefix))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAlert)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list spend alerts for project %s: %w", r.Id.Data, err)
	}
	return res, nil
}
