// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	logs "github.com/stackitcloud/stackit-sdk-go/services/logs/v1api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func (r *mqlStackitLogs) id() (string, error) {
	return "stackit.logs/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackit) logs() (*mqlStackitLogs, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.logs")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitLogs), nil
}

func (r *mqlStackitLogs) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Logs()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListLogsInstances(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		// The Logs API answers 404 for a project that never enabled the service.
		if isNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items := resp.GetInstances()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.logs.instance", logsInstanceArgs(&items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func logsInstanceArgs(inst *logs.LogsInstance) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":            llx.StringData(inst.GetId()),
		"name":          llx.StringData(inst.GetDisplayName()),
		"description":   llx.StringData(inst.GetDescription()),
		"status":        llx.StringData(string(inst.GetStatus())),
		"createdAt":     llx.TimeDataPtr(timeOrNil(inst.GetCreatedOk())),
		"retentionDays": llx.IntData(int64(inst.GetRetentionDays())),
		"acl":           strSliceData(inst.GetAcl()),
		"ingestUrl":     llx.StringData(inst.GetIngestUrl()),
		"ingestOtlpUrl": llx.StringData(inst.GetIngestOtlpUrl()),
		"queryUrl":      llx.StringData(inst.GetQueryUrl()),
		"queryRangeUrl": llx.StringData(inst.GetQueryRangeUrl()),
		"datasourceUrl": llx.StringData(inst.GetDatasourceUrl()),
	}
}

func (r *mqlStackitLogsInstance) id() (string, error) {
	return "stackit.logs.instance/" + r.Id.Data, nil
}

func (r *mqlStackitLogsInstance) accessTokens() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Logs()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListAccessTokens(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp.GetTokens()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.logs.accessToken", logsAccessTokenArgs(r.Id.Data, &items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// logsAccessTokenArgs maps an access token's metadata. The token value, which
// the API returns only when the token is created, is deliberately not mapped.
func logsAccessTokenArgs(instanceID string, t *logs.AccessToken) map[string]*llx.RawData {
	perms := make([]any, 0, len(t.GetPermissions()))
	for _, p := range t.GetPermissions() {
		perms = append(perms, string(p))
	}
	return map[string]*llx.RawData{
		"__id":        llx.StringData(qualifiedId("stackit.logs.accessToken", instanceID, t.GetId())),
		"id":          llx.StringData(t.GetId()),
		"name":        llx.StringData(t.GetDisplayName()),
		"description": llx.StringData(t.GetDescription()),
		"creator":     llx.StringData(t.GetCreator()),
		"permissions": llx.ArrayData(perms, types.String),
		"expires":     llx.BoolData(t.GetExpires()),
		"validUntil":  llx.TimeDataPtr(timeOrNil(t.GetValidUntilOk())),
		"status":      llx.StringData(string(t.GetStatus())),
	}
}
