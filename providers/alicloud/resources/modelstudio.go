// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"

	modelstudioclient "github.com/alibabacloud-go/modelstudio-20260210/v2/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

const modelStudioPageSize = 100

// modelStudioTokenList walks a NextToken listing. fetch returns one page and
// the token for the next. The walk ends on an empty token, or when the API
// hands back the token it was just given, so a stuck cursor cannot loop.
func modelStudioTokenList[T any](fetch func(token *string) ([]T, *string, error)) ([]T, error) {
	res := []T{}
	var token *string
	for {
		items, next, err := fetch(token)
		if err != nil {
			return nil, err
		}
		res = append(res, items...)
		if next == nil || *next == "" || (token != nil && *next == *token) {
			return res, nil
		}
		token = next
	}
}

// modelStudioBodyError turns a response that reports failure in its body
// (success false) into an error. A body with no success flag is accepted.
func modelStudioBodyError(op string, success *bool, code, message *string) error {
	if success == nil || *success {
		return nil
	}
	return fmt.Errorf("alicloud> Model Studio %s failed: %s %s", op, tea.StringValue(code), tea.StringValue(message))
}

// modelStudioKeyEnabled maps the API's disabled flag (0 enabled, 1 disabled)
// onto enabled. An absent flag is null.
func modelStudioKeyEnabled(disabled *int32) *llx.RawData {
	if disabled == nil {
		return llx.NilData
	}
	return llx.BoolData(*disabled == 0)
}

func (r *mqlAlicloudModelStudio) id() (string, error) {
	return "alicloud.modelStudio", nil
}

// modelStudioRegional collects one Model Studio listing across every region
// that offers it. A denied or failed region is logged and skipped.
func modelStudioRegional(runtime *plugin.Runtime, service string, list func(region string) ([]any, error)) ([]any, error) {
	conn := runtime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.ModelStudioRegions()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, region := range regions {
		items, err := list(region)
		if err != nil {
			logSkippedRegion(err, service, region)
			continue
		}
		res = append(res, items...)
	}
	return res, nil
}

// dedupeResources drops repeated resources from a list, keeping the first.
// Model Studio may return the same workspace or key from more than one
// regional endpoint.
func dedupeResources(items []any) []any {
	seen := map[any]struct{}{}
	res := make([]any, 0, len(items))
	for _, it := range items {
		if _, ok := seen[it]; ok {
			continue
		}
		seen[it] = struct{}{}
		res = append(res, it)
	}
	return res
}

// ---------------------------------------------------------------------------
// Workspaces
// ---------------------------------------------------------------------------

func (r *mqlAlicloudModelStudio) workspaces() ([]any, error) {
	res, err := modelStudioRegional(r.MqlRuntime, "Model Studio workspace", func(region string) ([]any, error) {
		return listModelStudioWorkspaces(r.MqlRuntime, region, "")
	})
	if err != nil {
		return nil, err
	}
	return dedupeResources(res), nil
}

func listModelStudioWorkspaces(runtime *plugin.Runtime, region, workspaceID string) ([]any, error) {
	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ModelStudioClient(region)
	if err != nil {
		return nil, err
	}
	items, err := modelStudioTokenList(func(token *string) ([]*modelstudioclient.ListWorkspacesResponseBodyWorkspaces, *string, error) {
		req := &modelstudioclient.ListWorkspacesRequest{
			MaxResults: tea.Int32(modelStudioPageSize),
			NextToken:  token,
		}
		if workspaceID != "" {
			req.WorkspaceId = new(workspaceID)
		}
		resp, err := client.ListWorkspaces(req)
		if err != nil {
			return nil, nil, classifyAlicloudError(err, "modelstudio:ListWorkspaces")
		}
		if resp == nil || resp.Body == nil {
			return nil, nil, nil
		}
		b := resp.Body
		if err := modelStudioBodyError("ListWorkspaces", b.Success, b.Code, b.Message); err != nil {
			return nil, nil, err
		}
		return b.Workspaces, b.NextToken, nil
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, w := range items {
		if w == nil || tea.StringValue(w.WorkspaceId) == "" {
			continue
		}
		mqlW, err := newModelStudioWorkspace(runtime, region, w)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlW)
	}
	return res, nil
}

func newModelStudioWorkspace(runtime *plugin.Runtime, region string, w *modelstudioclient.ListWorkspacesResponseBodyWorkspaces) (*mqlAlicloudModelStudioWorkspace, error) {
	if v := tea.StringValue(w.Region); v != "" {
		region = v
	}
	res, err := CreateResource(runtime, "alicloud.modelStudio.workspace", map[string]*llx.RawData{
		"__id":        llx.StringData(tea.StringValue(w.WorkspaceId)),
		"regionId":    llx.StringData(region),
		"workspaceId": llx.StringDataPtr(w.WorkspaceId),
		"name":        llx.StringDataPtr(w.WorkspaceName),
		"serviceSite": llx.StringDataPtr(w.ServiceSite),
		"apiHost":     llx.StringDataPtr(w.ApiHost),
		"createTime":  llx.TimeDataPtr(epochAuto(w.GmtCreate)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudModelStudioWorkspace), nil
}

// initAlicloudModelStudioWorkspace resolves a workspace by id, reusing an
// already-listed workspace from the resource cache. regionId names the
// endpoint to ask when the workspace has not been listed.
func initAlicloudModelStudioWorkspace(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	workspaceID, err := requiredStringArg(args, "workspaceId", "alicloud.modelStudio.workspace")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.modelStudio.workspace\x00" + workspaceID); ok {
		return nil, x, nil
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.modelStudio.workspace")
	if err != nil {
		return nil, nil, err
	}
	found, err := listModelStudioWorkspaces(runtime, region, workspaceID)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range found {
		if w := f.(*mqlAlicloudModelStudioWorkspace); w.WorkspaceId.Data == workspaceID {
			return nil, w, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.modelStudio.workspace %q not found in region %q", workspaceID, region)
}

func (r *mqlAlicloudModelStudioWorkspace) id() (string, error) {
	return r.WorkspaceId.Data, nil
}

func (r *mqlAlicloudModelStudioWorkspace) apiKeys() ([]any, error) {
	return listModelStudioApiKeys(r.MqlRuntime, r.RegionId.Data, r.WorkspaceId.Data)
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

func (r *mqlAlicloudModelStudio) apiKeys() ([]any, error) {
	res, err := modelStudioRegional(r.MqlRuntime, "Model Studio API key", func(region string) ([]any, error) {
		return listModelStudioApiKeys(r.MqlRuntime, region, "")
	})
	if err != nil {
		return nil, err
	}
	return dedupeResources(res), nil
}

func listModelStudioApiKeys(runtime *plugin.Runtime, region, workspaceID string) ([]any, error) {
	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ModelStudioClient(region)
	if err != nil {
		return nil, err
	}
	items, err := modelStudioTokenList(func(token *string) ([]*modelstudioclient.ListApiKeysResponseBodyApiKeys, *string, error) {
		req := &modelstudioclient.ListApiKeysRequest{
			MaxResults: tea.Int32(modelStudioPageSize),
			NextToken:  token,
		}
		if workspaceID != "" {
			req.WorkspaceId = new(workspaceID)
		}
		resp, err := client.ListApiKeys(req)
		if err != nil {
			return nil, nil, classifyAlicloudError(err, "modelstudio:ListApiKeys")
		}
		if resp == nil || resp.Body == nil {
			return nil, nil, nil
		}
		b := resp.Body
		if err := modelStudioBodyError("ListApiKeys", b.Success, b.Code, b.Message); err != nil {
			return nil, nil, err
		}
		return b.ApiKeys, b.NextToken, nil
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, k := range items {
		if k == nil || k.ApiKeyId == nil {
			continue
		}
		mqlK, err := newModelStudioApiKey(runtime, region, k)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlK)
	}
	return res, nil
}

type mqlAlicloudModelStudioApiKeyInternal struct {
	cacheWorkspaceId string
}

// newModelStudioApiKey builds an alicloud.modelStudio.apiKey. The record's
// apiKeyValue (the key itself, even when masked) is never read.
func newModelStudioApiKey(runtime *plugin.Runtime, region string, k *modelstudioclient.ListApiKeysResponseBodyApiKeys) (*mqlAlicloudModelStudioApiKey, error) {
	authType := ""
	accessIps := []any{}
	allowAll := llx.NilData
	models := []any{}
	if a := k.Auth; a != nil {
		authType = tea.StringValue(a.Type)
		accessIps = strPtrsToAny(a.AccessIps)
		if s := a.ModelAccessScope; s != nil {
			allowAll = llx.BoolDataPtr(s.AllowAllModels)
			models = strPtrsToAny(s.AccessibleModels)
		}
	}
	keyID := tea.Int64Value(k.ApiKeyId)
	res, err := CreateResource(runtime, "alicloud.modelStudio.apiKey", map[string]*llx.RawData{
		"__id":             llx.StringData(strconv.FormatInt(keyID, 10)),
		"regionId":         llx.StringData(region),
		"id":               llx.IntData(keyID),
		"description":      llx.StringDataPtr(k.Description),
		"createdBy":        llx.StringDataPtr(k.CreatedBy),
		"createdAt":        llx.TimeDataPtr(epochAuto(k.GmtCreate)),
		"enabled":          modelStudioKeyEnabled(k.Disabled),
		"authType":         llx.StringData(authType),
		"accessIps":        llx.ArrayData(accessIps, types.String),
		"allowAllModels":   allowAll,
		"accessibleModels": llx.ArrayData(models, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlK := res.(*mqlAlicloudModelStudioApiKey)
	mqlK.cacheWorkspaceId = tea.StringValue(k.WorkspaceId)
	return mqlK, nil
}

func (r *mqlAlicloudModelStudioApiKey) id() (string, error) {
	return strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlAlicloudModelStudioApiKey) workspace() (*mqlAlicloudModelStudioWorkspace, error) {
	if r.cacheWorkspaceId == "" {
		r.Workspace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.modelStudio.workspace", map[string]*llx.RawData{
		"workspaceId": llx.StringData(r.cacheWorkspaceId),
		"regionId":    llx.StringData(r.RegionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudModelStudioWorkspace), nil
}
