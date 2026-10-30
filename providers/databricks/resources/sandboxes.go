// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/databricks/databricks-sdk-go/service/sandbox"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// sandboxState reports the sandbox lifecycle state, or null when the server
// returned no status block. An empty string would read as a real state that is
// none of the documented ones.
func sandboxState(s sandbox.Sandbox) *llx.RawData {
	if s.Status == nil || s.Status.State == "" {
		return llx.NilData
	}
	return llx.StringData(string(s.Status.State))
}

// sandboxInactivityTimeoutSeconds reports the configured idle timeout in whole
// seconds, or null when none is set. Zero is never a real timeout, so a nil
// pointer and an unset duration both read as null rather than as "stops at
// once".
func sandboxInactivityTimeoutSeconds(s sandbox.Sandbox) *llx.RawData {
	if s.Spec == nil || s.Spec.Compute == nil || s.Spec.Compute.InactivityTimeout == nil {
		return llx.NilData
	}
	d := s.Spec.Compute.InactivityTimeout.AsDuration()
	if d <= 0 {
		return llx.NilData
	}
	return llx.IntData(int64(d.Seconds()))
}

// sandboxFields maps one sandbox record to its MQL fields. Kept apart from the
// API call so the absent cases can be asserted directly: a sandbox without a
// status block, without a compute spec, or without timestamps has to arrive as
// null rather than as an empty state, a zero timeout, or the zero time.
func sandboxFields(s sandbox.Sandbox) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                     llx.StringData("databricks.sandbox/" + s.Name),
		"name":                     llx.StringData(s.Name),
		"displayName":              llx.StringData(s.DisplayName),
		"state":                    sandboxState(s),
		"inactivityTimeoutSeconds": sandboxInactivityTimeoutSeconds(s),
		"createTime":               llx.TimeDataPtr(sdkTime(s.CreateTime)),
		"updateTime":               llx.TimeDataPtr(sdkTime(s.UpdateTime)),
	}
}

// sandboxes lists the workspace's serverless sandboxes. A caller who may not
// read them gets null rather than an empty list, and a workspace where the
// feature is not served reports none.
func (r *mqlDatabricks) sandboxes() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	list, err := ws.Sandbox.ListSandboxesAll(context.Background(), sandbox.ListSandboxesRequest{})
	if err != nil {
		if isDatabricksUnreadable(err) {
			r.Sandboxes = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		if isDatabricksFeatureUnavailable(err) {
			return []any{}, nil
		}
		return nil, err
	}

	out := []any{}
	for i := range list {
		res, err := CreateResource(r.MqlRuntime, "databricks.sandbox", sandboxFields(list[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
