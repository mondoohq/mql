// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	serviceenablement "github.com/stackitcloud/stackit-sdk-go/services/serviceenablement/v2api"
	"go.mondoo.com/mql/llx"
)

type mqlStackitServiceEnablementInternal struct {
	// cacheHard and cacheSoft hold the dependency service ids, resolved
	// against the project's service list on demand.
	cacheHard []string
	cacheSoft []string
}

// listAllServiceStatuses walks every page of ListServiceStatusRegional. fetch
// is the single-page call, taking the cursor ("" for the first page).
func listAllServiceStatuses(fetch func(cursor string) (*serviceenablement.ListServiceStatusRegional200Response, error)) ([]serviceenablement.ServiceStatus, error) {
	var out []serviceenablement.ServiceStatus
	cursor := ""
	seen := map[string]bool{}
	for {
		resp, err := fetch(cursor)
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return out, nil
		}
		out = append(out, resp.GetItems()...)
		next, ok := resp.GetNextCursorOk()
		if !ok || next == nil || *next == "" || seen[*next] {
			return out, nil
		}
		seen[*next] = true
		cursor = *next
	}
}

func (r *mqlStackit) serviceEnablements() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServiceEnablement()
	if err != nil {
		return nil, err
	}
	items, err := listAllServiceStatuses(func(cursor string) (*serviceenablement.ListServiceStatusRegional200Response, error) {
		req := client.DefaultAPI.ListServiceStatusRegional(bgctx(), c.Region(), c.ProjectID())
		if cursor != "" {
			req = req.Cursor(cursor)
		}
		return req.Execute()
	})
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	idBase := c.ProjectID() + "/" + c.Region()
	out := make([]any, 0, len(items))
	for i := range items {
		st := &items[i]
		if st.GetServiceId() == "" {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.serviceEnablement", serviceEnablementArgs(idBase, st))
		if err != nil {
			return nil, err
		}
		se := res.(*mqlStackitServiceEnablement)
		if deps, ok := st.GetDependenciesOk(); ok && deps != nil {
			se.cacheHard = deps.GetHard()
			se.cacheSoft = deps.GetSoft()
		}
		out = append(out, res)
	}
	return out, nil
}

func serviceEnablementArgs(idBase string, st *serviceenablement.ServiceStatus) map[string]*llx.RawData {
	var errAction, errReason string
	if e, ok := st.GetErrorOk(); ok && e != nil {
		errAction = string(e.GetAction())
		errReason = e.GetReason()
	}
	return map[string]*llx.RawData{
		"__id":        llx.StringData(qualifiedId("stackit.serviceEnablement", idBase, st.GetServiceId())),
		"serviceId":   llx.StringData(st.GetServiceId()),
		"state":       llx.StringData(string(st.GetState())),
		"enablement":  llx.StringData(string(st.GetEnablement())),
		"scope":       llx.StringData(string(st.GetScope())),
		"lifecycle":   llx.StringData(string(st.GetLifecycle())),
		"labels":      stringMapData(st.GetLabels()),
		"errorAction": llx.StringData(errAction),
		"errorReason": llx.StringData(errReason),
	}
}

// serviceEnablementsByID resolves service ids against the project's service
// list. A dependency the list does not carry is skipped.
func (r *mqlStackitServiceEnablement) serviceEnablementsByID(ids []string) ([]any, error) {
	if len(ids) == 0 {
		return []any{}, nil
	}
	root, err := CreateResource(r.MqlRuntime, "stackit", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	all := root.(*mqlStackit).GetServiceEnablements()
	if all.Error != nil {
		return nil, all.Error
	}
	byID := make(map[string]any, len(all.Data))
	for _, item := range all.Data {
		if se, ok := item.(*mqlStackitServiceEnablement); ok {
			byID[se.ServiceId.Data] = item
		}
	}
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		if se, ok := byID[id]; ok {
			out = append(out, se)
		}
	}
	return out, nil
}

func (r *mqlStackitServiceEnablement) hardDependencies() ([]any, error) {
	return r.serviceEnablementsByID(r.cacheHard)
}

func (r *mqlStackitServiceEnablement) softDependencies() ([]any, error) {
	return r.serviceEnablementsByID(r.cacheSoft)
}
