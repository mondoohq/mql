// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/n8n/connection"
	"go.mondoo.com/mql/types"
)

func n8nConnection(runtime *plugin.Runtime) *connection.N8nConnection {
	return runtime.Connection.(*connection.N8nConnection)
}

func initN8n(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["url"]; !ok {
		args["url"] = llx.StringData(n8nConnection(runtime).InstanceURL())
	}
	return args, nil, nil
}

func (r *mqlN8n) id() (string, error) {
	return "n8n", nil
}

// rootResource returns the instance resource. It is a singleton, so the
// runtime hands back the cached instance and every list it holds is fetched
// once per scan.
func rootResource(runtime *plugin.Runtime) (*mqlN8n, error) {
	res, err := CreateResource(runtime, ResourceN8n, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlN8n), nil
}

func (r *mqlN8n) apiKeyScopes() ([]any, error) {
	scopes, err := n8nConnection(r.MqlRuntime).Client().APIKeyScopes(context.Background())
	if err != nil {
		return nil, err
	}
	return toAnySlice(scopes), nil
}

func (r *mqlN8n) securityAudit() (*mqlN8nAudit, error) {
	res, err := CreateResource(r.MqlRuntime, ResourceN8nAudit, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlN8nAudit), nil
}

// byID indexes a resource list by the id each resource reports.
func byID[T plugin.Resource](list []any, id func(T) string) map[string]T {
	out := make(map[string]T, len(list))
	for _, item := range list {
		if res, ok := item.(T); ok {
			out[id(res)] = res
		}
	}
	return out
}

func workflowsByID(runtime *plugin.Runtime) (map[string]*mqlN8nWorkflow, error) {
	root, err := rootResource(runtime)
	if err != nil {
		return nil, err
	}
	list := root.GetWorkflows()
	if list.Error != nil {
		return nil, list.Error
	}
	return byID(list.Data, func(w *mqlN8nWorkflow) string { return w.Id.Data }), nil
}

func credentialsByID(runtime *plugin.Runtime) (map[string]*mqlN8nCredential, error) {
	root, err := rootResource(runtime)
	if err != nil {
		return nil, err
	}
	list := root.GetCredentials()
	if list.Error != nil {
		return nil, list.Error
	}
	return byID(list.Data, func(c *mqlN8nCredential) string { return c.Id.Data }), nil
}

func tagsByID(runtime *plugin.Runtime) (map[string]*mqlN8nTag, error) {
	root, err := rootResource(runtime)
	if err != nil {
		return nil, err
	}
	list := root.GetTags()
	if list.Error != nil {
		return nil, list.Error
	}
	return byID(list.Data, func(t *mqlN8nTag) string { return t.Id.Data }), nil
}

// pick returns the resources for ids in the order given, skipping ids the
// index does not hold, such as a credential a node references that was
// deleted or that the API key cannot see.
func pick[T any](index map[string]T, ids []string) []any {
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		if res, ok := index[id]; ok {
			out = append(out, res)
		}
	}
	return out
}

// lookupInit resolves a resource created from its id alone, as in
// n8n.workflow(id: "..."), against the instance's list.
func lookupInit[T plugin.Resource](args map[string]*llx.RawData, name string, index func() (map[string]T, error)) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	raw, ok := args["id"]
	if !ok {
		return nil, nil, errors.New(name + " requires an id")
	}
	id, _ := raw.Value.(string)
	resources, err := index()
	if err != nil {
		return nil, nil, err
	}
	if res, ok := resources[id]; ok {
		return args, res, nil
	}
	return nil, nil, errors.New(name + " with id " + id + " not found")
}

// optString maps an unset value to null.
func optString(s string) *llx.RawData {
	if s == "" {
		return llx.NilData
	}
	return llx.StringData(s)
}

func toAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

func stringArray(in []string) *llx.RawData {
	return llx.ArrayData(toAnySlice(in), types.String)
}

// optStringArray maps a nil list, a setting that does not apply, to null.
func optStringArray(in []string) *llx.RawData {
	if in == nil {
		return llx.NilData
	}
	return stringArray(in)
}
