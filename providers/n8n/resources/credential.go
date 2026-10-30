// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"slices"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlN8n) credentials() ([]any, error) {
	creds, err := n8nConnection(r.MqlRuntime).Client().Credentials(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(creds))
	for _, c := range creds {
		res, err := CreateResource(r.MqlRuntime, ResourceN8nCredential, map[string]*llx.RawData{
			"id":        llx.StringData(c.ID),
			"name":      llx.StringData(c.Name),
			"type":      llx.StringData(c.Type),
			"createdAt": llx.TimeData(c.CreatedAt),
			"updatedAt": llx.TimeData(c.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func initN8nCredential(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return lookupInit(args, ResourceN8nCredential, func() (map[string]*mqlN8nCredential, error) {
		return credentialsByID(runtime)
	})
}

func (r *mqlN8nCredential) id() (string, error) {
	return r.Id.Data, nil
}

// workflows scans the instance's workflow list for the ones whose nodes use
// the credential.
func (r *mqlN8nCredential) workflows() ([]any, error) {
	root, err := rootResource(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := root.GetWorkflows()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, item := range list.Data {
		wf, ok := item.(*mqlN8nWorkflow)
		if ok && slices.Contains(wf.credentialIDs, r.Id.Data) {
			out = append(out, wf)
		}
	}
	return out, nil
}
