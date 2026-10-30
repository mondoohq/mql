// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/auth0/go-auth0/management"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// actions lists the custom Node.js actions bound to the tenant's flows.
func (a *mqlAuth0) actions() ([]any, error) {
	conn := a.conn()
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.Action.List(context.Background(),
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, act := range list.Actions {
			r, err := newMqlAuth0Action(a.MqlRuntime, act)
			if err != nil {
				return nil, err
			}
			all = append(all, r)
		}
		if !list.HasNext() {
			break
		}
		page++
	}
	return all, nil
}

// newMqlAuth0Action maps a single SDK action to its MQL resource.
func newMqlAuth0Action(runtime *plugin.Runtime, act *management.Action) (plugin.Resource, error) {
	triggers, err := convert.JsonToDictSlice(act.SupportedTriggers)
	if err != nil {
		return nil, err
	}

	var dependencies, secrets []any
	if act.Dependencies != nil {
		dependencies, err = convert.JsonToDictSlice(*act.Dependencies)
		if err != nil {
			return nil, err
		}
	}
	if act.Secrets != nil {
		secrets, err = convert.JsonToDictSlice(*act.Secrets)
		if err != nil {
			return nil, err
		}
	}

	deployed := act.AllChangesDeployed

	r, err := CreateResource(runtime, "auth0.action", map[string]*llx.RawData{
		"id":                llx.StringDataPtr(act.ID),
		"name":              llx.StringDataPtr(act.Name),
		"runtime":           llx.StringDataPtr(act.Runtime),
		"supportedTriggers": llx.ArrayData(triggers, types.Dict),
		"status":            llx.StringDataPtr(act.Status),
		"deployed":          llx.BoolData(deployed),
		"code":              llx.StringDataPtr(act.Code),
		"dependencies":      llx.ArrayData(dependencies, types.Dict),
		"secrets":           llx.ArrayData(secrets, types.Dict),
		"createdAt":         llx.TimeDataPtr(act.CreatedAt),
		"updatedAt":         llx.TimeDataPtr(act.UpdatedAt),
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *mqlAuth0Action) id() (string, error) {
	return "auth0.action/" + r.Id.Data, nil
}
