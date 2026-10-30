// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/auth0/connection"
)

// roles lists the administrative and application roles defined in the tenant.
func (a *mqlAuth0) roles() ([]any, error) {
	conn := a.conn()
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.Role.List(context.Background(),
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, role := range list.Roles {
			r, err := newMqlAuth0Role(a.MqlRuntime, role)
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

// newMqlAuth0Role maps a single SDK role to its MQL resource.
func newMqlAuth0Role(runtime *plugin.Runtime, role *management.Role) (plugin.Resource, error) {
	r, err := CreateResource(runtime, "auth0.role", map[string]*llx.RawData{
		"id":          llx.StringDataPtr(role.ID),
		"name":        llx.StringDataPtr(role.Name),
		"description": llx.StringDataPtr(role.Description),
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// permissions lists the resource-server scopes the role grants.
func (r *mqlAuth0Role) permissions() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.Auth0Connection)
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.Role.Permissions(context.Background(), r.Id.Data,
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, p := range list.Permissions {
			all = append(all, map[string]any{
				"permissionName":           auth0.StringValue(p.Name),
				"resourceServerIdentifier": auth0.StringValue(p.ResourceServerIdentifier),
				"resourceServerName":       auth0.StringValue(p.ResourceServerName),
				"description":              auth0.StringValue(p.Description),
			})
		}
		if !list.HasNext() {
			break
		}
		page++
	}
	return all, nil
}

// users lists the accounts currently assigned this role.
func (r *mqlAuth0Role) users() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.Auth0Connection)
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.Role.Users(context.Background(), r.Id.Data,
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, u := range list.Users {
			res, err := newMqlAuth0User(r.MqlRuntime, u)
			if err != nil {
				return nil, err
			}
			all = append(all, res)
		}
		if !list.HasNext() {
			break
		}
		page++
	}
	return all, nil
}

func (r *mqlAuth0Role) id() (string, error) {
	return "auth0.role/" + r.Id.Data, nil
}
