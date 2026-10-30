// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/providers/okta/resources/sdk"
)

func (o *mqlOkta) customRoles() ([]any, error) {
	runtime := o.MqlRuntime

	conn := runtime.Connection.(*connection.OktaConnection)

	ctx := context.Background()
	apiSupplement := conn.ApiExtension()

	respList, resp, err := apiSupplement.ListCustomRoles(ctx)
	if err != nil {
		// handle case where no custom roles exist
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}

	if len(respList) == 0 {
		return nil, nil
	}

	list := []any{}
	for i := range respList {
		r, err := newMqlOktaCustomRole(o.MqlRuntime, respList[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}

	return list, nil
}

func initOktaCustomRole(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// If we already have the full set of fields, no fetch needed.
	if len(args) > 1 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok || idArg == nil || idArg.Value == nil {
		// Bare resource construction (no id) is a valid empty state.
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	role, resp, err := client.RoleECustomAPI.GetRole(ctx, id).Execute()
	if err != nil {
		if isOktaNotFound(resp) {
			return nil, nil, fmt.Errorf("%w: okta.customRole %q", errOktaResourceNotFound, id)
		}
		return nil, nil, err
	}
	if role == nil {
		return nil, nil, fmt.Errorf("okta.customRole with id %q not found", id)
	}

	args["id"] = llx.StringData(oktaStr(role.Id))
	args["label"] = llx.StringData(role.Label)
	args["description"] = llx.StringData(role.Description)
	return args, nil, nil
}

func newMqlOktaCustomRole(runtime *plugin.Runtime, entry *sdk.CustomRole) (any, error) {
	return CreateResource(runtime, "okta.customRole", map[string]*llx.RawData{
		"id":          llx.StringData(entry.Id),
		"label":       llx.StringData(entry.Label),
		"description": llx.StringData(entry.Description),
	})
}

// permissions lists the fine-grained Okta permission identifiers this custom
// role confers. Permissions are a sub-resource (GET /api/v1/iam/roles/{id}/
// permissions), not embedded in the role listing, so we resolve them per role
// on demand. This keeps the collection path (okta.customRoles) and the
// single-role path (okta.customRole) returning the same permission set.
func (o *mqlOktaCustomRole) permissions() ([]any, error) {
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	perms, _, err := client.RoleECustomPermissionAPI.ListRolePermissions(ctx, o.Id.Data).Execute()
	if err != nil {
		return nil, err
	}

	permissions := []any{}
	if perms != nil {
		for i := range perms.Permissions {
			permissions = append(permissions, oktaStr(perms.Permissions[i].Label))
		}
	}
	return permissions, nil
}

func (o *mqlOktaRole) id() (string, error) {
	return "okta.role/" + o.Id.Data, o.Id.Error
}

func (o *mqlOktaCustomRole) id() (string, error) {
	return "okta.customRole/" + o.Id.Data, o.Id.Error
}
