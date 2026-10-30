// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func (r *mqlMongodbatlas) customDatabaseRoles() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	// ListCustomDatabaseRoles returns the full set in one call (no pagination).
	roles, _, err := client.CustomDatabaseRolesAPI.ListCustomDbRoles(ctx, pid).Execute()
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range roles {
		role := roles[i]

		actions := []any{}
		for _, a := range role.GetActions() {
			resources := []any{}
			for _, res := range a.GetResources() {
				resources = append(resources, map[string]any{
					"cluster":    res.GetCluster(),
					"db":         res.GetDb(),
					"collection": res.GetCollection(),
				})
			}
			actions = append(actions, map[string]any{
				"action":    a.GetAction(),
				"resources": resources,
			})
		}

		inheritedRoles := []any{}
		for _, ir := range role.GetInheritedRoles() {
			inheritedRoles = append(inheritedRoles, map[string]any{
				"role": ir.GetRole(),
				"db":   ir.GetDb(),
			})
		}

		res, err := CreateResource(r.MqlRuntime, "mongodbatlas.customDatabaseRole", map[string]*llx.RawData{
			"__id":           llx.StringData("mongodbatlas.customDatabaseRole/" + pid + "/" + role.GetRoleName()),
			"roleName":       llx.StringData(role.GetRoleName()),
			"actions":        llx.ArrayData(actions, types.Dict),
			"inheritedRoles": llx.ArrayData(inheritedRoles, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
