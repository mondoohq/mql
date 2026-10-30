// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/google-workspace/connection"
	"go.mondoo.com/mql/types"
	directory "google.golang.org/api/admin/directory/v1"
)

func (g *mqlGoogleworkspace) roles() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	directoryService, err := directoryService(conn, directory.AdminDirectoryRolemanagementReadonlyScope)
	if err != nil {
		return nil, err
	}

	res := []any{}
	roles, err := directoryService.Roles.List(conn.CustomerID()).MaxResults(100).Do()
	if err != nil {
		return nil, err
	}
	for {
		for i := range roles.Items {
			r, err := newMqlGoogleWorkspaceRole(g.MqlRuntime, roles.Items[i])
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}

		if roles.NextPageToken == "" {
			break
		}

		roles, err = directoryService.Roles.List(conn.CustomerID()).MaxResults(100).PageToken(roles.NextPageToken).Do()
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func newMqlGoogleWorkspaceRole(runtime *plugin.Runtime, entry *directory.Role) (any, error) {
	privileges, err := convert.JsonToDictSlice(entry.RolePrivileges)
	if err != nil {
		return nil, err
	}

	typedPrivileges := make([]any, 0, len(entry.RolePrivileges))
	for _, p := range entry.RolePrivileges {
		if p == nil {
			continue
		}
		mqlPriv, err := CreateResource(runtime, "googleworkspace.role.privilege", map[string]*llx.RawData{
			"privilegeName": llx.StringData(p.PrivilegeName),
			"serviceId":     llx.StringData(p.ServiceId),
		})
		if err != nil {
			return nil, err
		}
		typedPrivileges = append(typedPrivileges, mqlPriv)
	}

	return CreateResource(runtime, "googleworkspace.role", map[string]*llx.RawData{
		"id":               llx.IntData(entry.RoleId),
		"name":             llx.StringData(entry.RoleName),
		"description":      llx.StringData(entry.RoleDescription),
		"isSystemRole":     llx.BoolData(entry.IsSystemRole),
		"isSuperAdminRole": llx.BoolData(entry.IsSuperAdminRole),
		"privileges":       llx.ArrayData(privileges, types.Any),
		"rolePrivileges":   llx.ArrayData(typedPrivileges, types.Resource("googleworkspace.role.privilege")),
	})
}

func (g *mqlGoogleworkspaceRolePrivilege) id() (string, error) {
	return "googleworkspace.role.privilege/" + g.PrivilegeName.Data + "/" + g.ServiceId.Data, nil
}

func (g *mqlGoogleworkspaceRole) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "googleworkspace.role/" + strconv.FormatInt(id, 10), nil
}
