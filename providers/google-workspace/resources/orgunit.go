// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/google-workspace/connection"
	directory "google.golang.org/api/admin/directory/v1"
)

func (g *mqlGoogleworkspace) orgUnits() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	directoryService, err := directoryService(conn, directory.AdminDirectoryOrgunitReadonlyScope)
	if err != nil {
		return nil, err
	}

	res := []any{}

	// Type("all") returns the full org-unit subtree. The default ("children")
	// returns only the immediate children of the root, silently omitting every
	// nested org unit. The response carries no page token, so a single call
	// returns the whole hierarchy.
	orgUnits, err := directoryService.Orgunits.List(conn.CustomerID()).Type("all").Do()
	if err != nil {
		return nil, err
	}

	for i := range orgUnits.OrganizationUnits {
		r, err := newMqlGoogleWorkspaceOrgUnit(g.MqlRuntime, orgUnits.OrganizationUnits[i])
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}

func newMqlGoogleWorkspaceOrgUnit(runtime *plugin.Runtime, entry *directory.OrgUnit) (any, error) {
	return CreateResource(runtime, "googleworkspace.orgUnit", map[string]*llx.RawData{
		"id":                llx.StringData(entry.OrgUnitId),
		"name":              llx.StringData(entry.Name),
		"description":       llx.StringData(entry.Description),
		"orgUnitPath":       llx.StringData(entry.OrgUnitPath),
		"parentOrgUnitPath": llx.StringData(entry.ParentOrgUnitPath),
	})
}

func (g *mqlGoogleworkspaceOrgUnit) id() (string, error) {
	return "googleworkspace.orgUnit/" + g.Id.Data, g.Id.Error
}
