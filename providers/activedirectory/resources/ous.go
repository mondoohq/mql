// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sort"

	"github.com/go-ldap/ldap/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/activedirectory/connection"
)

func (a *mqlActivedirectory) organizationalUnits() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	baseDN := conn.BaseDN()

	attrs := []string{
		"name",
		"distinguishedName",
		"description",
		"gPOptions",
		"whenCreated",
	}

	entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=organizationalUnit)",
		attrs,
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to query organizational units: %w", err)
	}

	res := make([]any, 0, len(entries))
	for _, entry := range entries {
		dn := connection.GetStringAttr(entry, "distinguishedName")
		name := connection.GetStringAttr(entry, "name")
		desc := connection.GetStringAttr(entry, "description")
		gpoInheritanceBlocked := connection.GetStringAttr(entry, "gPOptions") == "1"
		whenCreated := parseADGeneralizedTime(connection.GetStringAttr(entry, "whenCreated"))

		resource, err := CreateResource(a.MqlRuntime, "activedirectory.ou",
			map[string]*llx.RawData{
				"name":                  llx.StringData(name),
				"distinguishedName":     llx.StringData(dn),
				"description":           llx.StringData(desc),
				"gpoInheritanceBlocked": llx.BoolData(gpoInheritanceBlocked),
				"whenCreated":           llx.TimeData(whenCreated),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, resource)
	}

	sort.Slice(res, func(i, j int) bool {
		oi := res[i].(plugin.Resource)
		oj := res[j].(plugin.Resource)
		return oi.MqlID() < oj.MqlID()
	})

	return res, nil
}

// gpLinksToResources converts parsed gpLinkEntry values into
// activedirectory.gpoLink MQL resources.
func gpLinksToResources(runtime *plugin.Runtime, scopeDN string, entries []gpLinkEntry) ([]any, error) {
	if len(entries) == 0 {
		return []any{}, nil
	}
	res := make([]any, 0, len(entries))
	for _, e := range entries {
		id := fmt.Sprintf("%s|%s/%d", scopeDN, e.rawDN, e.order)
		resource, err := CreateResource(runtime, "activedirectory.gpoLink",
			map[string]*llx.RawData{
				"__id":     llx.StringData(id),
				"target":   llx.StringData(e.rawDN),
				"order":    llx.IntData(int64(e.order)),
				"enforced": llx.BoolData(e.enforced),
				"enabled":  llx.BoolData(e.enabled),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func (a *mqlActivedirectoryOu) linkedGpos() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	dn := a.DistinguishedName.Data

	// Re-query for gPLink since it's not stored on the resource.
	entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"gPLink"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to query gPLink for OU %s: %w", dn, err)
	}

	if len(entries) == 0 {
		return []any{}, nil
	}

	raw := connection.GetStringAttr(entries[0], "gPLink")
	return gpLinksToResources(a.MqlRuntime, dn, parseGPLinks(raw))
}
