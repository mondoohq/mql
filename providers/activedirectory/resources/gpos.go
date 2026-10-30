// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/activedirectory/connection"
)

// gpLinkEntry represents a single parsed entry from an AD gPLink attribute.
type gpLinkEntry struct {
	gpoDN    string // lowercase-normalized DN of the linked GPO
	status   int    // raw status bits: 0=enabled+not enforced, 1=disabled, 2=enforced
	order    int    // 1 = highest precedence (last in the gPLink string)
	rawDN    string // original-case DN as found in gPLink
	enabled  bool
	enforced bool
}

// parseGPLinks parses the bracketed gPLink format used by AD:
//
//	[LDAP://cn=...,cn=policies,...;status][LDAP://...;status]
//
// Order is assigned such that the last entry in the string has order=1
// (highest precedence), matching AD's "Link Order" semantics.
func parseGPLinks(gplink string) []gpLinkEntry {
	if gplink == "" {
		return nil
	}

	// Split on "][" after trimming outer brackets.
	gplink = strings.TrimSpace(gplink)
	var raw []string
	for gplink != "" {
		start := strings.Index(gplink, "[")
		if start < 0 {
			break
		}
		end := strings.Index(gplink[start:], "]")
		if end < 0 {
			break
		}
		raw = append(raw, gplink[start+1:start+end])
		gplink = gplink[start+end+1:]
	}

	entries := make([]gpLinkEntry, 0, len(raw))
	for _, r := range raw {
		// Each entry: "LDAP://DN;status"
		path, statusStr, hasStatus := strings.CutLast(r, ";")
		if !hasStatus {
			continue
		}

		// Strip the LDAP:// (or ldap://) prefix.
		const prefix = "LDAP://"
		if len(path) > len(prefix) && strings.EqualFold(path[:len(prefix)], prefix) {
			path = path[len(prefix):]
		}

		status, _ := strconv.Atoi(statusStr)
		entries = append(entries, gpLinkEntry{
			gpoDN:    strings.ToLower(path),
			rawDN:    path,
			status:   status,
			enabled:  status&1 == 0, // bit 0 clear = enabled
			enforced: status&2 != 0, // bit 1 set = enforced
		})
	}

	// Assign order: last entry in string = order 1 (highest precedence).
	for i := range entries {
		entries[i].order = len(entries) - i
	}

	return entries
}

// gpoLinkMap maps each lowercase GPO DN to all scope objects that link it.
// Each scope is represented by its DN and the parsed link entries for that scope.
type gpoLinkMap struct {
	// byGPO maps lowercase GPO DN → []scopeLink
	byGPO map[string][]scopeLink
}

// scopeLink captures a single scope (domain root, OU, or site) that links a GPO.
type scopeLink struct {
	scopeDN string      // DN of the scope object
	link    gpLinkEntry // the parsed link entry for this specific GPO
}

// buildGPOLinkMap collects all gPLink attributes from domain root, OUs, and
// sites, parses them, and indexes by GPO DN. The result is cached on the
// connection under "gpoLinkMap".
func buildGPOLinkMap(conn *connection.ActiveDirectoryConnection) (*gpoLinkMap, error) {
	raw, err := conn.CachedFetch("gpoLinkMap", func() (any, error) {
		m := &gpoLinkMap{byGPO: make(map[string][]scopeLink)}

		collect := func(scopeDN, gplink string) {
			for _, entry := range parseGPLinks(gplink) {
				m.byGPO[entry.gpoDN] = append(m.byGPO[entry.gpoDN], scopeLink{
					scopeDN: scopeDN,
					link:    entry,
				})
			}
		}

		ldapConn := conn.LDAPConn()

		// 1. Domain root object.
		domainEntries, err := connection.PagedSearch(ldapConn, ldap.NewSearchRequest(
			conn.BaseDN(),
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"distinguishedName", "gPLink"},
			nil,
		))
		if err != nil {
			return nil, fmt.Errorf("querying domain root gPLink: %w", err)
		}
		for _, entry := range domainEntries {
			dn := connection.GetStringAttr(entry, "distinguishedName")
			gplink := connection.GetStringAttr(entry, "gPLink")
			if gplink != "" {
				collect(dn, gplink)
			}
		}

		// 2. All OUs.
		ouEntries, err := connection.PagedSearch(ldapConn, ldap.NewSearchRequest(
			conn.BaseDN(),
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=organizationalUnit)(gPLink=*))",
			[]string{"distinguishedName", "gPLink"},
			nil,
		))
		if err != nil {
			return nil, fmt.Errorf("querying OU gPLinks: %w", err)
		}
		for _, entry := range ouEntries {
			dn := connection.GetStringAttr(entry, "distinguishedName")
			gplink := connection.GetStringAttr(entry, "gPLink")
			if gplink != "" {
				collect(dn, gplink)
			}
		}

		// 3. Sites under CN=Sites,{configDN}.
		siteBase := "CN=Sites," + conn.ConfigDN()
		siteEntries, err := connection.PagedSearch(ldapConn, ldap.NewSearchRequest(
			siteBase,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(gPLink=*)",
			[]string{"distinguishedName", "gPLink"},
			nil,
		))
		if err != nil {
			// Sites may not exist or be accessible; log and continue.
			log.Warn().Err(err).Msg("failed to query site gPLinks, continuing without site links")
		} else {
			for _, entry := range siteEntries {
				dn := connection.GetStringAttr(entry, "distinguishedName")
				gplink := connection.GetStringAttr(entry, "gPLink")
				if gplink != "" {
					collect(dn, gplink)
				}
			}
		}

		return m, nil
	})
	if err != nil {
		return nil, err
	}
	return raw.(*gpoLinkMap), nil
}

// gpoStatusLabel converts the AD flags attribute on a groupPolicyContainer
// to a human-readable status string.
//
//	0 = enabled (user and computer)
//	1 = user configuration disabled
//	2 = computer configuration disabled
//	3 = all disabled
func gpoStatusLabel(flags int64) string {
	switch flags {
	case 0:
		return "enabled"
	case 1:
		return "user disabled"
	case 2:
		return "computer disabled"
	case 3:
		return "disabled"
	default:
		return "enabled"
	}
}

func (a *mqlActivedirectory) gpos() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	baseDN := conn.BaseDN()

	attrs := []string{
		"cn",
		"displayName",
		"distinguishedName",
		"gPCFileSysPath",
		"flags",
		"versionNumber",
		"whenCreated",
		"whenChanged",
	}

	entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		"CN=Policies,CN=System,"+baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=groupPolicyContainer)",
		attrs,
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to query GPOs: %w", err)
	}

	// Build the link map so we can determine isLinked per GPO.
	linkMap, err := buildGPOLinkMap(conn)
	if err != nil {
		log.Warn().Err(err).Msg("failed to build GPO link map, all GPOs will show isLinked=false")
		linkMap = &gpoLinkMap{byGPO: make(map[string][]scopeLink)}
	}

	res := make([]any, 0, len(entries))
	for _, entry := range entries {
		cn := connection.GetStringAttr(entry, "cn")
		displayName := connection.GetStringAttr(entry, "displayName")
		dn := connection.GetStringAttr(entry, "distinguishedName")
		gpcPath := connection.GetStringAttr(entry, "gPCFileSysPath")
		flags := parseInt64Attr(connection.GetStringAttr(entry, "flags"))
		version := parseInt64Attr(connection.GetStringAttr(entry, "versionNumber"))
		whenCreated := parseADGeneralizedTime(connection.GetStringAttr(entry, "whenCreated"))
		whenChanged := parseADGeneralizedTime(connection.GetStringAttr(entry, "whenChanged"))

		_, isLinked := linkMap.byGPO[strings.ToLower(dn)]

		resource, err := CreateResource(a.MqlRuntime, "activedirectory.gpo",
			map[string]*llx.RawData{
				"id":                llx.StringData(cn),
				"displayName":       llx.StringData(displayName),
				"distinguishedName": llx.StringData(dn),
				"gpoStatus":         llx.StringData(gpoStatusLabel(flags)),
				"gpcFileSysPath":    llx.StringData(gpcPath),
				"isLinked":          llx.BoolData(isLinked),
				"whenCreated":       llx.TimeData(whenCreated),
				"whenChanged":       llx.TimeData(whenChanged),
				"version":           llx.IntData(version),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, resource)
	}

	return res, nil
}

// links returns all scope objects (domain root, OUs, sites) that link this GPO,
// as activedirectory.gpoLink resources.
func (a *mqlActivedirectoryGpo) links() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)

	linkMap, err := buildGPOLinkMap(conn)
	if err != nil {
		return nil, fmt.Errorf("resolving GPO link map: %w", err)
	}

	gpoDN := strings.ToLower(a.DistinguishedName.Data)
	scopeLinks := linkMap.byGPO[gpoDN]
	if len(scopeLinks) == 0 {
		return []any{}, nil
	}

	res := make([]any, 0, len(scopeLinks))
	for _, sl := range scopeLinks {
		id := fmt.Sprintf("%s|%s/%d", a.DistinguishedName.Data, sl.scopeDN, sl.link.order)
		resource, err := CreateResource(a.MqlRuntime, "activedirectory.gpoLink",
			map[string]*llx.RawData{
				"__id":     llx.StringData(id),
				"target":   llx.StringData(sl.scopeDN),
				"order":    llx.IntData(int64(sl.link.order)),
				"enforced": llx.BoolData(sl.link.enforced),
				"enabled":  llx.BoolData(sl.link.enabled),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}

	return res, nil
}
