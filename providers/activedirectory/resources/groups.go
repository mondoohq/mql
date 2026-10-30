// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/activedirectory/connection"
)

// parseGroupType interprets the AD groupType bitmask and returns a
// human-readable label (e.g. "Security - Global") plus the raw int64 value.
// groupType is stored as a decimal string representing a signed 32-bit integer.
func parseGroupType(raw int64) (string, int64) {
	// Signed 32-bit interpretation: bit 31 → security group.
	isSecurity := (raw & 0x80000000) != 0

	var kind string
	if isSecurity {
		kind = "Security"
	} else {
		kind = "Distribution"
	}

	scope := "Unknown"
	switch {
	case raw&0x02 != 0:
		scope = "Global"
	case raw&0x04 != 0:
		scope = "DomainLocal"
	case raw&0x08 != 0:
		scope = "Universal"
	}

	return kind + " - " + scope, raw
}

// privilegedGroupSIDs builds the set of well-known privileged group SIDs
// from the shared privilegedGroups definitions in privileged.go.
func privilegedGroupSIDs(domainSID, rootDomainSID string) map[string]bool {
	sids := make(map[string]bool, len(privilegedGroups))
	for _, pg := range privilegedGroups {
		var sid string
		switch pg.Base {
		case "domain":
			sid = domainSID + "-" + pg.RID
		case "forest":
			sid = rootDomainSID + "-" + pg.RID
		case "builtin":
			sid = "S-1-5-32-" + pg.RID
		default:
			continue
		}
		sids[sid] = true
	}
	return sids
}

const groupMemberLookupBatchSize = 50

type groupMemberLookupBatch struct {
	searchBase string
	memberDNs  []string
}

func (a *mqlActivedirectory) groups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	baseDN := conn.BaseDN()

	attrs := []string{
		"sAMAccountName",
		"distinguishedName",
		"displayName",
		"objectSid",
		"groupType",
		"description",
		"adminCount",
		"whenCreated",
	}

	entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=group)",
		attrs,
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to query groups: %w", err)
	}

	privSIDs := privilegedGroupSIDs(conn.DomainSID(), conn.RootDomainSID())

	res := make([]any, 0, len(entries))
	for _, entry := range entries {
		samName := connection.GetStringAttr(entry, "sAMAccountName")
		dn := connection.GetStringAttr(entry, "distinguishedName")
		displayName := connection.GetStringAttr(entry, "displayName")
		desc := connection.GetStringAttr(entry, "description")

		// SID
		sidRaw := connection.GetBinaryAttr(entry, "objectSid")
		sid, _ := connection.DecodeSID(sidRaw)

		// groupType: stored as signed 32-bit decimal string
		groupTypeRaw := parseInt64Attr(connection.GetStringAttr(entry, "groupType"))
		// Sign-extend from 32-bit: AD stores negative values like -2147483646.
		// parseInt64Attr already parses negative strings correctly, but if the value
		// came as unsigned 32-bit, force sign extension.
		groupTypeLabel, groupTypeVal := parseGroupType(groupTypeRaw)

		// adminCount: AD stores as "1" when set; 0 or absent otherwise
		adminCount := connection.GetStringAttr(entry, "adminCount") == "1"

		// whenCreated: AD generalized time "20060102150405.0Z"
		whenCreated := parseADGeneralizedTime(connection.GetStringAttr(entry, "whenCreated"))
		ouPath := extractOU(dn)
		isPrivileged := privSIDs[sid]

		resource, err := CreateResource(a.MqlRuntime, "activedirectory.group",
			map[string]*llx.RawData{
				"sAMAccountName":    llx.StringData(samName),
				"distinguishedName": llx.StringData(dn),
				"displayName":       llx.StringData(displayName),
				"sid":               llx.StringData(sid),
				"groupType":         llx.StringData(groupTypeLabel),
				"groupTypeRaw":      llx.IntData(groupTypeVal),
				"description":       llx.StringData(desc),
				"adminCount":        llx.BoolData(adminCount),
				"isPrivileged":      llx.BoolData(isPrivileged),
				"whenCreated":       llx.TimeData(whenCreated),
				"ouPath":            llx.StringData(ouPath),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, resource)
	}

	return res, nil
}

func (a *mqlActivedirectoryGroup) id() (string, error) {
	return a.DistinguishedName.Data, nil
}

func (a *mqlActivedirectoryGroup) memberCount() (int64, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	groupDN := a.DistinguishedName.Data

	memberDNs, err := fetchGroupMemberDNs(conn, groupDN)
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve member count for group %s: %w", groupDN, err)
	}

	return int64(len(memberDNs)), nil
}

// members performs full range retrieval of the group's member attribute and
// resolves each member DN to an activedirectory.groupMember resource.
func (a *mqlActivedirectoryGroup) members() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	groupDN := a.DistinguishedName.Data

	memberDNs, err := fetchGroupMemberDNs(conn, groupDN)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve members for group %s: %w", groupDN, err)
	}

	return resolveMembers(a.MqlRuntime, conn, memberDNs)
}

// rangeRetrieveMembers collects all member DNs from a group using AD's
// range retrieval mechanism. AD returns at most MaxValRange (typically 1500)
// values per request; this function pages through until all are collected.
func rangeRetrieveMembers(l *ldap.Conn, groupDN string) ([]string, error) {
	var allMembers []string
	rangeStart := 0

	for {
		rangeAttr := fmt.Sprintf("member;range=%d-*", rangeStart)
		entries, err := connection.PagedSearch(l, ldap.NewSearchRequest(
			groupDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{rangeAttr},
			nil,
		))
		if err != nil {
			return nil, err
		}
		if len(entries) == 0 {
			break
		}

		entry := entries[0]
		var found bool
		var isTerminal bool
		for _, attr := range entry.Attributes {
			if !strings.HasPrefix(strings.ToLower(attr.Name), "member;range=") {
				continue
			}
			found = true
			allMembers = append(allMembers, attr.Values...)

			// Parse range header to determine if this is the last page.
			// Format: "member;range=X-Y" where Y="*" on the terminal page.
			rangePart := attr.Name[len("member;range="):]
			parts := strings.SplitN(rangePart, "-", 2)
			if len(parts) == 2 && parts[1] == "*" {
				isTerminal = true
			} else if len(parts) == 2 {
				endVal, err := strconv.Atoi(parts[1])
				if err != nil {
					return allMembers, nil
				}
				rangeStart = endVal + 1
			}
			break
		}

		if !found || isTerminal {
			// No member attribute returned (empty group) or terminal page reached.
			break
		}
	}

	return allMembers, nil
}

func fetchGroupMemberDNs(conn *connection.ActiveDirectoryConnection, groupDN string) ([]string, error) {
	raw, err := conn.CachedFetch("groupMembers:"+strings.ToLower(groupDN), func() (any, error) {
		return rangeRetrieveMembers(conn.LDAPConn(), groupDN)
	})
	if err != nil {
		return nil, err
	}

	memberDNs, ok := raw.([]string)
	if !ok {
		return nil, fmt.Errorf("cached group members for %s have unexpected type %T", groupDN, raw)
	}

	return memberDNs, nil
}

func resolveMembers(runtime *plugin.Runtime, conn *connection.ActiveDirectoryConnection, memberDNs []string) ([]any, error) {
	searchBases := memberLookupSearchBases(conn)
	batches := memberLookupBatches(memberDNs, searchBases, groupMemberLookupBatchSize)
	resolved := make(map[string]any, len(memberDNs))

	for _, batch := range batches {
		entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
			batch.searchBase,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			buildDistinguishedNameFilter(batch.memberDNs),
			[]string{"distinguishedName", "sAMAccountName", "objectSid", "objectClass"},
			nil,
		))
		if err != nil {
			continue
		}

		for _, entry := range entries {
			memberDN := entry.DN
			if memberDN == "" {
				memberDN = connection.GetStringAttr(entry, "distinguishedName")
			}
			if memberDN == "" {
				continue
			}

			member, err := createGroupMemberResource(runtime, entry, memberDN)
			if err != nil {
				continue
			}

			resolved[strings.ToLower(memberDN)] = member
		}
	}

	res := make([]any, 0, len(memberDNs))
	for _, memberDN := range memberDNs {
		if member, ok := resolved[strings.ToLower(memberDN)]; ok {
			res = append(res, member)
			continue
		}

		member, err := resolveMember(runtime, conn, memberDN)
		if err != nil {
			// Skip orphaned or deleted objects gracefully.
			continue
		}
		res = append(res, member)
	}

	return res, nil
}

func memberLookupSearchBases(conn *connection.ActiveDirectoryConnection) []string {
	candidates := append([]string{conn.BaseDN()}, conn.DomainNamingContexts()...)
	seen := make(map[string]bool, len(candidates))
	searchBases := make([]string, 0, len(candidates))

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}

		key := strings.ToLower(candidate)
		if seen[key] {
			continue
		}

		seen[key] = true
		searchBases = append(searchBases, candidate)
	}

	return searchBases
}

func memberLookupBatches(memberDNs, searchBases []string, batchSize int) []groupMemberLookupBatch {
	if batchSize <= 0 {
		batchSize = len(memberDNs)
	}

	fallbackBase := ""
	if len(searchBases) > 0 {
		fallbackBase = searchBases[0]
	}

	grouped := make(map[string][]string, len(searchBases))
	for _, memberDN := range memberDNs {
		searchBase := bestMatchingSearchBase(memberDN, searchBases)
		if searchBase == "" {
			searchBase = fallbackBase
		}
		if searchBase == "" {
			continue
		}

		grouped[searchBase] = append(grouped[searchBase], memberDN)
	}

	var batches []groupMemberLookupBatch
	for _, searchBase := range searchBases {
		dns := grouped[searchBase]
		for start := 0; start < len(dns); start += batchSize {
			end := min(start+batchSize, len(dns))

			batches = append(batches, groupMemberLookupBatch{
				searchBase: searchBase,
				memberDNs:  dns[start:end],
			})
		}
	}

	return batches
}

func bestMatchingSearchBase(memberDN string, searchBases []string) string {
	best := ""
	for _, searchBase := range searchBases {
		if !dnWithinBase(memberDN, searchBase) {
			continue
		}
		if len(searchBase) > len(best) {
			best = searchBase
		}
	}
	return best
}

func dnWithinBase(dn, baseDN string) bool {
	dn = strings.ToLower(dn)
	baseDN = strings.ToLower(baseDN)
	if dn == baseDN {
		return true
	}
	return strings.HasSuffix(dn, ","+baseDN)
}

func buildDistinguishedNameFilter(memberDNs []string) string {
	parts := make([]string, 0, len(memberDNs))
	for _, memberDN := range memberDNs {
		parts = append(parts, fmt.Sprintf("(distinguishedName=%s)", ldap.EscapeFilter(memberDN)))
	}
	return fmt.Sprintf("(|%s)", strings.Join(parts, ""))
}

// resolveMember queries a single member DN to determine its type and
// creates an activedirectory.groupMember resource.
func resolveMember(runtime *plugin.Runtime, conn *connection.ActiveDirectoryConnection, memberDN string) (any, error) {
	entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		memberDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"sAMAccountName", "objectSid", "objectClass"},
		nil,
	))
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("member not found: %s", memberDN)
	}

	return createGroupMemberResource(runtime, entries[0], memberDN)
}

func createGroupMemberResource(runtime *plugin.Runtime, entry *ldap.Entry, memberDN string) (any, error) {
	name := connection.GetStringAttr(entry, "sAMAccountName")
	sidRaw := connection.GetBinaryAttr(entry, "objectSid")
	sid, _ := connection.DecodeSID(sidRaw)

	classes := connection.GetStringSliceAttr(entry, "objectClass")
	memberType := classifyMember(classes)

	return CreateResource(runtime, "activedirectory.groupMember",
		map[string]*llx.RawData{
			"name":              llx.StringData(name),
			"distinguishedName": llx.StringData(memberDN),
			"sid":               llx.StringData(sid),
			"type":              llx.StringData(memberType),
		})
}

// classifyMember determines the member type from its objectClass list.
func classifyMember(classes []string) string {
	for _, c := range classes {
		lower := strings.ToLower(c)
		if lower == "computer" {
			return "computer"
		}
	}
	for _, c := range classes {
		if strings.ToLower(c) == "group" {
			return "group"
		}
	}
	return "user"
}

func (a *mqlActivedirectoryGroupMember) id() (string, error) {
	return a.DistinguishedName.Data, nil
}
