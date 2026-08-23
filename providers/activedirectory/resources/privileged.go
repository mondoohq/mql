// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/activedirectory/connection"
)

// privilegedGroupDef describes a well-known privileged AD group by its
// relative identifier and the scope it belongs to.
type privilegedGroupDef struct {
	RID   string // e.g. "512"
	Base  string // "domain", "forest", or "builtin"
	Label string // human-readable name, e.g. "Domain Admins"
}

// privilegedGroups enumerates the nine well-known privileged groups that
// security assessments universally flag.
var privilegedGroups = []privilegedGroupDef{
	// Current-domain groups — SID prefix is the domain SID.
	{RID: "512", Base: "domain", Label: "Domain Admins"},
	{RID: "525", Base: "domain", Label: "Protected Users"},

	// Forest-root groups — SID prefix is the root domain SID.
	{RID: "518", Base: "forest", Label: "Schema Admins"},
	{RID: "519", Base: "forest", Label: "Enterprise Admins"},

	// BUILTIN groups — SID prefix is S-1-5-32.
	{RID: "544", Base: "builtin", Label: "Administrators"},
	{RID: "548", Base: "builtin", Label: "Account Operators"},
	{RID: "549", Base: "builtin", Label: "Server Operators"},
	{RID: "550", Base: "builtin", Label: "Print Operators"},
	{RID: "551", Base: "builtin", Label: "Backup Operators"},
}

func privilegedGroupSID(conn *connection.ActiveDirectoryConnection, pg privilegedGroupDef) (string, error) {
	switch pg.Base {
	case "domain":
		return conn.DomainSID() + "-" + pg.RID, nil
	case "forest":
		return conn.RootDomainSID() + "-" + pg.RID, nil
	case "builtin":
		return "S-1-5-32-" + pg.RID, nil
	default:
		return "", fmt.Errorf("unknown privileged group base %q", pg.Base)
	}
}

// privilegedMemberships holds sets of distinguished names that are (recursively)
// members of each well-known privileged group.
type privilegedMemberships struct {
	DomainAdmins     map[string]bool
	EnterpriseAdmins map[string]bool
	SchemaAdmins     map[string]bool
	ProtectedUsers   map[string]bool
	AllPrivileged    map[string]bool // union of all privileged group members
}

// ---------------------------------------------------------------------------
// SID encoding helpers
// ---------------------------------------------------------------------------

// sidStringToBytes converts a canonical SID string (e.g. "S-1-5-21-…-512")
// to its binary representation — the inverse of connection.DecodeSID.
func sidStringToBytes(sidStr string) ([]byte, error) {
	parts := strings.Split(sidStr, "-")
	// Minimum: S-<rev>-<authority>  → 3 parts
	if len(parts) < 3 || strings.ToUpper(parts[0]) != "S" {
		return nil, fmt.Errorf("invalid SID string: %s", sidStr)
	}

	revision, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("bad SID revision %q: %w", parts[1], err)
	}

	authority, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("bad SID authority %q: %w", parts[2], err)
	}

	subAuthCount := len(parts) - 3
	// The binary SID encodes SubAuthorityCount in a single byte (buf[1] below),
	// so a valid SID has at most 255 sub-authorities. Reject anything larger
	// before sizing the buffer, both to keep the encoding correct and to avoid
	// computing an allocation size from an unbounded, externally-derived value.
	if subAuthCount > 255 {
		return nil, fmt.Errorf("invalid SID string: too many sub-authorities (%d): %s", subAuthCount, sidStr)
	}
	buf := make([]byte, 8+4*subAuthCount)

	buf[0] = byte(revision)
	buf[1] = byte(subAuthCount)

	// Authority is stored big-endian in bytes [2..7].
	buf[2] = byte(authority >> 40)
	buf[3] = byte(authority >> 32)
	buf[4] = byte(authority >> 24)
	buf[5] = byte(authority >> 16)
	buf[6] = byte(authority >> 8)
	buf[7] = byte(authority)

	for i := 0; i < subAuthCount; i++ {
		sa, err := strconv.ParseUint(parts[3+i], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad SID sub-authority %q: %w", parts[3+i], err)
		}
		binary.LittleEndian.PutUint32(buf[8+4*i:], uint32(sa))
	}

	return buf, nil
}

// escapeBinaryForLDAP produces an LDAP-safe hex-escaped string from raw bytes,
// e.g. []byte{0x01, 0x05} → `\01\05`.
func escapeBinaryForLDAP(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 3)
	for _, c := range b {
		fmt.Fprintf(&sb, "\\%02x", c)
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Privileged group resolution
// ---------------------------------------------------------------------------

// resolvePrivilegedGroupDNs looks up the distinguished name of each well-known
// privileged group by constructing its expected SID and querying LDAP with a
// binary-escaped objectSid filter.
//
// The returned map is keyed by SID string → DN. Groups that don't exist in the
// directory (e.g. Enterprise Admins in a child domain) are silently skipped.
func resolvePrivilegedGroupDNs(conn *connection.ActiveDirectoryConnection) (map[string]string, error) {
	type privilegedGroupQuery struct {
		sidFilter string
	}

	queriesByBase := make(map[string][]privilegedGroupQuery)
	for _, pg := range privilegedGroups {
		sidStr, err := privilegedGroupSID(conn, pg)
		if err != nil {
			return nil, err
		}

		sidBytes, err := sidStringToBytes(sidStr)
		if err != nil {
			return nil, fmt.Errorf("encoding SID %s for %s: %w", sidStr, pg.Label, err)
		}

		searchBase := conn.BaseDN()
		if pg.Base == "forest" {
			searchBase = conn.RootDomainDN()
		}
		if searchBase == "" {
			continue
		}

		queriesByBase[searchBase] = append(queriesByBase[searchBase], privilegedGroupQuery{
			sidFilter: fmt.Sprintf("(objectSid=%s)", escapeBinaryForLDAP(sidBytes)),
		})
	}

	result := make(map[string]string, len(privilegedGroups))
	for searchBase, queries := range queriesByBase {
		filterParts := make([]string, 0, len(queries))
		for _, query := range queries {
			filterParts = append(filterParts, query.sidFilter)
		}

		entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
			searchBase,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(&(objectClass=group)(|%s))", strings.Join(filterParts, "")),
			[]string{"distinguishedName", "objectSid"},
			nil,
		))
		if err != nil {
			// BUILTIN groups live under CN=Builtin which is always under baseDN,
			// but forest-root groups may not exist in this domain at all.
			// Treat search errors for each search base as non-fatal.
			continue
		}

		for _, entry := range entries {
			sidStr, err := connection.DecodeSID(connection.GetBinaryAttr(entry, "objectSid"))
			if err != nil || sidStr == "" {
				continue
			}
			result[sidStr] = entry.DN
		}
	}

	return result, nil
}

// labelForRID returns the label index used by privilegedMemberships for the
// given group. Only the four groups that have dedicated sets are tracked; the
// rest contribute only to AllPrivileged.
var ridToField = map[string]string{
	"512": "DomainAdmins",
	"519": "EnterpriseAdmins",
	"518": "SchemaAdmins",
	"525": "ProtectedUsers",
}

// markPrivileged records a distinguished name in the union set and, when the
// group has a dedicated set, in that set as well.
func markPrivileged(pm *privilegedMemberships, field, dn string) {
	pm.AllPrivileged[dn] = true

	switch field {
	case "DomainAdmins":
		pm.DomainAdmins[dn] = true
	case "EnterpriseAdmins":
		pm.EnterpriseAdmins[dn] = true
	case "SchemaAdmins":
		pm.SchemaAdmins[dn] = true
	case "ProtectedUsers":
		pm.ProtectedUsers[dn] = true
	}
}

// ---------------------------------------------------------------------------
// Primary group membership
// ---------------------------------------------------------------------------
//
// An account's primary group is stored as the primaryGroupID attribute (a RID
// relative to the account's own domain) and is a full membership: the account
// is a member of that group even though the group never appears in memberOf
// and the account never appears in the group's member attribute. The
// LDAP_MATCHING_RULE_IN_CHAIN queries above therefore cannot see it, so it is
// resolved separately here.

// primaryGroupRecord is one account's primary group assignment, as read from
// LDAP.
type primaryGroupRecord struct {
	dn             string
	objectSID      string
	primaryGroupID int64
}

// domainSIDFromObjectSID strips the trailing RID from an object SID, yielding
// the SID of the domain that issued it. It returns "" for SIDs that no domain
// issued, such as the well-known S-1-5-11 (Authenticated Users) or a BUILTIN
// SID like S-1-5-32-544, neither of which can prefix a primaryGroupID.
func domainSIDFromObjectSID(objectSID string) string {
	// A domain account SID is S-1-5-21-<a>-<b>-<c>-<rid>: eight dash-separated
	// parts. Anything shorter has no domain prefix to extract.
	parts := strings.Split(objectSID, "-")
	if len(parts) < 8 {
		return ""
	}
	return strings.Join(parts[:len(parts)-1], "-")
}

// primaryGroupSIDForAccount resolves an account's primaryGroupID to the SID of
// the group it names. The RID is relative to the domain that issued the
// account's own SID, which keeps this correct in a multi-domain forest.
func primaryGroupSIDForAccount(objectSID string, primaryGroupID int64) string {
	if primaryGroupID <= 0 {
		return ""
	}
	domainSID := domainSIDFromObjectSID(objectSID)
	if domainSID == "" {
		return ""
	}
	return domainSID + "-" + strconv.FormatInt(primaryGroupID, 10)
}

// primaryGroupCandidateRIDs returns the privileged RIDs that can appear as an
// account's primaryGroupID. BUILTIN groups (S-1-5-32-*) are domain-local
// groups on the machine and can never be a primary group, so they are skipped.
func primaryGroupCandidateRIDs() []string {
	rids := make([]string, 0, len(privilegedGroups))
	seen := make(map[string]bool, len(privilegedGroups))
	for _, pg := range privilegedGroups {
		if pg.Base == "builtin" || seen[pg.RID] {
			continue
		}
		seen[pg.RID] = true
		rids = append(rids, pg.RID)
	}
	return rids
}

// primaryGroupSearchFilter builds the LDAP filter that selects every account
// whose primaryGroupID is one of the given privileged RIDs. It returns "" when
// there is nothing to search for.
func primaryGroupSearchFilter(rids []string) string {
	if len(rids) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rids))
	for _, rid := range rids {
		parts = append(parts, fmt.Sprintf("(primaryGroupID=%s)", ldap.EscapeFilter(rid)))
	}
	return fmt.Sprintf("(&%s(|%s))", userObjectFilter, strings.Join(parts, ""))
}

// privilegedGroupSIDIndex maps the SID of every privileged group that can be a
// primary group to the privilegedMemberships field it feeds. Groups that only
// contribute to AllPrivileged map to "".
func privilegedGroupSIDIndex(conn *connection.ActiveDirectoryConnection) (map[string]string, error) {
	index := make(map[string]string, len(privilegedGroups))
	for _, pg := range privilegedGroups {
		if pg.Base == "builtin" {
			continue
		}
		sidStr, err := privilegedGroupSID(conn, pg)
		if err != nil {
			return nil, err
		}
		// A group SID with no domain prefix means the domain SID was never
		// discovered; skip it rather than indexing a bare "-512".
		if strings.HasPrefix(sidStr, "-") {
			continue
		}
		index[sidStr] = ridToField[pg.RID]
	}
	return index, nil
}

// fetchPrimaryGroupRecords reads every account whose primaryGroupID names a
// privileged group, across all domain naming contexts the connection knows.
func fetchPrimaryGroupRecords(conn *connection.ActiveDirectoryConnection) ([]primaryGroupRecord, error) {
	filter := primaryGroupSearchFilter(primaryGroupCandidateRIDs())
	if filter == "" {
		return nil, nil
	}

	searchBases := conn.DomainNamingContexts()
	if len(searchBases) == 0 {
		searchBases = []string{conn.BaseDN()}
	}

	seen := make(map[string]bool)
	var records []primaryGroupRecord

	for _, searchBase := range searchBases {
		if searchBase == "" {
			continue
		}

		entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
			searchBase,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			filter,
			[]string{"distinguishedName", "objectSid", "primaryGroupID"},
			nil,
		))
		if err != nil {
			// Non-fatal: a naming context may not be searchable with these
			// credentials. Keep whatever the other contexts returned.
			log.Warn().Err(err).Str("searchBase", searchBase).Msg("primary group search failed")
			continue
		}

		for _, entry := range entries {
			dn := entry.DN
			if dn == "" || seen[dn] {
				continue
			}
			seen[dn] = true

			sidStr, err := connection.DecodeSID(connection.GetBinaryAttr(entry, "objectSid"))
			if err != nil {
				log.Warn().Err(err).Str("dn", dn).Msg("failed to decode SID for primary group lookup")
				continue
			}

			records = append(records, primaryGroupRecord{
				dn:             dn,
				objectSID:      sidStr,
				primaryGroupID: parseInt64Attr(entry.GetAttributeValue("primaryGroupID")),
			})
		}
	}

	return records, nil
}

// applyPrimaryGroupMemberships folds primary group membership into the
// privileged sets. sidToField maps a privileged group SID to the
// privilegedMemberships field it feeds.
func applyPrimaryGroupMemberships(pm *privilegedMemberships, sidToField map[string]string, records []primaryGroupRecord) {
	for _, rec := range records {
		if rec.dn == "" {
			continue
		}

		groupSID := primaryGroupSIDForAccount(rec.objectSID, rec.primaryGroupID)
		if groupSID == "" {
			continue
		}

		field, ok := sidToField[groupSID]
		if !ok {
			continue
		}

		markPrivileged(pm, field, rec.dn)
	}
}

// addPrimaryGroupMemberships resolves and folds primary group membership into
// the already-populated privileged sets.
func addPrimaryGroupMemberships(conn *connection.ActiveDirectoryConnection, pm *privilegedMemberships) error {
	index, err := privilegedGroupSIDIndex(conn)
	if err != nil {
		return err
	}
	if len(index) == 0 {
		return nil
	}

	records, err := fetchPrimaryGroupRecords(conn)
	if err != nil {
		return err
	}

	applyPrimaryGroupMemberships(pm, index, records)
	return nil
}

// buildPrivilegedMembershipSets resolves all well-known privileged group
// memberships via recursive LDAP queries and returns populated sets.
// Results are cached on the connection for the lifetime of the scan.
func buildPrivilegedMembershipSets(conn *connection.ActiveDirectoryConnection) (*privilegedMemberships, error) {
	raw, err := conn.CachedFetch("privilegedMemberships", func() (interface{}, error) {
		groupDNs, err := resolvePrivilegedGroupDNs(conn)
		if err != nil {
			return nil, fmt.Errorf("resolving privileged group DNs: %w", err)
		}

		pm := &privilegedMemberships{
			DomainAdmins:     make(map[string]bool),
			EnterpriseAdmins: make(map[string]bool),
			SchemaAdmins:     make(map[string]bool),
			ProtectedUsers:   make(map[string]bool),
			AllPrivileged:    make(map[string]bool),
		}

		for _, pg := range privilegedGroups {
			sidStr, err := privilegedGroupSID(conn, pg)
			if err != nil {
				return nil, err
			}

			groupDN, ok := groupDNs[sidStr]
			if !ok {
				continue
			}

			// Recursive membership via LDAP_MATCHING_RULE_IN_CHAIN.
			filter := fmt.Sprintf(
				"(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=%s))",
				ldap.EscapeFilter(groupDN),
			)

			searchBases := []string{conn.BaseDN()}
			if pg.Base == "forest" {
				searchBases = conn.DomainNamingContexts()
			}

			field := ridToField[pg.RID]
			for _, searchBase := range searchBases {
				entries, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
					searchBase,
					ldap.ScopeWholeSubtree,
					ldap.NeverDerefAliases, 0, 0, false,
					filter,
					[]string{"distinguishedName"},
					nil,
				))
				if err != nil {
					// Non-fatal: some groups may not be searchable in this naming context.
					continue
				}

				for _, entry := range entries {
					markPrivileged(pm, field, entry.DN)
				}
			}
		}

		// Primary group membership is invisible to the memberOf chain above,
		// so fold it in separately. A failure here must not drop the
		// memberOf-derived results, so it is logged rather than returned.
		if err := addPrimaryGroupMemberships(conn, pm); err != nil {
			log.Warn().Err(err).Msg("failed to resolve primary group memberships")
		}

		return pm, nil
	})
	if err != nil {
		return nil, err
	}

	return raw.(*privilegedMemberships), nil
}
