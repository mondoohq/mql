// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"
)

// Documentation-example domain SIDs. S-1-5-21-100-200-300 stands in for the
// scanned domain and S-1-5-21-900-800-700 for the forest root.
const (
	testDomainSID     = "S-1-5-21-100-200-300"
	testRootDomainSID = "S-1-5-21-900-800-700"
)

// testSIDIndex mirrors what privilegedGroupSIDIndex builds from a connection,
// without needing a live directory.
func testSIDIndex() map[string]string {
	return map[string]string{
		testDomainSID + "-512":     "DomainAdmins",
		testDomainSID + "-525":     "ProtectedUsers",
		testRootDomainSID + "-518": "SchemaAdmins",
		testRootDomainSID + "-519": "EnterpriseAdmins",
	}
}

func newTestMemberships() *privilegedMemberships {
	return &privilegedMemberships{
		DomainAdmins:     make(map[string]bool),
		EnterpriseAdmins: make(map[string]bool),
		SchemaAdmins:     make(map[string]bool),
		ProtectedUsers:   make(map[string]bool),
		AllPrivileged:    make(map[string]bool),
	}
}

func TestDomainSIDFromObjectSID(t *testing.T) {
	tests := []struct {
		name string
		sid  string
		want string
	}{
		{"user SID", testDomainSID + "-1105", testDomainSID},
		{"domain admins group SID", testDomainSID + "-512", testDomainSID},
		{"forest root user SID", testRootDomainSID + "-1200", testRootDomainSID},
		{"well-known Authenticated Users", "S-1-5-11", ""},
		{"well-known Everyone", "S-1-1-0", ""},
		{"BUILTIN Administrators", "S-1-5-32-544", ""},
		{"empty", "", ""},
		{"no dash", "S", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := domainSIDFromObjectSID(tt.sid); got != tt.want {
				t.Errorf("domainSIDFromObjectSID(%q) = %q, want %q", tt.sid, got, tt.want)
			}
		})
	}
}

func TestPrimaryGroupSIDForAccount(t *testing.T) {
	tests := []struct {
		name      string
		objectSID string
		rid       int64
		want      string
	}{
		{"Domain Admins", testDomainSID + "-1105", 512, testDomainSID + "-512"},
		{"Domain Users", testDomainSID + "-1105", 513, testDomainSID + "-513"},
		{"Enterprise Admins in root domain", testRootDomainSID + "-1200", 519, testRootDomainSID + "-519"},
		// A RID is relative to the account's own domain, so 519 on an account
		// in a child domain does not name the forest-root Enterprise Admins.
		{"519 in a child domain", testDomainSID + "-1105", 519, testDomainSID + "-519"},
		{"unset primaryGroupID", testDomainSID + "-1105", 0, ""},
		{"negative primaryGroupID", testDomainSID + "-1105", -1, ""},
		{"well-known object SID", "S-1-5-11", 512, ""},
		{"empty object SID", "", 512, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := primaryGroupSIDForAccount(tt.objectSID, tt.rid); got != tt.want {
				t.Errorf("primaryGroupSIDForAccount(%q, %d) = %q, want %q",
					tt.objectSID, tt.rid, got, tt.want)
			}
		})
	}
}

func TestPrimaryGroupCandidateRIDs(t *testing.T) {
	rids := primaryGroupCandidateRIDs()

	want := map[string]bool{"512": true, "518": true, "519": true, "525": true}
	got := make(map[string]bool, len(rids))
	for _, rid := range rids {
		if got[rid] {
			t.Errorf("duplicate RID %q in candidate list", rid)
		}
		got[rid] = true
	}

	for rid := range want {
		if !got[rid] {
			t.Errorf("candidate RIDs missing %q, got %v", rid, rids)
		}
	}
	// BUILTIN groups are domain-local and can never be a primary group.
	for _, builtin := range []string{"544", "548", "549", "550", "551"} {
		if got[builtin] {
			t.Errorf("candidate RIDs must not contain BUILTIN RID %q, got %v", builtin, rids)
		}
	}
}

func TestPrimaryGroupSearchFilter(t *testing.T) {
	if got := primaryGroupSearchFilter(nil); got != "" {
		t.Errorf("primaryGroupSearchFilter(nil) = %q, want empty", got)
	}

	filter := primaryGroupSearchFilter([]string{"512", "519"})
	for _, want := range []string{"(primaryGroupID=512)", "(primaryGroupID=519)", userObjectFilter} {
		if !strings.Contains(filter, want) {
			t.Errorf("filter %q does not contain %q", filter, want)
		}
	}
	if !strings.HasPrefix(filter, "(&") || !strings.HasSuffix(filter, ")") {
		t.Errorf("filter %q is not a well-formed AND clause", filter)
	}
}

func TestApplyPrimaryGroupMemberships(t *testing.T) {
	const (
		stealthAdminDN = "CN=Stealth Admin,CN=Users,DC=example,DC=com"
		ordinaryUserDN = "CN=Ordinary User,CN=Users,DC=example,DC=com"
		rootAdminDN    = "CN=Root Admin,CN=Users,DC=example,DC=test"
		schemaAdminDN  = "CN=Schema Owner,CN=Users,DC=example,DC=test"
		protectedDN    = "CN=Protected,CN=Users,DC=example,DC=com"
	)

	pm := newTestMemberships()
	applyPrimaryGroupMemberships(pm, testSIDIndex(), []primaryGroupRecord{
		// The stealth case: primaryGroupID 512 with nothing in memberOf.
		{dn: stealthAdminDN, objectSID: testDomainSID + "-1105", primaryGroupID: 512},
		// Domain Users is the default and must not be privileged.
		{dn: ordinaryUserDN, objectSID: testDomainSID + "-1106", primaryGroupID: 513},
		{dn: rootAdminDN, objectSID: testRootDomainSID + "-1200", primaryGroupID: 519},
		{dn: schemaAdminDN, objectSID: testRootDomainSID + "-1201", primaryGroupID: 518},
		{dn: protectedDN, objectSID: testDomainSID + "-1107", primaryGroupID: 525},
		// 519 relative to a non-root domain is not Enterprise Admins.
		{dn: "CN=Child 519,CN=Users,DC=child,DC=example,DC=com", objectSID: testDomainSID + "-1108", primaryGroupID: 519},
		// Malformed / unusable records must be dropped, not panic.
		{dn: "", objectSID: testDomainSID + "-1109", primaryGroupID: 512},
		{dn: "CN=No SID,CN=Users,DC=example,DC=com", objectSID: "", primaryGroupID: 512},
		{dn: "CN=No RID,CN=Users,DC=example,DC=com", objectSID: testDomainSID + "-1110", primaryGroupID: 0},
	})

	if !pm.DomainAdmins[stealthAdminDN] {
		t.Errorf("account with primaryGroupID 512 is not in DomainAdmins")
	}
	if !pm.AllPrivileged[stealthAdminDN] {
		t.Errorf("account with primaryGroupID 512 is not privileged")
	}
	if pm.AllPrivileged[ordinaryUserDN] {
		t.Errorf("account with primaryGroupID 513 (Domain Users) must not be privileged")
	}
	if !pm.EnterpriseAdmins[rootAdminDN] || !pm.AllPrivileged[rootAdminDN] {
		t.Errorf("forest-root account with primaryGroupID 519 is not an Enterprise Admin")
	}
	if !pm.SchemaAdmins[schemaAdminDN] || !pm.AllPrivileged[schemaAdminDN] {
		t.Errorf("forest-root account with primaryGroupID 518 is not a Schema Admin")
	}
	if !pm.ProtectedUsers[protectedDN] || !pm.AllPrivileged[protectedDN] {
		t.Errorf("account with primaryGroupID 525 is not in Protected Users")
	}
	if pm.AllPrivileged["CN=Child 519,CN=Users,DC=child,DC=example,DC=com"] {
		t.Errorf("RID 519 relative to a non-root domain must not map to Enterprise Admins")
	}
	if pm.AllPrivileged["CN=No SID,CN=Users,DC=example,DC=com"] ||
		pm.AllPrivileged["CN=No RID,CN=Users,DC=example,DC=com"] ||
		pm.AllPrivileged[""] {
		t.Errorf("unusable records must not produce memberships: %v", pm.AllPrivileged)
	}
}

// TestPrimaryGroupMembershipDoesNotDisturbMemberOfResults proves the memberOf
// chain still works on its own and that folding primary groups in is additive.
func TestPrimaryGroupMembershipDoesNotDisturbMemberOfResults(t *testing.T) {
	const memberOfAdminDN = "CN=MemberOf Admin,CN=Users,DC=example,DC=com"

	pm := newTestMemberships()
	// Simulate what the LDAP_MATCHING_RULE_IN_CHAIN pass records.
	markPrivileged(pm, "DomainAdmins", memberOfAdminDN)

	applyPrimaryGroupMemberships(pm, testSIDIndex(), []primaryGroupRecord{
		{dn: "CN=Stealth,CN=Users,DC=example,DC=com", objectSID: testDomainSID + "-1105", primaryGroupID: 512},
	})

	if !pm.DomainAdmins[memberOfAdminDN] || !pm.AllPrivileged[memberOfAdminDN] {
		t.Errorf("memberOf-derived membership was lost when primary groups were folded in")
	}
	if len(pm.DomainAdmins) != 2 {
		t.Errorf("DomainAdmins = %v, want both the memberOf and primary group accounts", pm.DomainAdmins)
	}
}

func TestMarkPrivileged(t *testing.T) {
	const dn = "CN=Someone,CN=Users,DC=example,DC=com"

	// A group with no dedicated set still contributes to AllPrivileged.
	pm := newTestMemberships()
	markPrivileged(pm, "", dn)
	if !pm.AllPrivileged[dn] {
		t.Errorf("markPrivileged with no field must still record AllPrivileged")
	}
	if len(pm.DomainAdmins) != 0 || len(pm.EnterpriseAdmins) != 0 ||
		len(pm.SchemaAdmins) != 0 || len(pm.ProtectedUsers) != 0 {
		t.Errorf("markPrivileged with no field must not populate a dedicated set")
	}
}
