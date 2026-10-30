// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// A rule set is addressed by a name that is a path under the account, and the
// name is built here rather than by the SDK. A malformed name does not fail
// loudly: it selects a different rule set or none at all, and the answer to
// "who can act as this service principal" comes back wrong or empty.

func TestRuleSetName(t *testing.T) {
	const account = "00000000-0000-0000-0000-000000000000"

	tests := []struct {
		name       string
		accountID  string
		collection string
		resourceID string
		want       string
	}{
		{
			name:      "account rule set",
			accountID: account,
			want:      "accounts/" + account + "/ruleSets/default",
		},
		{
			name:       "service principal rule set keys on the application id",
			accountID:  account,
			collection: "servicePrincipals",
			resourceID: "11111111-1111-1111-1111-111111111111",
			want:       "accounts/" + account + "/servicePrincipals/11111111-1111-1111-1111-111111111111/ruleSets/default",
		},
		{
			name:       "group rule set",
			accountID:  account,
			collection: "groups",
			resourceID: "123456",
			want:       "accounts/" + account + "/groups/123456/ruleSets/default",
		},
		{
			// Without an account id the name would address a path that is not
			// this account's. An empty result makes the caller report null.
			name:       "missing account id yields no name",
			accountID:  "",
			collection: "groups",
			resourceID: "123456",
			want:       "",
		},
		{
			// A service principal with no application id would otherwise build
			// accounts/<id>/servicePrincipals//ruleSets/default, which is a
			// different object.
			name:       "missing resource id yields no name",
			accountID:  account,
			collection: "servicePrincipals",
			resourceID: "",
			want:       "",
		},
		{
			name:      "missing account id on the account rule set",
			accountID: "",
			want:      "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleSetName(tc.accountID, tc.collection, tc.resourceID)
			if got != tc.want {
				t.Fatalf("ruleSetName(%q, %q, %q) = %q, want %q",
					tc.accountID, tc.collection, tc.resourceID, got, tc.want)
			}
		})
	}
}

func TestPrincipalParts(t *testing.T) {
	tests := []struct {
		name      string
		principal string
		wantKind  string
		wantName  string
	}{
		{name: "user", principal: "users/someone@example.com", wantKind: "user", wantName: "someone@example.com"},
		{name: "group", principal: "groups/data-engineers", wantKind: "group", wantName: "data-engineers"},
		{
			name:      "service principal",
			principal: "servicePrincipals/11111111-1111-1111-1111-111111111111",
			wantKind:  "servicePrincipal",
			wantName:  "11111111-1111-1111-1111-111111111111",
		},
		{
			// A name that itself contains a slash keeps everything after the
			// first separator, so the principal round-trips.
			name:      "name containing a slash",
			principal: "groups/team/subteam",
			wantKind:  "group",
			wantName:  "team/subteam",
		},
		{
			// An unrecognized collection must not be guessed at. Reporting it
			// as a user would attribute an act-as grant to the wrong kind of
			// identity.
			name:      "unknown collection is not guessed",
			principal: "robots/hal",
			wantKind:  "",
			wantName:  "",
		},
		{name: "no separator", principal: "someone@example.com", wantKind: "", wantName: ""},
		{name: "empty name", principal: "users/", wantKind: "", wantName: ""},
		{name: "empty principal", principal: "", wantKind: "", wantName: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, name := principalParts(tc.principal)
			if kind != tc.wantKind || name != tc.wantName {
				t.Fatalf("principalParts(%q) = (%q, %q), want (%q, %q)",
					tc.principal, kind, name, tc.wantKind, tc.wantName)
			}
		})
	}
}

// A grant rule repeats along the rule set, the role, and the principal. If the
// cache key misses any of them, CreateResource hands back the first instance
// for every later one, and a rule set reports fewer principals than actually
// hold a role. Under-reporting a permission set is the failure direction that
// makes an audit pass.
func TestRuleSetGrantCacheKeysAreDistinct(t *testing.T) {
	const account = "00000000-0000-0000-0000-000000000000"
	spSet := ruleSetName(account, "servicePrincipals", "app-a")
	otherSet := ruleSetName(account, "servicePrincipals", "app-b")

	key := func(ruleSet, role, principal string) string {
		return "databricks.ruleSet.grant/" + ruleSet + "/" + role + "/" + principal
	}

	keys := []string{
		key(spSet, "roles/servicePrincipal.user", "users/a@example.com"),
		// same rule set and role, different principal
		key(spSet, "roles/servicePrincipal.user", "users/b@example.com"),
		// same rule set and principal, different role
		key(spSet, "roles/servicePrincipal.manager", "users/a@example.com"),
		// same role and principal, different rule set
		key(otherSet, "roles/servicePrincipal.user", "users/a@example.com"),
	}

	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			t.Fatalf("duplicate rule set grant cache key %q", k)
		}
		seen[k] = true
	}
}
