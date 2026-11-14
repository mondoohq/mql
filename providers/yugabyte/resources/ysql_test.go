// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// Synthetic: pg_hba_file_rules.options entries are name=value.
func TestParseHBAOptions(t *testing.T) {
	got := parseHBAOptions([]string{"clientcert=verify-full", "map=users", "flag", "ldapurl=ldap://h/x?a=b"})
	want := map[string]string{"clientcert": "verify-full", "map": "users", "flag": "", "ldapurl": "ldap://h/x?a=b"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %q", k, got[k], v)
		}
	}
	if len(parseHBAOptions(nil)) != 0 {
		t.Error("no options parsed to entries")
	}
}
