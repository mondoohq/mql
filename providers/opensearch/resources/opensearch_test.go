// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestRealmServesREST(t *testing.T) {
	boolp := func(b bool) *bool { return &b }
	cases := []struct {
		name string
		cfg  osAuthcRealmCfg
		want bool
	}{
		// Absent keys default to enabled (the common case for built-in domains).
		{"both absent", osAuthcRealmCfg{}, true},
		{"http absent, enabled true", osAuthcRealmCfg{Enabled: boolp(true)}, true},
		{"http true explicit", osAuthcRealmCfg{HTTPEnabled: boolp(true)}, true},
		// Explicitly disabled either way excludes the realm.
		{"http false", osAuthcRealmCfg{HTTPEnabled: boolp(false)}, false},
		{"enabled false", osAuthcRealmCfg{Enabled: boolp(false)}, false},
		{"http true, enabled false", osAuthcRealmCfg{HTTPEnabled: boolp(true), Enabled: boolp(false)}, false},
	}
	for _, c := range cases {
		if got := realmServesREST(c.cfg); got != c.want {
			t.Errorf("%s: realmServesREST = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestToStringSlice(t *testing.T) {
	got := toStringSlice([]string{"a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("toStringSlice = %v", got)
	}
	// Never nil, so llx.ArrayData receives a real slice.
	if got := toStringSlice(nil); got == nil || len(got) != 0 {
		t.Errorf("toStringSlice(nil) = %v, want empty non-nil", got)
	}
}
