// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"go.mondoo.com/mql/llx"
)

// The roles of the sweep fixture (system_auth.roles on Cassandra 5.0.9):
// db3_subsuper is granted db3_super, db3_app is granted db3_group.
func TestEffectiveSuperusers(t *testing.T) {
	direct := map[string]bool{
		"cassandra":    true,
		"db3_super":    true,
		"db3_subsuper": false,
		"db3_group":    false,
		"db3_app":      false,
		"db3_plain":    false,
		"chain_a":      false,
		"chain_b":      false,
		"loop_a":       false,
		"loop_b":       false,
	}
	grantedTo := map[string][]string{
		"db3_subsuper": {"db3_super"},
		"db3_app":      {"db3_group"},
		// two levels down
		"chain_a": {"chain_b"},
		"chain_b": {"db3_subsuper"},
		// a grant cycle with no superuser in it
		"loop_a": {"loop_b"},
		"loop_b": {"loop_a"},
	}
	got := effectiveSuperusers(direct, grantedTo)
	want := map[string]bool{
		"cassandra": true, "db3_super": true, "db3_subsuper": true,
		"chain_a": true, "chain_b": true,
		"db3_group": false, "db3_app": false, "db3_plain": false,
		"loop_a": false, "loop_b": false,
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: effective superuser = %v, want %v", name, got[name], w)
		}
	}
}

func TestEffectiveSuperusersCycleThroughSuperuser(t *testing.T) {
	// A cycle that contains a superuser makes every member a superuser, in
	// whichever order the walk visits them.
	direct := map[string]bool{"a": false, "b": false, "s": true}
	grantedTo := map[string][]string{"a": {"b"}, "b": {"a", "s"}}
	for i := 0; i < 20; i++ {
		got := effectiveSuperusers(direct, grantedTo)
		if !got["a"] || !got["b"] || !got["s"] {
			t.Fatalf("run %d: got %v", i, got)
		}
	}
}

func TestRefusedIsForbidden(t *testing.T) {
	err := refused(errors.New("User db3_plain has no SELECT permission on <table system_auth.roles> or any of its parents"), "SELECT ON system_auth.roles")
	if !errors.Is(err, llx.ErrForbidden) {
		t.Fatalf("want forbidden, got %v", llx.KindOf(err))
	}
	var le *llx.Error
	if !errors.As(err, &le) || len(le.Permissions) != 1 || le.Permissions[0] != "SELECT ON system_auth.roles" {
		t.Errorf("permission not named: %+v", le)
	}
}
