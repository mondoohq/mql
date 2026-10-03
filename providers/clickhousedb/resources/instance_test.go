// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// Rows below are the system.grants rows ClickHouse 26.9 holds for a user after
//
//	GRANT SELECT ON db5.* TO grantor WITH GRANT OPTION;
//	REVOKE GRANT OPTION FOR SELECT ON db5.t FROM grantor;
//
// for which SHOW GRANTS prints the two statements back.
func TestRenderGrant(t *testing.T) {
	cases := []struct {
		accessType, scope string
		partial, option   bool
		want              string
	}{
		{"SELECT", "db5.*", false, true, "SELECT ON db5.* WITH GRANT OPTION"},
		{"SELECT", "db5.t", true, true, "REVOKE GRANT OPTION FOR SELECT ON db5.t"},
		{"SELECT", "db5.t", true, false, "REVOKE SELECT ON db5.t"},
		{"ALL", "*.*", false, false, "ALL ON *.*"},
	}
	for _, c := range cases {
		if got := renderGrant(c.accessType, c.scope, c.partial, c.option); got != c.want {
			t.Errorf("renderGrant(%s, %s, partial=%v, option=%v) = %q, want %q",
				c.accessType, c.scope, c.partial, c.option, got, c.want)
		}
	}
}
