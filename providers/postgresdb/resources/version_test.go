// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestColumnForVersion(t *testing.T) {
	cases := []struct {
		name       string
		server     int
		minVersion int
		column     string
		fallback   string
		want       string
	}{
		// 9.6 (Debian 9, AlmaLinux 8) has no polpermissive: every policy is permissive
		{"polpermissive on 9.6", 90622, pgVersion10, "pol.polpermissive", "true", "true AS polpermissive"},
		{"polpermissive on 10", 100023, pgVersion10, "pol.polpermissive", "true", "pol.polpermissive"},
		// slot temporary is PG10+
		{"temporary on 9.6", 90622, pgVersion10, "temporary", "false", "false AS temporary"},
		// pubtruncate is PG11+, so PG10 (Ubuntu 18.04) must not select it
		{"pubtruncate on 10", 100023, pgVersion11, "p.pubtruncate", "false", "false AS pubtruncate"},
		{"pubtruncate on 11", 110000, pgVersion11, "p.pubtruncate", "false", "p.pubtruncate"},
		// pending_restart is 9.5+, so 9.2 (RHEL 7) must not select it
		{"pending_restart on 9.2", 90224, pgVersion95, "pending_restart", "false", "false AS pending_restart"},
		{"relrowsecurity on 9.4", 90426, pgVersion95, "c.relrowsecurity", "false", "false AS relrowsecurity"},
		{"current server", 180001, pgVersion95, "c.relrowsecurity", "false", "c.relrowsecurity"},
		// an unknown version selects the column and lets the server answer
		{"unknown version", 0, pgVersion11, "p.pubtruncate", "false", "p.pubtruncate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, columnForVersion(tc.server, tc.minVersion, tc.column, tc.fallback))
		})
	}
}

func TestRoleColumnsSelectBypassRLS(t *testing.T) {
	// roleColumnsFor swaps exactly this column; keep the two in step
	assert.Contains(t, roleColumns, "r.rolbypassrls,")
	assert.Equal(t, "false AS rolbypassrls", columnForVersion(90224, pgVersion95, "r.rolbypassrls", "false"))
}
