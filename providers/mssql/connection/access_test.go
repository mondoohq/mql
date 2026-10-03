// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"database/sql"
	"testing"
)

func TestHasPerm(t *testing.T) {
	// HAS_PERMS_BY_NAME returns NULL for a permission name the server does
	// not know, such as VIEW ANY SECURITY DEFINITION before SQL Server 2022
	if hasPerm(sql.NullInt64{}) {
		t.Error("NULL counted as held")
	}
	if hasPerm(sql.NullInt64{Valid: true, Int64: 0}) {
		t.Error("0 counted as held")
	}
	if !hasPerm(sql.NullInt64{Valid: true, Int64: 1}) {
		t.Error("1 not counted as held")
	}
}

func TestSecurityCatalogVisible(t *testing.T) {
	// values read live on SQL Server 2025 for each login
	cases := map[string]struct {
		server ServerAccess
		want   bool
	}{
		"db4_lowpriv (CONNECT only)":             {ServerAccess{ViewAnyDatabase: true}, false},
		"db4_auditor (VIEW ANY DEFINITION)":      {ServerAccess{ViewAnyDefinition: true, ViewAnySecurityDefinition: true, ViewAnyDatabase: true}, true},
		"VIEW ANY SECURITY DEFINITION only":      {ServerAccess{ViewAnySecurityDefinition: true, ViewAnyDatabase: true}, true},
		"VIEW ANY DEFINITION on SQL Server 2019": {ServerAccess{ViewAnyDefinition: true}, true},
	}
	for name, c := range cases {
		if got := c.server.SecurityCatalogVisible(); got != c.want {
			t.Errorf("%s: SecurityCatalogVisible = %v, want %v", name, got, c.want)
		}
	}
	if (DatabaseAccess{}).SecurityCatalogVisible() {
		t.Error("a database with neither permission is visible")
	}
	if !(DatabaseAccess{ViewSecurityDefinition: true}).SecurityCatalogVisible() {
		t.Error("VIEW SECURITY DEFINITION does not show the security catalog")
	}
}
