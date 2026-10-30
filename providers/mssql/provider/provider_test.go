// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"database/sql"
	"strings"
	"testing"
)

func TestScopedDatabaseState(t *testing.T) {
	if err := scopedDatabaseState("db4_app", sql.NullString{String: "ONLINE", Valid: true}); err != nil {
		t.Errorf("ONLINE database refused: %v", err)
	}
	// DATABASEPROPERTYEX returns NULL for a database that does not exist
	err := scopedDatabaseState("nosuchdb", sql.NullString{})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing database: %v", err)
	}
	for _, state := range []string{"OFFLINE", "RESTORING", "RECOVERING", "SUSPECT", "EMERGENCY"} {
		err := scopedDatabaseState("db4_off", sql.NullString{String: state, Valid: true})
		if err == nil || !strings.Contains(err.Error(), state) {
			t.Errorf("%s database: %v", state, err)
		}
	}
}
