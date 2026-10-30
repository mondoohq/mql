// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"
)

// On PostgreSQL 16+ pg_hba.conf can include other files, and line_number is
// relative to each file. These two rows come from a live 18 server whose
// pg_hba.conf has `include db2_inc.conf` on line 2 and a trust rule on line 3,
// while db2_inc.conf has a scram-sha-256 rule on its own line 3.
func TestHbaRuleResourceIDDistinguishesFiles(t *testing.T) {
	main := hbaRuleResourceID("7311", "/etc/postgresql/18/main/pg_hba.conf", 3)
	inc := hbaRuleResourceID("7311", "/etc/postgresql/18/main/db2_inc.conf", 3)
	if main == inc {
		t.Fatalf("rules on line 3 of two files share the id %q", main)
	}
}

// Servers before 16 report no file_name; their ids stay as they were.
func TestHbaRuleResourceIDWithoutFileIsUnchanged(t *testing.T) {
	if got, want := hbaRuleResourceID("7311", "", 12), "7311/hba/12"; got != want {
		t.Errorf("id = %q, want %q", got, want)
	}
}

func TestHbaRulesQuery(t *testing.T) {
	q16 := hbaRulesQuery(160015)
	if !strings.Contains(q16, "ORDER BY rule_number") {
		t.Errorf("PG16+ query must follow evaluation order (rule_number):\n%s", q16)
	}
	if !strings.Contains(q16, "file_name") {
		t.Errorf("PG16+ query must select file_name:\n%s", q16)
	}
	q15 := hbaRulesQuery(150019)
	if strings.Contains(q15, "rule_number") || strings.Contains(q15, "file_name") {
		t.Errorf("PG15 has no rule_number/file_name columns:\n%s", q15)
	}
	// An invalid pg_hba.conf line is reported with NULL type, database,
	// user_name and (on 16+) rule_number. Scanning a NULL into a string fails
	// the whole list, so every text column must be coalesced.
	for _, q := range []string{q15, q16} {
		if !strings.Contains(q, "COALESCE(type, '')") {
			t.Errorf("type must be coalesced so an invalid line can be listed:\n%s", q)
		}
	}
}
