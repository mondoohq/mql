// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	sqlserverflex "github.com/stackitcloud/stackit-sdk-go/services/sqlserverflex/v2api"
)

// decodeSqlServerInstance builds the SDK instance from a payload shaped like
// the GetInstance response, so the option keys are read through the same
// JSON path the provider takes.
func decodeSqlServerInstance(t *testing.T, payload string) *sqlserverflex.Instance {
	t.Helper()
	var inst sqlserverflex.Instance
	if err := json.Unmarshal([]byte(payload), &inst); err != nil {
		t.Fatalf("decoding sqlserverflex instance: %v", err)
	}
	return &inst
}

// TestSqlServerRetentionDays pins the parse of the retentionDays option. The
// API carries it as a decimal string, and a value that is absent or not a
// number has to read as "not present" so the field reports null rather than a
// zero-day retention that would fail every retention check.
func TestSqlServerRetentionDays(t *testing.T) {
	cases := []struct {
		name     string
		payload  string
		wantDays int64
		wantOk   bool
	}{
		{"documented default", `{"id": "i1", "options": {"edition": "developer", "retentionDays": "32"}}`, 32, true},
		{"upper bound", `{"id": "i1", "options": {"retentionDays": "365"}}`, 365, true},
		{"surrounding whitespace", `{"id": "i1", "options": {"retentionDays": " 45 "}}`, 45, true},
		{"absent option", `{"id": "i1", "options": {"edition": "developer"}}`, 0, false},
		{"no options at all", `{"id": "i1"}`, 0, false},
		{"empty string", `{"id": "i1", "options": {"retentionDays": ""}}`, 0, false},
		{"not a number", `{"id": "i1", "options": {"retentionDays": "thirty"}}`, 0, false},
		{"negative is rejected", `{"id": "i1", "options": {"retentionDays": "-1"}}`, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sqlServerRetentionDays(decodeSqlServerInstance(t, tc.payload))
			if ok != tc.wantOk || got != tc.wantDays {
				t.Fatalf("sqlServerRetentionDays = (%d, %v), want (%d, %v)", got, ok, tc.wantDays, tc.wantOk)
			}
		})
	}

	t.Run("nil instance", func(t *testing.T) {
		if _, ok := sqlServerRetentionDays(nil); ok {
			t.Fatal("nil instance must not report a retention")
		}
	})
}

func TestSqlServerOptionEdition(t *testing.T) {
	inst := decodeSqlServerInstance(t, `{"id": "i1", "options": {"edition": "standard", "retentionDays": "32"}}`)
	if got, ok := sqlServerOption(inst, "edition"); !ok || got != "standard" {
		t.Fatalf("edition = (%q, %v), want (standard, true)", got, ok)
	}
	if _, ok := sqlServerOption(decodeSqlServerInstance(t, `{"id": "i1", "options": {"edition": "  "}}`), "edition"); ok {
		t.Fatal("a blank edition must read as absent")
	}
}
