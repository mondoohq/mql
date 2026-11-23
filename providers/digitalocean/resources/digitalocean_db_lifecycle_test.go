// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// Synthetic body shaped like GET /v2/databases/options.
const databaseOptionsBody = `{
  "options": {
    "pg": {
      "regions": ["nyc1", "fra1"],
      "versions": ["14", "15", "16"],
      "layouts": [{"num_nodes": 1, "sizes": ["db-s-1vcpu-1gb"]}],
      "version_availability": [
        {"version": "14", "end_of_life": "2026-11-12T00:00:00Z", "end_of_availability": "2026-05-12T00:00:00Z"},
        {"version": "15", "end_of_life": "2027-11-11T00:00:00Z", "end_of_availability": "2027-05-11T00:00:00Z"},
        {"version": "16", "end_of_life": null, "end_of_availability": null}
      ]
    },
    "mysql": {
      "versions": ["8"],
      "version_availability": [
        {"version": "8", "end_of_life": "2026-04-30", "end_of_availability": ""}
      ]
    },
    "kafka": {
      "versions": ["3.7"]
    }
  }
}`

func parseOptions(t *testing.T, body string) connection.DatabaseOptions {
	t.Helper()
	var root struct {
		Options connection.DatabaseOptions `json:"options"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &root))
	return root.Options
}

func date(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func TestDatabaseVersionLifecycle(t *testing.T) {
	opts := parseOptions(t, databaseOptionsBody)

	tests := []struct {
		name            string
		engine, version string
		eol, eoa        *time.Time
	}{
		{name: "published dates", engine: "pg", version: "15", eol: ptr(date(2027, 11, 11)), eoa: ptr(date(2027, 5, 11))},
		{name: "picks the matching version", engine: "pg", version: "14", eol: ptr(date(2026, 11, 12)), eoa: ptr(date(2026, 5, 12))},
		{name: "version with null dates", engine: "pg", version: "16"},
		{name: "bare date and empty string", engine: "mysql", version: "8", eol: ptr(date(2026, 4, 30))},
		{name: "unknown version", engine: "pg", version: "9"},
		{name: "engine without version_availability", engine: "kafka", version: "3.7"},
		{name: "unknown engine", engine: "valkey", version: "8"},
		{name: "version of another engine", engine: "mysql", version: "15"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eol, eoa, err := databaseVersionLifecycle(opts, tt.engine, tt.version)
			require.NoError(t, err)
			assertTimePtr(t, tt.eol, eol, "end of life")
			assertTimePtr(t, tt.eoa, eoa, "end of availability")
		})
	}
}

func TestDatabaseVersionLifecycleBadDate(t *testing.T) {
	opts := parseOptions(t, `{"options": {"pg": {"version_availability": [
		{"version": "15", "end_of_life": "next year", "end_of_availability": ""}
	]}}}`)
	_, _, err := databaseVersionLifecycle(opts, "pg", "15")
	assert.Error(t, err)
}

func TestDatabaseVersionLifecycleNilOptions(t *testing.T) {
	eol, eoa, err := databaseVersionLifecycle(nil, "pg", "15")
	require.NoError(t, err)
	assert.Nil(t, eol)
	assert.Nil(t, eoa)
}

func ptr[T any](v T) *T { return &v }

func assertTimePtr(t *testing.T, want, got *time.Time, what string) {
	t.Helper()
	if want == nil {
		assert.Nil(t, got, what)
		return
	}
	require.NotNil(t, got, what)
	assert.True(t, want.Equal(*got), "%s: want %s, got %s", what, want, got)
}
