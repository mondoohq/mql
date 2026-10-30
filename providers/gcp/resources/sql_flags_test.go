// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNormalizeSqlFlagKey pins the separator folding that lets one lookup match
// every engine's spelling of the same Cloud SQL database flag.
func TestNormalizeSqlFlagKey(t *testing.T) {
	// All three are the same flag, spelled per engine.
	assert.Equal(t, "cloudsql_iam_authentication", normalizeSqlFlagName("cloudsql.iam_authentication"))
	assert.Equal(t, "cloudsql_iam_authentication", normalizeSqlFlagName("cloudsql_iam_authentication"))
	assert.Equal(t, "cloudsql_iam_authentication", normalizeSqlFlagName("cloudsql iam authentication"))
	assert.Equal(t, "cloudsql_iam_authentication", normalizeSqlFlagName("cloudsql-iam-authentication"))
	// Case is folded too, so a mixed-case flag name still matches.
	assert.Equal(t, "cloudsql_iam_authentication", normalizeSqlFlagName("CloudSQL.IAM_Authentication"))
	assert.Equal(t, "", normalizeSqlFlagName(""))
}

// TestSqlFlagOn covers the predicate behind iamAuthenticationEnabled.
//
// The accessor previously compared against the PostgreSQL spelling only, so a
// MySQL or SQL Server instance with IAM database authentication correctly
// ENABLED reported false -- a compliant estate failing its own control, and the
// inverse check passing vacuously.
func TestSqlFlagOn(t *testing.T) {
	const want = "cloudsql.iam_authentication"

	tests := []struct {
		name  string
		flags map[string]any
		want  bool
	}{
		{
			name:  "postgres spelling",
			flags: map[string]any{"cloudsql.iam_authentication": "on"},
			want:  true,
		},
		{
			name:  "mysql spelling",
			flags: map[string]any{"cloudsql_iam_authentication": "on"},
			want:  true,
		},
		{
			name:  "sql server spelling",
			flags: map[string]any{"cloudsql iam authentication": "on"},
			want:  true,
		},
		{
			name:  "explicitly off",
			flags: map[string]any{"cloudsql_iam_authentication": "off"},
			want:  false,
		},
		{
			// The Cloud SQL default is off, so an absent flag is false -- and
			// must stay distinguishable from an explicit "off" only in the raw
			// databaseFlags map, not here.
			name:  "flag absent",
			flags: map[string]any{"max_connections": "100"},
			want:  false,
		},
		{
			name:  "value case is folded",
			flags: map[string]any{"cloudsql.iam_authentication": "ON"},
			want:  true,
		},
		{
			name:  "non-string value does not panic",
			flags: map[string]any{"cloudsql.iam_authentication": 1},
			want:  false,
		},
		{name: "nil map", flags: nil, want: false},
		{name: "empty map", flags: map[string]any{}, want: false},
		{
			// Must not match a different flag that merely shares a prefix.
			name:  "similar flag name does not match",
			flags: map[string]any{"cloudsql.iam_authentication_extra": "on"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sqlFlagOn(tt.flags, want))
		})
	}
}
