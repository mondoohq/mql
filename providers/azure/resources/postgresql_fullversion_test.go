// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// TestPostgresFullVersion pins the join that fullVersion documents.
//
// Azure splits the engine version: properties.version carries the major ("16")
// and properties.minorVersion only the minor ("14"). Publishing minorVersion on
// its own reported a PostgreSQL 16.14 server as "14" -- read as PostgreSQL 14,
// the wrong major release and older than what is running, which is exactly
// backwards for a version-currency check.
func TestPostgresFullVersion(t *testing.T) {
	ver := func(s string) *string { return &s }
	str := func(s string) *string { return &s }

	tests := []struct {
		name    string
		version *string
		minor   *string
		want    *string
	}{
		{
			name:    "major and minor join into the full version",
			version: ver("16"),
			minor:   str("14"),
			want:    str("16.14"),
		},
		{
			name:    "the live case that exposed the bug",
			version: ver("16"),
			minor:   str("4"),
			want:    str("16.4"),
		},
		{
			// documented as empty rather than guessed: a bare major is not a
			// full version, and reporting one would look complete
			name:    "missing minor yields no full version",
			version: ver("16"),
			minor:   nil,
			want:    nil,
		},
		{
			name:    "empty minor yields no full version",
			version: ver("16"),
			minor:   str(""),
			want:    nil,
		},
		{
			name:    "missing major yields no full version",
			version: nil,
			minor:   str("14"),
			want:    nil,
		},
		{
			name:    "empty major yields no full version",
			version: ver(""),
			minor:   str("14"),
			want:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := postgresFullVersion(tc.version, tc.minor)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("postgresFullVersion() = %q, want nil", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("postgresFullVersion() = nil, want %q", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Errorf("postgresFullVersion() = %q, want %q", *got, *tc.want)
			}
		})
	}
}

// TestPostgresFullVersionNeverReportsAnOlderMajor is the regression itself: the
// result must never be mistakable for a lower major release.
func TestPostgresFullVersionNeverReportsAnOlderMajor(t *testing.T) {
	v, minor := "16", "14"
	got := postgresFullVersion(&v, &minor)
	if got == nil {
		t.Fatal("expected a full version")
	}
	if *got == "14" {
		t.Fatalf("fullVersion reported %q for a PostgreSQL 16 server", *got)
	}
	if *got != "16.14" {
		t.Errorf("fullVersion = %q, want \"16.14\"", *got)
	}
}
