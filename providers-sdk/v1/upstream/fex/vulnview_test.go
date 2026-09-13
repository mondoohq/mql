// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fex

import (
	"reflect"
	"testing"
)

func TestSeverityLabel(t *testing.T) {
	tests := []struct {
		name string
		vex  *VulnerabilityExchange
		want string
	}{
		{"nil", nil, SeverityNone},
		{"no ratings", &VulnerabilityExchange{}, SeverityNone},
		{"critical word", ratingVex(&Rating{Severity: "critical"}), SeverityCritical},
		{"high word", ratingVex(&Rating{Severity: "high"}), SeverityHigh},
		{"medium word", ratingVex(&Rating{Severity: "medium"}), SeverityMedium},
		{"moderate word", ratingVex(&Rating{Severity: "moderate"}), SeverityMedium},
		{"low word", ratingVex(&Rating{Severity: "low"}), SeverityLow},
		{"negligible word", ratingVex(&Rating{Severity: "negligible"}), SeverityLow},
		{"none word stays none", ratingVex(&Rating{Severity: "none"}), SeverityNone},
		{"none word falls back to score", ratingVex(&Rating{Severity: "none", Score: 5.0}), SeverityMedium},
		{"unknown word falls to none", ratingVex(&Rating{Severity: "banana"}), SeverityNone},
		{"score 9.8 -> critical", ratingVex(&Rating{Score: 9.8}), SeverityCritical},
		{"score 7.5 -> high", ratingVex(&Rating{Score: 7.5}), SeverityHigh},
		{"score 5.0 -> medium", ratingVex(&Rating{Score: 5.0}), SeverityMedium},
		{"score 2.0 -> low", ratingVex(&Rating{Score: 2.0}), SeverityLow},
		{"score 0 -> none", ratingVex(&Rating{Score: 0}), SeverityNone},
		{"word beats score when both present", ratingVex(&Rating{Severity: "critical", Score: 2.0}), SeverityCritical},
		{"unknown word falls back to score", ratingVex(&Rating{Severity: "banana", Score: 9.5}), SeverityCritical},
		{
			"most severe of several ratings wins",
			ratingVex(&Rating{Severity: "low"}, &Rating{Severity: "high"}, &Rating{Score: 4.0}),
			SeverityHigh,
		},
		{"nil rating entry is skipped", ratingVex(nil, &Rating{Severity: "medium"}), SeverityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SeverityLabel(tt.vex); got != tt.want {
				t.Errorf("SeverityLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  string
		want int
	}{
		{"CRITICAL", 4},
		{"critical", 4},
		{"HIGH", 3},
		{"ERROR", 3},
		{"MEDIUM", 2},
		{"MODERATE", 2},
		{"WARNING", 2},
		{"LOW", 1},
		{"INFO", 1},
		{"NEGLIGIBLE", 1},
		{"NONE", 0},
		{"", 0},
		{"nonsense", 0},
	}
	for _, tt := range tests {
		t.Run(tt.sev, func(t *testing.T) {
			if got := SeverityRank(tt.sev); got != tt.want {
				t.Errorf("SeverityRank(%q) = %d, want %d", tt.sev, got, tt.want)
			}
		})
	}
}

func TestFixedVersion(t *testing.T) {
	tests := []struct {
		name string
		vex  *VulnerabilityExchange
		want string
	}{
		{"nil", nil, ""},
		{"nothing resolvable", &VulnerabilityExchange{}, ""},
		{
			"structured fixed_version identifier",
			&VulnerabilityExchange{Affects: []*Affects{{Component: &Component{
				Id: "lodash", Identifiers: map[string]string{"fixed_version": "4.17.21"},
			}}}},
			"4.17.21",
		},
		{
			"structured fixed identifier",
			&VulnerabilityExchange{Affects: []*Affects{{Component: &Component{
				Id: "lodash", Identifiers: map[string]string{"fixed": "1.2.3"},
			}}}},
			"1.2.3",
		},
		{
			"structured wins over prose",
			&VulnerabilityExchange{
				Affects: []*Affects{{Component: &Component{
					Id: "lodash", Identifiers: map[string]string{"fixed_version": "4.17.21"},
				}}},
				Remediations: []*Remediation{{Summary: "upgrade to 9.9.9"}},
			},
			"4.17.21",
		},
		{
			"prose parse with intent",
			&VulnerabilityExchange{Remediations: []*Remediation{{Summary: "please upgrade to 2.5.0"}}},
			"2.5.0",
		},
		{
			"prose parse empty fix type eligible",
			&VulnerabilityExchange{Remediations: []*Remediation{{FixType: "", Details: "fixed in 3.0.1"}}},
			"3.0.1",
		},
		{
			"prose parse skips non-package fix type",
			&VulnerabilityExchange{Remediations: []*Remediation{{FixType: "terraform", Summary: "upgrade to 3.0.1"}}},
			"",
		},
		{
			"prose parse honors explicit package fix type",
			&VulnerabilityExchange{Remediations: []*Remediation{{FixType: "package", Summary: "upgrade to 3.0.1"}}},
			"3.0.1",
		},
		{
			"prose without intent yields nothing",
			&VulnerabilityExchange{Remediations: []*Remediation{{Summary: "affects 1.2.3"}}},
			"",
		},
		{
			"ambiguous prose yields nothing",
			&VulnerabilityExchange{Remediations: []*Remediation{{Summary: "upgrade from 1.2.3 to 4.5.6"}}},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FixedVersion(tt.vex); got != tt.want {
				t.Errorf("FixedVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseFixedVersion(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		want  string
		wantB bool
	}{
		{"empty", "", "", false},
		{"no intent", "affects version 1.2.3", "", false},
		{"intent no version", "please upgrade soon", "", false},
		{"single version with intent", "upgrade to 1.2.3", "1.2.3", true},
		{"v-prefixed", "fixed in v2.0", "v2.0", true},
		{"repeated same version ok", "upgrade to 1.2.3, i.e. version 1.2.3", "1.2.3", true},
		{"two distinct versions ambiguous", "upgrade from 1.0.0 to 2.0.0", "", false},
		{"two-part version", "bump to 3.4", "3.4", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseFixedVersion(tt.text)
			if got != tt.want || ok != tt.wantB {
				t.Errorf("parseFixedVersion(%q) = (%q, %v), want (%q, %v)", tt.text, got, ok, tt.want, tt.wantB)
			}
		})
	}
}

func TestEcosystemOf(t *testing.T) {
	tests := []struct {
		purl string
		want string
	}{
		{"", ""},
		{"lodash", ""},
		{"pkg:npm/lodash@4.17.20", "npm"},
		{"pkg:golang/go.mondoo.com/mql@1.0.0", "golang"},
		{"pkg:gem/rails@6.1.0", "gem"},
		{"not-a-purl", ""},
	}
	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			if got := EcosystemOf(tt.purl); got != tt.want {
				t.Errorf("EcosystemOf(%q) = %q, want %q", tt.purl, got, tt.want)
			}
		})
	}
}

func TestComponentCoords(t *testing.T) {
	tests := []struct {
		name        string
		component   *Component
		wantName    string
		wantVersion string
		wantPurl    string
	}{
		{"nil", nil, "", "", ""},
		{
			"identifiers carry purl and version",
			&Component{Id: "lodash", Identifiers: map[string]string{"purl": "pkg:npm/lodash@4.17.20", "version": "4.17.20"}},
			"lodash", "4.17.20", "pkg:npm/lodash@4.17.20",
		},
		{
			"purl-in-id parses to friendly name and version",
			&Component{Id: "pkg:npm/lodash@4.17.20"},
			"lodash", "4.17.20", "pkg:npm/lodash@4.17.20",
		},
		{
			"namespaced purl keeps namespace in name",
			&Component{Id: "pkg:golang/go.mondoo.com/mql@1.0.0"},
			"go.mondoo.com/mql", "1.0.0", "pkg:golang/go.mondoo.com/mql@1.0.0",
		},
		{
			"bare name no purl",
			&Component{Id: "openssl", Identifiers: map[string]string{"version": "1.1.1"}},
			"openssl", "1.1.1", "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version, purl := ComponentCoords(tt.component)
			if name != tt.wantName || version != tt.wantVersion || purl != tt.wantPurl {
				t.Errorf("ComponentCoords() = (%q, %q, %q), want (%q, %q, %q)",
					name, version, purl, tt.wantName, tt.wantVersion, tt.wantPurl)
			}
		})
	}
}

func TestReferenceURLsAndRemediationHint(t *testing.T) {
	v := &VulnerabilityExchange{
		References: []*Reference{
			{Url: "https://example.com/CVE-1"},
			nil,
			{Url: ""},
			{Url: "https://example.com/advisory"},
		},
		Remediations: []*Remediation{
			nil,
			{Summary: "", Details: "  upgrade the package  "},
			{Summary: "unused"},
		},
	}
	gotURLs := ReferenceURLs(v)
	wantURLs := []string{"https://example.com/CVE-1", "https://example.com/advisory"}
	if !reflect.DeepEqual(gotURLs, wantURLs) {
		t.Errorf("ReferenceURLs() = %v, want %v", gotURLs, wantURLs)
	}
	if got := RemediationHint(v); got != "upgrade the package" {
		t.Errorf("RemediationHint() = %q, want %q", got, "upgrade the package")
	}
	if got := ReferenceURLs(nil); got != nil {
		t.Errorf("ReferenceURLs(nil) = %v, want nil", got)
	}
	if got := RemediationHint(nil); got != "" {
		t.Errorf("RemediationHint(nil) = %q, want empty", got)
	}
}

func TestVulnRows(t *testing.T) {
	vex := []*VulnerabilityExchange{
		nil,                        // skipped
		{Id: "", Summary: "no id"}, // skipped
		{
			// A medium vuln affecting two sub-components -> two rows.
			Id:      "CVE-2021-MEDIUM",
			Summary: "medium issue",
			Ratings: []*Rating{{Severity: "medium"}},
			Affects: []*Affects{{
				Component: &Component{Id: "npm"},
				SubComponents: []*Component{
					{Id: "pkg:npm/lodash@4.17.20"},
					{Id: "pkg:npm/minimist@1.2.0"},
				},
			}},
			Remediations: []*Remediation{{Summary: "upgrade to 4.17.21"}},
			References:   []*Reference{{Url: "https://example.com/lodash"}},
		},
		{
			// A critical vuln with no affected component -> one row, no package.
			Id:      "CVE-2022-CRIT",
			Summary: "critical issue",
			Ratings: []*Rating{{Score: 9.9}},
		},
		{
			// A low vuln affecting one component -> one row.
			Id:      "CVE-2020-LOW",
			Summary: "low issue",
			Ratings: []*Rating{{Severity: "low"}},
			Affects: []*Affects{{Component: &Component{
				Id: "openssl", Identifiers: map[string]string{"version": "1.1.1", "fixed_version": "1.1.1k"},
			}}},
		},
	}

	rows := VulnRows(vex)

	// 2 (medium) + 1 (crit) + 1 (low) = 4 rows.
	if len(rows) != 4 {
		t.Fatalf("VulnRows() returned %d rows, want 4: %+v", len(rows), rows)
	}

	// Sorted by severity rank desc, then id: CRITICAL first, then the two
	// MEDIUM rows (same id, stable order preserves lodash before minimist),
	// then LOW last.
	wantOrder := []string{"CVE-2022-CRIT", "CVE-2021-MEDIUM", "CVE-2021-MEDIUM", "CVE-2020-LOW"}
	for i, want := range wantOrder {
		if rows[i].ID != want {
			t.Errorf("row[%d].ID = %q, want %q", i, rows[i].ID, want)
		}
	}

	// Severities.
	if rows[0].Severity != SeverityCritical {
		t.Errorf("crit row severity = %q, want CRITICAL", rows[0].Severity)
	}
	if rows[3].Severity != SeverityLow {
		t.Errorf("low row severity = %q, want LOW", rows[3].Severity)
	}

	// Critical row: no affected package, but summary preserved.
	if rows[0].AffectedName != "" || rows[0].AffectedPurl != "" {
		t.Errorf("crit row should have no package, got name=%q purl=%q", rows[0].AffectedName, rows[0].AffectedPurl)
	}
	if rows[0].Summary != "critical issue" {
		t.Errorf("crit row summary = %q", rows[0].Summary)
	}

	// Medium rows: two distinct components, shared fixed version + refs + hint.
	if rows[1].AffectedName != "lodash" || rows[2].AffectedName != "minimist" {
		t.Errorf("medium rows components = %q, %q; want lodash, minimist", rows[1].AffectedName, rows[2].AffectedName)
	}
	if rows[1].AffectedVersion != "4.17.20" {
		t.Errorf("lodash version = %q, want 4.17.20", rows[1].AffectedVersion)
	}
	if rows[1].FixedVersion != "4.17.21" || rows[2].FixedVersion != "4.17.21" {
		t.Errorf("medium fixed versions = %q, %q; want 4.17.21", rows[1].FixedVersion, rows[2].FixedVersion)
	}
	if rows[1].RemediationHint != "upgrade to 4.17.21" {
		t.Errorf("medium remediation hint = %q", rows[1].RemediationHint)
	}
	if !reflect.DeepEqual(rows[1].References, []string{"https://example.com/lodash"}) {
		t.Errorf("medium references = %v", rows[1].References)
	}

	// Low row: structured fixed version from identifiers.
	if rows[3].AffectedName != "openssl" || rows[3].AffectedVersion != "1.1.1" {
		t.Errorf("low row coords = %q@%q, want openssl@1.1.1", rows[3].AffectedName, rows[3].AffectedVersion)
	}
	if rows[3].FixedVersion != "1.1.1k" {
		t.Errorf("low row fixed version = %q, want 1.1.1k", rows[3].FixedVersion)
	}
}

// ratingVex builds a VulnerabilityExchange carrying the given ratings.
func ratingVex(ratings ...*Rating) *VulnerabilityExchange {
	return &VulnerabilityExchange{Ratings: ratings}
}
