// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
)

func TestParseHpeManagerLicense(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantType  string
		wantLabel string
		wantFound bool
	}{
		{
			name:      "current Hpe block",
			raw:       `{"Hpe":{"License":{"LicenseType":"Perpetual","LicenseString":"iLO Advanced"}}}`,
			wantType:  "Perpetual",
			wantLabel: "iLO Advanced",
			wantFound: true,
		},
		{
			name:      "legacy Hp block",
			raw:       `{"Hp":{"License":{"LicenseType":"Evaluation","LicenseString":"iLO Standard"}}}`,
			wantType:  "Evaluation",
			wantLabel: "iLO Standard",
			wantFound: true,
		},
		{
			name:      "prefers Hpe over Hp when both present",
			raw:       `{"Hpe":{"License":{"LicenseType":"Perpetual","LicenseString":"iLO Advanced"}},"Hp":{"License":{"LicenseType":"Evaluation","LicenseString":"iLO Standard"}}}`,
			wantType:  "Perpetual",
			wantLabel: "iLO Advanced",
			wantFound: true,
		},
		{name: "empty raw", raw: ``, wantFound: false},
		{name: "no HPE key", raw: `{"Dell":{}}`, wantFound: false},
		{name: "malformed json", raw: `{not json`, wantFound: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotLabel, gotFound := parseHpeManagerLicense(json.RawMessage(tt.raw))
			if gotFound != tt.wantFound {
				t.Fatalf("found = %v, want %v", gotFound, tt.wantFound)
			}
			if gotType != tt.wantType || gotLabel != tt.wantLabel {
				t.Errorf("got (%q, %q), want (%q, %q)", gotType, gotLabel, tt.wantType, tt.wantLabel)
			}
		})
	}
}

func TestParseDellSystemOem(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantGen   string
		wantID    int64
		wantBios  string
		wantFound bool
	}{
		{
			name:      "full block",
			raw:       `{"Dell":{"DellSystem":{"SystemGeneration":"15G","SystemID":1234,"BIOSReleaseDate":"03/01/2024"}}}`,
			wantGen:   "15G",
			wantID:    1234,
			wantBios:  "03/01/2024",
			wantFound: true,
		},
		{
			name:      "id only, no generation",
			raw:       `{"Dell":{"DellSystem":{"SystemID":42}}}`,
			wantID:    42,
			wantFound: true,
		},
		{
			name:      "generation only",
			raw:       `{"Dell":{"DellSystem":{"SystemGeneration":"16G"}}}`,
			wantGen:   "16G",
			wantFound: true,
		},
		{name: "empty raw", raw: ``, wantFound: false},
		{name: "empty dell system", raw: `{"Dell":{"DellSystem":{}}}`, wantFound: false},
		{name: "non-dell", raw: `{"Hpe":{}}`, wantFound: false},
		{name: "malformed json", raw: `{`, wantFound: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotGen, gotID, gotBios, gotFound := parseDellSystemOem(json.RawMessage(tt.raw))
			if gotFound != tt.wantFound {
				t.Fatalf("found = %v, want %v", gotFound, tt.wantFound)
			}
			if gotGen != tt.wantGen || gotID != tt.wantID || gotBios != tt.wantBios {
				t.Errorf("got (%q, %d, %q), want (%q, %d, %q)", gotGen, gotID, gotBios, tt.wantGen, tt.wantID, tt.wantBios)
			}
		})
	}
}
