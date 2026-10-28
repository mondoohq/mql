// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSearchServiceInternetReachable(t *testing.T) {
	tests := []struct {
		name      string
		pna       string
		ipRules   []string
		want      bool
		wantKnown bool
	}{
		// Synthetic: public access disabled ignores even a catch-all rule; no target showed this.
		{"disabled", "disabled", []string{"0.0.0.0/0"}, false, true},
		// Synthetic: enabled with no IP rules has no firewall; no target showed this.
		{"enabled without rules", "enabled", nil, true, true},
		// Synthetic: enabled with narrow rules is an allowlist; no target showed this.
		{"enabled with narrow rules", "enabled", []string{"203.0.113.0/24", "198.51.100.7"}, false, true},
		// Synthetic: enabled with a catch-all rule; no target showed this.
		{"enabled with catch-all rule", "enabled", []string{"0.0.0.0/0"}, true, true},
		// Synthetic: two halves of IPv4 together cover the internet; no target showed this.
		{"enabled with split halves", "enabled", []string{"0.0.0.0/1", "128.0.0.0/1"}, true, true},
		// Synthetic: a network security perimeter decides, so the answer is unknown; no target showed this.
		{"secured by perimeter", "securedByPerimeter", nil, false, false},
		// Synthetic: services predating the property report it empty and are public; no target showed this.
		{"empty public access", "", nil, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, known := searchServiceInternetReachable(tt.pna, tt.ipRules)
			assert.Equal(t, tt.wantKnown, known)
			assert.Equal(t, tt.want, got)
		})
	}
}
