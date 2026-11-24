// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Synthetic: the two documented values plus the empty value the SDK decodes
// when the API omits the setting; no live account was checked.
func TestEnabledDisabled(t *testing.T) {
	tests := []struct {
		in          string
		wantEnabled bool
		wantOK      bool
	}{
		{"enabled", true, true},
		{"disabled", false, true},
		// Omitted: the field must read as null, not as disabled.
		{"", false, false},
		// A value added later is not a known state either.
		{"pending", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			enabled, ok := enabledDisabled(tt.in)
			assert.Equal(t, tt.wantEnabled, enabled)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}
