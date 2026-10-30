// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitNetworks(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected []string
	}{
		{"single", "10.0.0.0/24", []string{"10.0.0.0/24"}},
		{"comma separated", "10.0.0.0/24,10.0.1.0/24", []string{"10.0.0.0/24", "10.0.1.0/24"}},
		{"trims whitespace", "10.0.0.0/24, 10.0.1.0/24", []string{"10.0.0.0/24", "10.0.1.0/24"}},
		{"drops empty entries", "10.0.0.0/24,,", []string{"10.0.0.0/24"}},
		{"empty string", "", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, splitNetworks(tt.value))
		})
	}
}
