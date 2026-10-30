// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/nextdns/connection"
)

func TestHandleTargets(t *testing.T) {
	tests := []struct {
		name     string
		targets  []string
		expected []string
	}{
		{
			name:     "all expands to account and profiles",
			targets:  []string{connection.DiscoveryAll},
			expected: []string{connection.DiscoveryAccounts, connection.DiscoveryProfiles},
		},
		{
			name:     "auto discovers profiles only (no empty account asset)",
			targets:  []string{connection.DiscoveryAuto},
			expected: []string{connection.DiscoveryProfiles},
		},
		{
			name:     "explicit accounts stays accounts only",
			targets:  []string{connection.DiscoveryAccounts},
			expected: []string{connection.DiscoveryAccounts},
		},
		{
			name:     "explicit profiles stays profiles only",
			targets:  []string{connection.DiscoveryProfiles},
			expected: []string{connection.DiscoveryProfiles},
		},
		{
			name:     "all wins even when combined with an explicit target",
			targets:  []string{connection.DiscoveryProfiles, connection.DiscoveryAll},
			expected: []string{connection.DiscoveryAccounts, connection.DiscoveryProfiles},
		},
		{
			name:     "empty targets discovers nothing",
			targets:  []string{},
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, handleTargets(tc.targets))
		})
	}
}
