// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/claude/connection"
)

func TestHandleTargets(t *testing.T) {
	expanded := []string{connection.DiscoveryOrg, connection.DiscoveryWorkspaces}

	tests := []struct {
		name    string
		targets []string
		want    []string
	}{
		{
			name:    "all expands to the full target set",
			targets: []string{connection.DiscoveryAll},
			want:    expanded,
		},
		{
			name:    "auto expands to the full target set",
			targets: []string{connection.DiscoveryAuto},
			want:    expanded,
		},
		{
			name:    "all wins even when mixed with explicit targets",
			targets: []string{connection.DiscoveryOrg, connection.DiscoveryAll},
			want:    expanded,
		},
		{
			name:    "explicit targets pass through untouched",
			targets: []string{connection.DiscoveryWorkspaces},
			want:    []string{connection.DiscoveryWorkspaces},
		},
		{
			name:    "empty stays empty",
			targets: []string{},
			want:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, handleTargets(tt.targets))
		})
	}
}
