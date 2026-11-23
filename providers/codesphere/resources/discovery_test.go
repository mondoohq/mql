// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/codesphere/connection"
)

// Synthetic: --discover values; no live Codesphere account was available.
func TestDiscoveryTargets(t *testing.T) {
	assert.Equal(t, []string{connection.DiscoveryResourceGroups, connection.DiscoveryWorkspaces},
		discoveryTargets([]string{connection.DiscoveryAuto}), "auto leaves organizations out")
	assert.Equal(t, []string{connection.DiscoveryOrganizations, connection.DiscoveryResourceGroups, connection.DiscoveryWorkspaces},
		discoveryTargets([]string{connection.DiscoveryAll}))
	assert.Equal(t, []string{connection.DiscoveryOrganizations, connection.DiscoveryResourceGroups, connection.DiscoveryWorkspaces},
		discoveryTargets([]string{connection.DiscoveryAuto, connection.DiscoveryAll}), "all wins over auto")
	assert.Equal(t, []string{connection.DiscoveryWorkspaces},
		discoveryTargets([]string{connection.DiscoveryWorkspaces}))
}
