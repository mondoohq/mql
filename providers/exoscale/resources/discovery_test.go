// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/exoscale/connection"
)

func TestResolveDiscoveryTargets(t *testing.T) {
	all := resolveDiscoveryTargets([]string{connection.DiscoveryAuto})
	require.Len(t, all, len(connection.SubAssets))
	assert.Equal(t, []string{connection.DiscoveryNlbs}, resolveDiscoveryTargets([]string{connection.DiscoveryNlbs}))
}

func TestChildLabels(t *testing.T) {
	got := childLabels(discoveredChild{
		region: "ch-gva-2",
		labels: map[string]any{"env": "prod", "bad": 42},
	}, "//platformid.api.mondoo.app/runtime/exoscale/organization/o1")
	assert.Equal(t, map[string]string{
		"env":                  "prod",
		"mondoo.com/region":    "ch-gva-2",
		"mondoo.com/parent-id": "//platformid.api.mondoo.app/runtime/exoscale/organization/o1",
	}, got)

	// An organization-wide resource has no region label.
	got = childLabels(discoveredChild{}, "p")
	assert.Equal(t, map[string]string{"mondoo.com/parent-id": "p"}, got)
}
