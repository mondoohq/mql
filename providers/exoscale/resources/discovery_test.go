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
