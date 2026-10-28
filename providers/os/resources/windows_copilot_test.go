// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/registry"
)

func TestComputeCopilotTurnedOff(t *testing.T) {
	t.Run("not configured is nil", func(t *testing.T) {
		// Synthetic: no WindowsCopilot policy key; no target showed this.
		assert.Nil(t, computeCopilotTurnedOff(map[string]registry.RegistryKeyItem{}))
	})

	t.Run("1 turns Copilot off", func(t *testing.T) {
		// Synthetic: allowed value 1 (Disable Copilot) from Policy CSP - WindowsAI; no target showed this.
		got := computeCopilotTurnedOff(dwordItems(map[string]int64{"turnoffwindowscopilot": 1}))
		require.NotNil(t, got)
		assert.True(t, *got)
	})

	t.Run("0 leaves Copilot on", func(t *testing.T) {
		// Synthetic: allowed value 0 (Enable Copilot) from Policy CSP - WindowsAI; no target showed this.
		got := computeCopilotTurnedOff(dwordItems(map[string]int64{"turnoffwindowscopilot": 0}))
		require.NotNil(t, got)
		assert.False(t, *got)
	})
}
