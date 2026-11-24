// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	appstreamtypes "github.com/aws/aws-sdk-go-v2/service/appstream/types"
	"github.com/stretchr/testify/assert"
)

// Synthetic: image builder agent access settings; no target showed this.
func TestAppstreamAgentActions(t *testing.T) {
	got := appstreamAgentActions([]appstreamtypes.AgentAccessSetting{
		{AgentAction: appstreamtypes.AgentActionComputerVision, Permission: appstreamtypes.PermissionEnabled},
		{AgentAction: appstreamtypes.AgentActionComputerInput, Permission: appstreamtypes.PermissionDisabled},
		{AgentAction: "", Permission: appstreamtypes.PermissionEnabled},
	})
	assert.Equal(t, map[string]any{
		"COMPUTER_VISION": "ENABLED",
		"COMPUTER_INPUT":  "DISABLED",
	}, got)
	assert.Empty(t, appstreamAgentActions(nil))
}
