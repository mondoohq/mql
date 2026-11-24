// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/mistral/internal/mistralai"
)

// Synthetic: one action of each target kind from the TriggerActionType enum; no live account was checked.
func TestTriggerTarget(t *testing.T) {
	agentID, target := triggerTarget(mistralai.TriggerAction{PrimitiveID: "ag-1", Type: "start_agent_session"})
	assert.Equal(t, "ag-1", agentID)
	assert.Nil(t, target, "an agent target is reported through agent, not as a raw id")

	for _, typ := range []string{"start_workflow", "build_app", "deploy_app"} {
		agentID, target = triggerTarget(mistralai.TriggerAction{PrimitiveID: "x-1", Type: typ})
		assert.Empty(t, agentID, typ)
		if assert.NotNil(t, target, typ) {
			assert.Equal(t, "x-1", *target)
		}
	}

	agentID, target = triggerTarget(mistralai.TriggerAction{Type: "start_workflow"})
	assert.Empty(t, agentID)
	assert.Nil(t, target, "an absent target is null, not an empty string")
}
