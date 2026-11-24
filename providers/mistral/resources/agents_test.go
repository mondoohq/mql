// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Synthetic: two tools of one type on one agent, and the same position on two agents; no live account was checked.
func TestAgentToolID(t *testing.T) {
	assert.NotEqual(t, agentToolID("ag-1", 0), agentToolID("ag-1", 1),
		"two tools on one agent must not share an id")
	assert.NotEqual(t, agentToolID("ag-1", 0), agentToolID("ag-2", 0),
		"the same position on two agents must not share an id")
	assert.Equal(t, "ag-1/tools/10", agentToolID("ag-1", 10))
}
