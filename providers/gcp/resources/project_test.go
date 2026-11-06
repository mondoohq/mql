// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/cloudresourcemanager/v3"
)

func TestProjectManagementType(t *testing.T) {
	// Synthetic: a hub management project as the Resource Manager v3 reference
	// documents it; no management project was available to measure.
	var hub cloudresourcemanager.Project
	require.NoError(t, json.Unmarshal([]byte(`{"projectId":"hub","isManagementProject":true,"managementType":"HUB"}`), &hub))
	got := projectManagementType(&hub)
	require.NotNil(t, got)
	assert.Equal(t, "HUB", *got)

	// Synthetic: an ordinary project carries no managementType, which is null.
	var plain cloudresourcemanager.Project
	require.NoError(t, json.Unmarshal([]byte(`{"projectId":"plain"}`), &plain))
	assert.Nil(t, projectManagementType(&plain))
	assert.Nil(t, projectManagementType(nil))
}
