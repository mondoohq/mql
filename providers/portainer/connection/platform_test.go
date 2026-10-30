// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestEnvironmentType(t *testing.T) {
	cases := map[int64]string{
		1:  "docker",
		2:  "agent-docker",
		3:  "azure-aci",
		4:  "edge-agent-docker",
		5:  "kubernetes",
		6:  "agent-kubernetes",
		7:  "edge-agent-kubernetes",
		0:  "unknown",
		99: "unknown",
		-1: "unknown",
	}
	for typ, want := range cases {
		assert.Equalf(t, want, EnvironmentType(typ), "EnvironmentType(%d)", typ)
	}
}

func TestEnvironmentClassification(t *testing.T) {
	assert.True(t, IsDockerEnvironment(1))
	assert.True(t, IsDockerEnvironment(2))
	assert.True(t, IsDockerEnvironment(4))
	assert.False(t, IsDockerEnvironment(5))

	assert.True(t, IsKubernetesEnvironment(5))
	assert.True(t, IsKubernetesEnvironment(6))
	assert.True(t, IsKubernetesEnvironment(7))
	assert.False(t, IsKubernetesEnvironment(1))

	assert.True(t, IsEdgeEnvironment(4))
	assert.True(t, IsEdgeEnvironment(7))
	assert.False(t, IsEdgeEnvironment(1))
}

func TestEnvironmentPlatformTitle(t *testing.T) {
	assert.Equal(t, "Portainer Environment (kubernetes)", EnvironmentPlatform(5).Title)
	assert.Equal(t, "Portainer Environment (docker)", EnvironmentPlatform(1).Title)
	assert.Equal(t, "Portainer Environment (unknown)", EnvironmentPlatform(0).Title)
}

// TestSubAssetPlatform_UsesDiscoveredEnvironmentType is a regression test: the
// sub-asset platform must reflect the environment type captured at discovery
// time, not a hard-coded 0 that always renders as "unknown".
func TestSubAssetPlatform_UsesDiscoveredEnvironmentType(t *testing.T) {
	conn := &PortainerConnection{
		instanceID: "inst-1",
		Conf: &inventory.Config{
			Options: map[string]string{
				OptionEnvironmentID:   "7",
				OptionEnvironmentType: "5", // kubernetes
			},
		},
	}

	plat, id, name := conn.SubAssetPlatform()
	require.NotNil(t, plat)
	assert.Equal(t, "Portainer Environment (kubernetes)", plat.Title)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/portainer/instance/inst-1/environment/7", id)
	assert.Equal(t, "Portainer environment 7", name)
}

// TestSubAssetPlatform_MissingTypeFallsBack ensures a missing/malformed type
// option degrades gracefully to "unknown" instead of erroring.
func TestSubAssetPlatform_MissingTypeFallsBack(t *testing.T) {
	conn := &PortainerConnection{
		instanceID: "inst-1",
		Conf: &inventory.Config{
			Options: map[string]string{
				OptionEnvironmentID: "7",
			},
		},
	}

	plat, _, _ := conn.SubAssetPlatform()
	require.NotNil(t, plat)
	assert.Equal(t, "Portainer Environment (unknown)", plat.Title)
}

// TestSubAssetPlatform_InstanceConnection returns nil when the connection is a
// plain instance connection (no scoped environment).
func TestSubAssetPlatform_InstanceConnection(t *testing.T) {
	conn := &PortainerConnection{
		instanceID: "inst-1",
		Conf:       &inventory.Config{Options: map[string]string{}},
	}

	plat, id, name := conn.SubAssetPlatform()
	assert.Nil(t, plat)
	assert.Empty(t, id)
	assert.Empty(t, name)
}
