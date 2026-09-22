// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func connectWithName(t *testing.T, path, name string) *inventory.Asset {
	t.Helper()
	resp, err := Init().Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Name: name,
			Connections: []*inventory.Config{
				{Type: DefaultConnectionType, Options: map[string]string{"path": path}},
			},
		},
	}, nil)
	require.NoError(t, err)
	return resp.Asset
}

// A caller who passed --asset-name has already named the asset; detection runs
// afterwards and must leave that name alone. Dropping the `asset.Name == ""`
// guard in detect() fails the "keeps a caller-supplied name" cases.
func TestDetect_AssetName(t *testing.T) {
	const playbook = "../play/testdata/play_default.yml"
	const project = "../resources/testdata/project"

	t.Run("names an unnamed playbook after its path", func(t *testing.T) {
		asset := connectWithName(t, playbook, "")
		assert.Equal(t, "Ansible Playbook Static Analysis play_default", asset.Name)
	})

	t.Run("keeps a caller-supplied name on a playbook", func(t *testing.T) {
		asset := connectWithName(t, playbook, "test-local")
		assert.Equal(t, "test-local", asset.Name)
		// The name is display only; identity still comes from detection.
		require.Len(t, asset.PlatformIds, 1)
		assert.Contains(t, asset.PlatformIds[0], "//platformid.api.mondoo.app/runtime/ansible/hash/")
		assert.Equal(t, "ansible-playbook", asset.Platform.Name)
	})

	t.Run("keeps a caller-supplied name on a project", func(t *testing.T) {
		asset := connectWithName(t, project, "test-local")
		assert.Equal(t, "test-local", asset.Name)
		assert.Equal(t, "ansible-project", asset.Platform.Name)
	})
}
