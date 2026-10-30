// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
)

func recordedAssets() []*recording.Asset {
	return []*recording.Asset{
		{Asset: &inventory.Asset{
			Name:        "host",
			Mrn:         "//assets/host",
			PlatformIds: []string{"//platformid/host"},
		}},
		{Asset: &inventory.Asset{
			Name:        "mcp-server",
			Mrn:         "//assets/mcp",
			PlatformIds: []string{"//platformid/mcp"},
		}},
	}
}

// Taking assets[0] regardless of what was asked for is the bug this fixes: a
// cross-asset resolve (ADR 031) that asks for the second recorded asset used to
// get the host's data back under the target's name.
func TestPickAssetRecording(t *testing.T) {
	assets := recordedAssets()

	t.Run("by mrn", func(t *testing.T) {
		got := pickAssetRecording(assets, &inventory.Asset{Mrn: "//assets/mcp"})
		require.NotNil(t, got)
		assert.Equal(t, "mcp-server", got.Asset.Name)
	})

	t.Run("by platform id", func(t *testing.T) {
		got := pickAssetRecording(assets, &inventory.Asset{PlatformIds: []string{"//platformid/mcp"}})
		require.NotNil(t, got)
		assert.Equal(t, "mcp-server", got.Asset.Name)
	})

	t.Run("by name, for a stub carrying neither", func(t *testing.T) {
		got := pickAssetRecording(assets, &inventory.Asset{Name: "mcp-server"})
		require.NotNil(t, got)
		assert.Equal(t, "mcp-server", got.Asset.Name)
	})

	t.Run("mrn wins over a name that points elsewhere", func(t *testing.T) {
		got := pickAssetRecording(assets, &inventory.Asset{Mrn: "//assets/mcp", Name: "host"})
		require.NotNil(t, got)
		assert.Equal(t, "mcp-server", got.Asset.Name)
	})

	t.Run("unidentified request keeps the historical behavior", func(t *testing.T) {
		got := pickAssetRecording(assets, &inventory.Asset{})
		require.NotNil(t, got)
		assert.Equal(t, "host", got.Asset.Name, "the first asset, as before")

		got = pickAssetRecording(assets, nil)
		require.NotNil(t, got)
		assert.Equal(t, "host", got.Asset.Name)
	})

	// A miss has to stay a miss. Falling back to assets[0] here is exactly the
	// wrong-answer-instead-of-an-error shape the fix exists to remove.
	t.Run("no match is nil, not the first asset", func(t *testing.T) {
		assert.Nil(t, pickAssetRecording(assets, &inventory.Asset{Mrn: "//assets/nope"}))
		assert.Nil(t, pickAssetRecording(assets, &inventory.Asset{Name: "nope"}))
		assert.Nil(t, pickAssetRecording(nil, &inventory.Asset{Mrn: "//assets/host"}))
	})
}

func TestAssetLabel(t *testing.T) {
	assert.Equal(t, "//assets/host", assetLabel(&inventory.Asset{Mrn: "//assets/host", Name: "host"}))
	assert.Equal(t, "//platformid/host", assetLabel(&inventory.Asset{PlatformIds: []string{"//platformid/host"}, Name: "host"}))
	assert.Equal(t, "host", assetLabel(&inventory.Asset{Name: "host"}))
	assert.Equal(t, "<unidentified>", assetLabel(&inventory.Asset{}))
	assert.Equal(t, "<none>", assetLabel(nil))
}
