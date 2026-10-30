// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package recording

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/utils/syncx"
)

func TestAssetRecording(t *testing.T) {
	t.Run("add asset without mrn or platform ids is ignored", func(t *testing.T) {
		rec := &recording{
			assets: syncx.Map[*Asset]{},
			Assets: []*Asset{},
		}

		asset := &inventory.Asset{
			Id:          "asset-id",
			PlatformIds: []string{},
			Platform:    &inventory.Platform{},
		}
		conf := &inventory.Config{
			Type: "local",
		}
		rec.EnsureAsset(asset, "provider", 1, conf)

		require.Len(t, rec.Assets, 0)
	})

	t.Run("add asset by mrn", func(t *testing.T) {
		rec := &recording{
			assets: syncx.Map[*Asset]{},
			Assets: []*Asset{},
		}

		asset := &inventory.Asset{
			Mrn:         "asset-mrn",
			PlatformIds: []string{"platform-id"},
			Platform:    &inventory.Platform{},
		}
		conf := &inventory.Config{
			Type: "local",
			Id:   1,
		}
		rec.EnsureAsset(asset, "provider", 1, conf)

		require.Len(t, rec.Assets, 1)
		require.Len(t, rec.Assets[0].connections, 1)
		require.Len(t, rec.Assets[0].Resources, 0)
		a := rec.Assets[0].Asset
		require.Equal(t, "asset-mrn", a.Mrn)
		require.Equal(t, []string{"platform-id"}, a.PlatformIds)

		// re-add again by MRN, ensure nothing gets duplicated
		asset.Mrn = "asset-mrn"
		asset.PlatformIds = []string{"platform-id", "asset-mrn"}
		rec.EnsureAsset(asset, "provider", 1, conf)
		require.Len(t, rec.Assets, 1)
		require.Len(t, rec.Assets[0].connections, 1)
		require.Len(t, rec.Assets[0].Resources, 0)
		a = rec.Assets[0].Asset

		require.Equal(t, "asset-mrn", a.Mrn)
		require.Equal(t, []string{"platform-id", "asset-mrn"}, a.PlatformIds)
	})

	t.Run("add asset by platform id and mrn", func(t *testing.T) {
		rec := &recording{
			assets: syncx.Map[*Asset]{},
			Assets: []*Asset{},
		}

		asset := &inventory.Asset{
			Mrn:         "asset-mrn",
			PlatformIds: []string{"platform-id"},
			Platform:    &inventory.Platform{},
		}
		conf := &inventory.Config{
			Type: "local",
			Id:   1,
		}
		rec.EnsureAsset(asset, "provider", 1, conf)

		require.Len(t, rec.Assets, 1)
		require.Len(t, rec.Assets[0].connections, 1)
		require.Len(t, rec.Assets[0].Resources, 0)
		a := rec.Assets[0].Asset
		require.Equal(t, "asset-mrn", a.Mrn)
		require.Equal(t, []string{"platform-id"}, a.PlatformIds)

		// re-add again by platform id only (no MRN), ensure nothing gets duplicated
		asset2 := &inventory.Asset{
			PlatformIds: []string{"platform-id"},
			Platform:    &inventory.Platform{},
		}
		rec.EnsureAsset(asset2, "provider", 1, conf)
		require.Len(t, rec.Assets, 1)
		require.Len(t, rec.Assets[0].connections, 1)
		require.Len(t, rec.Assets[0].Resources, 0)
		a = rec.Assets[0].Asset

		require.Equal(t, "asset-mrn", a.Mrn)
		require.Equal(t, []string{"platform-id"}, a.PlatformIds)

		// re-add again by mrn, ensure nothing gets duplicated
		asset3 := &inventory.Asset{
			Mrn:         "asset-mrn",
			PlatformIds: []string{"platform-id"},
			Platform:    &inventory.Platform{},
		}
		rec.EnsureAsset(asset3, "provider", 1, conf)
		require.Len(t, rec.Assets, 1)
		require.Len(t, rec.Assets[0].connections, 1)
		require.Len(t, rec.Assets[0].Resources, 0)
		a = rec.Assets[0].Asset

		require.Equal(t, "asset-mrn", a.Mrn)
		require.Equal(t, []string{"platform-id"}, a.PlatformIds)
	})
}
