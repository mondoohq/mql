// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsebs

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func TestExtractInjectedPlatformId(t *testing.T) {
	t.Run("without fs connection", func(t *testing.T) {
		a := &inventory.Asset{Mrn: "test"}
		osConn := local.NewConnection(1, nil, a)
		m := &ebsMetadata{conn: osConn}
		platformId, instanceId, exists := m.extractInjectedPlatformID()
		require.Empty(t, platformId)
		require.Empty(t, instanceId)
		require.False(t, exists)
	})

	t.Run("with fs connection, but asset has no connections", func(t *testing.T) {
		platformId := "//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/185972265011/regions/us-east-1/instances/i-07f67838ada5879af"
		conn := &inventory.Config{
			Type: shared.Type_FileSystem.String(),
			Options: map[string]string{
				"inject-platform-ids": platformId,
				// required to init the fs conn
				"path": "test",
			},
		}
		a := &inventory.Asset{Mrn: "test"}
		fsConn, err := fs.NewConnection(1, conn, a)
		require.NoError(t, err)

		m := &ebsMetadata{conn: fsConn}
		platformId, instanceId, exists := m.extractInjectedPlatformID()
		require.Empty(t, platformId)
		require.Empty(t, instanceId)
		require.False(t, exists)
	})

	t.Run("with fs connection and asset has connections", func(t *testing.T) {
		platformId := "//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/185972265011/regions/us-east-1/instances/i-07f67838ada5879af"
		assetConns := []*inventory.Config{
			{
				Type: shared.Type_FileSystem.String(),
				Options: map[string]string{
					"inject-platform-ids": platformId,
					// required to init the fs conn
					"path": "test",
				},
			},
		}
		a := &inventory.Asset{Mrn: "test", Connections: assetConns}
		fsConn, err := fs.NewConnection(1, assetConns[0], a)
		require.NoError(t, err)

		m := &ebsMetadata{conn: fsConn}
		actualPlatformId, instanceId, exists := m.extractInjectedPlatformID()
		require.Equal(t, platformId, actualPlatformId)
		require.Equal(t, "i-07f67838ada5879af", instanceId.Id)
		require.Equal(t, "185972265011", instanceId.Account)
		require.Equal(t, "us-east-1", instanceId.Region)
		require.True(t, exists)
	})
}
