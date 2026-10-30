// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers/mondoo/connection"
)

func TestFillAsset(t *testing.T) {
	t.Run("mondoo organization asset", func(t *testing.T) {
		a := &inventory.Asset{
			Connections: []*inventory.Config{
				{},
			},
		}
		conn := &connection.Connection{
			Connection: plugin.NewConnection(1, a),
			Type:       connection.ConnTypeOrganization,
			Upstream: &upstream.UpstreamClient{
				SpaceMrn: "//captain.api.mondoo.app/organization/romantic-hopper-662653",
			},
		}
		fillAsset(conn, a)
		require.Equal(t, "Mondoo Organization romantic-hopper-662653", a.Name)

		expectedPlatform := &inventory.Platform{
			Name:    "mondoo-organization",
			Title:   "Mondoo Organization",
			Family:  []string{},
			Kind:    "api",
			Runtime: "mondoo",
			Labels:  map[string]string{},
		}
		require.Equal(t, expectedPlatform, a.Platform)
	})

	t.Run("mondoo space asset", func(t *testing.T) {
		a := &inventory.Asset{
			Connections: []*inventory.Config{
				{},
			},
		}
		conn := &connection.Connection{
			Connection: plugin.NewConnection(1, a),
			Type:       connection.ConnTypeSpace,
			Upstream: &upstream.UpstreamClient{
				SpaceMrn: "//captain.api.mondoo.app/spaces/romantic-hopper-662653",
			},
		}
		fillAsset(conn, a)
		require.Equal(t, "Mondoo Space romantic-hopper-662653", a.Name)

		expectedPlatform := &inventory.Platform{
			Name:    "mondoo-space",
			Title:   "Mondoo Space",
			Family:  []string{},
			Kind:    "api",
			Runtime: "mondoo",
			Labels:  map[string]string{},
		}
		require.Equal(t, expectedPlatform, a.Platform)
	})
}
