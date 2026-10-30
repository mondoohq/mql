// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hetznercloud_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/id/hetznercloud"
)

func TestIdentifyLinux(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/metadata_linux.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	resolver, err := hetznercloud.Resolve(conn, platform)
	require.NoError(t, err)

	ident, err := resolver.Identify()
	require.NoError(t, err)

	assert.Equal(t, "//platformid.api.mondoo.app/runtime/hetzner/instances/110512417", ident.InstanceID)
	assert.Equal(t, "ubuntu-8gb-hil-1", ident.Hostname)
	assert.Equal(t, "us-west", ident.Region)
}

func TestRawMetadataLinux(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/metadata_linux.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	resolver, err := hetznercloud.Resolve(conn, platform)
	require.NoError(t, err)

	raw, err := resolver.RawMetadata()
	require.NoError(t, err)

	m, ok := raw.(map[string]any)
	require.True(t, ok)

	assert.Equal(t, 110512417, m["instance-id"])
	assert.Equal(t, "ubuntu-8gb-hil-1", m["hostname"])
	assert.Equal(t, "us-west", m["region"])
	assert.Equal(t, "hil-dc1", m["availability-zone"])
	assert.Equal(t, "5.78.107.208", m["public-ipv4"])
}
