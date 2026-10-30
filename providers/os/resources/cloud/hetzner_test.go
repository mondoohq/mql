// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cloud_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/resources/cloud"
)

func newHetznerCloud(t *testing.T, path string) cloud.OSCloud {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath(path))
	require.NoError(t, err)

	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)
	conn.Asset().Platform = platform

	hc, err := cloud.NewHetznerCloud(conn)
	require.NoError(t, err)
	return hc
}

func TestHetznerInstance(t *testing.T) {
	hc := newHetznerCloud(t, "../../id/hetznercloud/testdata/metadata_linux.toml")

	md, err := hc.Instance()
	require.NoError(t, err)

	assert.Equal(t, "ubuntu-8gb-hil-1", md.PrivateHostname)
	assert.Equal(t, "5.78.107.208", md.PublicIP())

	require.Len(t, md.PublicIpv4, 1)
	assert.Equal(t, "5.78.107.208", md.PublicIpv4[0].IP)

	// local-ipv4 is empty in test data, so PrivateIpv4 should be empty
	assert.Empty(t, md.PrivateIpv4)
}

func TestHetznerInstanceWithLocalIP(t *testing.T) {
	hc := newHetznerCloud(t, "./testdata/hetzner_with_local_ip.toml")

	md, err := hc.Instance()
	require.NoError(t, err)

	assert.Equal(t, "ubuntu-8gb-hil-1", md.PrivateHostname)
	assert.Equal(t, "5.78.107.208", md.PublicIP())
	assert.Equal(t, "10.0.0.5", md.PrivateIP())

	require.Len(t, md.PublicIpv4, 1)
	assert.Equal(t, "5.78.107.208", md.PublicIpv4[0].IP)

	require.Len(t, md.PrivateIpv4, 1)
	assert.Equal(t, "10.0.0.5", md.PrivateIpv4[0].IP)
}
