// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/utils/syncx"
)

func testTunnelRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

// TestVpnTunnelFlag covers the true/false strings the per-tunnel options use
// where the connection-level fields are already booleans. Reading an absent
// switch as false would report dead peer detection as deliberately off on a
// tunnel the API said nothing about.
func TestVpnTunnelFlag(t *testing.T) {
	assert.Nil(t, vpnTunnelFlag(nil))
	assert.Nil(t, vpnTunnelFlag(tea.String("")))
	// the connection-level vocabulary, which the tunnel options do not use
	assert.Nil(t, vpnTunnelFlag(tea.String("enable")))
	assert.Nil(t, vpnTunnelFlag(tea.String("yes")))

	require.NotNil(t, vpnTunnelFlag(tea.String("true")))
	assert.True(t, *vpnTunnelFlag(tea.String("true")))
	require.NotNil(t, vpnTunnelFlag(tea.String("false")))
	assert.False(t, *vpnTunnelFlag(tea.String("false")))
	require.NotNil(t, vpnTunnelFlag(tea.String("True")))
	assert.True(t, *vpnTunnelFlag(tea.String("True")))
}

// TestVpnTunnelLifetime covers the lifetime parse. The per-tunnel configs
// report seconds as a string, so an unparseable value read as zero would look
// like a security association that never lives.
func TestVpnTunnelLifetime(t *testing.T) {
	assert.Nil(t, vpnTunnelLifetime(nil))
	assert.Nil(t, vpnTunnelLifetime(tea.String("")))
	assert.Nil(t, vpnTunnelLifetime(tea.String("86400s")))
	assert.Nil(t, vpnTunnelLifetime(tea.String("a while")))

	require.NotNil(t, vpnTunnelLifetime(tea.String("86400")))
	assert.Equal(t, int64(86400), *vpnTunnelLifetime(tea.String("86400")))
	require.NotNil(t, vpnTunnelLifetime(tea.String(" 3600 ")))
	assert.Equal(t, int64(3600), *vpnTunnelLifetime(tea.String(" 3600 ")))
}

// TestVpnTunnelKey pins the part of the cache key that separates the tunnels of
// one connection. A key that repeats makes CreateResource hand back the first
// tunnel for the second, so the standby tunnel would report the active tunnel's
// algorithms.
func TestVpnTunnelKey(t *testing.T) {
	t.Run("the tunnel id wins", func(t *testing.T) {
		tunnel := &vpnTunnelOptions{TunnelId: tea.String("tun-bp1sm4b5f2vz2abcd"), TunnelIndex: tea.Int32(2)}
		assert.Equal(t, "tun-bp1sm4b5f2vz2abcd", vpnTunnelKey(tunnel, 1))
	})
	t.Run("the index carries a tunnel reported without an id", func(t *testing.T) {
		assert.Equal(t, "index-2", vpnTunnelKey(&vpnTunnelOptions{TunnelIndex: tea.Int32(2)}, 0))
	})
	t.Run("a blank id falls through to the index", func(t *testing.T) {
		tunnel := &vpnTunnelOptions{TunnelId: tea.String("  "), TunnelIndex: tea.Int32(1)}
		assert.Equal(t, "index-1", vpnTunnelKey(tunnel, 0))
	})
	t.Run("the position carries a tunnel with neither", func(t *testing.T) {
		assert.Equal(t, "position-1", vpnTunnelKey(&vpnTunnelOptions{}, 1))
		assert.Equal(t, "position-0", vpnTunnelKey(nil, 0))
	})
	t.Run("two tunnels with neither id nor index stay distinct", func(t *testing.T) {
		assert.NotEqual(t, vpnTunnelKey(&vpnTunnelOptions{}, 0), vpnTunnelKey(&vpnTunnelOptions{}, 1))
	})
}

// TestNewVpnConnectionTunnelsDecode reads a two-tunnel connection the way
// DescribeVpnConnections reports one and checks that each tunnel carries its
// own negotiated algorithms. A field wired to the wrong source, or two tunnels
// sharing a cache key, both surface here as the second tunnel reporting the
// first one's values.
func TestNewVpnConnectionTunnelsDecode(t *testing.T) {
	spec := &vpnTunnelOptionsSpec{
		TunnelOptions: []*vpnTunnelOptions{
			{
				TunnelId:           tea.String("tun-aaaaaaaaaaaaaaaaa"),
				TunnelIndex:        tea.Int32(1),
				Role:               tea.String("master"),
				Status:             tea.String("active"),
				State:              tea.String("ike_sa_established"),
				InternetIp:         tea.String("47.100.0.1"),
				CustomerGatewayId:  tea.String("cgw-aaaaaaaaaaaaaaaaa"),
				EnableDpd:          tea.String("true"),
				EnableNatTraversal: tea.String("false"),
				TunnelIkeConfig: &vpcclient.DescribeVpnConnectionsResponseBodyVpnConnectionsVpnConnectionTunnelOptionsSpecificationTunnelOptionsTunnelIkeConfig{
					IkeVersion:  tea.String("ikev2"),
					IkeMode:     tea.String("main"),
					IkeEncAlg:   tea.String("aes256"),
					IkeAuthAlg:  tea.String("sha256"),
					IkePfs:      tea.String("group14"),
					IkeLifetime: tea.String("86400"),
					LocalId:     tea.String("47.100.0.1"),
					RemoteId:    tea.String("203.0.113.10"),
					// the pre-shared key must never reach a scan result
					Psk: tea.String("super-secret-psk"),
				},
				TunnelIpsecConfig: &vpcclient.DescribeVpnConnectionsResponseBodyVpnConnectionsVpnConnectionTunnelOptionsSpecificationTunnelOptionsTunnelIpsecConfig{
					IpsecEncAlg:   tea.String("aes256"),
					IpsecAuthAlg:  tea.String("sha256"),
					IpsecPfs:      tea.String("group14"),
					IpsecLifetime: tea.String("86400"),
				},
			},
			{
				// the standby tunnel negotiated weaker algorithms, which is the
				// case the connection-level fields cannot describe
				TunnelId:    tea.String("tun-bbbbbbbbbbbbbbbbb"),
				TunnelIndex: tea.Int32(2),
				Role:        tea.String("slave"),
				Status:      tea.String("active"),
				TunnelIkeConfig: &vpcclient.DescribeVpnConnectionsResponseBodyVpnConnectionsVpnConnectionTunnelOptionsSpecificationTunnelOptionsTunnelIkeConfig{
					IkeEncAlg: tea.String("des"),
					IkePfs:    tea.String("group2"),
				},
				TunnelIpsecConfig: &vpcclient.DescribeVpnConnectionsResponseBodyVpnConnectionsVpnConnectionTunnelOptionsSpecificationTunnelOptionsTunnelIpsecConfig{
					IpsecEncAlg: tea.String("des"),
					IpsecPfs:    tea.String("group2"),
				},
			},
		},
	}

	tunnels, err := newVpnConnectionTunnels(testTunnelRuntime(), "cn-hangzhou/vco-abc", spec)
	require.NoError(t, err)
	require.Len(t, tunnels, 2)

	first, ok := tunnels[0].(*mqlAlicloudVpcVpnConnectionTunnel)
	require.True(t, ok)
	second, ok := tunnels[1].(*mqlAlicloudVpcVpnConnectionTunnel)
	require.True(t, ok)

	// two entries of one connection must be two resources, not the same one
	// handed back twice
	assert.NotEqual(t, first.MqlID(), second.MqlID())
	assert.Equal(t, "cn-hangzhou/vco-abc/tun-aaaaaaaaaaaaaaaaa", first.MqlID())
	assert.Equal(t, "cn-hangzhou/vco-abc/tun-bbbbbbbbbbbbbbbbb", second.MqlID())

	assert.Equal(t, "tun-aaaaaaaaaaaaaaaaa", first.TunnelId.Data)
	assert.Equal(t, int64(1), first.TunnelIndex.Data)
	assert.Equal(t, "master", first.Role.Data)
	assert.Equal(t, "active", first.Status.Data)
	assert.Equal(t, "ike_sa_established", first.State.Data)
	assert.Equal(t, "47.100.0.1", first.InternetIp.Data)
	assert.True(t, first.EnableDpd.Data)
	assert.False(t, first.EnableNatTraversal.Data)
	assert.Equal(t, "ikev2", first.IkeVersion.Data)
	assert.Equal(t, "main", first.IkeMode.Data)
	assert.Equal(t, "aes256", first.IkeEncryptionAlgorithm.Data)
	assert.Equal(t, "sha256", first.IkeAuthenticationAlgorithm.Data)
	assert.Equal(t, "group14", first.IkePfs.Data)
	assert.Equal(t, int64(86400), first.IkeLifetime.Data)
	assert.Equal(t, "47.100.0.1", first.IkeLocalId.Data)
	assert.Equal(t, "203.0.113.10", first.IkeRemoteId.Data)
	assert.Equal(t, "aes256", first.IpsecEncryptionAlgorithm.Data)
	assert.Equal(t, "sha256", first.IpsecAuthenticationAlgorithm.Data)
	assert.Equal(t, "group14", first.IpsecPfs.Data)
	assert.Equal(t, int64(86400), first.IpsecLifetime.Data)
	assert.Equal(t, "cgw-aaaaaaaaaaaaaaaaa", first.cacheCustomerGateway)

	// the weaker tunnel reports its own algorithms rather than the first one's
	assert.Equal(t, "slave", second.Role.Data)
	assert.Equal(t, int64(2), second.TunnelIndex.Data)
	assert.Equal(t, "des", second.IkeEncryptionAlgorithm.Data)
	assert.Equal(t, "group2", second.IkePfs.Data)
	assert.Equal(t, "des", second.IpsecEncryptionAlgorithm.Data)
	assert.Equal(t, "group2", second.IpsecPfs.Data)
	assert.Equal(t, "", second.cacheCustomerGateway)
}

// TestNewVpnConnectionTunnelsAbsent covers the connections the API reports
// without per-tunnel options. An empty list passes an all() check, so building
// a blank tunnel here would fail every single-tunnel connection instead.
func TestNewVpnConnectionTunnelsAbsent(t *testing.T) {
	t.Run("no specification at all", func(t *testing.T) {
		tunnels, err := newVpnConnectionTunnels(testTunnelRuntime(), "cn-hangzhou/vco-abc", nil)
		require.NoError(t, err)
		assert.Empty(t, tunnels)
	})
	t.Run("a specification holding no tunnels", func(t *testing.T) {
		tunnels, err := newVpnConnectionTunnels(testTunnelRuntime(), "cn-hangzhou/vco-abc", &vpnTunnelOptionsSpec{})
		require.NoError(t, err)
		assert.Empty(t, tunnels)
	})
	t.Run("a nil element is skipped rather than built blank", func(t *testing.T) {
		spec := &vpnTunnelOptionsSpec{
			TunnelOptions: []*vpnTunnelOptions{nil, {TunnelId: tea.String("tun-ccccccccccccccccc")}},
		}
		tunnels, err := newVpnConnectionTunnels(testTunnelRuntime(), "cn-hangzhou/vco-abc", spec)
		require.NoError(t, err)
		require.Len(t, tunnels, 1)
		assert.Equal(t, "tun-ccccccccccccccccc", tunnels[0].(*mqlAlicloudVpcVpnConnectionTunnel).TunnelId.Data)
	})
}

// TestNewVpnConnectionTunnelsUnkeyed builds the pair the API could report
// without tunnel ids. Both entries must still become their own resource, which
// only holds while the cache key falls back past the id.
func TestNewVpnConnectionTunnelsUnkeyed(t *testing.T) {
	spec := &vpnTunnelOptionsSpec{
		TunnelOptions: []*vpnTunnelOptions{
			{Role: tea.String("master"), Status: tea.String("active")},
			{Role: tea.String("slave"), Status: tea.String("updating")},
		},
	}

	tunnels, err := newVpnConnectionTunnels(testTunnelRuntime(), "cn-hangzhou/vco-abc", spec)
	require.NoError(t, err)
	require.Len(t, tunnels, 2)

	first := tunnels[0].(*mqlAlicloudVpcVpnConnectionTunnel)
	second := tunnels[1].(*mqlAlicloudVpcVpnConnectionTunnel)
	assert.NotEqual(t, first.MqlID(), second.MqlID())
	assert.Equal(t, "master", first.Role.Data)
	assert.Equal(t, "slave", second.Role.Data)
	assert.Equal(t, "updating", second.Status.Data)
}

// TestNewVpnConnectionTunnelsNullLifetimes checks that a tunnel reported
// without IKE or IPsec configuration leaves the algorithm and lifetime fields
// null. A zero lifetime or an empty algorithm string would read as a measured
// fact and score a check that was never able to look.
func TestNewVpnConnectionTunnelsNullLifetimes(t *testing.T) {
	spec := &vpnTunnelOptionsSpec{
		TunnelOptions: []*vpnTunnelOptions{{TunnelId: tea.String("tun-ddddddddddddddddd")}},
	}

	tunnels, err := newVpnConnectionTunnels(testTunnelRuntime(), "cn-hangzhou/vco-abc", spec)
	require.NoError(t, err)
	require.Len(t, tunnels, 1)

	tunnel := tunnels[0].(*mqlAlicloudVpcVpnConnectionTunnel)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, tunnel.IkeEncryptionAlgorithm.State)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, tunnel.IkeLifetime.State)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, tunnel.IpsecEncryptionAlgorithm.State)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, tunnel.IpsecLifetime.State)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, tunnel.EnableDpd.State)
}
