// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// network-list.json is GET /v1.51/networks from Docker Engine 29.8 (Docker
// Desktop), trimmed to the predefined networks and ones created with
// --internal, --ipv6 and two subnets, bridge options turning off ICC and
// masquerading, --attachable, and --ip-range.
func loadDockerNetworks(t *testing.T) map[string]network.Summary {
	t.Helper()
	raw, err := os.ReadFile("testdata/docker/network-list.json")
	require.NoError(t, err)
	var list []network.Summary
	require.NoError(t, json.Unmarshal(raw, &list))
	res := map[string]network.Summary{}
	for _, n := range list {
		res[n.Name] = n
	}
	return res
}

// container-list-networks.json is GET /v1.51/containers/json?all=1 for three
// containers: c1 running on two networks, c2 running on one, and c3 created
// but never started.
func loadDockerContainerList(t *testing.T) map[string]container.Summary {
	t.Helper()
	raw, err := os.ReadFile("testdata/docker/container-list-networks.json")
	require.NoError(t, err)
	var list []container.Summary
	require.NoError(t, json.Unmarshal(raw, &list))
	res := map[string]container.Summary{}
	for _, c := range list {
		res[c.Names[0]] = c
	}
	return res
}

func TestDockerNetworkDecode(t *testing.T) {
	nets := loadDockerNetworks(t)

	internal := nets["mqltest-internal"]
	assert.True(t, internal.Internal)
	assert.False(t, internal.EnableIPv6)
	assert.Equal(t, "bridge", internal.Driver)
	assert.Equal(t, "local", internal.Scope)
	assert.False(t, internal.Created.IsZero())

	assert.True(t, nets["mqltest-v6"].EnableIPv6)
	assert.True(t, nets["mqltest-attach"].Attachable)
	assert.False(t, nets["bridge"].Attachable)
	assert.Equal(t, "sec", nets["mqltest-noicc"].Labels["team"])
	assert.Equal(t, "null", nets["none"].Driver)
}

func TestDockerNetworkSubnets(t *testing.T) {
	nets := loadDockerNetworks(t)

	assert.Equal(t, []dockerNetworkSubnet{
		{subnet: "172.30.10.0/24", gateway: "172.30.10.1"},
		{subnet: "fd00:dead:beef::/64", gateway: "fd00:dead:beef::1"},
	}, dockerNetworkSubnets(nets["mqltest-v6"].IPAM))

	assert.Equal(t, []dockerNetworkSubnet{
		{subnet: "172.31.0.0/16", gateway: "172.31.0.254", ipRange: "172.31.5.0/24"},
	}, dockerNetworkSubnets(nets["mqltest-range"].IPAM))

	// the predefined none and host networks have no address management config
	assert.Empty(t, dockerNetworkSubnets(nets["none"].IPAM))
	assert.Empty(t, dockerNetworkSubnets(nets["host"].IPAM))
}

func TestDockerBridgeOptions(t *testing.T) {
	nets := loadDockerNetworks(t)
	opts := func(name string) map[string]any {
		return convert.MapToInterfaceMap(nets[name].Options)
	}

	t.Run("options turned off", func(t *testing.T) {
		icc, ok := dockerBridgeBoolOption("bridge", opts("mqltest-noicc"), dockerBridgeOptICC)
		assert.True(t, ok)
		assert.False(t, icc)
		masq, ok := dockerBridgeBoolOption("bridge", opts("mqltest-noicc"), dockerBridgeOptIPMasquerade)
		assert.True(t, ok)
		assert.False(t, masq)
		addr, ok := dockerBridgeHostBinding("bridge", opts("mqltest-noicc"))
		assert.True(t, ok)
		assert.Equal(t, "127.0.0.1", addr)
	})

	t.Run("predefined bridge states them", func(t *testing.T) {
		icc, ok := dockerBridgeBoolOption("bridge", opts("bridge"), dockerBridgeOptICC)
		assert.True(t, ok)
		assert.True(t, icc)
		addr, ok := dockerBridgeHostBinding("bridge", opts("bridge"))
		assert.True(t, ok)
		assert.Equal(t, "0.0.0.0", addr)
	})

	t.Run("absent options read as the driver default", func(t *testing.T) {
		icc, ok := dockerBridgeBoolOption("bridge", opts("mqltest-internal"), dockerBridgeOptICC)
		assert.True(t, ok)
		assert.True(t, icc)
		masq, ok := dockerBridgeBoolOption("bridge", opts("mqltest-internal"), dockerBridgeOptIPMasquerade)
		assert.True(t, ok)
		assert.True(t, masq)
		_, ok = dockerBridgeHostBinding("bridge", opts("mqltest-internal"))
		assert.False(t, ok, "an unset binding address is the daemon's, not one the network states")
	})

	t.Run("other drivers have no bridge options", func(t *testing.T) {
		_, ok := dockerBridgeBoolOption("host", opts("host"), dockerBridgeOptICC)
		assert.False(t, ok)
		_, ok = dockerBridgeBoolOption("null", opts("none"), dockerBridgeOptIPMasquerade)
		assert.False(t, ok)
		_, ok = dockerBridgeHostBinding("overlay", map[string]any{dockerBridgeOptHostBindingIPv4: "127.0.0.1"})
		assert.False(t, ok)
	})
}

func TestDockerContainerEndpoints(t *testing.T) {
	nets := loadDockerNetworks(t)
	ctrs := loadDockerContainerList(t)

	connected := func(c container.Summary, netName string) bool {
		n := nets[netName]
		for _, ep := range dockerContainerEndpoints(c) {
			if ep.connectedTo(n.ID, n.Name) {
				return true
			}
		}
		return false
	}

	c1 := ctrs["/mqltest-c1"]
	assert.True(t, connected(c1, "mqltest-noicc"))
	assert.True(t, connected(c1, "mqltest-v6"))
	assert.False(t, connected(c1, "mqltest-internal"))
	assert.False(t, connected(c1, "bridge"))

	// a container that never started has no endpoint ID, only the network name
	c3 := ctrs["/mqltest-c3"]
	eps := dockerContainerEndpoints(c3)
	require.Len(t, eps, 1)
	assert.Empty(t, eps[0].networkID)
	assert.True(t, connected(c3, "mqltest-attach"))
	assert.False(t, connected(c3, "mqltest-noicc"))

	// a recorded ID wins over the name, so a network recreated under the same
	// name is not mistaken for the one the container was attached to
	ep := dockerContainerEndpoint{name: "mqltest-internal", networkID: "deadbeef"}
	assert.False(t, ep.connectedTo(nets["mqltest-internal"].ID, "mqltest-internal"))

	assert.Empty(t, dockerContainerEndpoints(container.Summary{}))
}
