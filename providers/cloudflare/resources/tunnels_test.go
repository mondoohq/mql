// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTunnels(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cfd_tunnel", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		// cloudflare-go keeps fetching pages until result is empty.
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"result":[],"success":true,"errors":[],"messages":[]}`)
			return
		}
		jsonResponse(w, loadFixture("tunnels"))
	})

	// Connection details now come from the dedicated per-tunnel endpoint.
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cfd_tunnel/{tunnelID}/connections", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("tunnel_connections"))
	})

	result, err := acc.tunnels()
	require.NoError(t, err)
	require.Len(t, result, 2)

	tunnel := result[0].(*mqlCloudflareTunnel)
	assert.Equal(t, "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415", tunnel.Id.Data)
	assert.Equal(t, "blog-tunnel", tunnel.Name.Data)
	assert.Equal(t, "cfd_tunnel", tunnel.TunnelType.Data)
	assert.Equal(t, "healthy", tunnel.Status.Data)
	assert.True(t, tunnel.RemoteConfig.Data)
	assert.False(t, tunnel.CreatedAt.Data.IsZero())

	// Verify connections
	require.Len(t, tunnel.Connections.Data, 1)
	conn := tunnel.Connections.Data[0].(*mqlCloudflareTunnelConnection)
	assert.Equal(t, "conn-1234", conn.Id.Data)
	assert.Equal(t, "DFW", conn.ColoName.Data)
	assert.Equal(t, "198.51.100.1", conn.OriginIp.Data)
	// Cloudflare removed is_pending_reconnect from the API. The field must
	// read null, never false, which would assert the connection is actively
	// serving traffic.
	assert.True(t, conn.IsPendingReconnect.IsNull(), "isPendingReconnect must be null")
	assert.True(t, conn.IsPendingReconnect.IsSet(), "isPendingReconnect must be resolved, not left unset")
	assert.False(t, conn.OpenedAt.Data.IsZero())

	// Second tunnel has no connections
	tunnel2 := result[1].(*mqlCloudflareTunnel)
	assert.Equal(t, "api-tunnel", tunnel2.Name.Data)
	assert.Equal(t, "down", tunnel2.Status.Data)
	assert.Len(t, tunnel2.Connections.Data, 0)
}

func TestTunnelRoutes(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/teamnet/routes", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"result":[],"success":true,"errors":[],"messages":[]}`)
			return
		}
		jsonResponse(w, loadFixture("tunnel_routes"))
	})

	result, err := acc.tunnelRoutes()
	require.NoError(t, err)
	require.Len(t, result, 1)

	route := result[0].(*mqlCloudflareTunnelRoute)
	assert.Equal(t, "10.0.0.0/8", route.Network.Data)
	assert.Equal(t, "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415", route.TunnelId.Data)
	assert.Equal(t, "blog-tunnel", route.TunnelName.Data)
	assert.Equal(t, "Internal network", route.Comment.Data)
}

func TestTunnelVirtualNetworks(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/teamnet/virtual_networks", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("tunnel_virtual_networks"))
	})

	result, err := acc.tunnelVirtualNetworks()
	require.NoError(t, err)
	require.Len(t, result, 1)

	vnet := result[0].(*mqlCloudflareTunnelVirtualNetwork)
	assert.Equal(t, "vnet-1234", vnet.Id.Data)
	assert.Equal(t, "default-vnet", vnet.Name.Data)
	assert.True(t, vnet.IsDefaultNetwork.Data)
	assert.Equal(t, "Default virtual network", vnet.Comment.Data)
}

// TestTunnelRoutesVnetIDInCacheKey verifies that two routes advertising the
// same network through the same tunnel from two different virtual networks
// produce two distinct rows (rather than collapsing into one cached entry).
// The previous __id `tunnelRoute@<network>@<tunnelId>` collided in this case.
func TestTunnelRoutesVnetIDInCacheKey(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/teamnet/routes", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{
			"success": true, "errors": [], "messages": [],
			"result": [
				{"network": "10.0.0.0/8", "tunnel_id": "tun-1", "tunnel_name": "t", "comment": "via vnet-a", "virtual_network_id": "vnet-a", "created_at": "2024-01-01T00:00:00Z"},
				{"network": "10.0.0.0/8", "tunnel_id": "tun-1", "tunnel_name": "t", "comment": "via vnet-b", "virtual_network_id": "vnet-b", "created_at": "2024-01-01T00:00:00Z"}
			]
		}`)
	})

	result, err := acc.tunnelRoutes()
	require.NoError(t, err)
	require.Len(t, result, 2, "routes with distinct virtual_network_id must not collapse into one")

	r1 := result[0].(*mqlCloudflareTunnelRoute)
	r2 := result[1].(*mqlCloudflareTunnelRoute)

	// Same (network, tunnelId) but distinct vnet IDs.
	assert.Equal(t, r1.Network.Data, r2.Network.Data)
	assert.Equal(t, r1.TunnelId.Data, r2.TunnelId.Data)
	assert.NotEqual(t, r1.cacheVirtualNetworkID, r2.cacheVirtualNetworkID)
	assert.NotEqual(t, r1.Comment.Data, r2.Comment.Data, "each row must keep its own data, not share with its collision peer")
}

// TestTunnelRoutesPagination guards against the previously single-page call
// silently truncating large accounts. The handler returns full-size pages
// (perPage=50) twice, then a short page, and we assert the loop consumed all
// three pages and bumped page numbers monotonically.
func TestTunnelRoutesPagination(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	const perPage = 50
	var calls atomic.Int32

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/teamnet/routes", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		count := perPage
		if page >= 3 {
			count = 7 // short page → terminates loop
		}
		fmt.Fprint(w, `{"success": true, "errors": [], "messages": [], "result": [`)
		for i := 0; i < count; i++ {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"network": "10.%d.%d.0/24", "tunnel_id": "t-p%d-i%d", "tunnel_name": "t", "comment": "", "virtual_network_id": "v-p%d-i%d", "created_at": "2024-01-01T00:00:00Z"}`, page, i, page, i, page, i)
		}
		fmt.Fprint(w, `]}`)
	})

	result, err := acc.tunnelRoutes()
	require.NoError(t, err)
	require.Equal(t, perPage*2+7, len(result), "all three pages must be consumed")
	require.Equal(t, int32(3), calls.Load(), "exactly three calls (page=1,2,3)")
}

// tunnelsForConfigTest returns the two tunnels from the standard fixture, with
// their account binding set, so the configuration accessor can be exercised.
func tunnelsForConfigTest(t *testing.T, env *testEnv) []any {
	t.Helper()
	acc := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cfd_tunnel", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"result":[],"success":true,"errors":[],"messages":[]}`)
			return
		}
		jsonResponse(w, loadFixture("tunnels"))
	})
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cfd_tunnel/{tunnelID}/connections", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("tunnel_connections"))
	})

	tunnels, err := acc.tunnels()
	require.NoError(t, err)
	require.Len(t, tunnels, 2)
	return tunnels
}

func TestTunnelConfiguration(t *testing.T) {
	env := setupTestEnv(t)
	tunnels := tunnelsForConfigTest(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cfd_tunnel/{tunnelID}/configurations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("tunnel_configuration"))
	})

	tunnel := tunnels[0].(*mqlCloudflareTunnel)
	cfg, err := tunnel.configuration()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "cloudflare", cfg.Source.Data)
	assert.Equal(t, int64(7), cfg.Version.Data)
	assert.False(t, cfg.OriginNoTlsVerify.Data)
	assert.True(t, cfg.OriginHttp2.Data)
	assert.True(t, cfg.WarpRoutingEnabled.Data, "warp-routing is dropped by the SDK's typed config struct")

	require.Len(t, cfg.Ingress.Data, 3)

	// A rule that turns off origin certificate validation: the leg from the
	// connector to the service is encrypted but unauthenticated.
	admin := cfg.Ingress.Data[0].(*mqlCloudflareTunnelIngressRule)
	assert.Equal(t, "blog.example.com", admin.Hostname.Data)
	assert.Equal(t, "/admin", admin.Path.Data)
	assert.Equal(t, "https://10.0.0.5:8443", admin.Service.Data)
	assert.True(t, admin.NoTlsVerify.Data)
	assert.Equal(t, "blog.internal", admin.HttpHostHeader.Data)
	assert.False(t, admin.AccessRequired.Data)

	// A rule that does not mention noTLSVerify inherits the tunnel default, so
	// it must read null rather than a confident false.
	ssh := cfg.Ingress.Data[1].(*mqlCloudflareTunnelIngressRule)
	assert.Equal(t, "ssh://10.0.0.6:22", ssh.Service.Data)
	assert.True(t, ssh.NoTlsVerify.IsNull(), "an inherited setting must not read as an explicit false")
	assert.True(t, ssh.Http2Origin.IsNull())
	assert.True(t, ssh.AccessRequired.IsNull())
	assert.Equal(t, "/etc/cloudflared/origin-ca.pem", ssh.CaPool.Data)

	// The catch-all that ends every ingress list.
	catchAll := cfg.Ingress.Data[2].(*mqlCloudflareTunnelIngressRule)
	assert.Equal(t, "", catchAll.Hostname.Data)
	assert.Equal(t, "http_status:404", catchAll.Service.Data)
}

func TestTunnelConfiguration_locallyManagedIsNull(t *testing.T) {
	env := setupTestEnv(t)
	tunnels := tunnelsForConfigTest(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cfd_tunnel/{tunnelID}/configurations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("tunnel_configuration_local"))
	})

	tunnel := tunnels[0].(*mqlCloudflareTunnel)
	cfg, err := tunnel.configuration()
	require.NoError(t, err)
	assert.Nil(t, cfg, "a locally managed tunnel has no readable ingress, which is not the same as publishing nothing")
	assert.True(t, tunnel.Configuration.IsNull())
}

func TestTunnelConfiguration_warpConnectorIsNullWithoutACall(t *testing.T) {
	env := setupTestEnv(t)
	tunnels := tunnelsForConfigTest(t, env)

	called := false
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cfd_tunnel/{tunnelID}/configurations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		called = true
		jsonResponse(w, loadFixture("tunnel_configuration"))
	})

	// The second tunnel in the fixture is a warp_connector, which has no ingress.
	warp := tunnels[1].(*mqlCloudflareTunnel)
	require.Equal(t, "warp_connector", warp.TunnelType.Data)

	cfg, err := warp.configuration()
	require.NoError(t, err)
	assert.Nil(t, cfg)
	assert.True(t, warp.Configuration.IsNull())
	assert.False(t, called, "a WARP connector has no configurations endpoint to call")
}
