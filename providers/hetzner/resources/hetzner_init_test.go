// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/hetzner/connection"
)

type initFunc func(*plugin.Runtime, map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error)

// initRuntime is a runtime with a resource cache, so an init that succeeds can
// build its resource, pointed at a test server. extra connection options are
// how a test stands in for a discovered child asset.
func initRuntime(t *testing.T, extra map[string]string, h http.HandlerFunc) *plugin.Runtime {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	opts := map[string]string{
		connection.OPTION_TOKEN:    "test-token",
		connection.OPTION_ENDPOINT: srv.URL,
	}
	for k, v := range extra {
		opts[k] = v
	}
	conn, err := connection.NewHetznerConnection(0, &inventory.Asset{}, &inventory.Config{Options: opts})
	require.NoError(t, err)
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

// Every init looks its resource up by id. When no usable id is given, it has
// to fail. Handing the args back instead makes the runtime build a blank
// resource whose fields are all unset, and every query against it reads null
// with no error saying why.
func TestInitsWithoutAnIDFail(t *testing.T) {
	inits := map[string]initFunc{
		"certificate":      initHetznerCertificate,
		"datacenter":       initHetznerDatacenter,
		"firewall":         initHetznerFirewall,
		"floatingIp":       initHetznerFloatingIp,
		"image":            initHetznerImage,
		"iso":              initHetznerIso,
		"loadBalancer":     initHetznerLoadBalancer,
		"loadBalancerType": initHetznerLoadBalancerType,
		"location":         initHetznerLocation,
		"network":          initHetznerNetwork,
		"placementGroup":   initHetznerPlacementGroup,
		"primaryIp":        initHetznerPrimaryIp,
		"server":           initHetznerServer,
		"serverType":       initHetznerServerType,
		"sshKey":           initHetznerSshKey,
		"storageBox":       initHetznerStorageBox,
		"storageBoxType":   initHetznerStorageBoxType,
		"volume":           initHetznerVolume,
		"zone":             initHetznerZone,
	}

	cases := map[string]map[string]*llx.RawData{
		// hetzner.server
		"no args": {},
		// hetzner.server(name: "web") compiles, because name is a field, but
		// the init never searched by it.
		"a field the init does not key on": {"name": llx.StringData("web")},
		// hetzner.server(id: "12")
		"an id of the wrong type": {"id": llx.StringData("12")},
	}

	for name, init := range inits {
		for desc, args := range cases {
			t.Run(name+"/"+desc, func(t *testing.T) {
				runtime := initRuntime(t, nil, func(w http.ResponseWriter, r *http.Request) {
					t.Errorf("no id, so nothing to look up, but the init requested %s", r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
				})

				_, res, err := init(runtime, args)
				require.Error(t, err, "a blank hetzner.%s must not be built", name)
				assert.Nil(t, res)
				assert.Contains(t, err.Error(), "hetzner."+name+" requires a numeric id")
			})
		}
	}
}

// The firewall and load balancer inits have a second source for the id: the
// discovered child asset the scan is connected to. The missing-id error must
// only fire once that has been tried too.
func TestInitsFallBackToTheConnectedAsset(t *testing.T) {
	cases := []struct {
		name   string
		init   initFunc
		option string
		path   string
		body   string
	}{
		{
			name:   "firewall",
			init:   initHetznerFirewall,
			option: connection.OptionFirewall,
			path:   "/firewalls/7",
			body:   `{"firewall":{"id":7,"name":"edge","rules":[],"applied_to":[],"labels":{}}}`,
		},
		{
			name:   "loadBalancer",
			init:   initHetznerLoadBalancer,
			option: connection.OptionLoadBalancer,
			path:   "/load_balancers/7",
			body: `{"load_balancer":{"id":7,"name":"front","public_net":{"enabled":true,"ipv4":{"ip":"192.0.2.10"},"ipv6":{"ip":"2001:db8::10"}},` +
				`"private_net":[],"algorithm":{"type":"round_robin"},"services":[],"targets":[],"protection":{"delete":false},"labels":{}}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requested string
			runtime := initRuntime(t, map[string]string{tc.option: "7"}, func(w http.ResponseWriter, r *http.Request) {
				requested = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})

			_, res, err := tc.init(runtime, map[string]*llx.RawData{})
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, tc.path, requested)
			assert.Equal(t, "hetzner."+tc.name+"/7", res.MqlID())
		})
	}
}

// With an id the init still looks the resource up by it.
func TestInitLooksUpByTheGivenID(t *testing.T) {
	var requested string
	runtime := initRuntime(t, nil, func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"server":{"id":42,"name":"web","status":"running","public_net":{},"private_net":[],"labels":{}}}`))
	})

	_, res, err := initHetznerServer(runtime, map[string]*llx.RawData{"id": llx.IntData(42)})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "/servers/42", requested)
	s := res.(*mqlHetznerServer)
	assert.Equal(t, int64(42), s.Id.Data)
	assert.Equal(t, "web", s.Name.Data)
}
