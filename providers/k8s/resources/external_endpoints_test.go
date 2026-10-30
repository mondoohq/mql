// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/utils/syncx"
)

func externalEndpointsRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{}},
	}, manifest.WithManifestFile("./testdata/external_endpoints.yaml"))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

func serviceByName(t *testing.T, runtime *plugin.Runtime, name string) *mqlK8sService {
	t.Helper()
	s, err := NewResource(runtime, "k8s.service", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	return s.(*mqlK8sService)
}

func TestEndpointSliceExternalAddresses(t *testing.T) {
	runtime := externalEndpointsRuntime(t)

	es, err := NewResource(runtime, "k8s.endpointslice", map[string]*llx.RawData{
		"name":      llx.StringData("external-db-1"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	addrs := es.(*mqlK8sEndpointslice).GetExternalAddresses()
	require.NoError(t, addrs.Error)
	assert.Equal(t, []any{"8.8.8.8"}, addrs.Data)

	// Pod-backed endpoints are not external.
	podBacked, err := NewResource(runtime, "k8s.endpointslice", map[string]*llx.RawData{
		"name":      llx.StringData("internal-app-1"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	pb := podBacked.(*mqlK8sEndpointslice).GetExternalAddresses()
	require.NoError(t, pb.Error)
	assert.Empty(t, pb.Data)
}

func TestServiceExternalEndpoints(t *testing.T) {
	runtime := externalEndpointsRuntime(t)

	tests := []struct {
		name     string
		external []any
		toPublic bool
	}{
		{"external-db", []any{"8.8.8.8"}, true},   // public off-cluster target
		{"private-ext", []any{"10.1.2.3"}, false}, // private off-cluster target
		{"internal-app", nil, false},              // pod-backed, nothing external
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := serviceByName(t, runtime, tt.name)

			ext := svc.GetExternalEndpoints()
			require.NoError(t, ext.Error)
			if tt.external == nil {
				assert.Empty(t, ext.Data)
			} else {
				assert.Equal(t, tt.external, ext.Data)
			}

			pub := svc.GetRoutesToPublicEndpoint()
			require.NoError(t, pub.Error)
			assert.Equal(t, tt.toPublic, pub.Data)
		})
	}
}
