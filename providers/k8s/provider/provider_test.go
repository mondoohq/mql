// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"k8s.io/apimachinery/pkg/api/meta"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
)

func newTestService(t *testing.T, path string) (*Service, *plugin.ConnectRes) {
	srv := &Service{
		Service: plugin.NewService(),
	}

	callbacks := &providerCallbacks{}

	resp, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type: "k8s",
					Options: map[string]string{
						shared.OPTION_MANIFEST: path,
					},
				},
			},
		},
	}, callbacks)
	if err != nil {
		panic(err)
	}
	return srv, resp
}

func TestK8sServiceAccountAutomount(t *testing.T) {
	srv, connRes := newTestService(t, "../connection/shared/resources/testdata/serviceaccount-automount.yaml")

	dataResp, err := srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s",
	})
	require.NoError(t, err)
	resourceId := string(dataResp.Data.Value)

	dataResp, err = srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s",
		ResourceId: resourceId,
		Field:      "serviceaccounts",
	})
	require.NoError(t, err)

	// we have 1 service account
	assert.Equal(t, 1, len(dataResp.Data.Array))

	saResourceID := string(dataResp.Data.Array[0].Value)

	dataResp, err = srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s.serviceaccount",
		ResourceId: saResourceID,
		Field:      "automountServiceAccountToken",
	})
	require.NoError(t, err)

	assert.True(t, dataResp.Data.RawData().Value.(bool))
}

func TestK8sServiceAccountImplicitAutomount(t *testing.T) {
	srv, connRes := newTestService(t, "../connection/shared/resources/testdata/serviceaccount-implicit-automount.yaml")

	dataResp, err := srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s",
	})
	require.NoError(t, err)
	resourceId := string(dataResp.Data.Value)

	dataResp, err = srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s",
		ResourceId: resourceId,
		Field:      "serviceaccounts",
	})
	require.NoError(t, err)

	// we have 1 service account
	assert.Equal(t, 1, len(dataResp.Data.Array))

	saResourceID := string(dataResp.Data.Array[0].Value)

	dataResp, err = srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s.serviceaccount",
		ResourceId: saResourceID,
		Field:      "automountServiceAccountToken",
	})
	require.NoError(t, err)

	assert.True(t, dataResp.Data.RawData().Value.(bool))
}

func TestK8sServiceAccountNoAutomount(t *testing.T) {
	srv, connRes := newTestService(t, "../connection/shared/resources/testdata/serviceaccount-no-automount.yaml")

	dataResp, err := srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s",
	})
	require.NoError(t, err)
	resourceId := string(dataResp.Data.Value)

	dataResp, err = srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s",
		ResourceId: resourceId,
		Field:      "serviceaccounts",
	})
	require.NoError(t, err)

	// we have 1 service account
	assert.Equal(t, 1, len(dataResp.Data.Array))

	saResourceID := string(dataResp.Data.Array[0].Value)

	dataResp, err = srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s.serviceaccount",
		ResourceId: saResourceID,
		Field:      "automountServiceAccountToken",
	})
	require.NoError(t, err)

	assert.False(t, dataResp.Data.RawData().Value.(bool))
}

func TestIngress(t *testing.T) {
	srv, connRes := newTestService(t, "../connection/shared/resources/testdata/ingress.yaml")

	dataResp, err := srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s",
	})
	require.NoError(t, err)
	resourceId := string(dataResp.Data.Value)

	dataResp, err = srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s",
		ResourceId: resourceId,
		Field:      "ingresses",
	})
	require.NoError(t, err)

	assert.Equal(t, 3, len(dataResp.Data.Array))

	t.Run("without-tls", func(t *testing.T) {
		tlsResp, err := srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "k8s.ingress",
			ResourceId: string(dataResp.Data.Array[0].Value),
			Field:      "tls",
		})
		require.NoError(t, err)

		assert.Empty(t, tlsResp.Data.RawData().Value)
	})

	t.Run("with-tls", func(t *testing.T) {
		tlsResp, err := srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "k8s.ingress",
			ResourceId: string(dataResp.Data.Array[1].Value),
			Field:      "tls",
		})
		require.NoError(t, err)

		assert.Empty(t, tlsResp.Data.RawData().Value)
	})

	t.Run("missing-tls-secret", func(t *testing.T) {
		tlsResp, err := srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "k8s.ingress",
			ResourceId: string(dataResp.Data.Array[1].Value),
			Field:      "tls",
		})
		require.NoError(t, err)

		assert.Empty(t, tlsResp.Data.RawData().Value)
	})
}

// A staged scan connects the root manifest, then every namespace (without a
// parent connection), then every workload under a namespace (with one). All of
// them must use the objects parsed when the root connected: parsing the
// manifest again per connection multiplies memory by the number of assets.
func TestManifestParsedOncePerManifest(t *testing.T) {
	dir := t.TempDir()
	for ns, workloads := range map[string][]string{"team-a": {"api", "worker"}, "team-b": {"web"}} {
		docs := []string{"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: " + ns + "\n"}
		for _, name := range workloads {
			docs = append(docs, `apiVersion: apps/v1
kind: Deployment
metadata:
  name: `+name+`
  namespace: `+ns+`
spec:
  selector: {matchLabels: {app: `+name+`}}
  template:
    metadata: {labels: {app: `+name+`}}
    spec:
      containers:
      - name: main
        image: nginx:1.25
`)
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, ns+".yaml"), []byte(strings.Join(docs, "---\n")), 0o600))
	}

	srv := Init()
	var nextId uint32
	connect := func(asset *inventory.Asset) *plugin.ConnectRes {
		nextId++
		asset.Connections[0].Id = nextId
		res, err := srv.Connect(&plugin.ConnectReq{Asset: asset}, &providerCallbacks{})
		require.NoError(t, err)
		return res
	}
	firstObject := func(id uint32) k8sRuntime.Object {
		rt, err := srv.GetRuntime(id)
		require.NoError(t, err)
		conn := rt.Connection.(*manifest.Connection)
		require.NotEmpty(t, conn.Objects)
		return conn.Objects[0]
	}

	rootRes := connect(&inventory.Asset{
		Connections: []*inventory.Config{{
			Type: "k8s",
			Options: map[string]string{
				shared.OPTION_MANIFEST:       dir,
				plugin.OptionStagedDiscovery: "",
			},
			Discover: &inventory.Discovery{Targets: []string{"all"}},
		}},
	})
	want := firstObject(rootRes.Id)

	var namespaces, workloads int
	for _, nsAsset := range rootRes.Inventory.Spec.Assets {
		if nsAsset.Platform.GetName() != "k8s-namespace" {
			continue
		}
		namespaces++
		nsRes := connect(nsAsset)
		assert.Same(t, want, firstObject(nsRes.Id), "namespace %s parsed the manifest again", nsAsset.Name)
		for _, wAsset := range nsRes.Inventory.GetSpec().GetAssets() {
			workloads++
			wRes := connect(wAsset)
			assert.Same(t, want, firstObject(wRes.Id), "workload %s parsed the manifest again", wAsset.Name)
		}
	}
	// Guard against passing vacuously: both connection kinds were exercised.
	require.Equal(t, 2, namespaces)
	require.GreaterOrEqual(t, workloads, 3)

	// The namespace scope is still per connection, though the objects are shared.
	for _, nsAsset := range rootRes.Inventory.Spec.Assets {
		if nsAsset.Platform.GetName() != "k8s-namespace" {
			continue
		}
		rt, err := srv.GetRuntime(nsAsset.Connections[0].Id)
		require.NoError(t, err)
		res, err := rt.Connection.(*manifest.Connection).Resources("deployment", "", "")
		require.NoError(t, err)
		for _, o := range res.Resources {
			obj, err := meta.Accessor(o)
			require.NoError(t, err)
			assert.Equal(t, nsAsset.Name, obj.GetNamespace())
		}
	}
}

type providerCallbacks struct {
	runtime *plugin.Runtime
}

func (p *providerCallbacks) GetRecording(req *plugin.DataReq) (*plugin.ResourceData, error) {
	res := plugin.ResourceData{}
	return &res, nil
}

func (p *providerCallbacks) GetData(req *plugin.DataReq) (*plugin.DataRes, error) {
	return &plugin.DataRes{}, nil
}

func (p *providerCallbacks) Collect(req *plugin.DataRes) error {
	return nil
}

func TestParseCLI(t *testing.T) {
	srv := &Service{}

	t.Run("WithNamespace", func(t *testing.T) {
		req := &plugin.ParseCLIReq{
			Args:      []string{"path/to/manifest.yaml"},
			Connector: "k8s",
			Flags: map[string]*llx.Primitive{
				"namespace": {
					Value: []byte("my-namespace"),
				},
				"namespace-exclude": {
					Value: []byte("excluded-namespace"),
				},
			},
		}

		res, err := srv.ParseCLI(req)
		require.NoError(t, err)

		expectedConf := &inventory.Config{
			Discover: &inventory.Discovery{
				Targets: []string{"auto"},
			},
			Type: "k8s",
			Options: map[string]string{
				shared.OPTION_MANIFEST: "path/to/manifest.yaml",
			},
		}

		expectedAsset := &inventory.Asset{
			Connections: []*inventory.Config{expectedConf},
			IdDetector:  []string{"hostname"},
		}

		expectedRes := &plugin.ParseCLIRes{
			Asset: expectedAsset,
		}

		assert.Equal(t, expectedRes, res)
	})

	t.Run("WithNamespaces", func(t *testing.T) {
		req := &plugin.ParseCLIReq{
			Connector: "k8s",
			Flags: map[string]*llx.Primitive{
				"namespaces-exclude": {
					Value: []byte("excluded-namespace"),
				},
				"namespaces": {
					Value: []byte("my-namespace"),
				},
				"namespace-label-selector": {
					Value: []byte("tenant=t1"),
				},
				"object-label-selector": {
					Value: []byte("app in (api,worker)"),
				},
			},
		}

		res, err := srv.ParseCLI(req)
		require.NoError(t, err)

		expectedConf := &inventory.Config{
			Discover: &inventory.Discovery{
				Targets: []string{"auto"},
			},
			Type: "k8s",
			Options: map[string]string{
				shared.OPTION_NAMESPACE:                "my-namespace",
				shared.OPTION_NAMESPACE_EXCLUDE:        "excluded-namespace",
				shared.OPTION_NAMESPACE_LABEL_SELECTOR: "tenant=t1",
				shared.OPTION_OBJECT_LABEL_SELECTOR:    "app in (api,worker)",
			},
		}

		expectedAsset := &inventory.Asset{
			Connections: []*inventory.Config{expectedConf},
			IdDetector:  []string{"hostname"},
		}

		expectedRes := &plugin.ParseCLIRes{
			Asset: expectedAsset,
		}

		assert.Equal(t, expectedRes, res)
	})
}

func TestParseCLIInheritNamespaceLabels(t *testing.T) {
	srv := &Service{}
	res, err := srv.ParseCLI(&plugin.ParseCLIReq{
		Connector: "k8s",
		Flags: map[string]*llx.Primitive{
			"inherit-namespace-labels": {
				Value: []byte("my.company.com/team,my.company.com/*"),
			},
		},
	})
	require.NoError(t, err)
	conf := res.Asset.Connections[0]
	assert.Equal(t, "my.company.com/team,my.company.com/*", conf.Options[shared.OPTION_INHERIT_NAMESPACE_LABELS])
}
