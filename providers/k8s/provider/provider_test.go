// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
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

func TestK8sServiceAccountSecrets(t *testing.T) {
	srv, connRes := newTestService(t, "../connection/shared/resources/testdata/serviceaccount-secrets.yaml")

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
	require.Len(t, dataResp.Data.Array, 1)

	saResourceID := string(dataResp.Data.Array[0].Value)

	dataResp, err = srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "k8s.serviceaccount",
		ResourceId: saResourceID,
		Field:      "secrets",
	})
	require.NoError(t, err)
	assert.Len(t, dataResp.Data.Array, 1)
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

	t.Run("WithKyvernoOptions", func(t *testing.T) {
		req := &plugin.ParseCLIReq{
			Connector: "k8s",
			Flags: map[string]*llx.Primitive{
				shared.OPTION_KYVERNO_DEFAULT_MAPPINGS: {
					Type:  "bool",
					Value: []byte("false"),
				},
				shared.OPTION_KYVERNO_MAPPING_ANNOTATION_CHECK_UIDS: {
					Value: []byte("security.example.com/check-uid"),
				},
				shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_OWNERS: {
					Value: []byte("owner.example.com/team"),
				},
				shared.OPTION_KYVERNO_MIRROR_POLICY_EXCEPTIONS: {
					Type:  "bool",
					Value: []byte("true"),
				},
				shared.OPTION_KYVERNO_MIRRORED_EXCEPTION_ACTION: {
					Value: []byte("WORKAROUND"),
				},
				shared.OPTION_KYVERNO_FAIL_EXPIRED_POLICY_EXCEPTIONS: {
					Type:  "bool",
					Value: []byte("false"),
				},
				shared.OPTION_KYVERNO_REPORT_UNMAPPED_POLICY_RESULTS: nil,
			},
		}

		res, err := srv.ParseCLI(req)
		require.NoError(t, err)

		options := res.Asset.Connections[0].Options
		assert.Equal(t, "false", options[shared.OPTION_KYVERNO_DEFAULT_MAPPINGS])
		assert.Equal(t, "security.example.com/check-uid", options[shared.OPTION_KYVERNO_MAPPING_ANNOTATION_CHECK_UIDS])
		assert.Equal(t, "owner.example.com/team", options[shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_OWNERS])
		assert.Equal(t, "true", options[shared.OPTION_KYVERNO_MIRROR_POLICY_EXCEPTIONS])
		assert.Equal(t, "WORKAROUND", options[shared.OPTION_KYVERNO_MIRRORED_EXCEPTION_ACTION])
		assert.Equal(t, "false", options[shared.OPTION_KYVERNO_FAIL_EXPIRED_POLICY_EXCEPTIONS])
		assert.NotContains(t, options, shared.OPTION_KYVERNO_REPORT_UNMAPPED_POLICY_RESULTS)
	})
}
