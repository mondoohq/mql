// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	admissionconn "go.mondoo.com/mql/providers/k8s/connection/admission"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	sharedres "go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	"go.mondoo.com/mql/utils/syncx"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/version"
)

func TestDiscoverStagedDiscoveryWithCommaSeparatedNamespacesStartsClusterStage(t *testing.T) {
	cfg := &inventory.Config{
		Type: "k8s",
		Options: map[string]string{
			plugin.OptionStagedDiscovery: "",
			shared.OPTION_NAMESPACE:      "team-a,team-b",
		},
		Discover: &inventory.Discovery{
			Targets: []string{DiscoveryNamespaces},
		},
	}
	asset := &inventory.Asset{
		Name:        "K8s Cluster test",
		Connections: []*inventory.Config{cfg},
	}
	conn := &namespaceDiscoveryConnection{
		Connection: plugin.NewConnection(1, asset),
		asset:      asset,
		namespaces: []corev1.Namespace{
			newTestNamespace("team-a", "uid-team-a"),
			newTestNamespace("team-b", "uid-team-b"),
		},
	}
	pluginRuntime := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
	}
	pluginRuntime.CreateResource = func(runtime *plugin.Runtime, name string, args map[string]*llx.RawData) (plugin.Resource, error) {
		return &mqlK8s{MqlRuntime: runtime}, nil
	}

	inv, err := Discover(pluginRuntime, mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 2)
	require.Empty(t, conn.namespaceGetCalls)
	require.Equal(t, "team-a", inv.Spec.Assets[0].Connections[0].Options[shared.OPTION_NAMESPACE])
	require.Equal(t, "team-b", inv.Spec.Assets[1].Connections[0].Options[shared.OPTION_NAMESPACE])
}

func TestDiscoverStagedDiscoveryWithNamespaceGlobStartsClusterStage(t *testing.T) {
	cfg := &inventory.Config{
		Type: "k8s",
		Options: map[string]string{
			plugin.OptionStagedDiscovery: "",
			shared.OPTION_NAMESPACE:      "team-*",
		},
		Discover: &inventory.Discovery{
			Targets: []string{DiscoveryNamespaces},
		},
	}
	asset := &inventory.Asset{
		Name:        "K8s Cluster test",
		Connections: []*inventory.Config{cfg},
	}
	conn := &namespaceDiscoveryConnection{
		Connection: plugin.NewConnection(1, asset),
		asset:      asset,
		namespaces: []corev1.Namespace{
			newTestNamespace("team-a", "uid-team-a"),
			newTestNamespace("team-b", "uid-team-b"),
		},
	}
	pluginRuntime := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
	}
	pluginRuntime.CreateResource = func(runtime *plugin.Runtime, name string, args map[string]*llx.RawData) (plugin.Resource, error) {
		return &mqlK8s{MqlRuntime: runtime}, nil
	}

	inv, err := Discover(pluginRuntime, mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 2)
	require.Empty(t, conn.namespaceGetCalls)
}

func TestDiscoverKyvernoWithNamespaceFilterUsesNamespaceAssets(t *testing.T) {
	for _, staged := range []bool{false, true} {
		t.Run(fmt.Sprintf("staged=%t", staged), func(t *testing.T) {
			options := map[string]string{shared.OPTION_NAMESPACE: "team-a"}
			if staged {
				options[plugin.OptionStagedDiscovery] = ""
			}
			cfg := &inventory.Config{
				Type:    "k8s",
				Options: options,
				Discover: &inventory.Discovery{
					Targets: []string{DiscoveryKyverno},
				},
			}
			asset := &inventory.Asset{
				Name:        "K8s Cluster test",
				Connections: []*inventory.Config{cfg},
			}
			conn := &namespaceDiscoveryConnection{
				Connection: plugin.NewConnection(1, asset),
				asset:      asset,
				namespaces: []corev1.Namespace{newTestNamespace("team-a", "uid-team-a")},
			}
			pluginRuntime := &plugin.Runtime{
				Resources:  &syncx.Map[plugin.Resource]{},
				Connection: conn,
			}
			pluginRuntime.CreateResource = func(runtime *plugin.Runtime, name string, args map[string]*llx.RawData) (plugin.Resource, error) {
				return &mqlK8s{MqlRuntime: runtime}, nil
			}

			inv, err := Discover(pluginRuntime, mql.Features{})
			require.NoError(t, err)
			require.Len(t, inv.Spec.Assets, 1)
			assert.Equal(t, "team-a", inv.Spec.Assets[0].Name)
			assert.NotEmpty(t, inv.Spec.Assets[0].PlatformIds)
			assert.Contains(t, inv.Spec.Assets[0].PlatformIds[0], "/namespace/team-a")
			assert.Equal(t, "team-a", inv.Spec.Assets[0].Connections[0].Options[shared.OPTION_NAMESPACE])
		})
	}
}

func TestDiscoverStagedKyvernoRemovesTargetFromNamespaceAssets(t *testing.T) {
	cfg := &inventory.Config{
		Type: "k8s",
		Options: map[string]string{
			plugin.OptionStagedDiscovery: "",
		},
		Discover: &inventory.Discovery{
			Targets: []string{DiscoveryKyverno, DiscoveryPods},
		},
	}
	asset := &inventory.Asset{
		Name:        "K8s Cluster test",
		Connections: []*inventory.Config{cfg},
	}
	conn := &namespaceDiscoveryConnection{
		Connection: plugin.NewConnection(1, asset),
		asset:      asset,
		namespaces: []corev1.Namespace{newTestNamespace("team-a", "uid-team-a")},
	}
	pluginRuntime := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
	}

	inv, err := Discover(pluginRuntime, mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 2)
	assert.Empty(t, inv.Spec.Assets[0].Connections[0].Discover.Targets)
	assert.Equal(t, []string{DiscoveryPods}, inv.Spec.Assets[1].Connections[0].Discover.Targets)
}

func newTestNamespace(name, uid string) corev1.Namespace {
	return corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Namespace",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  types.UID(uid),
		},
	}
}

type namespaceDiscoveryConnection struct {
	plugin.Connection
	asset             *inventory.Asset
	namespaces        []corev1.Namespace
	namespaceGetCalls []string
}

func (c *namespaceDiscoveryConnection) Name() string {
	return c.asset.Name
}

func (c *namespaceDiscoveryConnection) Runtime() string {
	return "k8s-cluster"
}

func (c *namespaceDiscoveryConnection) Resources(kind string, name string, namespace string) (*shared.ResourceResult, error) {
	return nil, fmt.Errorf("unexpected resource lookup %s/%s/%s", kind, namespace, name)
}

func (c *namespaceDiscoveryConnection) ServerVersion() *version.Info {
	return nil
}

func (c *namespaceDiscoveryConnection) SupportedResourceTypes() (*sharedres.ApiResourceIndex, error) {
	return nil, nil
}

func (c *namespaceDiscoveryConnection) Platform() *inventory.Platform {
	return &inventory.Platform{
		Name:    "k8s-cluster",
		Family:  []string{"k8s"},
		Kind:    "api",
		Runtime: c.Runtime(),
		Title:   "Kubernetes Cluster",
	}
}

func (c *namespaceDiscoveryConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *namespaceDiscoveryConnection) AssetId() (string, error) {
	return shared.NewPlatformId("cluster-uid"), nil
}

func (c *namespaceDiscoveryConnection) BasePlatformId() (string, error) {
	return shared.IdPrefix, nil
}

func (c *namespaceDiscoveryConnection) AdmissionReviews() ([]admissionv1.AdmissionReview, error) {
	return []admissionv1.AdmissionReview{}, nil
}

func (c *namespaceDiscoveryConnection) Namespace(name string) (*corev1.Namespace, error) {
	c.namespaceGetCalls = append(c.namespaceGetCalls, name)
	for i := range c.namespaces {
		if c.namespaces[i].Name == name {
			return &c.namespaces[i], nil
		}
	}
	return nil, fmt.Errorf("namespace %q not found", name)
}

func (c *namespaceDiscoveryConnection) Namespaces() ([]corev1.Namespace, error) {
	return c.namespaces, nil
}

func (c *namespaceDiscoveryConnection) InventoryConfig() *inventory.Config {
	return c.asset.Connections[0]
}

var _ shared.Connection = (*namespaceDiscoveryConnection)(nil)

func TestLabelSelectorFilters(t *testing.T) {
	cfg := &inventory.Config{
		Options: map[string]string{
			shared.OPTION_NAMESPACE_LABEL_SELECTOR: "tenant=t1",
			shared.OPTION_OBJECT_LABEL_SELECTOR:    "app in (api,worker)",
		},
	}

	filters, err := labelSelectorFilters(cfg)
	require.NoError(t, err)

	assert.False(t, filters.IsEmpty())
	assert.True(t, filters.MatchNamespace(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"tenant": "t1"}},
	}))
	assert.False(t, filters.MatchNamespace(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"tenant": "t2"}},
	}))
	assert.True(t, filters.MatchObject(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
	}))
	assert.False(t, filters.MatchObject(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "db"}},
	}))
}

func TestLabelSelectorFilters_EmptySelectorsMatchAll(t *testing.T) {
	filters, err := labelSelectorFilters(&inventory.Config{Options: map[string]string{}})
	require.NoError(t, err)

	assert.True(t, filters.IsEmpty())
	assert.True(t, filters.MatchNamespace(&corev1.Namespace{}))
	assert.True(t, filters.MatchObject(&corev1.Pod{}))
}

func TestLabelSelectorFilters_InvalidSelector(t *testing.T) {
	_, err := labelSelectorFilters(&inventory.Config{
		Options: map[string]string{
			shared.OPTION_OBJECT_LABEL_SELECTOR: "app in (",
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), shared.OPTION_OBJECT_LABEL_SELECTOR)
}

func TestAdmissionReviewObjectNamespace(t *testing.T) {
	assert.Equal(t, "object-ns", admissionReviewObjectNamespace(admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{Namespace: "request-ns"},
	}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "object-ns"}}))

	assert.Equal(t, "request-ns", admissionReviewObjectNamespace(admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{Namespace: "request-ns"},
	}, &corev1.Pod{}))

	assert.Empty(t, admissionReviewObjectNamespace(admissionv1.AdmissionReview{}, &corev1.Namespace{}))
}

func TestAssetFromAdmissionReviewRejectsMalformedRequestObject(t *testing.T) {
	tests := []struct {
		name       string
		review     admissionv1.AdmissionReview
		wantErrMsg string
	}{
		{
			name:       "nil request",
			review:     admissionv1.AdmissionReview{},
			wantErrMsg: "admission review request is nil",
		},
		{
			name: "empty object",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{},
			},
			wantErrMsg: "admission review request object is empty",
		},
		{
			name: "no resources",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{Raw: []byte("# no resources\n")},
				},
			},
			wantErrMsg: "admission review request object did not contain any resources",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset, matched, err := assetFromAdmissionReview(nil, tt.review, "k8s-admission", &inventory.Config{}, "", FilterOpts{}, nil)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
			assert.False(t, matched)
			assert.Nil(t, asset)
		})
	}
}

func TestAssetFromAdmissionReviewUsesAdmittedObjectPlatform(t *testing.T) {
	podRaw := []byte(`{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "admitted-pod",
    "namespace": "default",
    "uid": "pod-uid",
    "resourceVersion": "42",
    "labels": {
      "app": "api"
    }
  }
}`)
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("review-uid"),
			Namespace: "default",
			Object:    runtime.RawExtension{Raw: podRaw},
		},
	}
	reviewJSON, err := json.Marshal(review)
	require.NoError(t, err)

	connection := &inventory.Config{Options: map[string]string{}}
	parent := &inventory.Asset{
		Name:        "admission-review",
		Connections: []*inventory.Config{connection},
	}
	conn, err := admissionconn.NewConnection(1, parent, base64.StdEncoding.EncodeToString(reviewJSON))
	require.NoError(t, err)

	asset, matched, err := assetFromAdmissionReview(conn, review, conn.Runtime(), connection, "cluster-id", FilterOpts{}, nil)

	require.NoError(t, err)
	require.True(t, matched)
	require.NotNil(t, asset)
	assert.Equal(t, "default/admitted-pod", asset.Name)
	assert.Equal(t, "k8s-pod", asset.Platform.Name)
	assert.Equal(t, "Kubernetes Pod", asset.Platform.Title)
	assert.Equal(t, "v1", asset.Platform.Version)
	assert.Equal(t, "42", asset.Platform.Build)
	assert.Equal(t, "Pod", asset.Labels["k8s.mondoo.com/kind"])
	assert.Equal(t, "v1", asset.Labels["k8s.mondoo.com/apiVersion"])
	assert.NotContains(t, asset.PlatformIds[0], "admissionreview")
	assert.Contains(t, asset.PlatformIds[0], "pod")
}

func TestAssetFromAdmissionReviewAppliesNamespaceLabelSelector(t *testing.T) {
	podRaw := []byte(`{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "admitted-pod",
    "namespace": "default",
    "uid": "pod-uid",
    "labels": {
      "app": "api"
    }
  }
}`)
	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			Namespace: "default",
			Object:    runtime.RawExtension{Raw: podRaw},
		},
	}
	filters, err := labelSelectorFilters(&inventory.Config{Options: map[string]string{
		shared.OPTION_NAMESPACE_LABEL_SELECTOR: "tenant=t1",
	}})
	require.NoError(t, err)

	asset, matched, err := assetFromAdmissionReview(nil, review, "k8s-admission", &inventory.Config{}, "", FilterOpts{}, filters)

	require.NoError(t, err)
	assert.False(t, matched)
	assert.Nil(t, asset)
}

func TestAssetFromAdmissionReviewUsesGenericPlatformForUnsupportedObjectKind(t *testing.T) {
	configMapRaw := []byte(`{
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {
    "name": "admitted-config",
    "namespace": "default",
    "uid": "configmap-uid",
    "resourceVersion": "43",
    "labels": {
      "app": "api"
    }
  }
}`)
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("review-uid"),
			Namespace: "default",
			Object:    runtime.RawExtension{Raw: configMapRaw},
		},
	}
	reviewJSON, err := json.Marshal(review)
	require.NoError(t, err)

	connection := &inventory.Config{Options: map[string]string{}}
	parent := &inventory.Asset{
		Name:        "admission-review",
		Connections: []*inventory.Config{connection},
	}
	conn, err := admissionconn.NewConnection(1, parent, base64.StdEncoding.EncodeToString(reviewJSON))
	require.NoError(t, err)

	asset, matched, err := assetFromAdmissionReview(conn, review, conn.Runtime(), connection, "cluster-id", FilterOpts{}, nil)

	require.NoError(t, err)
	require.True(t, matched)
	require.NotNil(t, asset)
	assert.Equal(t, "default/admitted-config", asset.Name)
	assert.Equal(t, "k8s-object", asset.Platform.Name)
	assert.Equal(t, "Kubernetes ConfigMap", asset.Platform.Title)
	assert.Equal(t, "ConfigMap", asset.Labels["k8s.mondoo.com/kind"])
	assert.Contains(t, asset.PlatformIds[0], "configmap")
	assert.NotContains(t, asset.PlatformIds[0], "admissionreview")
}
