// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	admissionconn "go.mondoo.com/mql/providers/k8s/connection/admission"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/providers/k8s/connection/shared/distro"
	sharedres "go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	"go.mondoo.com/mql/utils/syncx"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
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

func newTestNamespace(name, uid string) corev1.Namespace {
	return corev1.Namespace{
		APIVersion: "v1",
		Kind:       "Namespace",
		Name:       name,
		UID:        types.UID(uid),
	}
}

type namespaceDiscoveryConnection struct {
	plugin.Connection
	asset      *inventory.Asset
	namespaces []corev1.Namespace
	pods       []corev1.Pod
	// forbidClusterWidePods makes a cluster-wide pod list come back empty, as the
	// API connection does when namespace-scoped RBAC forbids it.
	forbidClusterWidePods bool
	namespaceGetCalls     []string
}

func (c *namespaceDiscoveryConnection) Name() string {
	return c.asset.Name
}

func (c *namespaceDiscoveryConnection) Runtime() string {
	return "k8s-cluster"
}

// Resources serves the fake's pods for the pods kind and nothing for any
// other kind, so discovery targets other than pods find an empty cluster.
func (c *namespaceDiscoveryConnection) Resources(kind string, name string, namespace string) (*shared.ResourceResult, error) {
	res := &shared.ResourceResult{Kind: kind, Name: name, Namespace: namespace}
	if kind != gvkString(corev1.SchemeGroupVersion.WithKind("pods")) {
		return res, nil
	}
	if namespace == "" && c.forbidClusterWidePods {
		return res, nil
	}
	for i := range c.pods {
		if namespace != "" && c.pods[i].Namespace != namespace {
			continue
		}
		res.Resources = append(res.Resources, &c.pods[i])
	}
	return res, nil
}

func (c *namespaceDiscoveryConnection) ServerVersion() *version.Info {
	return nil
}

func (c *namespaceDiscoveryConnection) Distro() *distro.Result {
	return &distro.Result{Name: distro.Unknown}
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
		Labels: map[string]string{"tenant": "t1"},
	}))
	assert.False(t, filters.MatchNamespace(&corev1.Namespace{
		Labels: map[string]string{"tenant": "t2"},
	}))
	assert.True(t, filters.MatchObject(&corev1.Pod{
		Labels: map[string]string{"app": "api"},
	}))
	assert.False(t, filters.MatchObject(&corev1.Pod{
		Labels: map[string]string{"app": "db"},
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
	}, &corev1.Pod{Namespace: "object-ns"}))

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
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
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
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
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

func TestInheritedLabelKeys(t *testing.T) {
	cases := []struct {
		name    string
		set     bool
		value   string
		want    []string
		wantErr string
	}{
		{name: "absent", set: false, want: nil},
		{name: "empty", set: true, value: "", want: nil},
		{name: "only separators", set: true, value: " , ,", want: nil},
		{name: "keys and globs", set: true, value: "my.company.com/team, my.company.com/*", want: []string{"my.company.com/team", "my.company.com/*"}},
		{name: "invalid glob", set: true, value: "my.company.com/[team", wantErr: "inherit-namespace-labels"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &inventory.Config{Options: map[string]string{}}
			if tc.set {
				cfg.Options[shared.OPTION_INHERIT_NAMESPACE_LABELS] = tc.value
			}
			got, err := inheritedLabelKeys(cfg)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestInheritNamespaceLabels(t *testing.T) {
	ns := map[string]string{
		"my.company.com/team":         "aaabbbccc",
		"my.company.com/department":   "d-42",
		"kubernetes.io/metadata.name": "team-a",
	}
	workload := func(labels map[string]string) *inventory.Asset {
		return &inventory.Asset{
			PlatformIds: []string{"//platformid.api.mondoo.app/runtime/k8s/uid/c/namespace/team-a/pods/name/web"},
			Labels:      labels,
			Connections: []*inventory.Config{{Type: "k8s"}},
		}
	}

	t.Run("exact key is copied", func(t *testing.T) {
		a := workload(map[string]string{"app": "web"})
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, []string{"my.company.com/team"})
		assert.Equal(t, map[string]string{"app": "web", "my.company.com/team": "aaabbbccc"}, a.Labels)
	})
	t.Run("glob copies every matching key", func(t *testing.T) {
		a := workload(map[string]string{})
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, []string{"my.company.com/*"})
		assert.Equal(t, map[string]string{"my.company.com/team": "aaabbbccc", "my.company.com/department": "d-42"}, a.Labels)
	})
	t.Run("workload's own value wins", func(t *testing.T) {
		a := workload(map[string]string{"my.company.com/team": "zzz"})
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, []string{"my.company.com/team"})
		assert.Equal(t, "zzz", a.Labels["my.company.com/team"])
	})
	t.Run("namespace lacking the key changes nothing", func(t *testing.T) {
		a := workload(map[string]string{"app": "web"})
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, []string{"other.io/owner"})
		assert.Equal(t, map[string]string{"app": "web"}, a.Labels)
	})
	t.Run("nil labels map is initialised", func(t *testing.T) {
		a := workload(nil)
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, []string{"my.company.com/team"})
		assert.Equal(t, "aaabbbccc", a.Labels["my.company.com/team"])
	})
	t.Run("image assets are skipped", func(t *testing.T) {
		image := &inventory.Asset{Connections: []*inventory.Config{{Type: registryImageConnectionType, Host: "nginx@sha256:abc"}}}
		inheritNamespaceLabels([]*inventory.Asset{image}, ns, []string{"*"})
		assert.Nil(t, image.Labels)
	})
	t.Run("no patterns is a no-op", func(t *testing.T) {
		a := workload(map[string]string{"app": "web"})
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, nil)
		assert.Equal(t, map[string]string{"app": "web"}, a.Labels)
	})
}

// newTestPod builds a pod with no owner references. Each image becomes one
// container whose status reports that image as already resolved.
func newTestPod(namespace, name, uid string, labels map[string]string, images ...string) corev1.Pod {
	pod := corev1.Pod{
		APIVersion: "v1", Kind: "Pod",
		Namespace: namespace,
		Name:      name,
		UID:       types.UID(uid),
		Labels:    labels,
	}
	for i, image := range images {
		containerName := fmt.Sprintf("c%d", i)
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: containerName, Image: image})
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{Name: containerName, Image: image, ImageID: image})
	}
	return pod
}

// newDiscoveryTestRuntime wires the fake connection into a runtime whose
// CreateResource serves the k8s root resource and delegates every other
// resource to the generated factories.
func newDiscoveryTestRuntime(conn shared.Connection) *plugin.Runtime {
	rt := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
	}
	rt.CreateResource = func(runtime *plugin.Runtime, name string, args map[string]*llx.RawData) (plugin.Resource, error) {
		if name == "k8s" {
			return &mqlK8s{MqlRuntime: runtime}, nil
		}
		return CreateResource(runtime, name, args)
	}
	return rt
}

// inheritanceTestConn returns a fake cluster with one namespace "team-a"
// labeled with a team id, serving the given pods, and the staged namespace
// stage config for it. options are merged into the connection options.
func inheritanceTestConn(options map[string]string, targets []string, pods ...corev1.Pod) *namespaceDiscoveryConnection {
	cfg := &inventory.Config{
		Type: "k8s",
		Options: map[string]string{
			plugin.OptionStagedDiscovery: "",
			shared.OPTION_NAMESPACE:      "team-a",
		},
		Discover: &inventory.Discovery{Targets: targets},
	}
	maps.Copy(cfg.Options, options)
	asset := &inventory.Asset{Name: "K8s Cluster test", Connections: []*inventory.Config{cfg}}
	ns := newTestNamespace("team-a", "uid-team-a")
	ns.Labels = map[string]string{"my.company.com/team": "aaabbbccc", "other": "x"}
	return &namespaceDiscoveryConnection{
		Connection: plugin.NewConnection(1, asset),
		asset:      asset,
		namespaces: []corev1.Namespace{ns},
		pods:       pods,
	}
}

func TestDiscoverNamespaceStageInheritsNamespaceLabels(t *testing.T) {
	conn := inheritanceTestConn(
		map[string]string{shared.OPTION_INHERIT_NAMESPACE_LABELS: "my.company.com/team"},
		[]string{DiscoveryPods},
		newTestPod("team-a", "web", "uid-web", map[string]string{"app": "web"}),
	)

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 1)
	got := inv.Spec.Assets[0]
	assert.Equal(t, "team-a/web", got.Name)
	assert.Equal(t, "aaabbbccc", got.Labels["my.company.com/team"])
	assert.Equal(t, "web", got.Labels["app"])
	assert.NotContains(t, got.Labels, "other")
}

func TestDiscoverNamespaceStageKeepsWorkloadLabelOnCollision(t *testing.T) {
	conn := inheritanceTestConn(
		map[string]string{shared.OPTION_INHERIT_NAMESPACE_LABELS: "my.company.com/team"},
		[]string{DiscoveryPods},
		newTestPod("team-a", "web", "uid-web", map[string]string{"my.company.com/team": "zzz"}),
	)

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 1)
	assert.Equal(t, "zzz", inv.Spec.Assets[0].Labels["my.company.com/team"])
}

func TestDiscoverNamespaceStageWithoutOptionLeavesLabelsUnchanged(t *testing.T) {
	conn := inheritanceTestConn(
		nil,
		[]string{DiscoveryPods},
		newTestPod("team-a", "web", "uid-web", map[string]string{"app": "web"}),
	)

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 1)
	assert.NotContains(t, inv.Spec.Assets[0].Labels, "my.company.com/team")
	assert.Equal(t, "web", inv.Spec.Assets[0].Labels["app"])
}

func TestDiscoverManifestUndeclaredNamespaceInheritsNothing(t *testing.T) {
	cfg := &inventory.Config{
		Type: "k8s",
		Options: map[string]string{
			plugin.OptionStagedDiscovery:           "",
			shared.OPTION_NAMESPACE:                "undeclared",
			shared.OPTION_INHERIT_NAMESPACE_LABELS: "*",
		},
		Discover: &inventory.Discovery{Targets: []string{DiscoveryPods}},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{cfg}}
	conn, err := manifest.NewConnection(0, asset, manifest.WithManifestFile("testdata/inherit_namespace_labels_undeclared_ns.yaml"))
	require.NoError(t, err)

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 1)
	got := inv.Spec.Assets[0]
	assert.Equal(t, "web", got.Labels["app"])
	for k := range got.Labels {
		if k == "app" {
			continue
		}
		assert.True(t, strings.HasPrefix(k, "k8s.mondoo.com/"), "unexpected inherited label %q", k)
	}
}

func TestDiscoverNamespacesReturnsOwnLabels(t *testing.T) {
	cfg := &inventory.Config{Type: "k8s", Options: map[string]string{}}
	asset := &inventory.Asset{Name: "K8s Cluster test", Connections: []*inventory.Config{cfg}}
	ns := newTestNamespace("team-a", "uid-team-a")
	ns.Labels = map[string]string{"my.company.com/team": "aaabbbccc", "kubernetes.io/metadata.name": "team-a"}
	conn := &namespaceDiscoveryConnection{
		Connection: plugin.NewConnection(1, asset),
		asset:      asset,
		namespaces: []corev1.Namespace{ns},
	}
	nsFilter, err := newFilterOpts(nil, nil)
	require.NoError(t, err)

	assets, own, err := discoverNamespaces(conn, cfg, "", nil, nsFilter, &LabelSelectorFilters{})
	require.NoError(t, err)
	require.Len(t, assets, 1)
	assert.Equal(t, "team-a", assets[0].Labels["k8s.mondoo.com/name"])
	assert.Equal(t, map[string]string{"my.company.com/team": "aaabbbccc", "kubernetes.io/metadata.name": "team-a"}, own["team-a"])
}

func TestDiscoverLegacyInheritsNamespaceLabels(t *testing.T) {
	conn := inheritanceTestConn(
		map[string]string{shared.OPTION_INHERIT_NAMESPACE_LABELS: "my.company.com/team"},
		[]string{DiscoveryPods},
		newTestPod("team-a", "web", "uid-web", map[string]string{"app": "web"}),
	)
	delete(conn.asset.Connections[0].Options, plugin.OptionStagedDiscovery)

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 1)
	got := inv.Spec.Assets[0]
	assert.Equal(t, "team-a/web", got.Name)
	assert.Equal(t, "aaabbbccc", got.Labels["my.company.com/team"])
	assert.NotContains(t, got.Labels, "other")
}

func TestInheritedNamespaceLabels(t *testing.T) {
	ns := map[string]string{
		"my.company.com/team":         "aaabbbccc",
		"my.company.com/department":   "d-42",
		"kubernetes.io/metadata.name": "team-a",
	}
	t.Run("returns the matching subset", func(t *testing.T) {
		got := inheritedNamespaceLabels(ns, []string{"my.company.com/*"})
		assert.Equal(t, map[string]string{"my.company.com/team": "aaabbbccc", "my.company.com/department": "d-42"}, got)
	})
	t.Run("star matches every own label", func(t *testing.T) {
		got := inheritedNamespaceLabels(ns, []string{"*"})
		assert.Equal(t, ns, got)
	})
	t.Run("nothing matching is nil", func(t *testing.T) {
		assert.Nil(t, inheritedNamespaceLabels(ns, []string{"other.io/*"}))
	})
	t.Run("no patterns is nil", func(t *testing.T) {
		assert.Nil(t, inheritedNamespaceLabels(ns, nil))
	})
}

// clusterStageImageConn is a cluster with team-alpha {team=alpha}, team-beta
// {team=beta} and an unlabeled platform-tools, where nginx is shared by alpha and
// beta and web is shared by alpha and platform-tools.
func clusterStageImageConn(targets []string, options map[string]string) *namespaceDiscoveryConnection {
	cfg := &inventory.Config{
		Type:     "k8s",
		Options:  map[string]string{plugin.OptionStagedDiscovery: ""},
		Discover: &inventory.Discovery{Targets: targets},
	}
	maps.Copy(cfg.Options, options)
	asset := &inventory.Asset{Name: "K8s Cluster test", Connections: []*inventory.Config{cfg}}
	alpha := newTestNamespace("team-alpha", "uid-alpha")
	alpha.Labels = map[string]string{"my.company.com/team": "alpha"}
	beta := newTestNamespace("team-beta", "uid-beta")
	beta.Labels = map[string]string{"my.company.com/team": "beta"}
	tools := newTestNamespace("platform-tools", "uid-tools")
	return &namespaceDiscoveryConnection{
		Connection: plugin.NewConnection(1, asset),
		asset:      asset,
		namespaces: []corev1.Namespace{alpha, beta, tools},
		pods: []corev1.Pod{
			newTestPod("team-alpha", "web", "u1", nil, "nginx@sha256:shared", "web@sha256:alpha"),
			newTestPod("team-beta", "proxy", "u2", nil, "nginx@sha256:shared"),
			newTestPod("platform-tools", "agent", "u3", nil, "web@sha256:alpha"),
		},
	}
}

func TestDiscoverClusterStageAttachesImageVerdicts(t *testing.T) {
	conn := clusterStageImageConn([]string{DiscoveryContainerImages}, map[string]string{shared.OPTION_INHERIT_NAMESPACE_LABELS: "my.company.com/team"})

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 3)

	payloads := map[string]map[string]imageLabelVerdict{}
	for _, ns := range inv.Spec.Assets {
		raw, ok := ns.Connections[0].Options[shared.OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS]
		require.True(t, ok, "namespace %s has no verdict option", ns.Name)
		verdicts, skip, err := decodeImageLabelVerdicts(raw)
		require.NoError(t, err)
		require.False(t, skip)
		payloads[ns.Name] = verdicts
	}
	conflict := imageLabelVerdict{Conflicts: []string{"my.company.com/team"}}
	alphaOnly := imageLabelVerdict{Labels: map[string]string{"my.company.com/team": "alpha"}}
	assert.Equal(t, map[string]imageLabelVerdict{"nginx@sha256:shared": conflict, "web@sha256:alpha": alphaOnly}, payloads["team-alpha"])
	assert.Equal(t, map[string]imageLabelVerdict{"nginx@sha256:shared": conflict}, payloads["team-beta"])
	// the unlabeled namespace carries alpha's verdict for the image it shares with alpha
	assert.Equal(t, map[string]imageLabelVerdict{"web@sha256:alpha": alphaOnly}, payloads["platform-tools"])
}

func TestDiscoverClusterStageWithoutImagesTargetAttachesNoVerdicts(t *testing.T) {
	conn := clusterStageImageConn([]string{DiscoveryPods}, map[string]string{shared.OPTION_INHERIT_NAMESPACE_LABELS: "my.company.com/team"})

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 3)
	for _, ns := range inv.Spec.Assets {
		assert.NotContains(t, ns.Connections[0].Options, shared.OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS)
	}
}

const testImageRef = "docker.io/library/nginx@sha256:0123456789abcdef"

// splitImageAndWorkload returns the single registry-image asset and the single
// workload asset of a stage-2 run that targeted pods and container images.
func splitImageAndWorkload(t *testing.T, inv *inventory.Inventory) (image, workload *inventory.Asset) {
	t.Helper()
	require.Len(t, inv.Spec.Assets, 2)
	for _, a := range inv.Spec.Assets {
		if a.Connections[0].Type == registryImageConnectionType {
			image = a
		} else {
			workload = a
		}
	}
	require.NotNil(t, image)
	require.NotNil(t, workload)
	return image, workload
}

func TestDiscoverNamespaceStageLabelsImagesFromVerdicts(t *testing.T) {
	verdicts := encodeImageLabelVerdicts(map[string]imageLabelVerdict{
		testImageRef: {Labels: map[string]string{"my.company.com/team": "aaabbbccc"}, Conflicts: []string{"my.company.com/department"}},
	})
	conn := inheritanceTestConn(
		map[string]string{
			shared.OPTION_INHERIT_NAMESPACE_LABELS:          "my.company.com/team",
			shared.OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS: verdicts,
		},
		[]string{DiscoveryPods, DiscoveryContainerImages},
		newTestPod("team-a", "web", "uid-web", map[string]string{"app": "web"}, testImageRef),
	)

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	image, workload := splitImageAndWorkload(t, inv)
	assert.Equal(t, map[string]string{"my.company.com/team": "aaabbbccc", LabelNamespaceLabelConflict: "my.company.com/department"}, image.Labels)
	assert.Equal(t, "aaabbbccc", workload.Labels["my.company.com/team"])
}

func TestDiscoverNamespaceStageStandaloneFoldsOwnNamespace(t *testing.T) {
	conn := inheritanceTestConn(
		map[string]string{shared.OPTION_INHERIT_NAMESPACE_LABELS: "my.company.com/team"},
		[]string{DiscoveryPods, DiscoveryContainerImages},
		newTestPod("team-a", "web", "uid-web", map[string]string{"app": "web"}, testImageRef),
	)

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	image, _ := splitImageAndWorkload(t, inv)
	assert.Equal(t, map[string]string{"my.company.com/team": "aaabbbccc"}, image.Labels)
}

func TestDiscoverNamespaceStageSentinelSkipsImageLabels(t *testing.T) {
	conn := inheritanceTestConn(
		map[string]string{
			shared.OPTION_INHERIT_NAMESPACE_LABELS:          "my.company.com/team",
			shared.OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS: imageLabelVerdictsSentinel,
		},
		[]string{DiscoveryPods, DiscoveryContainerImages},
		newTestPod("team-a", "web", "uid-web", map[string]string{"app": "web"}, testImageRef),
	)

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	image, workload := splitImageAndWorkload(t, inv)
	assert.Nil(t, image.Labels)
	assert.Equal(t, "aaabbbccc", workload.Labels["my.company.com/team"])
}

func TestDiscoverNamespaceStageWithoutOptionLeavesImagesUnchanged(t *testing.T) {
	conn := inheritanceTestConn(
		nil,
		[]string{DiscoveryPods, DiscoveryContainerImages},
		newTestPod("team-a", "web", "uid-web", map[string]string{"app": "web"}, testImageRef),
	)

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	image, _ := splitImageAndWorkload(t, inv)
	assert.Nil(t, image.Labels)
}

func TestDiscoverLegacyLabelsImagesAcrossNamespaces(t *testing.T) {
	conn := clusterStageImageConn([]string{DiscoveryContainerImages}, map[string]string{
		shared.OPTION_INHERIT_NAMESPACE_LABELS: "my.company.com/team",
		shared.OPTION_NAMESPACE:                "team-*,platform-tools",
	})
	delete(conn.asset.Connections[0].Options, plugin.OptionStagedDiscovery)

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)

	// Legacy discovery emits an image once per namespace that runs it; every copy
	// must carry the same verdict.
	byHost := map[string][]*inventory.Asset{}
	for _, a := range inv.Spec.Assets {
		require.Equal(t, registryImageConnectionType, a.Connections[0].Type)
		byHost[a.Connections[0].Host] = append(byHost[a.Connections[0].Host], a)
	}
	require.Len(t, byHost["nginx@sha256:shared"], 2)
	for _, a := range byHost["nginx@sha256:shared"] {
		assert.Equal(t, map[string]string{LabelNamespaceLabelConflict: "my.company.com/team"}, a.Labels)
	}
	require.Len(t, byHost["web@sha256:alpha"], 2)
	for _, a := range byHost["web@sha256:alpha"] {
		assert.Equal(t, map[string]string{"my.company.com/team": "alpha"}, a.Labels)
	}
}
