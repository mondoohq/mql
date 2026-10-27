// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/syncx"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLoadRuntimeCacheSettings(t *testing.T) {
	delegatesFile := filepath.Join(t.TempDir(), "delegates.yml")
	require.NoError(t, os.WriteFile(delegatesFile, []byte(`
runtimeImageCache:
  allowPull: false
  scanOnlyInUse: true
  maxConcurrentImageScans: 1
  maxConcurrentLayerReaders: 2
  delegates:
  - id: containerd-primary
    kind: containerd
    endpoint: unix:///host/run/containerd/containerd.sock
    priority: 5
    namespaces:
    - k8s.io
    readonly: true
`), 0o644))

	settings, err := loadRuntimeCacheSettings(&inventory.Config{Options: map[string]string{
		runtimeCacheOptionDelegatesFile: delegatesFile,
	}})
	require.NoError(t, err)

	require.Len(t, settings.Delegates, 1)
	assert.Equal(t, "containerd-primary", settings.Delegates[0].ID)
	assert.Equal(t, "containerd", settings.Delegates[0].Kind)
	assert.Equal(t, "unix:///host/run/containerd/containerd.sock", settings.Delegates[0].Endpoint)
	assert.True(t, settings.ScanOnlyInUse)
	assert.False(t, settings.AllowPull)
}

func TestRuntimeCacheDelegatesByKindSortsAndSkipsUnsafeDelegates(t *testing.T) {
	delegates := runtimeCacheDelegatesByKind([]runtimeCacheDelegate{
		{ID: "rw", Kind: "containerd", Endpoint: "unix:///rw.sock", Priority: 0, ReadOnly: false},
		{ID: "missing-endpoint", Kind: "containerd", Priority: 5, ReadOnly: true},
		{ID: "secondary", Kind: "containerd", Endpoint: "unix:///secondary.sock", Priority: 20, ReadOnly: true},
		{ID: "primary", Kind: "containerd", Endpoint: "unix:///primary.sock", Priority: 10, Namespaces: []string{"prod"}, ReadOnly: true},
		{ID: "crio", Kind: "cri-o", Endpoint: "unix:///crio.sock", Priority: 0, ReadOnly: true},
	})

	require.Len(t, delegates["containerd"], 2)
	assert.Equal(t, "primary", delegates["containerd"][0].ID)
	assert.Equal(t, []string{"prod"}, delegates["containerd"][0].Namespaces)
	assert.Equal(t, "secondary", delegates["containerd"][1].ID)
	assert.Equal(t, []string{"k8s.io"}, delegates["containerd"][1].Namespaces)
	require.Len(t, delegates["cri-o"], 1)
}

func TestRuntimeCacheImageReference(t *testing.T) {
	ref, digest := runtimeCacheImageReference(corev1.ContainerStatus{
		Image:   "registry.example.com/team/app:1.2.3",
		ImageID: "docker-pullable://registry.example.com/team/app@sha256:abc123",
	})

	assert.Equal(t, "registry.example.com/team/app:1.2.3", ref)
	assert.Equal(t, "sha256:abc123", digest)

	ref, digest = runtimeCacheImageReference(corev1.ContainerStatus{
		ImageID: "containerd://sha256:def456",
	})

	assert.Equal(t, "sha256:def456", ref)
	assert.Empty(t, digest)

	ref, digest = runtimeCacheImageReference(corev1.ContainerStatus{
		Image:   "registry.example.com/team/app:1.2.3",
		ImageID: "sha256:configdigest",
	})

	assert.Equal(t, "registry.example.com/team/app:1.2.3", ref)
	assert.Empty(t, digest)
}

func TestRuntimeCacheImageDedupeKeyPrefersDigest(t *testing.T) {
	first := runtimeCacheImageDedupeKey("node-a", "containerd-primary", "registry.example.com/team/app:1.2.3", "sha256:abc123")
	second := runtimeCacheImageDedupeKey("node-a", "containerd-primary", "registry.example.com/team/app:latest", "sha256:abc123")
	otherDelegate := runtimeCacheImageDedupeKey("node-a", "containerd-secondary", "registry.example.com/team/app:latest", "sha256:abc123")
	otherNode := runtimeCacheImageDedupeKey("node-b", "containerd-primary", "registry.example.com/team/app:latest", "sha256:abc123")
	withoutDigest := runtimeCacheImageDedupeKey("node-a", "containerd-primary", "registry.example.com/team/app:latest", "")

	assert.Equal(t, first, second)
	assert.Equal(t, first, otherDelegate)
	assert.Equal(t, first, otherNode)
	assert.NotEqual(t, first, withoutDigest)
}

func TestRuntimeCacheImageDedupeKeyScopesTagFallback(t *testing.T) {
	first := runtimeCacheImageDedupeKey("node-a", "containerd-primary", "registry.example.com/team/app:latest", "")
	otherDelegate := runtimeCacheImageDedupeKey("node-a", "containerd-secondary", "registry.example.com/team/app:latest", "")
	otherNode := runtimeCacheImageDedupeKey("node-b", "containerd-primary", "registry.example.com/team/app:latest", "")
	otherRef := runtimeCacheImageDedupeKey("node-a", "containerd-primary", "registry.example.com/team/app:1.2.3", "")

	assert.NotEqual(t, first, otherDelegate)
	assert.NotEqual(t, first, otherNode)
	assert.NotEqual(t, first, otherRef)
}

func TestRuntimeCacheImageOwnerKeySelectsStableNode(t *testing.T) {
	nodeA := runtimeCacheImageOwnerKey("node-a", "containerd-primary", "registry.example.com/team/app:latest")
	nodeB := runtimeCacheImageOwnerKey("node-b", "containerd-primary", "registry.example.com/team/app:latest")

	assert.Less(t, nodeA, nodeB)
}

func TestRuntimeCacheActiveScannerNodeNamesUsesSelector(t *testing.T) {
	active, constrained, err := runtimeCacheActiveScannerNodeNames([]*corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scanner-a",
				Labels: map[string]string{
					"app":       "mondoo-runtime-cache-scan",
					"scan":      "runtime-cache",
					"mondoo_cr": "mondoo-client",
				},
			},
			Spec: corev1.PodSpec{NodeName: "node-a"},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				Conditions: []corev1.PodCondition{{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scanner-b",
				Labels: map[string]string{
					"app":       "mondoo-runtime-cache-scan",
					"scan":      "runtime-cache",
					"mondoo_cr": "other-config",
				},
			},
			Spec: corev1.PodSpec{NodeName: "node-b"},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				Conditions: []corev1.PodCondition{{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pending-scanner",
				Labels: map[string]string{
					"app":       "mondoo-runtime-cache-scan",
					"scan":      "runtime-cache",
					"mondoo_cr": "mondoo-client",
				},
			},
		},
	}, "app=mondoo-runtime-cache-scan,scan=runtime-cache,mondoo_cr=mondoo-client")
	require.NoError(t, err)
	assert.True(t, constrained)

	require.Contains(t, active, "node-a")
	assert.NotContains(t, active, "node-b")
	assert.NotContains(t, active, "")
}

func TestRuntimeCacheActiveScannerNodeNamesUsesKubernetesSelectorSyntax(t *testing.T) {
	active, constrained, err := runtimeCacheActiveScannerNodeNames([]*corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scanner-a",
				Labels: map[string]string{
					"app":         "mondoo-runtime-cache-scan",
					"mondoo_cr":   "mondoo-client",
					"scanner_set": "workers",
				},
			},
			Spec: corev1.PodSpec{NodeName: "node-a"},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				Conditions: []corev1.PodCondition{{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scanner-b",
				Labels: map[string]string{
					"app":       "mondoo-runtime-cache-scan",
					"mondoo_cr": "mondoo-client",
				},
			},
			Spec: corev1.PodSpec{NodeName: "node-b"},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				Conditions: []corev1.PodCondition{{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				}},
			},
		},
	}, "app in (mondoo-runtime-cache-scan),scanner_set,mondoo_cr==mondoo-client")
	require.NoError(t, err)
	assert.True(t, constrained)
	assert.Equal(t, map[string]struct{}{"node-a": {}}, active)
}

func TestRuntimeCacheActiveScannerNodeNamesRejectsInvalidSelector(t *testing.T) {
	active, constrained, err := runtimeCacheActiveScannerNodeNames([]*corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "mondoo-runtime-cache-scan"}},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
	}}, "app in (")

	assert.Nil(t, active)
	assert.False(t, constrained)
	require.ErrorContains(t, err, "invalid runtime-cache-scanner-pod-selector")
}

func TestRuntimeCacheActiveScannerNodeNamesFallsBackWhenSelectorHasNoActivePods(t *testing.T) {
	active, constrained, err := runtimeCacheActiveScannerNodeNames([]*corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "mondoo-runtime-cache-scan"}},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}}, "app=mondoo-runtime-cache-scan")

	require.NoError(t, err)
	assert.Nil(t, active)
	assert.False(t, constrained)
}

func TestRuntimeCacheActiveScannerNodeNamesRequiresRunningReadyPods(t *testing.T) {
	deletingTime := metav1.Now()
	active, constrained, err := runtimeCacheActiveScannerNodeNames([]*corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "mondoo-runtime-cache-scan"}},
			Spec:       corev1.PodSpec{NodeName: "pending-node"},
			Status:     corev1.PodStatus{Phase: corev1.PodPending},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "mondoo-runtime-cache-scan"}},
			Spec:       corev1.PodSpec{NodeName: "unready-node"},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				Conditions: []corev1.PodCondition{{
					Type:   corev1.PodReady,
					Status: corev1.ConditionFalse,
				}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Labels:            map[string]string{"app": "mondoo-runtime-cache-scan"},
				DeletionTimestamp: &deletingTime,
				Finalizers:        []string{"test"},
			},
			Spec: corev1.PodSpec{NodeName: "deleting-node"},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				Conditions: []corev1.PodCondition{{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "mondoo-runtime-cache-scan"}},
			Spec:       corev1.PodSpec{NodeName: "ready-node"},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				Conditions: []corev1.PodCondition{{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				}},
			},
		},
	}, "app=mondoo-runtime-cache-scan")

	require.NoError(t, err)
	assert.True(t, constrained)
	assert.Equal(t, map[string]struct{}{"ready-node": {}}, active)
}

func TestRuntimeCachePodEligibleForRuntimeCacheNode(t *testing.T) {
	activeScannerNodes := map[string]struct{}{"node-a": {}, "node-b": {}}

	assert.True(t, runtimeCachePodEligibleForRuntimeCacheNode("node-a", "node-b", activeScannerNodes, true))
	assert.False(t, runtimeCachePodEligibleForRuntimeCacheNode("node-c", "node-b", activeScannerNodes, true))
	assert.True(t, runtimeCachePodEligibleForRuntimeCacheNode("node-b", "node-b", nil, false))
	assert.False(t, runtimeCachePodEligibleForRuntimeCacheNode("node-a", "node-b", nil, false))
	assert.False(t, runtimeCachePodEligibleForRuntimeCacheNode("", "node-b", activeScannerNodes, true))
}

func TestRuntimeCacheImageAssetNameUsesDigestWhenAvailable(t *testing.T) {
	assert.Equal(t,
		"registry.example.com/team/app:latest@abc123",
		runtimeCacheImageAssetName("node-a", "registry.example.com/team/app:latest", "sha256:abc123"),
	)
	assert.Equal(t,
		"node-a/registry.example.com/team/app:latest",
		runtimeCacheImageAssetName("node-a", "registry.example.com/team/app:latest", ""),
	)
}

func TestRuntimeCacheContainerStatusesIncludesAllContainerKinds(t *testing.T) {
	statuses := runtimeCacheContainerStatuses(&corev1.Pod{
		Status: corev1.PodStatus{
			InitContainerStatuses:      []corev1.ContainerStatus{{Name: "init"}},
			ContainerStatuses:          []corev1.ContainerStatus{{Name: "main"}},
			EphemeralContainerStatuses: []corev1.ContainerStatus{{Name: "debug"}},
		},
	})

	require.Len(t, statuses, 3)
	assert.Equal(t, "init", statuses[0].Name)
	assert.Equal(t, "main", statuses[1].Name)
	assert.Equal(t, "debug", statuses[2].Name)
}

func TestRuntimeCacheResolveInventoryTemplateOption(t *testing.T) {
	t.Setenv("NODE_NAME", "node-a")

	got, err := runtimeCacheResolveInventoryTemplateOption(`{{ getenv "NODE_NAME" }}`)
	require.NoError(t, err)
	assert.Equal(t, "node-a", got)

	got, err = runtimeCacheResolveInventoryTemplateOption(`{{ printf "%s-runtime-cache" (getenv "NODE_NAME") }}`)
	require.NoError(t, err)
	assert.Equal(t, "node-a-runtime-cache", got)

	got, err = runtimeCacheResolveInventoryTemplateOption("node-b")
	require.NoError(t, err)
	assert.Equal(t, "node-b", got)

	_, err = runtimeCacheResolveInventoryTemplateOption(`{{ getenv "NODE_NAME" `)
	require.Error(t, err)
}

func TestRuntimeCacheDelegateForStatusOnlyUsesConfiguredRuntimeKind(t *testing.T) {
	delegates := runtimeCacheDelegatesByKind([]runtimeCacheDelegate{
		{ID: "containerd-primary", Kind: "containerd", Endpoint: "unix:///containerd.sock", Priority: 0, ReadOnly: true},
	})

	delegate, ok := runtimeCacheDelegateForStatus(delegates, corev1.ContainerStatus{
		ContainerID: "containerd://abc123",
	})
	require.True(t, ok)
	assert.Equal(t, "containerd-primary", delegate.ID)

	_, ok = runtimeCacheDelegateForStatus(delegates, corev1.ContainerStatus{
		ContainerID: "cri-o://abc123",
	})
	assert.False(t, ok)

	_, ok = runtimeCacheDelegateForStatus(delegates, corev1.ContainerStatus{})
	assert.False(t, ok)
}

func TestRuntimeImageStatusMatchesWithConfiguredRuntimeDelegate(t *testing.T) {
	delegatesFile := filepath.Join(t.TempDir(), "delegates.yml")
	require.NoError(t, os.WriteFile(delegatesFile, []byte(`
runtimeImageCache:
  allowPull: false
  scanOnlyInUse: true
  delegates:
  - id: containerd-primary
    kind: containerd
    endpoint: unix:///host/run/containerd/containerd.sock
    priority: 10
    namespaces:
    - k8s.io
    readonly: true
`), 0o644))

	rootAsset := &inventory.Asset{
		Connections: []*inventory.Config{{
			Type: "k8s",
			Options: map[string]string{
				runtimeCacheOptionDelegatesFile: delegatesFile,
			},
		}},
	}
	conn, err := manifest.NewConnection(0, rootAsset,
		manifest.WithManifestContent([]byte(runtimeCacheNodeImageManifest)),
		manifest.WithManifestFile("runtime-cache-node-image.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Resources:      &syncx.Map[plugin.Resource]{},
		Connection:     conn,
		Callback:       runtimeCacheSharedResourceCallback{},
		CreateResource: CreateResource,
	}
	k8s := &mqlK8s{MqlRuntime: runtime}
	nodes := k8s.GetNodes()
	require.NoError(t, nodes.Error)
	require.Len(t, nodes.Data, 1)

	delegates := nodes.Data[0].(*mqlK8sNode).GetRuntimeDelegates()
	require.NoError(t, delegates.Error)
	require.Len(t, delegates.Data, 1)
	assert.True(t, runtimeDelegateAvailable(runtime, delegates.Data, "containerd"))

	pods := k8s.GetPods()
	require.NoError(t, pods.Error)
	require.Len(t, pods.Data, 1)
	statuses := pods.Data[0].(*mqlK8sPod).GetContainerStatuses()
	require.NoError(t, statuses.Error)
	require.Len(t, statuses.Data, 1)

	status := statuses.Data[0].(*mqlK8sContainerStatus).GetRuntimeImageStatus()
	require.NoError(t, status.Error)
	assert.Equal(t, "matched", status.Data)
}

type runtimeCacheSharedResourceCallback struct{}

func (runtimeCacheSharedResourceCallback) Collect(_ *plugin.DataRes) error {
	return nil
}

func (runtimeCacheSharedResourceCallback) GetRecording(_ *plugin.DataReq) (*plugin.ResourceData, error) {
	return &plugin.ResourceData{}, nil
}

func (runtimeCacheSharedResourceCallback) GetData(req *plugin.DataReq) (*plugin.DataRes, error) {
	if req.Field != "" {
		return runtimeCacheSharedFieldData(req), nil
	}
	switch req.Resource {
	case "container.runtimeDelegate":
		return sharedResourceData(&fakeRuntimeDelegate{
			id:        "node-a/containerd-primary",
			kind:      plugin.TValue[string]{Data: "containerd"},
			endpoint:  plugin.TValue[string]{Data: "unix:///host/run/containerd/containerd.sock"},
			readonly:  plugin.TValue[bool]{Data: true},
			allowPull: plugin.TValue[bool]{Data: false},
			status:    plugin.TValue[string]{Data: "ready"},
		}, req.Resource), nil
	case "container.runtimeImage":
		return sharedResourceData(&fakeRuntimeImage{
			id:             "node-a/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			imageID:        plugin.TValue[string]{Data: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			repoTags:       plugin.TValue[[]any]{Data: []any{"registry.example.com/team/app:1.2.3"}},
			repoDigests:    plugin.TValue[[]any]{Data: []any{"registry.example.com/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
			resolvedDigest: plugin.TValue[string]{Data: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			targetDigest:   plugin.TValue[string]{Data: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		}, req.Resource), nil
	default:
		return &plugin.DataRes{Error: "unexpected shared resource " + req.Resource}, nil
	}
}

func runtimeCacheSharedFieldData(req *plugin.DataReq) *plugin.DataRes {
	switch req.Resource {
	case "container.runtimeDelegate":
		switch req.Field {
		case "kind":
			return sharedPrimitiveData(llx.StringData("containerd"))
		case "endpoint":
			return sharedPrimitiveData(llx.StringData("unix:///host/run/containerd/containerd.sock"))
		case "readonly":
			return sharedPrimitiveData(llx.BoolData(true))
		case "allowPull":
			return sharedPrimitiveData(llx.BoolData(false))
		case "status":
			return sharedPrimitiveData(llx.StringData("ready"))
		}
	case "container.runtimeImage":
		switch req.Field {
		case "imageId":
			return sharedPrimitiveData(llx.StringData("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
		case "repoTags":
			return sharedPrimitiveData(llx.ArrayData([]any{"registry.example.com/team/app:1.2.3"}, types.String))
		case "repoDigests":
			return sharedPrimitiveData(llx.ArrayData([]any{"registry.example.com/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, types.String))
		case "resolvedDigest", "targetDigest":
			return sharedPrimitiveData(llx.StringData("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
		}
	}
	return &plugin.DataRes{Error: "unexpected shared field " + req.Resource + "." + req.Field}
}

func sharedResourceData(resource plugin.Resource, name string) *plugin.DataRes {
	return &plugin.DataRes{Data: llx.ResourceData(resource, name).Result().Data}
}

func sharedPrimitiveData(raw *llx.RawData) *plugin.DataRes {
	return &plugin.DataRes{Data: raw.Result().Data}
}

func TestRuntimeCacheApplyConcurrencyOptions(t *testing.T) {
	options := map[string]string{}
	runtimeCacheApplyConcurrencyOptions(options, &runtimeCacheSettings{
		MaxConcurrentImageScans:   3,
		MaxConcurrentLayerReaders: 4,
	}, map[string]string{
		runtimeImageOptionMaxConcurrentImage: "1",
		runtimeImageOptionMaxLayerReaders:    "2",
	})

	assert.Equal(t, "3", options[runtimeImageOptionMaxConcurrentImage])
	assert.Equal(t, "4", options[runtimeImageOptionMaxLayerReaders])

	options = map[string]string{}
	runtimeCacheApplyConcurrencyOptions(options, &runtimeCacheSettings{}, map[string]string{
		runtimeImageOptionMaxConcurrentImage: "5",
		runtimeImageOptionMaxLayerReaders:    "6",
	})

	assert.Equal(t, "5", options[runtimeImageOptionMaxConcurrentImage])
	assert.Equal(t, "6", options[runtimeImageOptionMaxLayerReaders])
}

func TestDiscoverRuntimeCacheImagesDedupesByDigestAcrossActiveScannerNodes(t *testing.T) {
	delegatesFile := filepath.Join(t.TempDir(), "delegates.yml")
	require.NoError(t, os.WriteFile(delegatesFile, []byte(`
runtimeImageCache:
  allowPull: false
  scanOnlyInUse: true
  maxConcurrentImageScans: 2
  maxConcurrentLayerReaders: 3
  delegates:
  - id: containerd-primary
    kind: containerd
    endpoint: unix:///host/run/containerd/containerd.sock
    priority: 10
    namespaces:
    - k8s.io
    readonly: true
`), 0o644))

	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{Options: map[string]string{}}},
	}, manifest.WithManifestContent([]byte(runtimeCachePodsManifest)), manifest.WithManifestFile("runtime-cache-pods.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	k8s := &mqlK8s{MqlRuntime: runtime}

	invConfig := &inventory.Config{
		Id: 1,
		Options: map[string]string{
			runtimeCacheOptionNodeName:      "node-a",
			runtimeCacheOptionDelegatesFile: delegatesFile,
			runtimeCacheOptionScannerPods:   "app=mondoo-runtime-cache-scan,scan=runtime-cache,mondoo_cr=mondoo-client",
		},
	}
	assets, err := discoverRuntimeCacheImages(conn, invConfig, k8s, FilterOpts{})
	require.NoError(t, err)
	require.Len(t, assets, 1)

	asset := assets[0]
	assert.Equal(t, "registry.example.com/team/app:1.0@aaaaaaaaaaaa", asset.Name)
	assert.Equal(t, []string{"//platformid.api.mondoo.app/runtime/docker/images/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, asset.PlatformIds)
	assert.Equal(t, "node-a", asset.Labels["mondoo.com/runtime-cache-owner-node"])
	assert.Equal(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", asset.Labels["mondoo.com/runtime-image-digest"])
	assert.Equal(t, "containerd://container-a,containerd://container-b", asset.Annotations["mondoo.com/runtime-cache-containers"])
	assert.Equal(t, "prod", asset.Annotations["mondoo.com/runtime-cache-namespaces"])
	assert.Equal(t, "node-a,node-b", asset.Annotations["mondoo.com/runtime-cache-nodes"])
	assert.Equal(t, "containerd-primary", asset.Annotations["mondoo.com/runtime-cache-delegates"])
	require.Len(t, asset.Connections, 1)
	assert.Equal(t, runtimeImageConnectionType, asset.Connections[0].Type)
	assert.Equal(t, "registry.example.com/team/app:1.0", asset.Connections[0].Options[runtimeImageOptionRef])
	assert.Equal(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", asset.Connections[0].Options[runtimeImageOptionDigest])
	assert.Equal(t, "containerd-primary", asset.Connections[0].Options[runtimeImageOptionDelegateID])
	assert.Equal(t, "2", asset.Connections[0].Options[runtimeImageOptionMaxConcurrentImage])
	assert.Equal(t, "3", asset.Connections[0].Options[runtimeImageOptionMaxLayerReaders])

	invConfig.Options[runtimeCacheOptionNodeName] = "node-b"
	assets, err = discoverRuntimeCacheImages(conn, invConfig, k8s, FilterOpts{})
	require.NoError(t, err)
	assert.Empty(t, assets)

	delete(invConfig.Options, runtimeCacheOptionScannerPods)
	assets, err = discoverRuntimeCacheImages(conn, invConfig, k8s, FilterOpts{})
	require.NoError(t, err)
	require.Len(t, assets, 1)
	assert.Equal(t, "registry.example.com/team/app:latest@aaaaaaaaaaaa", assets[0].Name)
	assert.Equal(t, "node-b", assets[0].Labels["mondoo.com/runtime-cache-owner-node"])
	assert.Equal(t, "containerd://container-b", assets[0].Annotations["mondoo.com/runtime-cache-containers"])
	assert.Equal(t, "node-b", assets[0].Annotations["mondoo.com/runtime-cache-nodes"])
}

func TestDiscoverRuntimeCacheImagesPassesOrderedDelegateCandidates(t *testing.T) {
	delegatesFile := filepath.Join(t.TempDir(), "delegates.yml")
	require.NoError(t, os.WriteFile(delegatesFile, []byte(`
runtimeImageCache:
  allowPull: false
  scanOnlyInUse: true
  delegates:
  - id: containerd-primary
    kind: containerd
    endpoint: unix:///host/run/containerd-primary.sock
    priority: 10
    namespaces:
    - prod
    readonly: true
  - id: containerd-secondary
    kind: containerd
    endpoint: unix:///host/run/containerd-secondary.sock
    priority: 20
    namespaces:
    - k8s.io
    readonly: true
`), 0o644))

	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{Options: map[string]string{}}},
	}, manifest.WithManifestContent([]byte(runtimeCachePodsManifest)), manifest.WithManifestFile("runtime-cache-pods.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	k8s := &mqlK8s{MqlRuntime: runtime}

	assets, err := discoverRuntimeCacheImages(conn, &inventory.Config{
		Id: 1,
		Options: map[string]string{
			runtimeCacheOptionNodeName:      "node-a",
			runtimeCacheOptionDelegatesFile: delegatesFile,
			runtimeCacheOptionScannerPods:   "app=mondoo-runtime-cache-scan,scan=runtime-cache,mondoo_cr=mondoo-client",
		},
	}, k8s, FilterOpts{})
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.Len(t, assets[0].Connections, 1)

	options := assets[0].Connections[0].Options
	assert.Equal(t, "containerd-primary", options[runtimeImageOptionDelegateID])
	assert.Equal(t, "unix:///host/run/containerd-primary.sock", options[runtimeImageOptionEndpoint])
	assert.Equal(t, "containerd-primary,containerd-secondary", assets[0].Annotations["mondoo.com/runtime-cache-delegates"])

	var candidates []runtimeCacheDelegate
	require.NoError(t, json.Unmarshal([]byte(options[runtimeImageOptionDelegateCandidates]), &candidates))
	require.Len(t, candidates, 2)
	assert.Equal(t, "containerd-primary", candidates[0].ID)
	assert.Equal(t, "unix:///host/run/containerd-primary.sock", candidates[0].Endpoint)
	assert.Equal(t, []string{"prod"}, candidates[0].Namespaces)
	assert.Equal(t, "containerd-secondary", candidates[1].ID)
}

func TestDiscoverRuntimeCacheImagesExpandsNodeNameTemplate(t *testing.T) {
	t.Setenv("NODE_NAME", "node-a")

	delegatesFile := filepath.Join(t.TempDir(), "delegates.yml")
	require.NoError(t, os.WriteFile(delegatesFile, []byte(`
runtimeImageCache:
  allowPull: false
  scanOnlyInUse: true
  delegates:
  - id: containerd-primary
    kind: containerd
    endpoint: unix:///host/run/containerd/containerd.sock
    priority: 10
    namespaces:
    - k8s.io
    readonly: true
`), 0o644))

	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{Options: map[string]string{}}},
	}, manifest.WithManifestContent([]byte(runtimeCachePodsManifest)), manifest.WithManifestFile("runtime-cache-pods.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	k8s := &mqlK8s{MqlRuntime: runtime}

	assets, err := discoverRuntimeCacheImages(conn, &inventory.Config{
		Id: 1,
		Options: map[string]string{
			runtimeCacheOptionNodeName:      `{{ getenv "NODE_NAME" }}`,
			runtimeCacheOptionDelegatesFile: delegatesFile,
			runtimeCacheOptionScannerPods:   "app=mondoo-runtime-cache-scan,scan=runtime-cache,mondoo_cr=mondoo-client",
		},
	}, k8s, FilterOpts{})
	require.NoError(t, err)
	require.Len(t, assets, 1)
	assert.Equal(t, "node-a", assets[0].Labels["mondoo.com/runtime-cache-owner-node"])
}

func TestDiscoverClusterStageRuntimeCacheImagesAreClusterScoped(t *testing.T) {
	delegatesFile := filepath.Join(t.TempDir(), "delegates.yml")
	require.NoError(t, os.WriteFile(delegatesFile, []byte(`
runtimeImageCache:
  allowPull: false
  scanOnlyInUse: true
  delegates:
  - id: containerd-primary
    kind: containerd
    endpoint: unix:///host/run/containerd/containerd.sock
    priority: 10
    namespaces:
    - k8s.io
    readonly: true
`), 0o644))

	rootAsset := &inventory.Asset{
		Connections: []*inventory.Config{{
			Type: "k8s",
			Options: map[string]string{
				plugin.OptionStagedDiscovery:    "",
				runtimeCacheOptionNodeName:      "node-a",
				runtimeCacheOptionDelegatesFile: delegatesFile,
				runtimeCacheOptionScannerPods:   "app=mondoo-runtime-cache-scan,scan=runtime-cache,mondoo_cr=mondoo-client",
			},
			Discover: &inventory.Discovery{Targets: []string{DiscoveryRuntimeCache}},
		}},
	}
	conn, err := manifest.NewConnection(0, rootAsset,
		manifest.WithManifestContent([]byte(runtimeCacheCrossNamespacePodsManifest)),
		manifest.WithManifestFile("runtime-cache-cross-namespace-pods.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Resources:      &syncx.Map[plugin.Resource]{},
		Connection:     conn,
		CreateResource: CreateResource,
	}
	inv, err := Discover(runtime, mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 1)

	asset := inv.Spec.Assets[0]
	assert.Equal(t, "registry.example.com/team/app:1.0@aaaaaaaaaaaa", asset.Name)
	assert.Equal(t, "node-a", asset.Labels["mondoo.com/runtime-cache-owner-node"])
	assert.Equal(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", asset.Labels["mondoo.com/runtime-image-digest"])
	assert.Equal(t, "containerd://container-a,containerd://container-c", asset.Annotations["mondoo.com/runtime-cache-containers"])
	assert.Equal(t, "prod,stage", asset.Annotations["mondoo.com/runtime-cache-namespaces"])
	assert.Equal(t, "node-a", asset.Annotations["mondoo.com/runtime-cache-nodes"])
	require.Len(t, asset.Connections, 1)
	assert.Equal(t, runtimeImageConnectionType, asset.Connections[0].Type)
}

func TestDiscoverLegacyRuntimeCacheImagesAreClusterScoped(t *testing.T) {
	delegatesFile := filepath.Join(t.TempDir(), "delegates.yml")
	require.NoError(t, os.WriteFile(delegatesFile, []byte(`
runtimeImageCache:
  allowPull: false
  scanOnlyInUse: true
  delegates:
  - id: containerd-primary
    kind: containerd
    endpoint: unix:///host/run/containerd/containerd.sock
    priority: 10
    namespaces:
    - k8s.io
    readonly: true
`), 0o644))

	rootAsset := &inventory.Asset{
		Connections: []*inventory.Config{{
			Type: "k8s",
			Options: map[string]string{
				runtimeCacheOptionNodeName:      "node-a",
				runtimeCacheOptionDelegatesFile: delegatesFile,
				runtimeCacheOptionScannerPods:   "app=mondoo-runtime-cache-scan,scan=runtime-cache,mondoo_cr=mondoo-client",
			},
			Discover: &inventory.Discovery{Targets: []string{DiscoveryRuntimeCache}},
		}},
	}
	conn, err := manifest.NewConnection(0, rootAsset,
		manifest.WithManifestContent([]byte(runtimeCacheCrossNamespacePodsManifest)),
		manifest.WithManifestFile("runtime-cache-cross-namespace-pods.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Resources:      &syncx.Map[plugin.Resource]{},
		Connection:     conn,
		CreateResource: CreateResource,
	}
	inv, err := Discover(runtime, mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 1)

	asset := inv.Spec.Assets[0]
	assert.Equal(t, "registry.example.com/team/app:1.0@aaaaaaaaaaaa", asset.Name)
	assert.Equal(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", asset.Labels["mondoo.com/runtime-image-digest"])
	assert.Equal(t, "containerd://container-a,containerd://container-c", asset.Annotations["mondoo.com/runtime-cache-containers"])
	assert.Equal(t, "prod,stage", asset.Annotations["mondoo.com/runtime-cache-namespaces"])
	assert.Equal(t, "node-a", asset.Annotations["mondoo.com/runtime-cache-nodes"])
	require.Len(t, asset.Connections, 1)
	assert.Equal(t, runtimeImageConnectionType, asset.Connections[0].Type)
}

const runtimeCachePodsManifest = `
apiVersion: v1
kind: Pod
metadata:
  name: app-a
  namespace: prod
  uid: "11111111-1111-1111-1111-111111111111"
spec:
  nodeName: node-a
  containers:
  - name: app
    image: registry.example.com/team/app:1.0
status:
  phase: Running
  containerStatuses:
  - name: app
    image: registry.example.com/team/app:1.0
    imageID: docker-pullable://registry.example.com/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    containerID: containerd://container-a
---
apiVersion: v1
kind: Pod
metadata:
  name: app-b
  namespace: prod
  uid: app-b-uid
spec:
  nodeName: node-b
  containers:
  - name: app
    image: registry.example.com/team/app:latest
status:
  phase: Running
  containerStatuses:
  - name: app
    image: registry.example.com/team/app:latest
    imageID: docker-pullable://registry.example.com/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    containerID: containerd://container-b
---
apiVersion: v1
kind: Pod
metadata:
  name: scanner-a
  namespace: mondoo-operator
  uid: scanner-a-uid
  labels:
    app: mondoo-runtime-cache-scan
    scan: runtime-cache
    mondoo_cr: mondoo-client
spec:
  nodeName: node-a
  containers:
  - name: scanner
    image: cnspec:test
status:
  phase: Running
  conditions:
  - type: Ready
    status: "True"
---
apiVersion: v1
kind: Pod
metadata:
  name: scanner-b
  namespace: mondoo-operator
  uid: scanner-b-uid
  labels:
    app: mondoo-runtime-cache-scan
    scan: runtime-cache
    mondoo_cr: mondoo-client
spec:
  nodeName: node-b
  containers:
  - name: scanner
    image: cnspec:test
status:
  phase: Running
  conditions:
  - type: Ready
    status: "True"
`

const runtimeCacheNodeImageManifest = `
apiVersion: v1
kind: Node
metadata:
  name: node-a
status:
  nodeInfo:
    containerRuntimeVersion: containerd://1.7.20
  images:
  - names:
    - registry.example.com/team/app:1.2.3
    - registry.example.com/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    sizeBytes: 123456
---
apiVersion: v1
kind: Pod
metadata:
  name: app-a
  namespace: prod
  uid: app-a-uid
spec:
  nodeName: node-a
  containers:
  - name: app
    image: registry.example.com/team/app:1.2.3
status:
  phase: Running
  containerStatuses:
  - name: app
    image: registry.example.com/team/app:1.2.3
    imageID: docker-pullable://registry.example.com/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    containerID: containerd://container-a
`

const runtimeCacheCrossNamespacePodsManifest = `
apiVersion: v1
kind: Pod
metadata:
  name: app-a
  namespace: prod
  uid: app-a-uid
spec:
  nodeName: node-a
  containers:
  - name: app
    image: registry.example.com/team/app:1.0
status:
  phase: Running
  containerStatuses:
  - name: app
    image: registry.example.com/team/app:1.0
    imageID: docker-pullable://registry.example.com/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    containerID: containerd://container-a
---
apiVersion: v1
kind: Pod
metadata:
  name: app-c
  namespace: stage
  uid: app-c-uid
spec:
  nodeName: node-a
  containers:
  - name: app
    image: registry.example.com/team/app:latest
status:
  phase: Running
  containerStatuses:
  - name: app
    image: registry.example.com/team/app:latest
    imageID: docker-pullable://registry.example.com/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    containerID: containerd://container-c
---
apiVersion: v1
kind: Pod
metadata:
  name: scanner-a
  namespace: mondoo-operator
  uid: scanner-a-uid
  labels:
    app: mondoo-runtime-cache-scan
    scan: runtime-cache
    mondoo_cr: mondoo-client
spec:
  nodeName: node-a
  containers:
  - name: scanner
    image: cnspec:test
status:
  phase: Running
  conditions:
  - type: Ready
    status: "True"
`
