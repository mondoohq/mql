// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	corev1 "k8s.io/api/core/v1"
)

func TestSplitK8sImageNames(t *testing.T) {
	tags, digests := splitK8sImageNames([]string{
		"registry.example.com/team/app:1.2.3",
		"registry.example.com/team/app@sha256:abc123",
		"docker-pullable://registry.example.com/team/sidecar@sha256:def456",
		"",
	})

	assert.Equal(t, []string{"registry.example.com/team/app:1.2.3"}, tags)
	assert.Equal(t, []string{"sha256:abc123", "sha256:def456"}, digests)
}

func TestRuntimeKindFromVersion(t *testing.T) {
	assert.Equal(t, "containerd", runtimeKindFromVersion("containerd://1.7.20"))
	assert.Equal(t, "cri-o", runtimeKindFromVersion("cri-o://1.30.0"))
	assert.Equal(t, "docker", runtimeKindFromVersion("docker"))
	assert.Equal(t, "", runtimeKindFromVersion(""))
}

func TestRuntimeKindFromContainerID(t *testing.T) {
	assert.Equal(t, "containerd", runtimeKindFromContainerID("containerd://abc123"))
	assert.Equal(t, "docker", runtimeKindFromContainerID("docker://abc123"))
	assert.Equal(t, "", runtimeKindFromContainerID("abc123"))
}

func TestRuntimeImageArgsFromK8sNamesDigest(t *testing.T) {
	args := runtimeImageArgsFromK8sNames("node-a", "containerd", []string{
		"registry.example.com/team/app:1.2.3",
		"registry.example.com/team/app@sha256:abc123",
	}, 123456, []string{"containerd://abc123"}, "pending")

	assert.Equal(t, "node-a/sha256:abc123", args["id"].Value)
	assert.Equal(t, "node-a", args["nodeName"].Value)
	assert.Equal(t, "containerd", args["delegateId"].Value)
	assert.Equal(t, "containerd", args["runtimeKind"].Value)
	assert.Equal(t, "sha256:abc123", args["imageId"].Value)
	assert.Equal(t, []any{"registry.example.com/team/app:1.2.3"}, args["repoTags"].Value)
	assert.Equal(t, []any{"sha256:abc123"}, args["repoDigests"].Value)
	assert.Equal(t, int64(123456), args["sizeBytes"].Value)
	assert.Equal(t, true, args["inUse"].Value)
	assert.Equal(t, []any{"containerd://abc123"}, args["containers"].Value)
	assert.Equal(t, "pending", args["scanStatus"].Value)
}

func TestRuntimeImageArgsAreNodeScoped(t *testing.T) {
	nodeA := runtimeImageArgsFromK8sNames("node-a", "containerd", []string{"registry.example.com/team/app@sha256:abc123"}, 123, nil, "pending")
	nodeB := runtimeImageArgsFromK8sNames("node-b", "containerd", []string{"registry.example.com/team/app@sha256:abc123"}, 456, nil, "pending")

	assert.Equal(t, "node-a/sha256:abc123", nodeA["id"].Value)
	assert.Equal(t, "node-b/sha256:abc123", nodeB["id"].Value)
	assert.NotEqual(t, nodeA["id"].Value, nodeB["id"].Value)
}

func TestRuntimeImageMatchKeysNormalizesImageIdsAndReferences(t *testing.T) {
	keys := runtimeImageMatchKeys(
		"registry.example.com/team/app:1.2.3",
		"docker-pullable://registry.example.com/team/app@sha256:abc123",
	)

	assert.Contains(t, keys, "registry.example.com/team/app:1.2.3")
	assert.Contains(t, keys, "docker-pullable://registry.example.com/team/app@sha256:abc123")
	assert.Contains(t, keys, "sha256:abc123")
}

func TestRuntimeImageResourceMatchKeysIncludesRuntimeImageFields(t *testing.T) {
	image := &fakeRuntimeImage{
		id:             "runtime-cache-id",
		imageID:        plugin.TValue[string]{Data: "containerd://sha256:abc123"},
		repoTags:       plugin.TValue[[]any]{Data: []any{"registry.example.com/team/app:1.2.3"}},
		repoDigests:    plugin.TValue[[]any]{Data: []any{"registry.example.com/team/app@sha256:abc123"}},
		resolvedDigest: plugin.TValue[string]{Data: "sha256:abc123"},
		targetDigest:   plugin.TValue[string]{Data: "sha256:abc123"},
	}

	keys := runtimeImageResourceMatchKeys(nil, image)

	assert.Contains(t, keys, "runtime-cache-id")
	assert.Contains(t, keys, "containerd://sha256:abc123")
	assert.Contains(t, keys, "sha256:abc123")
	assert.Contains(t, keys, "registry.example.com/team/app:1.2.3")
	assert.Contains(t, keys, "registry.example.com/team/app@sha256:abc123")
}

func TestRuntimeImageKeysIntersectMatchesDigestAndTag(t *testing.T) {
	byDigest := runtimeImageMatchKeys("", "docker-pullable://registry.example.com/team/app@sha256:abc123")
	byTag := runtimeImageMatchKeys("registry.example.com/team/app:1.2.3", "")
	image := runtimeImageResourceMatchKeys(nil, &fakeRuntimeImage{
		id:             "runtime-cache-id",
		repoTags:       plugin.TValue[[]any]{Data: []any{"registry.example.com/team/app:1.2.3"}},
		resolvedDigest: plugin.TValue[string]{Data: "sha256:abc123"},
	})
	miss := runtimeImageMatchKeys("registry.example.com/team/other:1.2.3", "sha256:def456")

	assert.True(t, runtimeImageKeysIntersect(byDigest, image))
	assert.True(t, runtimeImageKeysIntersect(byTag, image))
	assert.False(t, runtimeImageKeysIntersect(miss, image))
}

func TestRuntimeImageDigestKeysPreventStaleTagMatch(t *testing.T) {
	statusDigest := runtimeImageDigestMatchKeys("docker-pullable://registry.example.com/team/app@sha256:new")
	staleImage := runtimeImageResourceMatchKeys(nil, &fakeRuntimeImage{
		id:             "node-a/sha256:old",
		repoTags:       plugin.TValue[[]any]{Data: []any{"registry.example.com/team/app:1.2.3"}},
		resolvedDigest: plugin.TValue[string]{Data: "sha256:old"},
		targetDigest:   plugin.TValue[string]{Data: "sha256:old"},
	})

	assert.Contains(t, statusDigest, "sha256:new")
	assert.False(t, runtimeImageKeysIntersect(statusDigest, staleImage))
	assert.True(t, runtimeImageKeysIntersect(
		runtimeImageMatchKeys("registry.example.com/team/app:1.2.3", "docker-pullable://registry.example.com/team/app@sha256:new"),
		staleImage,
	), "tag matching alone would be unsafe when an immutable image ID is available")
}

func TestContainerStatusPodUIDSupportsAllStatusKinds(t *testing.T) {
	assert.Equal(t, "pod-uid", containerStatusPodUID("pod-uid-containerstatus-app"))
	assert.Equal(t, "pod-uid", containerStatusPodUID("pod-uid-initcontainerstatus-migrate"))
	assert.Equal(t, "pod-uid", containerStatusPodUID("pod-uid-ephemeralcontainerstatus-debug"))
	assert.Equal(t, "", containerStatusPodUID("pod-uid-sidecarstatus-app"))
	assert.Equal(t, "", containerStatusPodUID("-containerstatus-app"))
}

func TestRuntimeImageClusterLookupIndexesPodsAndNodes(t *testing.T) {
	pods := []any{
		&mqlK8sPod{
			Uid: plugin.TValue[string]{Data: "other-pod"},
			mqlK8sPodInternal: mqlK8sPodInternal{
				obj: &corev1.Pod{Spec: corev1.PodSpec{NodeName: "node-b"}},
			},
		},
		&mqlK8sPod{
			Uid: plugin.TValue[string]{Data: "pod-uid"},
			mqlK8sPodInternal: mqlK8sPodInternal{
				obj: &corev1.Pod{Spec: corev1.PodSpec{NodeName: "node-a"}},
			},
		},
	}
	node := &mqlK8sNode{Name: plugin.TValue[string]{Data: "node-a"}}

	lookup, err := newRuntimeImageClusterLookup(pods, []any{node})

	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "node-a", lookup.podNodeNames["pod-uid"])
	assert.Equal(t, "node-b", lookup.podNodeNames["other-pod"])
	assert.Same(t, node, lookup.nodes["node-a"])
}

func TestRuntimeImageClusterLookupOmitsMissingPod(t *testing.T) {
	lookup, err := newRuntimeImageClusterLookup([]any{
		&mqlK8sPod{
			Uid: plugin.TValue[string]{Data: "other-pod"},
			mqlK8sPodInternal: mqlK8sPodInternal{
				obj: &corev1.Pod{Spec: corev1.PodSpec{NodeName: "node-b"}},
			},
		},
	}, nil)

	if !assert.NoError(t, err) {
		return
	}
	_, found := lookup.podNodeNames["pod-uid"]
	assert.False(t, found)
}

func TestRuntimeDelegateAvailableAllowsUnknownRuntimeWhenAnyDelegateExists(t *testing.T) {
	delegates := []any{&fakeRuntimeDelegate{
		id:       "node-a/containerd",
		kind:     plugin.TValue[string]{Data: "containerd"},
		endpoint: plugin.TValue[string]{Data: "unix:///host/run/containerd/containerd.sock"},
		readonly: plugin.TValue[bool]{Data: true},
		status:   plugin.TValue[string]{Data: "ready"},
	}}

	assert.True(t, runtimeDelegateAvailable(nil, delegates, ""))
	assert.True(t, runtimeDelegateAvailable(nil, delegates, "containerd"))
	assert.False(t, runtimeDelegateAvailable(nil, delegates, "cri-o"))
}

func TestRuntimeDelegateAvailableRequiresConfiguredReadOnlyEndpoint(t *testing.T) {
	synthetic := []any{&fakeRuntimeDelegate{
		id:       "node-a/containerd",
		kind:     plugin.TValue[string]{Data: "containerd"},
		readonly: plugin.TValue[bool]{Data: true},
		status:   plugin.TValue[string]{Data: "ready"},
	}}
	writable := []any{&fakeRuntimeDelegate{
		id:       "node-a/containerd",
		kind:     plugin.TValue[string]{Data: "containerd"},
		endpoint: plugin.TValue[string]{Data: "unix:///host/run/containerd/containerd.sock"},
		readonly: plugin.TValue[bool]{Data: false},
		status:   plugin.TValue[string]{Data: "ready"},
	}}
	pullEnabled := []any{&fakeRuntimeDelegate{
		id:        "node-a/containerd",
		kind:      plugin.TValue[string]{Data: "containerd"},
		endpoint:  plugin.TValue[string]{Data: "unix:///host/run/containerd/containerd.sock"},
		readonly:  plugin.TValue[bool]{Data: true},
		allowPull: plugin.TValue[bool]{Data: true},
		status:    plugin.TValue[string]{Data: "ready"},
	}}
	failed := []any{&fakeRuntimeDelegate{
		id:       "node-a/containerd",
		kind:     plugin.TValue[string]{Data: "containerd"},
		endpoint: plugin.TValue[string]{Data: "unix:///host/run/containerd/containerd.sock"},
		readonly: plugin.TValue[bool]{Data: true},
		status:   plugin.TValue[string]{Data: "failed"},
	}}

	assert.False(t, runtimeDelegateAvailable(nil, synthetic, "containerd"))
	assert.False(t, runtimeDelegateAvailable(nil, writable, "containerd"))
	assert.False(t, runtimeDelegateAvailable(nil, pullEnabled, "containerd"))
	assert.False(t, runtimeDelegateAvailable(nil, failed, "containerd"))
}

func TestRuntimeDelegateArgsFromK8sNode(t *testing.T) {
	args := runtimeDelegateArgsFromK8sNode("node-a", "containerd")

	assert.Equal(t, "node-a/containerd", args["id"].Value)
	assert.Equal(t, "containerd", args["kind"].Value)
	assert.Equal(t, "node-a", args["nodeName"].Value)
	assert.Equal(t, true, args["readonly"].Value)
	assert.Equal(t, false, args["allowPull"].Value)
	assert.Equal(t, "unavailable", args["status"].Value)
	assert.Equal(t, "runtime-cache delegate is not configured", args["statusMessage"].Value)
}

type fakeRuntimeImage struct {
	id             string
	imageID        plugin.TValue[string]
	repoTags       plugin.TValue[[]any]
	repoDigests    plugin.TValue[[]any]
	resolvedDigest plugin.TValue[string]
	targetDigest   plugin.TValue[string]
}

func (f *fakeRuntimeImage) MqlID() string { return f.id }

func (f *fakeRuntimeImage) MqlName() string { return "container.runtimeImage" }

func (f *fakeRuntimeImage) GetImageId() *plugin.TValue[string] { return &f.imageID }

func (f *fakeRuntimeImage) GetRepoTags() *plugin.TValue[[]any] { return &f.repoTags }

func (f *fakeRuntimeImage) GetRepoDigests() *plugin.TValue[[]any] { return &f.repoDigests }

func (f *fakeRuntimeImage) GetResolvedDigest() *plugin.TValue[string] { return &f.resolvedDigest }

func (f *fakeRuntimeImage) GetTargetDigest() *plugin.TValue[string] { return &f.targetDigest }

type fakeRuntimeDelegate struct {
	id        string
	kind      plugin.TValue[string]
	endpoint  plugin.TValue[string]
	readonly  plugin.TValue[bool]
	allowPull plugin.TValue[bool]
	status    plugin.TValue[string]
}

func (f *fakeRuntimeDelegate) MqlID() string { return f.id }

func (f *fakeRuntimeDelegate) MqlName() string { return "container.runtimeDelegate" }

func (f *fakeRuntimeDelegate) GetKind() *plugin.TValue[string] { return &f.kind }

func (f *fakeRuntimeDelegate) GetEndpoint() *plugin.TValue[string] { return &f.endpoint }

func (f *fakeRuntimeDelegate) GetReadonly() *plugin.TValue[bool] { return &f.readonly }

func (f *fakeRuntimeDelegate) GetAllowPull() *plugin.TValue[bool] { return &f.allowPull }

func (f *fakeRuntimeDelegate) GetStatus() *plugin.TValue[string] { return &f.status }
