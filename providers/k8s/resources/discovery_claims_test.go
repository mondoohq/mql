// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const claimTestDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// claimTestPod builds a pod scheduled on nodeName whose single container
// reports imageID in its status.
func claimTestPod(name, nodeName, image, imageID string) *mqlK8sPod {
	obj := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: corev1.PodSpec{
			NodeName:   nodeName,
			Containers: []corev1.Container{{Name: "c", Image: image}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{Name: "c", Image: image, ImageID: imageID}},
		},
	}
	p := &mqlK8sPod{}
	p.obj = obj
	p.Namespace = plugin.TValue[string]{Data: "default", State: plugin.StateIsSet}
	return p
}

func claimTestNode(name, arch string) *mqlK8sNode {
	n := &mqlK8sNode{}
	n.obj = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{Architecture: arch}},
	}
	return n
}

// discoverClaimTestImages runs discoverContainerImages against a k8s resource
// whose pods and nodes are pre-populated, so no cluster access is involved.
func discoverClaimTestImages(t *testing.T, pods []*mqlK8sPod, nodes []*mqlK8sNode) []*inventory.Asset {
	t.Helper()
	k8s := &mqlK8s{}
	podData := make([]any, 0, len(pods))
	for _, p := range pods {
		podData = append(podData, p)
	}
	nodeData := make([]any, 0, len(nodes))
	for _, n := range nodes {
		nodeData = append(nodeData, n)
	}
	k8s.Pods = plugin.TValue[[]any]{Data: podData, State: plugin.StateIsSet}
	k8s.Nodes = plugin.TValue[[]any]{Data: nodeData, State: plugin.StateIsSet}

	asset := &inventory.Asset{Name: "cluster", Connections: []*inventory.Config{{Type: "k8s"}}}
	conn := &namespaceDiscoveryConnection{Connection: plugin.NewConnection(1, asset), asset: asset}

	labelFilters, err := labelSelectorFilters(&inventory.Config{Options: map[string]string{}})
	require.NoError(t, err)

	assets, err := discoverContainerImages(conn, &plugin.Runtime{}, &inventory.Config{Options: map[string]string{}}, k8s, FilterOpts{}, labelFilters, FilterOpts{})
	require.NoError(t, err)
	return assets
}

func TestDiscoverContainerImagesAttachesClaims(t *testing.T) {
	resolved := "docker.io/library/nginx@" + claimTestDigest
	assets := discoverClaimTestImages(t,
		[]*mqlK8sPod{claimTestPod("p1", "node-a", "nginx:1.25", "docker-pullable://"+resolved)},
		[]*mqlK8sNode{claimTestNode("node-a", "amd64")},
	)

	require.Len(t, assets, 1)
	require.Len(t, assets[0].Claims, 1)
	claim := assets[0].Claims[0]
	assert.Equal(t, inventory.AssetClaimKindContainerImage, claim.Kind)
	assert.Equal(t, map[string]string{
		inventory.AssetClaimDigest: claimTestDigest,
		inventory.AssetClaimRef:    resolved,
		inventory.AssetClaimArch:   "amd64",
	}, claim.Claims)
}

func TestDiscoverContainerImagesMultiArch(t *testing.T) {
	resolved := "docker.io/library/nginx@" + claimTestDigest
	imageID := "docker-pullable://" + resolved
	assets := discoverClaimTestImages(t,
		[]*mqlK8sPod{
			claimTestPod("p1", "node-a", "nginx:1.25", imageID),
			claimTestPod("p2", "node-b", "nginx:1.25", imageID),
			// a second pod on an already-seen arch must not add a third claim
			claimTestPod("p3", "node-c", "nginx:1.25", imageID),
		},
		[]*mqlK8sNode{
			claimTestNode("node-a", "amd64"),
			claimTestNode("node-b", "arm64"),
			claimTestNode("node-c", "amd64"),
		},
	)

	require.Len(t, assets, 1, "same resolved image from several pods is one asset")
	archs := []string{}
	for _, c := range assets[0].Claims {
		assert.Equal(t, claimTestDigest, c.Claims[inventory.AssetClaimDigest])
		assert.Equal(t, resolved, c.Claims[inventory.AssetClaimRef])
		archs = append(archs, c.Claims[inventory.AssetClaimArch])
	}
	assert.ElementsMatch(t, []string{"amd64", "arm64"}, archs)
}

func TestDiscoverContainerImagesNoDigestNoClaim(t *testing.T) {
	cases := map[string]string{
		"stopped pod without imageID":                  "",
		"imagePullPolicy Never, bare sha without repo": claimTestDigest,
		"short digest":                  "docker-pullable://nginx@sha256:abc123",
		"uppercase hex":                 "docker-pullable://nginx@sha256:" + strings.ToUpper(claimTestDigest[len("sha256:"):]),
		"unsupported algorithm":         "docker-pullable://nginx@sha512:" + claimTestDigest[len("sha256:"):],
		"trailing garbage after digest": "docker-pullable://nginx@" + claimTestDigest + "x",
	}
	for name, imageID := range cases {
		t.Run(name, func(t *testing.T) {
			assets := discoverClaimTestImages(t,
				[]*mqlK8sPod{claimTestPod("p1", "node-a", "nginx:1.25", imageID)},
				[]*mqlK8sNode{claimTestNode("node-a", "amd64")},
			)
			require.Len(t, assets, 1)
			assert.Empty(t, assets[0].Claims)
		})
	}
}

func TestDiscoverContainerImagesUnknownArch(t *testing.T) {
	resolved := "docker.io/library/nginx@" + claimTestDigest
	imageID := "docker-pullable://" + resolved

	t.Run("node not in the node list", func(t *testing.T) {
		assets := discoverClaimTestImages(t,
			[]*mqlK8sPod{claimTestPod("p1", "ghost-node", "nginx:1.25", imageID)},
			[]*mqlK8sNode{claimTestNode("node-a", "amd64")},
		)
		require.Len(t, assets, 1)
		require.Len(t, assets[0].Claims, 1)
		assert.Equal(t, map[string]string{
			inventory.AssetClaimDigest: claimTestDigest,
			inventory.AssetClaimRef:    resolved,
		}, assets[0].Claims[0].Claims)
	})

	t.Run("unscheduled pod and node without architecture", func(t *testing.T) {
		assets := discoverClaimTestImages(t,
			[]*mqlK8sPod{
				claimTestPod("p1", "", "nginx:1.25", imageID),
				claimTestPod("p2", "node-a", "nginx:1.25", imageID),
			},
			[]*mqlK8sNode{claimTestNode("node-a", "")},
		)
		require.Len(t, assets, 1)
		require.Len(t, assets[0].Claims, 1, "arch-less claims are deduplicated")
		assert.NotContains(t, assets[0].Claims[0].Claims, inventory.AssetClaimArch)
	})
}
