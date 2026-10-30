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
	corev1 "k8s.io/api/core/v1"
)

func coverageRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{}},
	}, manifest.WithManifestFile("./testdata/network_exposure_coverage.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

func exposureBySourceRef(t *testing.T, k8s *mqlK8s) map[string]*mqlK8sNetworkExposure {
	t.Helper()
	exps := k8s.GetNetworkExposures()
	require.NoError(t, exps.Error)
	out := map[string]*mqlK8sNetworkExposure{}
	for i := range exps.Data {
		e := exps.Data[i].(*mqlK8sNetworkExposure)
		out[e.SourceRef.Data] = e
	}
	return out
}

// TestNetworkExposureCoverage is the completeness guard: every modeled ingress
// vector must produce a network exposure record. If a future change drops a
// vector (or a new exposure-capable field is added without wiring it in), the
// missing sourceRef makes this fail.
func TestNetworkExposureCoverage(t *testing.T) {
	k8sObj, err := NewResource(coverageRuntime(t), "k8s", nil)
	require.NoError(t, err)
	k8s := k8sObj.(*mqlK8s)

	byRef := exposureBySourceRef(t, k8s)

	for _, ref := range []string{
		"Service:prod:lb-svc",       // LoadBalancer
		"Service:prod:np-svc",       // NodePort
		"Service:prod:eip-svc",      // ClusterIP externalIPs
		"Ingress:prod:ing",          // Ingress
		"Gateway:prod:gw",           // Gateway
		"Pod:prod:hostport-pub",     // hostPort
		"Pod:prod:hostnet-pub",      // hostNetwork
		"Pod:prod:hostport-priv",    // hostPort, private node
		"Pod:prod:hostport-unsched", // hostPort, unscheduled
	} {
		assert.Contains(t, byRef, ref, "ingress vector not covered by networkExposures()")
	}

	// An ordinary pod is not an exposure source.
	assert.NotContains(t, byRef, "Pod:prod:normal")
}

func TestHostExposureClassification(t *testing.T) {
	k8sObj, err := NewResource(coverageRuntime(t), "k8s", nil)
	require.NoError(t, err)
	byRef := exposureBySourceRef(t, k8sObj.(*mqlK8s))

	t.Run("hostPort on public node is internet-exposed", func(t *testing.T) {
		e := byRef["Pod:prod:hostport-pub"]
		require.NotNil(t, e)
		assert.Equal(t, "Pod", e.SourceKind.Data)
		assert.True(t, e.InternetExposed.Data)
		assert.Equal(t, "hostPortPublicNode", e.ExposureReason.Data)
		assert.Contains(t, e.Addresses.Data, "8.8.8.8")
		assert.Equal(t, "high", e.Confidence.Data)
	})

	t.Run("hostNetwork on public node exposes container ports", func(t *testing.T) {
		e := byRef["Pod:prod:hostnet-pub"]
		require.NotNil(t, e)
		assert.True(t, e.InternetExposed.Data)
		assert.Equal(t, "hostNetworkPublicNode", e.ExposureReason.Data)
	})

	t.Run("hostPort on private node is not internet-exposed", func(t *testing.T) {
		e := byRef["Pod:prod:hostport-priv"]
		require.NotNil(t, e)
		assert.False(t, e.InternetExposed.Data)
		assert.Equal(t, "hostPortPrivateNode", e.ExposureReason.Data)
		assert.Contains(t, e.Addresses.Data, "10.0.0.6")
	})

	t.Run("unscheduled hostPort pod has unknown node", func(t *testing.T) {
		e := byRef["Pod:prod:hostport-unsched"]
		require.NotNil(t, e)
		assert.False(t, e.InternetExposed.Data)
		assert.Equal(t, "hostPortNodeUnknown", e.ExposureReason.Data)
		assert.Equal(t, "medium", e.Confidence.Data)
		// An unknown node must not be misreported as internalOnly.
		assert.Equal(t, []any{"unknown"}, e.NetworkClassifications.Data)
	})
}

func TestHostExposureRoundTrip(t *testing.T) {
	k8sObj, err := NewResource(coverageRuntime(t), "k8s", nil)
	require.NoError(t, err)
	k8s := k8sObj.(*mqlK8s)
	byRef := exposureBySourceRef(t, k8s)

	// networkExposure.pods on a Pod-sourced exposure resolves to the pod itself.
	e := byRef["Pod:prod:hostport-pub"]
	require.NotNil(t, e)
	pods := e.GetPods()
	require.NoError(t, pods.Error)
	assert.Equal(t, []string{"hostport-pub"}, mqlResourceNames(t, pods.Data))

	// pod.exposures reports the host exposure (the inverse direction).
	pod, err := NewResource(k8s.MqlRuntime, "k8s.pod", map[string]*llx.RawData{
		"name":      llx.StringData("hostport-pub"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	podExps := pod.(*mqlK8sPod).GetExposures()
	require.NoError(t, podExps.Error)
	var sawHostExposure bool
	for i := range podExps.Data {
		if podExps.Data[i].(*mqlK8sNetworkExposure).SourceRef.Data == "Pod:prod:hostport-pub" {
			sawHostExposure = true
		}
	}
	assert.True(t, sawHostExposure, "pod.exposures must include the pod's own host exposure")
}

func TestEscapesNetworkPolicy(t *testing.T) {
	runtime := coverageRuntime(t)

	cases := map[string]bool{
		"hostnet-pub":  true,  // host network -> NetworkPolicy does not apply
		"hostport-pub": false, // hostPort alone does not exempt the pod
		"normal":       false,
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			pod, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
				"name":      llx.StringData(name),
				"namespace": llx.StringData("prod"),
			})
			require.NoError(t, err)
			esc := pod.(*mqlK8sPod).GetEscapesNetworkPolicy()
			require.NoError(t, esc.Error)
			assert.Equal(t, want, esc.Data)
		})
	}
}

// --- Unit tests for the host-exposure helpers (no manifest plumbing) ---

func TestHostExposurePorts(t *testing.T) {
	t.Run("only explicit hostPorts when not host-networked", func(t *testing.T) {
		spec := &corev1.PodSpec{
			Containers: []corev1.Container{{
				Ports: []corev1.ContainerPort{
					{ContainerPort: 8080, HostPort: 8080, Protocol: corev1.ProtocolTCP},
					{ContainerPort: 9090}, // no hostPort -> ignored
				},
			}},
			InitContainers: []corev1.Container{{
				Ports: []corev1.ContainerPort{{ContainerPort: 7070, HostPort: 7070}},
			}},
		}
		ports, protocols, hasHostPort := hostExposurePorts(spec)
		assert.True(t, hasHostPort)
		assert.Len(t, ports, 2, "both explicit hostPorts (container + init) are included")
		assert.Equal(t, []string{"TCP"}, protocols, "missing protocol defaults to TCP")
	})

	t.Run("hostNetwork promotes every containerPort", func(t *testing.T) {
		spec := &corev1.PodSpec{
			HostNetwork: true,
			Containers: []corev1.Container{{
				Ports: []corev1.ContainerPort{
					{ContainerPort: 9090, Protocol: corev1.ProtocolUDP},
				},
			}},
		}
		ports, protocols, hasHostPort := hostExposurePorts(spec)
		assert.False(t, hasHostPort, "containerPort promotion is not an explicit hostPort")
		assert.Len(t, ports, 1)
		assert.Equal(t, []string{"UDP"}, protocols)
	})
}

func TestPodHostExposureArgs(t *testing.T) {
	pubNodes := map[string][]string{"pub": {"203.0.113.5"}}

	t.Run("plain pod produces no exposure", func(t *testing.T) {
		pod := &corev1.Pod{Spec: corev1.PodSpec{
			NodeName:   "pub",
			Containers: []corev1.Container{{Ports: []corev1.ContainerPort{{ContainerPort: 80}}}},
		}}
		assert.Nil(t, podHostExposureArgs(pod, pubNodes))
	})

	t.Run("hostNetwork pod with no declared ports is still exposed", func(t *testing.T) {
		pod := &corev1.Pod{Spec: corev1.PodSpec{HostNetwork: true, NodeName: "pub"}}
		args := podHostExposureArgs(pod, pubNodes)
		require.Len(t, args, 1)
		assert.Equal(t, "hostNetworkPublicNode", args[0]["exposureReason"].Value)
		assert.Equal(t, true, args[0]["internetExposed"].Value)
	})
}
