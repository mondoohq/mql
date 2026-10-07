// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKubeletServingCertPath(t *testing.T) {
	// configured (K3s, RKE2, NixOS, Canonical Kubernetes)
	assert.Equal(t, "/var/lib/rancher/k3s/agent/serving-kubelet.crt",
		kubeletServingCertPath("/var/lib/rancher/k3s/agent/serving-kubelet.crt", false, ""))
	// none configured: the self-signed certificate the kubelet generates
	// (kubeadm on Flatcar, minikube)
	assert.Equal(t, "/var/lib/kubelet/pki/kubelet.crt", kubeletServingCertPath("", false, ""))
	// MicroK8s sets --cert-dir
	assert.Equal(t, "/var/snap/microk8s/9072/certs/kubelet.crt", kubeletServingCertPath("", false, "/var/snap/microk8s/9072/certs"))
	// serverTLSBootstrap: the certificate the API server issued (k0s)
	assert.Equal(t, "/var/lib/k0s/kubelet/pki/kubelet-server-current.pem",
		kubeletServingCertPath("", true, "/var/lib/k0s/kubelet/pki"))
}

func TestStaticPodManifestPaths(t *testing.T) {
	// find output on a kubeadm control plane node, unordered
	out := "/etc/kubernetes/manifests/kube-scheduler.yaml\n/etc/kubernetes/manifests/etcd.yaml\n" +
		"/etc/kubernetes/manifests/kube-apiserver.yaml\n/etc/kubernetes/manifests/kube-controller-manager.yaml\n"
	assert.Equal(t, []string{
		"/etc/kubernetes/manifests/etcd.yaml",
		"/etc/kubernetes/manifests/kube-apiserver.yaml",
		"/etc/kubernetes/manifests/kube-controller-manager.yaml",
		"/etc/kubernetes/manifests/kube-scheduler.yaml",
	}, staticPodManifestPaths(out))
	assert.Empty(t, staticPodManifestPaths(""))
	assert.Empty(t, staticPodManifestPaths("find: '/etc/kubernetes/manifests': No such file or directory\n"))
}

func TestKubeletList(t *testing.T) {
	// as K3s sets it in its drop-in
	assert.Equal(t, []any{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"},
		kubeletList([]any{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"}))
	assert.Equal(t, []any{}, kubeletList(nil))
}

func TestKubeletFeatureGates(t *testing.T) {
	// a config file holds booleans, --feature-gates strings
	assert.Equal(t, map[string]any{"KubeletCrashLoopBackOffMax": true, "UserNamespacesSupport": false},
		kubeletFeatureGates(map[string]any{"KubeletCrashLoopBackOffMax": true, "UserNamespacesSupport": "false"}))
	assert.Equal(t, map[string]any{}, kubeletFeatureGates(nil))
}
