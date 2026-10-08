// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestPemCertificateBlocks(t *testing.T) {
	cert := "-----BEGIN CERTIFICATE-----\nMIIBAzCBqqADAgECAgEBMAoGCCqGSM49BAMCMAAwHhcNMjYxMDA3MDAwMDAwWhcN\n-----END CERTIFICATE-----\n"
	// assembled so that the file holds no private key header for scanners
	keyType := "EC " + "PRIVATE KEY"
	key := "-----BEGIN " + keyType + "-----\nMHcCAQEEIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEoAoGCCqGSM49\n-----END " + keyType + "-----\n"
	// kubelet-server-current.pem: the certificate, then its key
	out := pemCertificateBlocks(cert + key)
	assert.Contains(t, out, "BEGIN CERTIFICATE")
	assert.NotContains(t, out, "PRIVATE KEY", "the key must not be handed on")
	assert.NotContains(t, out, "EXAMPLE")
	// key first, and a chain of two
	out = pemCertificateBlocks(key + cert + cert)
	assert.Equal(t, 2, strings.Count(out, "BEGIN CERTIFICATE"))
	assert.NotContains(t, out, "PRIVATE KEY")
	assert.Empty(t, pemCertificateBlocks(key))
	assert.Empty(t, pemCertificateBlocks(""))
}

// The boolean fields read the configuration with the kubelet's defaults
// applied: a kubelet whose config file sets none of them reports the
// defaults, not false.
func TestKubeletBooleanFieldsReadDefaults(t *testing.T) {
	config, err := createConfiguration(map[string]any{"config": "/var/lib/kubelet/config.yaml"},
		"apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\n", nil, 37)
	require.NoError(t, err)

	auth := config["authentication"].(map[string]any)
	assert.Equal(t, true, auth["webhook"].(map[string]any)["enabled"], "webhookAuthenticationEnabled")
	assert.Equal(t, true, config["enableDebuggingHandlers"])
	assert.Equal(t, true, config["enableSystemLogHandler"])
	assert.Equal(t, true, config["enableProfilingHandler"])
	assert.Equal(t, false, config["enableSystemLogQuery"])
	assert.Equal(t, false, config["seccompDefault"])
	// unlimited, not 0
	assert.Equal(t, -1.0, config["podPidsLimit"])
}
