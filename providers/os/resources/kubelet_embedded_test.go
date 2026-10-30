// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKubeletHostOf(t *testing.T) {
	// /proc/<pid>/status names
	assert.Equal(t, kubeletInK3s, kubeletHostOf("k3s-server", "/usr/local/bin/k3s server"))
	assert.Equal(t, kubeletInK3s, kubeletHostOf("k3s-agent", "/usr/local/bin/k3s agent"))
	// a process list from ps over SSH names the binary (seen on a K3s node)
	assert.Equal(t, kubeletInK3s, kubeletHostOf("k3s", "/usr/local/bin/k3s server"))
	assert.Equal(t, kubeletInK3s, kubeletHostOf("k3s", "/usr/local/bin/k3s agent --server https://10.0.0.1:6443"))
	assert.Equal(t, kubeletStandalone, kubeletHostOf("k3s", "/usr/local/bin/k3s kubectl get nodes"), "a one-off command is not a node")
	assert.Equal(t, kubeletInKubelite, kubeletHostOf("kubelite", "/snap/microk8s/9072/kubelite --kubelet-args-file=/var/snap/microk8s/9072/args/kubelet"))
	assert.Equal(t, kubeletStandalone, kubeletHostOf("kubelet", "/usr/bin/kubelet --config=/var/lib/kubelet/config.yaml"))
}

func TestK3sKubeletFlags(t *testing.T) {
	// a default "k3s server": only K3s's own settings
	flags := k3sKubeletFlags("/usr/local/bin/k3s server", "")
	assert.Equal(t, map[string]any{
		"read-only-port": "0",
		"config-dir":     "/var/lib/rancher/k3s/agent/etc/kubelet.conf.d",
		"kubeconfig":     "/var/lib/rancher/k3s/agent/kubelet.kubeconfig",
	}, flags)

	// --kubelet-arg in both forms, and a data dir that moves the drop-ins
	flags = k3sKubeletFlags("/usr/local/bin/k3s server --kubelet-arg=max-pods=250 --kubelet-arg --read-only-port=10255 --data-dir /opt/k3s", "")
	assert.Equal(t, "250", flags["max-pods"])
	assert.Equal(t, "10255", flags["read-only-port"], "a --kubelet-arg overrides K3s's own")
	assert.Equal(t, "/opt/k3s/agent/etc/kubelet.conf.d", flags["config-dir"])
	assert.Equal(t, "/opt/k3s/agent/kubelet.kubeconfig", flags["kubeconfig"])

	// the config file holds the same options; the command line wins
	configYAML := "data-dir: /srv/k3s\nkubelet-arg:\n  - \"anonymous-auth=false\"\n  - \"max-pods=110\"\n"
	flags = k3sKubeletFlags("/usr/local/bin/k3s agent --kubelet-arg=max-pods=200", configYAML)
	assert.Equal(t, "false", flags["anonymous-auth"])
	assert.Equal(t, "200", flags["max-pods"])
	assert.Equal(t, "/srv/k3s/agent/etc/kubelet.conf.d", flags["config-dir"])
	// a single kubelet-arg may be a string
	flags = k3sKubeletFlags("/usr/local/bin/k3s server", "kubelet-arg: \"event-qps=10\"\n")
	assert.Equal(t, "10", flags["event-qps"])
}

func TestMicroK8sKubeletFlags(t *testing.T) {
	// lines from /var/snap/microk8s/9072/args/kubelet on a MicroK8s 1.35.6 node
	content := `--resolv-conf=/run/systemd/resolve/resolv.conf
--kubeconfig=${SNAP_DATA}/credentials/kubelet.config
--root-dir=${SNAP_COMMON}/var/lib/kubelet
--eviction-hard="memory.available<100Mi,nodefs.available<1Gi,imagefs.available<1Gi"
--container-runtime-endpoint=${SNAP_COMMON}/run/containerd.sock
--read-only-port=0
`
	flags := microk8sKubeletFlags(content, "/var/snap/microk8s/9072/args/kubelet")
	assert.Equal(t, "/run/systemd/resolve/resolv.conf", flags["resolv-conf"])
	assert.Equal(t, "/var/snap/microk8s/9072/credentials/kubelet.config", flags["kubeconfig"])
	assert.Equal(t, "/var/snap/microk8s/common/var/lib/kubelet", flags["root-dir"])
	assert.Equal(t, "memory.available<100Mi,nodefs.available<1Gi,imagefs.available<1Gi", flags["eviction-hard"], "quotes removed")
	assert.Equal(t, "/var/snap/microk8s/common/run/containerd.sock", flags["container-runtime-endpoint"])
	assert.Equal(t, "0", flags["read-only-port"])
	assert.Len(t, flags, 6)
}

func TestMicroK8sSnapVersion(t *testing.T) {
	assert.Equal(t, "v1.35.6", microk8sSnapVersion("name: microk8s\nversion: v1.35.6\nsummary: Kubernetes for workstations\n"))
	assert.Equal(t, "v1.35.6", microk8sSnapVersion("version: 'v1.35.6'\n"))
	assert.Equal(t, "", microk8sSnapVersion("name: microk8s\n"))
}

func TestKubeletDropInFiles(t *testing.T) {
	assert.Equal(t, []string{"00-k3s-defaults.conf", "10-site.conf", "99-override.conf"},
		kubeletDropInFiles([]string{"99-override.conf", "README", "00-k3s-defaults.conf", "10-site.conf", "old.conf.bak"}))
	assert.Empty(t, kubeletDropInFiles([]string{""}))
}

func TestParseKubeletVersionK3s(t *testing.T) {
	assert.Equal(t, "v1.36.5+k3s1", parseKubeletVersion("k3s version v1.36.5+k3s1 (3dd98cc5)\ngo version go1.26.8\n"))
	assert.Equal(t, "v1.34.0", parseKubeletVersion("Kubernetes v1.34.0\n"))
}
