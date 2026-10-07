// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readCrioFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "crio", name))
	require.NoError(t, err)
	return string(b)
}

func TestParseCrioVersion(t *testing.T) {
	// /var/run/crio/version on CRI-O 1.37.2 (kubeadm node) and 1.35.7 (minikube)
	assert.Equal(t, "1.37.2", parseCrioVersion("\"1.37.2+585389f80055ab1a22b82802b6f9a2fb9487d9dd\""))
	assert.Equal(t, "1.35.7", parseCrioVersion("\"1.35.7+e79a9cbff48f30781b8c54cdbc589a372a113896\"\n"))
	assert.Equal(t, "", parseCrioVersion(""))
}

func TestCrioVersionFilePaths(t *testing.T) {
	// the default, and its /run form
	assert.Equal(t, []string{"/var/run/crio/version", "/run/crio/version"}, crioVersionFilePaths(""))
	assert.Equal(t, []string{"/var/run/crio/version", "/run/crio/version"}, crioVersionFilePaths("/var/run/crio/version"))
	assert.Equal(t, []string{"/opt/crio/version"}, crioVersionFilePaths("/opt/crio/version"))
}

// The effective configuration the running CRI-O reports over its socket
// (GET /config), captured on a kubeadm node with CRI-O 1.37.2.
func TestParseCrioConfigEffective(t *testing.T) {
	cfg, err := parseCrioConfig(readCrioFixture(t, "kubeadm/config.toml"))
	require.NoError(t, err)

	assert.Equal(t, "crun", crioConfigValue(cfg, "runtime", "default_runtime"))
	assert.Equal(t, "", crioConfigValue(cfg, "runtime", "seccomp_profile"))
	assert.Equal(t, "crio-default", crioConfigValue(cfg, "runtime", "apparmor_profile"))
	assert.Equal(t, false, crioConfigValue(cfg, "runtime", "selinux"))
	assert.Equal(t, false, crioConfigValue(cfg, "runtime", "read_only"))
	assert.Equal(t, []any{"CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "SETGID", "SETUID", "SETPCAP", "NET_BIND_SERVICE", "KILL"},
		crioList(crioConfigValue(cfg, "runtime", "default_capabilities")))
	assert.Equal(t, []any{"/dev/fuse", "/dev/net/tun"}, crioList(crioConfigValue(cfg, "runtime", "allowed_devices")))

	crio := cfg["crio"].(map[string]any)
	assert.Equal(t, "/var/lib/containers/storage", crio["root"])
	assert.Equal(t, "overlay", crio["storage_driver"])
}

// Without a running CRI-O the drop-ins are merged: minikube's 02-crio.conf
// and 10-crio.conf set different keys of the same [crio.runtime] table.
func TestMergeCrioConfig(t *testing.T) {
	merged := map[string]any{}
	for _, name := range []string{"minikube/02-crio.conf", "minikube/10-crio.conf"} {
		cfg, err := parseCrioConfig(readCrioFixture(t, name))
		require.NoError(t, err)
		mergeCrioConfig(merged, cfg)
	}
	// from 02-crio.conf
	assert.Equal(t, []any{"net.ipv4.ip_unprivileged_port_start=0"}, crioList(crioConfigValue(merged, "runtime", "default_sysctls")))
	assert.Equal(t, "systemd", crioConfigValue(merged, "runtime", "cgroup_manager"))
	assert.Equal(t, "registry.k8s.io/pause:3.10.2", crioConfigValue(merged, "image", "pause_image"))
	// from 10-crio.conf, in the same table
	assert.Equal(t, "crun", crioConfigValue(merged, "runtime", "default_runtime"))
	assert.Equal(t, "/etc/crio/policy.json", crioConfigValue(merged, "image", "signature_policy"))

	// a later drop-in replaces a key an earlier one set
	later := map[string]any{"crio": map[string]any{"runtime": map[string]any{"default_runtime": "runc"}}}
	mergeCrioConfig(merged, later)
	assert.Equal(t, "runc", crioConfigValue(merged, "runtime", "default_runtime"))
	assert.Equal(t, "systemd", crioConfigValue(merged, "runtime", "cgroup_manager"), "the rest of the table stays")
}

func TestCrioDropInFiles(t *testing.T) {
	assert.Equal(t, []string{"02-crio.conf", "10-crio.conf"}, crioDropInFiles([]string{"10-crio.conf", ".swp", "02-crio.conf", ""}))
}

// containers/storage's container list on the kubeadm node: five pod
// sandboxes and the five containers they hold.
func TestParseCrioStorageContainers(t *testing.T) {
	containers, err := parseCrioStorageContainers(readCrioFixture(t, "kubeadm/volatile-containers.json"))
	require.NoError(t, err)
	require.Len(t, containers, 5, "the pod sandboxes are left out")

	byName := map[string]crioContainer{}
	for _, c := range containers {
		byName[c.Name] = c
	}
	assert.ElementsMatch(t, []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd", "kube-proxy"},
		[]string{containers[0].Name, containers[1].Name, containers[2].Name, containers[3].Name, containers[4].Name})

	proxy := byName["kube-proxy"]
	assert.Equal(t, "f152ede83035f01992ea87ef4e60d980f033f34489afb47bc58435c64977c348", proxy.ID)
	assert.Equal(t, "kube-proxy-v4kdb", proxy.PodName)
	assert.Equal(t, "kube-system", proxy.PodNamespace)
	assert.Equal(t, "4fd48ba53f1e63f3e17bbc7aa04a0434ab9fa4326696fffc17e89762a380baf7", proxy.SandboxID)
	assert.True(t, proxy.Privileged, "kube-proxy runs privileged")
	assert.False(t, proxy.Created.IsZero())

	assert.False(t, byName["etcd"].Privileged)

	none, err := parseCrioStorageContainers("")
	require.NoError(t, err)
	assert.Empty(t, none)
	_, err = parseCrioStorageContainers("{not json")
	assert.Error(t, err)
}

func TestCrioPodFromSandboxName(t *testing.T) {
	pod, ns := crioPodFromSandboxName("k8s_kube-proxy-v4kdb_kube-system_b6d0cfc3-726e-4582-877c-f49759005805_0")
	assert.Equal(t, "kube-proxy-v4kdb", pod)
	assert.Equal(t, "kube-system", ns)
	pod, ns = crioPodFromSandboxName("not-a-sandbox")
	assert.Equal(t, "", pod)
	assert.Equal(t, "", ns)
}

// GET /containers/<id> for kube-proxy on the kubeadm node
func TestParseCrioInspect(t *testing.T) {
	inspect, err := parseCrioInspect(readCrioFixture(t, "kubeadm/inspect-kube-proxy.json"))
	require.NoError(t, err)
	assert.Equal(t, int64(2370), inspect.Pid)
	assert.Equal(t, "registry.k8s.io/kube-proxy:v1.37.1", inspect.Image)
	assert.Equal(t, "registry.k8s.io/kube-proxy@sha256:abbadc84931b520750bcda3350819f6a828ee44a4a0cab548a26016aa7e2a3b7", inspect.ImageRef)
	assert.True(t, inspect.HostNetwork)
	assert.Equal(t, "Unconfined", inspect.Annotations[crioSeccompAnnotation])
	assert.Equal(t, "kube-system", inspect.Labels["io.kubernetes.pod.namespace"])
}

func TestCrioEndpoint(t *testing.T) {
	assert.True(t, crioEndpoint.MatchString("/config"))
	assert.True(t, crioEndpoint.MatchString("/containers/f152ede83035f01992ea87ef4e60d980f033f34489afb47bc58435c64977c348"))
	assert.False(t, crioEndpoint.MatchString("/config; id"))
	assert.False(t, crioEndpoint.MatchString("/config$(id)"))
	assert.False(t, crioEndpoint.MatchString("/../config"))
	assert.False(t, crioEndpoint.MatchString("config"))
	assert.False(t, crioEndpoint.MatchString(""))
}

// One entry with unreadable metadata is skipped, not the whole list.
func TestParseCrioStorageContainersSkipsBadMetadata(t *testing.T) {
	content := `[{"id":"a","names":["k8s_POD_x"],"metadata":"{not json"},` +
		`{"id":"b","names":["k8s_c"],"metadata":"{\"pod-id\":\"p\",\"metadata-name\":\"c\",\"pod-name\":\"k8s_web_default_uid_0\"}"}]`
	containers, err := parseCrioStorageContainers(content)
	require.NoError(t, err)
	require.Len(t, containers, 1)
	assert.Equal(t, "c", containers[0].Name)
	assert.Equal(t, "web", containers[0].PodName)
}

func TestCrioContainerID(t *testing.T) {
	assert.True(t, crioContainerID.MatchString("f152ede83035f01992ea87ef4e60d980f033f34489afb47bc58435c64977c348"))
	assert.False(t, crioContainerID.MatchString("f152ede83035; rm -rf /"))
	assert.False(t, crioContainerID.MatchString("../config"))
}

// The policy the packages from the CRI-O project install: every image
// accepted without any signature check.
func TestParseCrioPolicyStock(t *testing.T) {
	p, err := parseCrioPolicy(readCrioFixture(t, "kubeadm/policy.json"))
	require.NoError(t, err)
	require.Len(t, p.Default, 1)
	assert.Equal(t, "insecureAcceptAnything", p.Default[0].Type)
	assert.Empty(t, p.scopes())
}

func TestParseCrioPolicySigned(t *testing.T) {
	p, err := parseCrioPolicy(readCrioFixture(t, "policy-signed.json"))
	require.NoError(t, err)
	assert.Equal(t, "reject", p.Default[0].Type)

	scopes := p.scopes()
	require.Len(t, scopes, 5)
	got := []string{}
	for _, s := range scopes {
		got = append(got, s.Transport+" "+s.Scope)
	}
	assert.Equal(t, []string{
		"docker ghcr.io/example", "docker quay.io/legacy", "docker registry.example.com/platform",
		"docker registry.k8s.io", "docker-daemon ",
	}, got, "by transport, then scope")

	byScope := map[string]crioPolicyRequirement{}
	for _, s := range scopes {
		byScope[s.Scope] = s.Requirements[0]
	}
	gpg := byScope["registry.example.com/platform"]
	assert.Equal(t, "signedBy", gpg.Type)
	assert.Equal(t, "GPGKeys", gpg.KeyType)
	assert.Equal(t, []string{"/etc/pki/containers/platform.gpg"}, gpg.keyPaths())
	assert.Equal(t, "matchRepoDigestOrExact", gpg.SignedIdentity["type"])

	keyless := byScope["ghcr.io/example"]
	assert.Equal(t, "sigstoreSigned", keyless.Type)
	require.NotNil(t, keyless.Fulcio)
	assert.Equal(t, "https://token.actions.githubusercontent.com", keyless.Fulcio.OIDCIssuer)
	assert.Equal(t, "release@example.com", keyless.Fulcio.SubjectEmail)
	assert.Equal(t, []string{"/etc/pki/containers/rekor.pub"}, keyless.rekorKeyPaths())
	assert.Empty(t, keyless.keyPaths())

	inline := byScope["registry.k8s.io"]
	assert.NotEmpty(t, inline.KeyData, "an inline key is reported as present, not by content")
	assert.Empty(t, inline.keyPaths())

	assert.Equal(t, "insecureAcceptAnything", byScope["quay.io/legacy"].Type)
}

func TestParseCrioPolicyMalformed(t *testing.T) {
	_, err := parseCrioPolicy(`{ "default": [ { "type": "reject" } `)
	assert.Error(t, err, "a broken policy must not read as one without requirements")
}

func TestCrioNamespacePolicyFiles(t *testing.T) {
	assert.Equal(t, []string{"kube-system.json", "payments.json"},
		crioNamespacePolicyFiles([]string{"payments.json", "README", ".hidden.json", "kube-system.json", ".json", ""}))
}

// [crio.runtime.runtimes] of the effective configuration on the kubeadm node
func TestCrioRuntimeHandlers(t *testing.T) {
	cfg, err := parseCrioConfig(readCrioFixture(t, "kubeadm/config.toml"))
	require.NoError(t, err)
	handlers := crioRuntimeHandlers(cfg)
	require.Len(t, handlers, 2)

	crun, runc := handlers[0], handlers[1]
	assert.Equal(t, "crun", crun.Name)
	assert.Equal(t, "/usr/libexec/crio/crun", crun.Path)
	assert.Equal(t, "oci", crun.Type, "an empty runtime_type is oci")
	assert.Equal(t, "/run/crun", crun.Root)
	assert.Equal(t, "/usr/libexec/crio/conmon", crun.MonitorPath)
	assert.Equal(t, []any{"io.containers.trace-syscall"}, crun.AllowedAnnotations)
	assert.False(t, crun.PrivilegedWithoutHostDevices)

	assert.Equal(t, "runc", runc.Name)
	assert.Equal(t, "/usr/libexec/crio/runc", runc.Path)
	assert.Empty(t, runc.AllowedAnnotations)

	assert.Empty(t, crioRuntimeHandlers(map[string]any{}))

	notTable := map[string]any{"crio": map[string]any{"runtime": map[string]any{"runtimes": map[string]any{
		"crun":   map[string]any{"runtime_path": "/usr/bin/crun"},
		"broken": "not a table",
	}}}}
	handlers = crioRuntimeHandlers(notTable)
	require.Len(t, handlers, 1)
	assert.Equal(t, "crun", handlers[0].Name)
}
