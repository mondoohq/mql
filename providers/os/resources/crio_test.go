// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
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

// crio.conf and the drop-ins are read through the connection's filesystem,
// so a filesystem or image scan finds them, in the order CRI-O applies them.
func TestCrioConfigFilePaths(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	writeMemFSFile(t, mockFS, "/etc/crio/crio.conf", []byte(readCrioFixture(t, "minikube/02-crio.conf")))
	writeMemFSFile(t, mockFS, "/etc/crio/crio.conf.d/10-crio.conf", []byte(readCrioFixture(t, "minikube/10-crio.conf")))
	writeMemFSFile(t, mockFS, "/etc/crio/crio.conf.d/02-crio.conf", []byte(readCrioFixture(t, "minikube/02-crio.conf")))
	require.NoError(t, mockFS.MkdirAll("/etc/crio/crio.conf.d/empty", 0o755))

	c := &mqlCrio{MqlRuntime: memFSRuntime(t, mockFS)}
	paths, err := c.crioConfigFilePaths()
	require.NoError(t, err)
	assert.Equal(t, []string{"/etc/crio/crio.conf", "/etc/crio/crio.conf.d/02-crio.conf", "/etc/crio/crio.conf.d/10-crio.conf"}, paths)

	// neither present
	c = &mqlCrio{MqlRuntime: memFSRuntime(t, afero.NewMemMapFs())}
	paths, err = c.crioConfigFilePaths()
	require.NoError(t, err)
	assert.Empty(t, paths)
}

// CRI-O walks crio.conf.d with filepath.Walk and applies every file it
// finds. Verified with CRI-O 1.37.2 on Ubuntu 24.04: a stream_port set in
// crio.conf.d/sub/50-sub.conf and a default_ulimits set in
// crio.conf.d/.hidden.conf both showed up in `crio status config`, and the
// subdirectory file, walked after 99-sweep.conf, won over its stream_port.
func TestCrioDropInPaths(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	for _, p := range []string{
		"/etc/crio/crio.conf.d/10-crio.conf",
		"/etc/crio/crio.conf.d/98-notes.txt",
		"/etc/crio/crio.conf.d/99-sweep.conf",
		"/etc/crio/crio.conf.d/.hidden.conf",
		"/etc/crio/crio.conf.d/sub/50-sub.conf",
	} {
		writeMemFSFile(t, mockFS, p, []byte("[crio]\n"))
	}
	require.NoError(t, mockFS.MkdirAll("/etc/crio/crio.conf.d/empty", 0o755))

	paths, err := crioDropInPaths(mockFS, "/etc/crio/crio.conf.d")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"/etc/crio/crio.conf.d/.hidden.conf",
		"/etc/crio/crio.conf.d/10-crio.conf",
		"/etc/crio/crio.conf.d/98-notes.txt",
		"/etc/crio/crio.conf.d/99-sweep.conf",
		"/etc/crio/crio.conf.d/sub/50-sub.conf",
	}, paths)

	paths, err = crioDropInPaths(afero.NewMemMapFs(), "/etc/crio/crio.conf.d")
	require.NoError(t, err)
	assert.Empty(t, paths)

	// an entry that cannot be stat'ed, as a dangling link is on a filesystem
	// that cannot lstat, is left out instead of failing the listing
	broken := &statErrorFs{Fs: mockFS, broken: "/etc/crio/crio.conf.d/98-notes.txt"}
	paths, err = crioDropInPaths(broken, "/etc/crio/crio.conf.d")
	require.NoError(t, err)
	assert.NotContains(t, paths, "/etc/crio/crio.conf.d/98-notes.txt")
	assert.Contains(t, paths, "/etc/crio/crio.conf.d/99-sweep.conf")
}

// afero.Walk lstats on a filesystem that can, so links reach the callback as
// links: one to a file is listed, one to a directory and a dangling one are
// not, as CRI-O cannot read them as configuration either.
func TestCrioDropInPathsSymlinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "crio.conf.d")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "elsewhere"), 0o755))
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "real.conf"), []byte("[crio]\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "10-crio.conf"), []byte("[crio]\n"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(root, "real.conf"), filepath.Join(dir, "20-link.conf")))
	require.NoError(t, os.Symlink(filepath.Join(root, "elsewhere"), filepath.Join(dir, "30-dirlink")))
	require.NoError(t, os.Symlink(filepath.Join(root, "missing.conf"), filepath.Join(dir, "40-dangling.conf")))

	paths, err := crioDropInPaths(afero.NewOsFs(), dir)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(dir, "10-crio.conf"), filepath.Join(dir, "20-link.conf")}, paths)
}

// statErrorFs fails to stat one path, like a dangling symbolic link on a
// filesystem that follows links when it stats.
type statErrorFs struct {
	afero.Fs
	broken string
}

func (f *statErrorFs) Stat(name string) (os.FileInfo, error) {
	if name == f.broken {
		return nil, os.ErrNotExist
	}
	return f.Fs.Stat(name)
}

// containers/storage on a Debian 12 host running CRI-O and Podman side by
// side: Podman's containers are in containers.json, CRI-O's pods and
// containers in volatile-containers.json.
func TestParseCrioStorageContainersSharedWithPodman(t *testing.T) {
	podman, err := parseCrioStorageContainers(readCrioFixture(t, "debian12/containers.json"))
	require.NoError(t, err)
	assert.Empty(t, podman, "Podman's 15 containers are not CRI-O's")

	crio, err := parseCrioStorageContainers(readCrioFixture(t, "debian12/volatile-containers.json"))
	require.NoError(t, err)
	names := []string{}
	for _, c := range crio {
		names = append(names, c.Name)
	}
	assert.ElementsMatch(t, []string{"nginx", "agent", "app", "shell", "bb", "stopped", "s2app"}, names)
}

// The state CRI-O persists in userdata/state.json for a container whose
// process exited and for one still running, on Debian 12 with CRI-O 1.37.2.
// CRI-O's own API reports the exited container's last pid (11985).
func TestParseCrioContainerState(t *testing.T) {
	state, ok := parseCrioContainerState(readCrioFixture(t, "debian12/state-stopped.json"))
	require.True(t, ok)
	assert.Equal(t, "stopped", state.Status)
	assert.Equal(t, int64(0), state.Pid)

	state, ok = parseCrioContainerState(readCrioFixture(t, "debian12/state-running.json"))
	require.True(t, ok)
	assert.Equal(t, "running", state.Status)
	assert.Equal(t, int64(11889), state.Pid)

	_, ok = parseCrioContainerState("")
	assert.False(t, ok)
	_, ok = parseCrioContainerState("{not json")
	assert.False(t, ok)
	_, ok = parseCrioContainerState("{}")
	assert.False(t, ok, "a state without a status says nothing")
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
	assert.Equal(t, "728902c90c8b555afa3fdb372f31c83f932a8c6369d37b44dea9e8ddc835d42e", proxy.ImageID)
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

func TestIsCrioNamespacePolicyFile(t *testing.T) {
	assert.True(t, isCrioNamespacePolicyFile("payments.json"))
	assert.True(t, isCrioNamespacePolicyFile("kube-system.json"))
	assert.False(t, isCrioNamespacePolicyFile("README"))
	assert.False(t, isCrioNamespacePolicyFile(".hidden.json"))
	assert.False(t, isCrioNamespacePolicyFile(".json"), "a name without a namespace")
	assert.False(t, isCrioNamespacePolicyFile("payments.json.bak"))
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

// The Volumes annotation of kube-proxy, from CRI-O's inspect output on the
// kubeadm node
func TestParseCrioMounts(t *testing.T) {
	inspect, err := parseCrioInspect(readCrioFixture(t, "kubeadm/inspect-kube-proxy.json"))
	require.NoError(t, err)
	mounts, err := parseCrioMounts(inspect.Annotations[crioVolumesAnnotation])
	require.NoError(t, err)
	require.Len(t, mounts, 6)

	assert.Equal(t, "/run/xtables.lock", mounts[0].ContainerPath)
	assert.Equal(t, "/run/xtables.lock", mounts[0].HostPath)
	assert.False(t, mounts[0].Readonly)
	assert.Equal(t, "/lib/modules", mounts[1].ContainerPath)
	assert.True(t, mounts[1].Readonly)
	assert.Equal(t, "/var/run/secrets/kubernetes.io/serviceaccount", mounts[5].ContainerPath)
	assert.True(t, mounts[5].Readonly)

	none, err := parseCrioMounts("[]")
	require.NoError(t, err)
	assert.Empty(t, none)
	_, err = parseCrioMounts("{not json")
	assert.Error(t, err)
}

// Without a running CRI-O, the annotation is read from the container's OCI
// config.json: etcd's on the kubeadm node.
func TestCrioSpecVolumes(t *testing.T) {
	volumes, ok := crioSpecVolumes(readCrioSpecFixture(t, "kubeadm/config-etcd.json"))
	require.True(t, ok)
	mounts, err := parseCrioMounts(volumes)
	require.NoError(t, err)
	require.Len(t, mounts, 4)
	assert.Equal(t, "/var/lib/etcd", mounts[2].HostPath)
	assert.Equal(t, "/etc/kubernetes/pki/etcd", mounts[3].ContainerPath)

	_, ok = crioSpecVolumes(readCrioSpecFixture(t, "minikube/config-sandbox-plain.json"))
	assert.False(t, ok, "a pod sandbox records no volumes")
	_, ok = crioSpecVolumes(nil)
	assert.False(t, ok)
}

func TestCrioPropagation(t *testing.T) {
	assert.Equal(t, "None", crioPropagation(0))
	assert.Equal(t, "HostToContainer", crioPropagation(1))
	assert.Equal(t, "Bidirectional", crioPropagation(2))
	assert.Equal(t, "7", crioPropagation(7))
}

func TestCrioPort(t *testing.T) {
	cfg, err := parseCrioConfig(readCrioFixture(t, "kubeadm/config.toml"))
	require.NoError(t, err)
	port, ok := crioPort(crioConfigValue(cfg, "api", "stream_port"))
	assert.True(t, ok)
	assert.Equal(t, int64(0), port)
	assert.Equal(t, "127.0.0.1", crioConfigValue(cfg, "api", "stream_address"))

	port, ok = crioPort(int64(10010))
	assert.True(t, ok)
	assert.Equal(t, int64(10010), port)
	port, ok = crioPort(float64(10010))
	assert.True(t, ok)
	assert.Equal(t, int64(10010), port)
	_, ok = crioPort(10010.5)
	assert.False(t, ok)
	_, ok = crioPort("ten")
	assert.False(t, ok)
	_, ok = crioPort(nil)
	assert.False(t, ok)
}

// CRI-O opens <signature_policy_dir>/<namespace>.json by path, so a symlinked
// policy counts, and a directory or a dangling link holds no policy.
func TestCrioNamespacePolicyListing(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc", "crio", "policies")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc", "crio", "shared"), 0o755))
	policy := []byte(`{"default":[{"type":"reject"}]}`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "payments.json"), policy, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc", "crio", "shared", "policy.json"), policy, 0o644))
	require.NoError(t, os.Symlink("../shared/policy.json", filepath.Join(dir, "linked.json")))
	require.NoError(t, os.Symlink("../shared/missing.json", filepath.Join(dir, "dangling.json")))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "dir.json"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".hidden.json"), policy, 0o644))

	rt := memFSRuntime(t, afero.NewBasePathFs(afero.NewOsFs(), root))
	files, err := listConfDFilesWith(rt, []string{"/etc/crio/policies"}, isCrioNamespacePolicyFile)
	require.NoError(t, err)
	assert.Equal(t, []string{"/etc/crio/policies/linked.json", "/etc/crio/policies/payments.json"}, files)
}

func readCrioSpecFixture(t *testing.T, name string) *ociSpec {
	t.Helper()
	spec, err := parseOCISpec([]byte(readCrioFixture(t, name)))
	require.NoError(t, err)
	require.NotNil(t, spec)
	return spec
}

// crioStorageFS lays out containers/storage as CRI-O 1.35.7 left it on a
// minikube node: the container list and the config.json of five test pods'
// containers and two of their sandboxes. The other containers have no
// config.json, as when it cannot be read.
func crioStorageFS(t *testing.T) afero.Fs {
	t.Helper()
	mockFS := afero.NewMemMapFs()
	dir := "/var/lib/containers/storage/overlay-containers"
	writeMemFSFile(t, mockFS, dir+"/volatile-containers.json", []byte(readCrioFixture(t, "minikube/volatile-containers.json")))
	for id, fixture := range map[string]string{
		"d8275b00bdbbcd45a07e862639f20f92f538661714b0faf4f7dc412199ed5648": "config-priv.json",
		"d63d698ce83b6dffcbe53ecc0d8558a6be7301d5182d89d6f3ff8ca6b7069871": "config-hostns.json",
		"97f10b8f12804fe6271d24d5239dd3f235a907cc38b42b468b760930240a1644": "config-hardened.json",
		"a0123d372f54b484ee748b0c85de60815c0c735f8cf6430b668f0ce44097ccba": "config-unconfined.json",
		"9341e1667aec5d6066ea7d2c37fe98dac6073fb0ae91c993a7029496df93fa4b": "config-plain.json",
		"194c3651d680c6b3aca850c2cace68277d8f9864dc26394e911ab2ee20cb509c": "config-sandbox-hostns.json",
		"ab6baaa75b5f09d672c05fb57aa3871bae1014e7ab1db864ed956cb1e2cc5ecb": "config-sandbox-plain.json",
	} {
		writeMemFSFile(t, mockFS, dir+"/"+id+"/userdata/config.json", []byte(readCrioFixture(t, "minikube/"+fixture)))
	}
	return mockFS
}

// Without a running CRI-O, a container's confinement is read from the
// config.json CRI-O created it with, and its host namespaces from its pod
// sandbox's.
func TestCrioContainerSpecFields(t *testing.T) {
	c := &mqlCrio{MqlRuntime: memFSRuntime(t, crioStorageFS(t))}
	list, err := c.containers()
	require.NoError(t, err)
	require.Len(t, list, 13, "the 13 containers of the list, without the sandboxes")

	byName := map[string]*mqlCrioContainer{}
	for _, r := range list {
		ctr := r.(*mqlCrioContainer)
		if ctr.PodNamespace.Data == "default" {
			byName[ctr.Name.Data] = ctr
		}
	}
	require.Len(t, byName, 5)

	priv := byName["priv"]
	assert.True(t, priv.Privileged.Data)
	assert.Len(t, priv.GetCapabilities().Data, 41)
	assert.True(t, priv.GetSeccompUnconfined().Data)
	assert.Equal(t, "Unconfined", priv.SeccompProfile.Data, "from the spec's annotation")
	assert.True(t, priv.GetHostPID().IsNull(), "its sandbox's config.json is missing")
	assert.True(t, priv.GetHostNetwork().IsNull())

	hostns := byName["hostns"]
	assert.False(t, hostns.Privileged.Data)
	assert.True(t, hostns.GetHostNetwork().Data)
	assert.True(t, hostns.GetHostPID().Data)
	assert.True(t, hostns.GetHostIPC().Data, "the container joins the node's IPC namespace by path, so only the sandbox tells")
	hostPaths := []string{}
	for _, m := range hostns.GetMounts().Data {
		hostPaths = append(hostPaths, m.(*mqlCrioContainerMount).HostPath.Data)
	}
	assert.Contains(t, hostPaths, "/var/run/crio/crio.sock")
	assert.Contains(t, hostPaths, "/etc")

	plain := byName["plain"]
	assert.False(t, plain.GetHostNetwork().Data)
	assert.False(t, plain.GetHostPID().Data)
	assert.False(t, plain.GetHostIPC().Data)
	assert.False(t, plain.GetHostNetwork().IsNull())
	assert.Equal(t, "plain", plain.Labels.Data["io.kubernetes.container.name"], "labels from the spec's annotation")
	assert.Len(t, plain.GetCapabilities().Data, 9)
	assert.False(t, plain.GetNoNewPrivileges().Data)
	assert.False(t, plain.GetReadOnlyRootfs().Data)
	assert.True(t, plain.GetMemoryLimit().IsNull())
	assert.True(t, plain.GetNanoCpus().IsNull())
	assert.True(t, plain.GetPidsLimit().IsNull(), "a limit of -1 is unlimited")
	assert.Equal(t, int64(2), plain.GetCpuShares().Data)

	hardened := byName["hardened"]
	assert.Equal(t, []any{"CAP_NET_BIND_SERVICE"}, hardened.GetCapabilities().Data)
	assert.Equal(t, []any{"CAP_NET_BIND_SERVICE"}, hardened.GetBoundingCapabilities().Data)
	assert.False(t, hardened.GetSeccompUnconfined().Data)
	assert.Equal(t, "SCMP_ACT_ERRNO", hardened.GetSeccompDefaultAction().Data)
	assert.Equal(t, "RuntimeDefault", hardened.SeccompProfile.Data)
	assert.True(t, hardened.GetNoNewPrivileges().Data)
	assert.True(t, hardened.GetReadOnlyRootfs().Data)
	assert.Equal(t, int64(1000), hardened.GetUid().Data)
	assert.Equal(t, int64(3000), hardened.GetGid().Data)
	assert.Equal(t, int64(67108864), hardened.GetMemoryLimit().Data)
	assert.Equal(t, int64(250000000), hardened.GetNanoCpus().Data)
	assert.Equal(t, int64(256), hardened.GetCpuShares().Data)

	unconfined := byName["unconfined"]
	assert.Contains(t, unconfined.GetCapabilities().Data, "CAP_SYS_ADMIN")
	assert.True(t, unconfined.GetSeccompUnconfined().Data)
	assert.Equal(t, "", unconfined.GetSeccompDefaultAction().Data)
	assert.False(t, unconfined.Privileged.Data)

	// a container whose config.json cannot be read
	for _, r := range list {
		ctr := r.(*mqlCrioContainer)
		if ctr.Name.Data == "etcd" {
			assert.True(t, ctr.GetCapabilities().IsNull())
			assert.True(t, ctr.GetUid().IsNull())
			assert.True(t, ctr.GetMounts().IsNull())
		}
	}
}

func TestCrioSandboxNamespaces(t *testing.T) {
	opts, ok := crioSandboxNamespaces(readCrioSpecFixture(t, "minikube/config-sandbox-hostns.json"))
	require.True(t, ok)
	assert.Equal(t, crioNamespaceOptions{Network: criNamespaceModeNode, Pid: criNamespaceModeNode, Ipc: criNamespaceModeNode}, opts)

	// a pod's own namespaces: POD is left out, its PID namespace is the container's
	opts, ok = crioSandboxNamespaces(readCrioSpecFixture(t, "minikube/config-sandbox-plain.json"))
	require.True(t, ok)
	assert.Equal(t, crioNamespaceOptions{Pid: 1}, opts)

	// a container's spec records none
	_, ok = crioSandboxNamespaces(readCrioSpecFixture(t, "minikube/config-plain.json"))
	assert.False(t, ok)
	_, ok = crioSandboxNamespaces(nil)
	assert.False(t, ok)
}
