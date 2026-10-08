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

// containerdSpecFixture reads the `ctr -n k8s.io containers info` output of a
// container of a kind node (containerd 2.2.0), and its spec.
func containerdSpecFixture(t *testing.T, name string) (*containerInfo, *ociSpec) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "containerd-container", name+".json"))
	require.NoError(t, err)
	info, err := parseContainerInfo(data)
	require.NoError(t, err)
	spec, err := parseOCISpec(info.Spec)
	require.NoError(t, err)
	require.NotNil(t, spec)
	return info, spec
}

func TestContainerdSpecPrivileged(t *testing.T) {
	// securityContext.privileged: true
	_, priv := containerdSpecFixture(t, "priv")
	assert.True(t, priv.isPrivileged())
	assert.True(t, priv.seccompUnconfined())
	assert.Equal(t, "", priv.seccompDefaultAction())
	assert.Contains(t, priv.Process.Capabilities.Effective, "CAP_SYS_ADMIN")

	// a container with SYS_ADMIN and seccomp Unconfined is not privileged
	_, unconfined := containerdSpecFixture(t, "unconfined")
	assert.False(t, unconfined.isPrivileged())
	assert.True(t, unconfined.seccompUnconfined())
	assert.Contains(t, unconfined.Process.Capabilities.Effective, "CAP_SYS_ADMIN")
	assert.Contains(t, unconfined.Process.Capabilities.Effective, "CAP_NET_ADMIN")

	_, plain := containerdSpecFixture(t, "plain")
	assert.False(t, plain.isPrivileged())
	assert.NotContains(t, plain.Process.Capabilities.Effective, "CAP_SYS_ADMIN")

	// pod sandboxes are not privileged either
	_, sandbox := containerdSpecFixture(t, "plain-sandbox")
	assert.False(t, sandbox.isPrivileged())
}

func TestContainerdSpecHardened(t *testing.T) {
	// runAsUser 1000, runAsGroup 3000, seccomp RuntimeDefault,
	// readOnlyRootFilesystem, allowPrivilegeEscalation false, drop ALL and add
	// NET_BIND_SERVICE, limits memory 64Mi and cpu 250m
	_, spec := containerdSpecFixture(t, "hardened")
	assert.False(t, spec.isPrivileged())
	assert.False(t, spec.seccompUnconfined())
	assert.Equal(t, "SCMP_ACT_ERRNO", spec.seccompDefaultAction())
	assert.True(t, spec.Process.NoNewPrivileges)
	assert.True(t, spec.Root.Readonly)
	assert.Equal(t, uint32(1000), spec.Process.User.UID)
	assert.Equal(t, uint32(3000), spec.Process.User.GID)
	assert.Equal(t, []string{"CAP_NET_BIND_SERVICE"}, spec.Process.Capabilities.Effective)
	assert.Equal(t, []string{"CAP_NET_BIND_SERVICE"}, spec.Process.Capabilities.Bounding)

	limits := spec.limits()
	require.NotNil(t, limits.memory)
	assert.Equal(t, int64(64*1024*1024), *limits.memory)
	require.NotNil(t, limits.nanoCpus)
	assert.Equal(t, int64(250_000_000), *limits.nanoCpus)
	require.NotNil(t, limits.cpuShares)
	assert.Equal(t, int64(102), *limits.cpuShares)
	assert.Nil(t, limits.pids)

	// without limits, memory and CPU quota are unlimited
	_, plain := containerdSpecFixture(t, "plain")
	assert.Nil(t, plain.limits().memory)
	assert.Nil(t, plain.limits().nanoCpus)
	assert.False(t, plain.Process.NoNewPrivileges)
	assert.False(t, plain.Root.Readonly)
}

func TestContainerdSpecHostNamespaces(t *testing.T) {
	// hostNetwork, hostPID and hostIPC: the container joins its sandbox's
	// namespaces by path either way, the sandbox's spec leaves them out
	hostInfo, host := containerdSpecFixture(t, "hostns")
	_, hostSandbox := containerdSpecFixture(t, "hostns-sandbox")
	_, plain := containerdSpecFixture(t, "plain")
	_, plainSandbox := containerdSpecFixture(t, "plain-sandbox")
	assert.Equal(t, hostInfo.SandboxID, host.Annotations[criSandboxIDAnnotation])
	assert.True(t, host.hasNamespace("network"))

	for _, ns := range []string{"network", "pid", "ipc"} {
		shared, ok := sharesHostNamespace(host, hostSandbox, ns)
		require.True(t, ok)
		assert.True(t, shared, ns)
		shared, ok = sharesHostNamespace(plain, plainSandbox, ns)
		require.True(t, ok)
		assert.False(t, shared, ns)

		// a sandbox is read from its own spec
		shared, ok = sharesHostNamespace(hostSandbox, nil, ns)
		require.True(t, ok)
		assert.True(t, shared, ns)
		shared, ok = sharesHostNamespace(plainSandbox, nil, ns)
		require.True(t, ok)
		assert.False(t, shared, ns)
	}

	// without its sandbox, a pod's container cannot tell
	_, ok := sharesHostNamespace(host, nil, "network")
	assert.False(t, ok)
	_, ok = sharesHostNamespace(nil, nil, "network")
	assert.False(t, ok)
}

func TestContainerdSpecMounts(t *testing.T) {
	// hostPath volumes of the containerd socket (read-write) and /etc (readOnly)
	_, spec := containerdSpecFixture(t, "hostns")
	byPath := map[string]ociMount{}
	for _, m := range spec.Mounts {
		byPath[m.Destination] = m
	}
	sock := byPath["/run/containerd/containerd.sock"]
	assert.Equal(t, "/run/containerd/containerd.sock", sock.Source)
	assert.Equal(t, "bind", sock.Type)
	assert.False(t, ociMountReadOnly(sock.Options))
	assert.Equal(t, "rprivate", ociMountPropagation(sock.Options))
	etc := byPath["/host/etc"]
	assert.Equal(t, "/etc", etc.Source)
	assert.True(t, ociMountReadOnly(etc.Options))
	assert.True(t, ociMountReadOnly(byPath["/sys"].Options))

	_, priv := containerdSpecFixture(t, "priv")
	for _, m := range priv.Mounts {
		if m.Destination == "/sys" {
			assert.False(t, ociMountReadOnly(m.Options))
		}
	}

	assert.False(t, ociMountReadOnly([]string{"ro", "rw"}))
	assert.True(t, ociMountReadOnly([]string{"rw", "ro"}))
	assert.Equal(t, "", ociMountPropagation([]string{"nosuid"}))
}

func TestContainerdSpecSeccompAllowsAll(t *testing.T) {
	spec, err := parseOCISpec([]byte(`{"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["ptrace"],"action":"SCMP_ACT_LOG"}]}}}`))
	require.NoError(t, err)
	assert.True(t, spec.seccompUnconfined())
	assert.Equal(t, "SCMP_ACT_ALLOW", spec.seccompDefaultAction())

	spec, err = parseOCISpec([]byte(`{"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["ptrace"],"action":"SCMP_ACT_ERRNO"}]}}}`))
	require.NoError(t, err)
	assert.False(t, spec.seccompUnconfined())

	spec, err = parseOCISpec(nil)
	require.NoError(t, err)
	assert.Nil(t, spec)
	_, err = parseOCISpec([]byte(`{"linux": 5}`))
	assert.Error(t, err)
}

func TestContainerdSpecCtrContainers(t *testing.T) {
	// `ctr run --net-host --privileged` and a plain `ctr run` on containerd
	// 1.7.18: no pod, so the container's own spec tells
	_, nethost := containerdSpecFixture(t, "ctr-nethost-1.7")
	assert.False(t, nethost.isCRIContainer())
	assert.True(t, nethost.isPrivileged())
	shared, ok := sharesHostNamespace(nethost, nil, "network")
	require.True(t, ok)
	assert.True(t, shared)
	shared, ok = sharesHostNamespace(nethost, nil, "pid")
	require.True(t, ok)
	assert.False(t, shared)

	_, plain := containerdSpecFixture(t, "ctr-plain-1.7")
	assert.False(t, plain.isPrivileged())
	shared, ok = sharesHostNamespace(plain, nil, "network")
	require.True(t, ok)
	assert.False(t, shared)
	// ctr applies no seccomp profile unless asked to
	assert.True(t, plain.seccompUnconfined())
}
