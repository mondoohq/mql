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

func readContainerdHostsFile(t *testing.T, dir string) []containerdRegistryHost {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "containerd", "certs.d", dir, "hosts.toml"))
	require.NoError(t, err)
	file := "/etc/containerd/certs.d/" + dir + "/hosts.toml"
	hosts, err := parseContainerdHostsFile(containerdNamespace(dir), file, string(data))
	require.NoError(t, err)
	return hosts
}

func TestParseContainerdHostsFile(t *testing.T) {
	// the hosts in the order listed, then the server
	hosts := readContainerdHostsFile(t, "docker.io")
	require.Len(t, hosts, 3)
	assert.Equal(t, containerdRegistryHost{
		Namespace:    "docker.io",
		URL:          "https://public-mirror.example.com",
		Capabilities: []string{"pull"},
		CACerts:      []string{},
		ClientCerts:  []string{},
		File:         "/etc/containerd/certs.d/docker.io/hosts.toml",
	}, hosts[0])
	assert.Equal(t, "https://docker-mirror.internal", hosts[1].URL)
	assert.Equal(t, []string{"pull", "resolve"}, hosts[1].Capabilities)
	// a relative ca is taken from the hosts.toml's directory
	assert.Equal(t, []string{"/etc/containerd/certs.d/docker.io/docker-mirror.crt"}, hosts[1].CACerts)
	assert.True(t, hosts[2].Server)
	assert.Equal(t, "https://registry-1.docker.io", hosts[2].URL)
	assert.Equal(t, []string{"pull", "resolve", "push"}, hosts[2].Capabilities)
	assert.False(t, hosts[2].SkipVerify)

	hosts = readContainerdHostsFile(t, "registry.local_5000_")
	require.Len(t, hosts, 2)
	assert.Equal(t, "registry.local:5000", hosts[0].Namespace)
	assert.Equal(t, "http://192.168.31.250:5000", hosts[0].URL)
	assert.True(t, hosts[0].SkipVerify)
	assert.False(t, hosts[1].SkipVerify)

	hosts = readContainerdHostsFile(t, "_default")
	require.Len(t, hosts, 1)
	assert.True(t, hosts[0].Server)
	assert.Equal(t, "_default", hosts[0].Namespace)
	assert.Equal(t, []string{"/etc/certs/test-1-ca.pem", "/etc/certs/special.pem"}, hosts[0].CACerts)
	assert.Equal(t, []string{"/etc/certs/client.cert", "/etc/certs/client.pem"}, hosts[0].ClientCerts)
}

func TestParseContainerdHostsFileServerOnly(t *testing.T) {
	// without a server the namespace's registry itself is the server, and a
	// host without a scheme is reached over https
	hosts, err := parseContainerdHostsFile("quay.io", "/h/hosts.toml", `
skip_verify = true
[host."mirror.example.com"]
`)
	require.NoError(t, err)
	require.Len(t, hosts, 2)
	assert.Equal(t, "https://mirror.example.com", hosts[0].URL)
	assert.False(t, hosts[0].SkipVerify)
	assert.Equal(t, "https://quay.io", hosts[1].URL)
	assert.True(t, hosts[1].Server)
	assert.True(t, hosts[1].SkipVerify)

	// Docker Hub's namespace is served from its registry host, and the
	// fallback namespace from whichever registry an image names
	hosts, err = parseContainerdHostsFile("docker.io", "/h/hosts.toml", `skip_verify = false`)
	require.NoError(t, err)
	assert.Equal(t, "https://registry-1.docker.io", hosts[0].URL)
	hosts, err = parseContainerdHostsFile("_default", "/h/hosts.toml", `[host."https://m.example.com"]`)
	require.NoError(t, err)
	require.Len(t, hosts, 2)
	assert.Equal(t, "", hosts[1].URL)

	_, err = parseContainerdHostsFile("quay.io", "/h/hosts.toml", `ca = 5`)
	assert.Error(t, err)
}

func TestContainerdHostsFiles(t *testing.T) {
	fsys := containerdTestFS(t, nil, "certs.d", "/etc/containerd/certs.d")
	require.NoError(t, afero.WriteFile(fsys, "/etc/docker/certs.d/docker.io/hosts.toml", []byte(`server = "https://hidden.example.com"`), 0o644))
	require.NoError(t, afero.WriteFile(fsys, "/etc/docker/certs.d/quay.io/hosts.toml", []byte(`server = "https://quay.io"`), 0o644))
	// Docker's certificate files without a hosts.toml configure no host
	require.NoError(t, afero.WriteFile(fsys, "/etc/docker/certs.d/ghcr.io/ca.crt", []byte(`x`), 0o644))

	got := containerdHostsFiles(fsys, []string{"/etc/containerd/certs.d", "/etc/docker/certs.d", "/missing"})
	assert.Equal(t, [][2]string{
		{"_default", "/etc/containerd/certs.d/_default/hosts.toml"},
		{"docker.io", "/etc/containerd/certs.d/docker.io/hosts.toml"},
		{"registry.local:5000", "/etc/containerd/certs.d/registry.local_5000_/hosts.toml"},
		{"quay.io", "/etc/docker/certs.d/quay.io/hosts.toml"},
	}, got)
}

func TestContainerdInlineRegistryHosts(t *testing.T) {
	fsys := containerdTestFS(t, nil, "mirrors", "/etc/containerd")
	cfg, err := loadContainerdConfig(fsys, containerdConfigFile, 1)
	require.NoError(t, err)
	paths, ok := cfg.registryConfigPaths(1)
	require.True(t, ok)
	assert.Empty(t, paths)
	registry, ok := cfg.effective(1, containerdRegistry)
	require.True(t, ok)

	// containerd 2.x reads no hosts.toml either while mirrors are configured
	paths, ok = cfg.registryConfigPaths(2)
	require.True(t, ok)
	assert.Empty(t, paths)

	hosts := containerdInlineRegistryHosts(registry.(map[string]any), false)
	all := []string{"pull", "resolve", "push"}
	assert.Equal(t, []containerdRegistryHost{
		{Namespace: "docker.io", URL: "https://mirror.example.com", Capabilities: all, CACerts: []string{"/etc/containerd/mirror-ca.crt"}},
		{Namespace: "docker.io", URL: "https://registry-1.docker.io", Server: true, Capabilities: all},
		{Namespace: "registry.local:5000", URL: "http://registry.local:5000", Server: true, Capabilities: all, SkipVerify: true},
		{Namespace: "quay.io", URL: "https://quay.io", Server: true, Capabilities: all, SkipVerify: true},
	}, hosts)
}

func TestContainerdNamespace(t *testing.T) {
	assert.Equal(t, "registry.local:5000", containerdNamespace("registry.local_5000_"))
	assert.Equal(t, "docker.io", containerdNamespace("docker.io"))
	assert.Equal(t, "_default", containerdNamespace("_default"))
}

func TestContainerdRegistryHostID(t *testing.T) {
	// a host and the server may share a URL, and ids must not depend on
	// the order of the files
	host := containerdRegistryHost{Namespace: "docker.io", URL: "https://registry-1.docker.io", File: "/etc/containerd/certs.d/docker.io/hosts.toml"}
	server := host
	server.Server = true
	other := host
	other.Namespace = "quay.io"
	inline := host
	inline.File = ""
	ids := map[string]bool{}
	for _, h := range []containerdRegistryHost{host, server, other, inline} {
		ids[containerdRegistryHostID(h)] = true
	}
	assert.Len(t, ids, 4)
	assert.Equal(t, containerdRegistryHostID(host), containerdRegistryHostID(host))
}
