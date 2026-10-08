// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// containerdTestFS returns a filesystem with the files of a directory of
// testdata/containerd placed at dst.
func containerdTestFS(t *testing.T, fsys afero.Fs, src, dst string) afero.Fs {
	t.Helper()
	if fsys == nil {
		fsys = afero.NewMemMapFs()
	}
	root := filepath.Join("testdata", "containerd", src)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return afero.WriteFile(fsys, path.Join(dst, filepath.ToSlash(rel)), data, 0o644)
	})
	require.NoError(t, err)
	return fsys
}

// containerdDump reads a `containerd config dump` or `containerd config
// default` output, the configuration containerd runs with.
func containerdDump(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "containerd", name))
	require.NoError(t, err)
	res := map[string]any{}
	_, err = toml.Decode(string(data), &res)
	require.NoError(t, err)
	return res
}

func dumpValue(t *testing.T, dump map[string]any, keys ...string) any {
	t.Helper()
	v, ok := containerdLookup(dump, keys, false)
	require.True(t, ok, "dump has no %v", keys)
	return v
}

// The locations of the CRI settings in the dumps: containerd 2.x dumps
// version 3, containerd 1.x version 2.
var (
	dumpV3Runtime = []string{"plugins", "io.containerd.cri.v1.runtime"}
	dumpV3Images  = []string{"plugins", "io.containerd.cri.v1.images"}
	dumpCRI       = []string{"plugins", "io.containerd.grpc.v1.cri"}
)

func at(prefix []string, keys ...string) []string {
	return append(append([]string{}, prefix...), keys...)
}

// assertContainerdMatchesDump checks the settings read from a configuration
// against what containerd itself reports it runs with.
func assertContainerdMatchesDump(t *testing.T, cfg *containerdConfig, version string, dump map[string]any) {
	t.Helper()
	major := containerdMajor(version)
	runtimePrefix, imagesPrefix := dumpV3Runtime, dumpV3Images
	sandboxKeys := at(dumpV3Images, "pinned_images", "sandbox")
	snapshotterKeys := at(dumpV3Images, "snapshotter")
	runtimesKeys := at(dumpV3Runtime, "containerd")
	if major == 1 {
		runtimePrefix, imagesPrefix = dumpCRI, dumpCRI
		sandboxKeys = at(dumpCRI, "sandbox_image")
		snapshotterKeys = at(dumpCRI, "containerd", "snapshotter")
		runtimesKeys = at(dumpCRI, "containerd")
	}

	settings := []struct {
		setting containerdSetting
		keys    []string
	}{
		{containerdRuntimeSetting("enable_selinux", false, false), at(runtimePrefix, "enable_selinux")},
		{containerdRuntimeSetting("enable_unprivileged_ports", false, true), at(runtimePrefix, "enable_unprivileged_ports")},
		{containerdRuntimeSetting("enable_unprivileged_icmp", false, true), at(runtimePrefix, "enable_unprivileged_icmp")},
		{containerdRuntimeSetting("restrict_oom_score_adj", false, false), at(runtimePrefix, "restrict_oom_score_adj")},
		{containerdRuntimeSetting("device_ownership_from_security_context", false, false), at(runtimePrefix, "device_ownership_from_security_context")},
		{containerdRuntimeSetting("disable_apparmor", false, false), at(runtimePrefix, "disable_apparmor")},
		{containerdRuntimeSetting("tolerate_missing_hugetlb_controller", true, true), at(runtimePrefix, "tolerate_missing_hugetlb_controller")},
		{containerdSnapshotter, snapshotterKeys},
		{containerdDefaultRuntime, at(runtimesKeys, "default_runtime_name")},
		{containerdStreamAddress, at(dumpCRI, "stream_server_address")},
		{containerdStreamPort, at(dumpCRI, "stream_server_port")},
		{containerdStreamTLS, at(dumpCRI, "enable_tls_streaming")},
	}
	for _, s := range settings {
		got, ok := cfg.effective(major, s.setting)
		require.True(t, ok, "%v", s.keys)
		assert.Equal(t, dumpValue(t, dump, s.keys...), got, "%v", s.keys)
	}

	sandbox, ok := cfg.sandboxImage(version)
	require.True(t, ok)
	assert.Equal(t, dumpValue(t, dump, sandboxKeys...), sandbox)

	paths, ok := cfg.registryConfigPaths(major)
	require.True(t, ok)
	assert.Equal(t, splitContainerdConfigPath(dumpValue(t, dump, at(imagesPrefix, "registry", "config_path")...).(string)), paths)

	want := dumpValue(t, dump, at(runtimesKeys, "runtimes")...).(map[string]any)
	got := containerdRuntimesFrom(effectiveContainerdRuntimes(cfg.merged, cfg.version, effectiveContainerdMajor(major, cfg.version)), major == 2)
	require.Equal(t, len(want), len(got))
	for _, rt := range got {
		w, ok := want[rt.Name].(map[string]any)
		require.True(t, ok, "runtime %s", rt.Name)
		options, _ := w["options"].(map[string]any)
		assert.Equal(t, w["runtime_type"], rt.Type, rt.Name)
		assert.Equal(t, w["runtime_path"], rt.ShimPath, rt.Name)
		assert.Equal(t, w["base_runtime_spec"], rt.BaseRuntimeSpec, rt.Name)
		assert.Equal(t, w["privileged_without_host_devices"], rt.PrivilegedWithoutHostDevices, rt.Name)
		assert.Equal(t, containerdStrings(w["pod_annotations"]), rt.PodAnnotations, rt.Name)
		// options holds what was configured, which may leave out the
		// binary, with containerd's runc shim then running runc
		systemd, _ := options["SystemdCgroup"].(bool)
		binary, _ := options["BinaryName"].(string)
		assert.Equal(t, systemd, rt.SystemdCgroup, rt.Name)
		assert.Equal(t, binary, rt.Path, rt.Name)
	}
}

func TestLoadContainerdConfigImports(t *testing.T) {
	fsys := containerdTestFS(t, nil, "imports", "/etc/containerd")

	for _, version := range []string{"2.2.0", "1.7.18"} {
		t.Run(version, func(t *testing.T) {
			cfg, err := loadContainerdConfig(fsys, "/etc/containerd/config.toml", containerdMajor(version))
			require.NoError(t, err)
			// the main file first, then its imports in name order
			assert.Equal(t, []string{
				"/etc/containerd/config.toml",
				"/etc/containerd/conf.d/10-kata.toml",
				"/etc/containerd/conf.d/20-selinux.toml",
			}, cfg.files)
			assert.Equal(t, int64(2), cfg.version)
			assertContainerdMatchesDump(t, cfg, version, containerdDump(t, "imports-dump-v"+version+".toml"))
		})
	}

	// containerd 2.x merges the imported plugin settings into the main file's,
	// 1.x lets the last import's CRI section replace all of it
	cfg2, err := loadContainerdConfig(fsys, "/etc/containerd/config.toml", 2)
	require.NoError(t, err)
	sandbox, _ := cfg2.sandboxImage("2.2.0")
	assert.Equal(t, "registry.example.com/pause:3.10", sandbox)
	cfg1, err := loadContainerdConfig(fsys, "/etc/containerd/config.toml", 1)
	require.NoError(t, err)
	sandbox, _ = cfg1.sandboxImage("1.7.18")
	assert.Equal(t, "registry.k8s.io/pause:3.8", sandbox)
}

func TestLoadContainerdConfigKind(t *testing.T) {
	fsys := containerdTestFS(t, nil, "kind", "/etc/containerd")
	for _, version := range []string{"2.2.0", "1.7.18"} {
		t.Run(version, func(t *testing.T) {
			cfg, err := loadContainerdConfig(fsys, "/etc/containerd/config.toml", containerdMajor(version))
			require.NoError(t, err)
			assertContainerdMatchesDump(t, cfg, version, containerdDump(t, "kind/dump-v"+version+".toml"))
		})
	}
}

func TestLoadContainerdConfigK3s(t *testing.T) {
	const main = "/var/lib/rancher/k3s/agent/etc/containerd/config.toml"
	fsys := afero.NewMemMapFs()
	data, err := os.ReadFile(filepath.Join("testdata", "containerd", "k3s", "config.toml"))
	require.NoError(t, err)
	require.NoError(t, afero.WriteFile(fsys, main, data, 0o644))

	cfg, err := loadContainerdConfig(fsys, main, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(3), cfg.version)
	assertContainerdMatchesDump(t, cfg, "2.1.4-k3s2", containerdDump(t, "k3s/dump-v2.1.4-k3s2.toml"))

	// a version 3 configuration is only loaded by containerd 2.x, so its
	// settings are known without the containerd version
	got, ok := cfg.effective(0, containerdRuntimeSetting("enable_unprivileged_ports", false, true))
	require.True(t, ok)
	assert.Equal(t, true, got)
}

func TestLoadContainerdConfigDefaults(t *testing.T) {
	fsys := afero.NewMemMapFs()
	for _, version := range []string{"2.2.0", "1.7.18"} {
		t.Run(version, func(t *testing.T) {
			cfg, err := loadContainerdConfig(fsys, containerdConfigFile, containerdMajor(version))
			require.NoError(t, err)
			assert.Empty(t, cfg.files)
			assert.Empty(t, cfg.merged)
			assertContainerdMatchesDump(t, cfg, version, containerdDump(t, "default-v"+version+".toml"))
		})
	}

	// without the containerd version, a default the releases disagree on is
	// unknown, one they share is known
	cfg, err := loadContainerdConfig(fsys, containerdConfigFile, 0)
	require.NoError(t, err)
	_, ok := cfg.effective(0, containerdRuntimeSetting("enable_unprivileged_ports", false, true))
	assert.False(t, ok)
	_, ok = cfg.registryConfigPaths(0)
	assert.False(t, ok)
	_, ok = cfg.sandboxImage("")
	assert.False(t, ok)
	got, ok := cfg.effective(0, containerdStreamAddress)
	require.True(t, ok)
	assert.Equal(t, "127.0.0.1", got)
}

func TestLoadContainerdConfigVersion1(t *testing.T) {
	fsys := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fsys, containerdConfigFile, []byte(`
[plugins.cri]
  enable_selinux = true
[plugins.cri.containerd]
  snapshotter = "native"
`), 0o644))
	cfg, err := loadContainerdConfig(fsys, containerdConfigFile, 1)
	require.NoError(t, err)
	got, ok := cfg.effective(1, containerdRuntimeSetting("enable_selinux", false, false))
	require.True(t, ok)
	assert.Equal(t, true, got)
	got, ok = cfg.effective(1, containerdSnapshotter)
	require.True(t, ok)
	assert.Equal(t, "native", got)
}

func TestLoadContainerdConfigCircularImports(t *testing.T) {
	fsys := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fsys, "/etc/containerd/config.toml", []byte(`version = 2
imports = ["/etc/containerd/b.toml"]
`), 0o644))
	require.NoError(t, afero.WriteFile(fsys, "/etc/containerd/b.toml", []byte(`version = 2
imports = ["config.toml", "missing.toml"]
disabled_plugins = ["io.containerd.grpc.v1.cri"]
`), 0o644))
	cfg, err := loadContainerdConfig(fsys, "/etc/containerd/config.toml", 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"/etc/containerd/config.toml", "/etc/containerd/b.toml"}, cfg.files)
	assert.Equal(t, []any{"io.containerd.grpc.v1.cri"}, cfg.merged["disabled_plugins"])
}

func TestLoadContainerdConfigMalformed(t *testing.T) {
	fsys := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fsys, containerdConfigFile, []byte("version = \n"), 0o644))
	_, err := loadContainerdConfig(fsys, containerdConfigFile, 2)
	assert.Error(t, err)
}

func TestMergeContainerdConfigTopLevel(t *testing.T) {
	dst := map[string]any{}
	mergeContainerdConfig(dst, map[string]any{
		"root":             "/var/lib/containerd",
		"disabled_plugins": []any{"a"},
		"grpc":             map[string]any{"address": "/run/a.sock", "uid": int64(0), "gid": int64(1000)},
		"timeouts":         map[string]any{"x": "1s", "y": "2s"},
	}, 2)
	mergeContainerdConfig(dst, map[string]any{
		"root":             "",
		"disabled_plugins": []any{"a", "b"},
		"grpc":             map[string]any{"address": "/run/b.sock", "gid": int64(0)},
		"timeouts":         map[string]any{"x": "3s"},
	}, 2)
	// an empty value does not override, lists are joined
	assert.Equal(t, "/var/lib/containerd", dst["root"])
	assert.Equal(t, []any{"a", "b"}, dst["disabled_plugins"])
	assert.Equal(t, map[string]any{"address": "/run/b.sock", "uid": int64(0), "gid": int64(1000)}, dst["grpc"])
	assert.Equal(t, map[string]any{"x": "3s", "y": "2s"}, dst["timeouts"])
}

func TestWithoutContainerdSecrets(t *testing.T) {
	fsys := containerdTestFS(t, nil, "mirrors", "/etc/containerd")
	cfg, err := loadContainerdConfig(fsys, containerdConfigFile, 1)
	require.NoError(t, err)

	clean := withoutContainerdSecrets(cfg.merged)
	registry, ok := containerdLookup(clean, []string{"plugins", containerdCRIPlugin, "registry"}, false)
	require.True(t, ok)
	configs := registry.(map[string]any)["configs"].(map[string]any)
	quay := configs["quay.io"].(map[string]any)
	assert.NotContains(t, quay, "auth")
	assert.Contains(t, quay, "tls")
	assert.Contains(t, registry.(map[string]any), "mirrors")

	// the loaded configuration itself keeps them
	_, ok = containerdLookup(cfg.merged, []string{"plugins", containerdCRIPlugin, "registry", "configs", "quay.io", "auth"}, false)
	assert.True(t, ok)
}

func TestParseContainerdCommandLine(t *testing.T) {
	// dockerd starts its own containerd this way
	assert.Equal(t, containerdFlags{config: "/var/run/docker/containerd/containerd.toml"},
		parseContainerdCommandLine("containerd --config /var/run/docker/containerd/containerd.toml"))
	assert.Equal(t, containerdFlags{
		config:  "/var/snap/microk8s/x1/args/containerd.toml",
		root:    "/var/snap/microk8s/common/var/lib/containerd",
		state:   "/var/snap/microk8s/common/run/containerd",
		address: "/var/snap/microk8s/common/run/containerd.sock",
	}, parseContainerdCommandLine("/snap/microk8s/8136/bin/containerd --config /var/snap/microk8s/x1/args/containerd.toml --root /var/snap/microk8s/common/var/lib/containerd --state /var/snap/microk8s/common/run/containerd --address /var/snap/microk8s/common/run/containerd.sock"))
	assert.Equal(t, containerdFlags{config: "/etc/c.toml", address: "/run/c.sock"},
		parseContainerdCommandLine("/usr/bin/containerd -c=/etc/c.toml -a /run/c.sock --log-level debug"))
	// what follows the subcommand is not containerd's
	assert.Equal(t, containerdFlags{}, parseContainerdCommandLine("containerd config dump --config /x.toml"))
	// kind and K3s run containerd without flags
	assert.Equal(t, containerdFlags{}, parseContainerdCommandLine("/usr/local/bin/containerd"))
	assert.Equal(t, containerdFlags{}, parseContainerdCommandLine("containerd"))
}

func TestParseContainerdVersion(t *testing.T) {
	assert.Equal(t, "2.2.0", parseContainerdVersion("containerd github.com/containerd/containerd/v2 v2.2.0 1c4457e00facac03ce1d75f7b6777a7a851e5c41\n"))
	assert.Equal(t, "1.7.18", parseContainerdVersion("containerd github.com/containerd/containerd v1.7.18 ae71819c4f5e67bb4d5ae76a6b735f29cc25774e\n"))
	assert.Equal(t, "2.1.4-k3s2", parseContainerdVersion("containerd github.com/k3s-io/containerd/v2 v2.1.4-k3s2 \n"))
	assert.Equal(t, "", parseContainerdVersion("k3s version v1.33.5+k3s1 (a1b2c3)"))
	assert.Equal(t, "", parseContainerdVersion(""))

	assert.Equal(t, 2, containerdMajor("2.1.4-k3s2"))
	assert.Equal(t, 1, containerdMajor("1.7.18"))
	assert.Equal(t, 0, containerdMajor(""))
	assert.Equal(t, "2.1", containerdMinor("2.1.4-k3s2"))
}

func TestIsContainerdProcess(t *testing.T) {
	assert.True(t, isContainerdProcess("/usr/local/bin/containerd", "/usr/local/bin/containerd"))
	// K3s runs containerd inside its own binary under the name containerd
	assert.True(t, isContainerdProcess("/bin/k3s", "containerd "))
	assert.False(t, isContainerdProcess("/usr/local/bin/containerd-shim-runc-v2", "/usr/local/bin/containerd-shim-runc-v2 -namespace k8s.io -id x -address /run/containerd/containerd.sock"))
	assert.False(t, isContainerdProcess("/usr/bin/dockerd", "/usr/bin/dockerd --containerd=/run/containerd/containerd.sock"))
}

func TestResolveContainerdImports(t *testing.T) {
	fsys := containerdTestFS(t, nil, "imports", "/etc/containerd")
	assert.Equal(t, []string{
		"/etc/containerd/conf.d/10-kata.toml",
		"/etc/containerd/conf.d/20-selinux.toml",
		"/etc/other.toml",
		"/etc/containerd/x.toml",
	}, resolveContainerdImports(fsys, "/etc/containerd/config.toml", []string{"conf.d/*.toml", "/etc/other.toml", "./x.toml"}))
	assert.Empty(t, resolveContainerdImports(fsys, "/etc/containerd/config.toml", []string{"/etc/containerd/none.d/*.toml"}))
	assert.Equal(t, []string{"/etc/containerd/conf.d/20-selinux.toml"},
		resolveContainerdImports(fsys, "/etc/containerd/config.toml", []string{"/etc/*/conf.d/2*.toml"}))
}

func TestEffectiveContainerdRuntimesMigration(t *testing.T) {
	// containerd 2.x adds the handlers of a version 2 section to those of
	// version 3, without replacing a version 3 handler of the same name
	cfg := map[string]any{"plugins": map[string]any{
		containerdCRIPlugin: map[string]any{"containerd": map[string]any{"runtimes": map[string]any{
			"kata": map[string]any{"runtime_type": "io.containerd.kata.v2"},
			"runc": map[string]any{"runtime_type": "io.containerd.runc.v1"},
		}}},
		containerdCRIRuntimePlugin: map[string]any{"containerd": map[string]any{"runtimes": map[string]any{
			"runc": map[string]any{"runtime_type": "io.containerd.runc.v2"},
		}}},
	}}
	got := containerdRuntimesFrom(effectiveContainerdRuntimes(cfg, 2, 2), true)
	names := []string{}
	for _, r := range got {
		names = append(names, r.Name+"="+r.Type)
	}
	sort.Strings(names)
	assert.Equal(t, "kata=io.containerd.kata.v2,runc=io.containerd.runc.v2", strings.Join(names, ","))

	// a version 3 configuration's version 2 section is not read
	got = containerdRuntimesFrom(effectiveContainerdRuntimes(cfg, 3, 2), true)
	require.Len(t, got, 1)
	assert.Equal(t, "runc", got[0].Name)
}

func TestLoadContainerdConfigCaseInsensitiveKeys(t *testing.T) {
	// containerd 2.x reads Enable_SELinux as enable_selinux, 1.x ignores it
	fsys := containerdTestFS(t, nil, "casefold", "/etc/containerd")
	for _, version := range []string{"2.2.0", "1.7.18"} {
		t.Run(version, func(t *testing.T) {
			cfg, err := loadContainerdConfig(fsys, containerdConfigFile, containerdMajor(version))
			require.NoError(t, err)
			assertContainerdMatchesDump(t, cfg, version, containerdDump(t, "casefold-dump-v"+version+".toml"))
		})
	}
	cfg, err := loadContainerdConfig(fsys, containerdConfigFile, 2)
	require.NoError(t, err)
	got, ok := cfg.effective(2, containerdRuntimeSetting("enable_selinux", false, false))
	require.True(t, ok)
	assert.Equal(t, true, got)
}

func TestWithoutContainerdSecretsAnyCase(t *testing.T) {
	// containerd 2.2 loads every one of these credentials, whatever the case
	// of their keys (checked with `containerd config dump`)
	fsys := containerdTestFS(t, nil, "secrets", "/etc/containerd")
	cfg, err := loadContainerdConfig(fsys, containerdConfigFile, 2)
	require.NoError(t, err)

	data, err := json.Marshal(withoutContainerdSecrets(cfg.merged))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "secret-")
	// the TLS settings next to them stay
	assert.Contains(t, string(data), "insecure_skip_verify")
}

func TestContainerdVersionBinaries(t *testing.T) {
	probe := func(rootExe, argv0 string, trusted ...string) kubeletBinaryProbe {
		return kubeletBinaryProbe{
			rootExe: func() string { return rootExe },
			argv0:   func() string { return argv0 },
			resolve: func(p string) string { return p },
			trustedBinary: func(p string) bool {
				for _, t := range trusted {
					if t == p {
						return true
					}
				}
				return false
			},
		}
	}

	// a process path is run only when root runs that very file
	assert.Equal(t, []string{"/usr/local/bin/containerd", "containerd"},
		containerdVersionBinaries(true, probe("/usr/local/bin/containerd", "/usr/local/bin/containerd")))
	// any other process named containerd gets nothing run from its path
	assert.Equal(t, []string{"containerd"},
		containerdVersionBinaries(true, probe("", "/tmp/evil/containerd")))
	// install paths only when root alone can change them
	assert.Equal(t, []string{"containerd", "/var/lib/rancher/rke2/bin/containerd"},
		containerdVersionBinaries(false, probe("", "", "/var/lib/rancher/rke2/bin/containerd")))
}
