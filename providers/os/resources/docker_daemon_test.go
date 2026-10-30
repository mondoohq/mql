// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/utils/syncx"
)

func readDockerDaemonFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "docker-daemon", name))
	require.NoError(t, err)
	return string(b)
}

func TestParseDockerDaemonJSON(t *testing.T) {
	t.Run("full Linux example from the dockerd reference", func(t *testing.T) {
		// docs/reference/dockerd.md in docker/cli; `dockerd --validate`
		// accepts every key and stops only at the empty TLS file paths
		cfg, err := parseDockerDaemonJSON(readDockerDaemonFixture(t, "docs-linux.json"))
		require.NoError(t, err)

		assert.False(t, dockerBool(cfg, "icc", true))
		assert.True(t, dockerBool(cfg, "live-restore", false))
		assert.False(t, dockerBool(cfg, "userland-proxy", true))
		assert.False(t, dockerBool(cfg, "iptables", true))
		assert.False(t, dockerBool(cfg, "ip-forward", true))
		assert.False(t, dockerBool(cfg, "selinux-enabled", true))
		assert.Equal(t, "json-file", dockerString(cfg, "log-driver", ""))
		// set to "", which dockerd treats as unset
		assert.Equal(t, "builtin", dockerString(cfg, "seccomp-profile", "builtin"))
		assert.Equal(t, "info", dockerString(cfg, "log-level", "info"))
		assert.Equal(t, "/var/lib/docker", dockerString(cfg, "data-root", "/var/lib/docker"))
		assert.Equal(t, "runc", dockerString(cfg, "default-runtime", ""))

		tls, verify := dockerTLS(cfg)
		assert.True(t, tls)
		assert.True(t, verify)

		// "hosts": [] listens on the default socket
		assert.Equal(t, []any{"unix:///var/run/docker.sock"}, dockerHosts(cfg, dockerdLinux.host))

		assert.Equal(t, map[string]any{
			"cc-runtime": "/usr/bin/cc-runtime",
			"custom":     "/usr/local/bin/my-runc-replacement",
		}, dockerRuntimes(cfg))

		assert.Equal(t, []dockerUlimit{{name: "nofile", soft: 64000, hard: 64000}}, dockerUlimits(cfg))
		assert.Equal(t, "10m", cfg["log-opts"].(map[string]any)["max-size"])
	})

	t.Run("empty file", func(t *testing.T) {
		cfg, err := parseDockerDaemonJSON("  \n")
		require.NoError(t, err)
		assert.Empty(t, cfg)
	})

	t.Run("malformed", func(t *testing.T) {
		_, err := parseDockerDaemonJSON(`{"icc": false,}`)
		assert.Error(t, err)
	})
}

func TestDockerDaemonDefaults(t *testing.T) {
	// nothing configured: what dockerd uses
	cfg := map[string]any{}
	assert.True(t, dockerBool(cfg, "icc", true))
	assert.Equal(t, []any{"unix:///var/run/docker.sock"}, dockerHosts(cfg, dockerdLinux.host))
	tls, verify := dockerTLS(cfg)
	assert.False(t, tls)
	assert.False(t, verify)
	assert.Empty(t, dockerRuntimes(cfg))
	assert.Empty(t, dockerUlimits(cfg))
	assert.Empty(t, dockerStringList(cfg["insecure-registries"]))
}

func TestDockerTLS(t *testing.T) {
	cases := []struct {
		name           string
		cfg            map[string]any
		tls, tlsVerify bool
	}{
		{"none", map[string]any{}, false, false},
		// dockerd copies tls into an unset tlsverify (cmd/dockerd/daemon.go:
		// "if conf.TLSVerify == nil && conf.TLS != nil"); verified live on
		// docker:29-dind started with --tls alone, which answers a client
		// without a certificate with "tlsv13 alert certificate required"
		{"tls alone verifies", map[string]any{"tls": true}, true, true},
		{"tls off", map[string]any{"tls": false}, false, false},
		{"tlsverify", map[string]any{"tlsverify": true}, true, true},
		// any tlsverify setting turns TLS on, even false
		{"tlsverify false", map[string]any{"tlsverify": false}, true, false},
		{"tlsverify false wins over tls false", map[string]any{"tls": false, "tlsverify": false}, true, false},
		{"tls without verification", map[string]any{"tls": true, "tlsverify": false}, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tls, verify := dockerTLS(c.cfg)
			assert.Equal(t, c.tls, tls)
			assert.Equal(t, c.tlsVerify, verify)
		})
	}
}

func TestDockerUlimitsKeyCase(t *testing.T) {
	// dockerd decodes with encoding/json, which matches keys regardless of case
	cfg, err := parseDockerDaemonJSON(`{"default-ulimits": {
		"nproc": {"name": "nproc", "soft": 2048, "hard": 4096},
		"core": {"Name": "core", "Soft": -1, "Hard": -1}}}`)
	require.NoError(t, err)
	assert.Equal(t, []dockerUlimit{
		{name: "core", soft: -1, hard: -1},
		{name: "nproc", soft: 2048, hard: 4096},
	}, dockerUlimits(cfg))
}

func TestDockerRuntimesShim(t *testing.T) {
	// a runtime with its own shim names a runtimeType instead of a path
	// (dockerd reference, "Configure containerd shims")
	cfg, err := parseDockerDaemonJSON(`{"runtimes": {"gvisor": {"runtimeType": "io.containerd.runsc.v1"}}}`)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"gvisor": "io.containerd.runsc.v1"}, dockerRuntimes(cfg))
}

func TestParseDockerdCommandLine(t *testing.T) {
	t.Run("docker:29-dind with TLS", func(t *testing.T) {
		// /proc/<pid>/cmdline of dockerd in docker:29-dind, started with extra flags
		c := parseDockerdCommandLine(strings.TrimSpace(readDockerDaemonFixture(t, "dind-tls.cmdline")))
		assert.Equal(t, "", c.configFile)
		s := c.settings
		assert.Equal(t, []any{"unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"}, s["hosts"])
		assert.Equal(t, true, s["tlsverify"])
		assert.Equal(t, "/certs/server/ca.pem", s["tlscacert"])
		assert.Equal(t, "/certs/server/cert.pem", s["tlscert"])
		assert.Equal(t, "/certs/server/key.pem", s["tlskey"])
		assert.Equal(t, false, s["icc"])
		assert.Equal(t, true, s["live-restore"])
		assert.Equal(t, false, s["userland-proxy"])
		assert.Equal(t, map[string]any{"max-size": "10m", "max-file": "3"}, s["log-opts"])
		assert.Equal(t, []any{"myreg.example:5000"}, s["insecure-registries"])
		assert.Equal(t, []dockerUlimit{{name: "nofile", soft: 1024, hard: 2048}}, dockerUlimits(s))

		tls, verify := dockerTLS(s)
		assert.True(t, tls)
		assert.True(t, verify)
	})

	t.Run("docker:29-dind without TLS", func(t *testing.T) {
		// DOCKER_TLS_CERTDIR= : a TCP listener with no TLS at all
		c := parseDockerdCommandLine(strings.TrimSpace(readDockerDaemonFixture(t, "dind-notls.cmdline")))
		assert.Equal(t, []any{"unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"}, dockerHosts(c.settings, dockerdLinux.host))
		tls, verify := dockerTLS(c.settings)
		assert.False(t, tls)
		assert.False(t, verify)
	})

	t.Run("docker-ce systemd unit", func(t *testing.T) {
		// ExecStart of docker.service in the docker-ce packages
		c := parseDockerdCommandLine("/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock")
		assert.Equal(t, map[string]any{
			"hosts":      []any{"fd://"},
			"containerd": "/run/containerd/containerd.sock",
		}, c.settings)
	})

	t.Run("config file, short flags and false booleans", func(t *testing.T) {
		c := parseDockerdCommandLine("/usr/bin/dockerd --config-file /srv/docker/daemon.json " +
			"-H unix:///run/docker.sock -Htcp://127.0.0.1:2376 -H=tcp://10.0.0.1:2376 " +
			"--tlsverify=false -D --selinux-enabled -s overlay2 --icc=0 " +
			"--add-runtime nvidia=/usr/bin/nvidia-container-runtime " +
			"--feature containerd-snapshotter --feature cdi=false " +
			"--dns 1.1.1.1,8.8.8.8 --dns 9.9.9.9 --default-ulimit nproc=512 --mtu 1400")
		assert.Equal(t, "/srv/docker/daemon.json", c.configFile)
		s := c.settings
		assert.Equal(t, []any{"unix:///run/docker.sock", "tcp://127.0.0.1:2376", "tcp://10.0.0.1:2376"}, s["hosts"])
		assert.Equal(t, false, s["tlsverify"])
		assert.Equal(t, true, s["debug"])
		assert.Equal(t, true, s["selinux-enabled"])
		assert.Equal(t, "overlay2", s["storage-driver"])
		assert.Equal(t, false, s["icc"])
		assert.Equal(t, map[string]any{"nvidia": "/usr/bin/nvidia-container-runtime"}, dockerRuntimes(s))
		assert.Equal(t, map[string]any{"containerd-snapshotter": true, "cdi": false}, s["features"])
		assert.Equal(t, []any{"1.1.1.1", "8.8.8.8", "9.9.9.9"}, s["dns"])
		assert.Equal(t, []dockerUlimit{{name: "nproc", soft: 512, hard: 512}}, dockerUlimits(s))
		assert.Equal(t, float64(1400), s["mtu"])
		assert.NotContains(t, s, "config-file")

		tls, verify := dockerTLS(s)
		assert.True(t, tls)
		assert.False(t, verify)
	})

	t.Run("a boolean flag never takes the next word", func(t *testing.T) {
		c := parseDockerdCommandLine("dockerd --tlsverify --tlscacert /etc/docker/ca.pem")
		assert.Equal(t, true, c.settings["tlsverify"])
		assert.Equal(t, "/etc/docker/ca.pem", c.settings["tlscacert"])
	})

	t.Run("combined short booleans", func(t *testing.T) {
		c := parseDockerdCommandLine("dockerd -DH unix:///var/run/docker.sock")
		assert.Equal(t, true, c.settings["debug"])
		assert.Equal(t, []any{"unix:///var/run/docker.sock"}, c.settings["hosts"])
	})
}

func TestMergeDockerDaemonConfig(t *testing.T) {
	// /etc/docker/daemon.json and command line of the docker:29-dind container
	// verified live: dockerd started with both and reported their union
	file, err := parseDockerDaemonJSON(readDockerDaemonFixture(t, "dind.json"))
	require.NoError(t, err)
	flags := parseDockerdCommandLine(strings.TrimSpace(readDockerDaemonFixture(t, "dind-tls.cmdline"))).settings

	cfg := mergeDockerDaemonConfig(file, flags)
	assert.True(t, dockerBool(cfg, "no-new-privileges", false))
	assert.Equal(t, "unconfined", dockerString(cfg, "seccomp-profile", "builtin"))
	assert.Equal(t, []any{"https://mirror.gcr.io"}, dockerStringList(cfg["registry-mirrors"]))
	assert.False(t, dockerBool(cfg, "icc", true))
	assert.True(t, dockerBool(cfg, "live-restore", false))

	// SUSE's docker.service adds the oci runtime on the command line. With a
	// runtime in daemon.json as well, dockerd 29.4 on SLES 15 SP7 started and
	// `docker info` listed both, crun and oci, besides the built-in runc.
	file, err = parseDockerDaemonJSON(readDockerDaemonFixture(t, "sles15-hardened.json"))
	require.NoError(t, err)
	flags = parseDockerdCommandLine(strings.TrimSpace(readDockerDaemonFixture(t, "sles15.cmdline"))).settings
	cfg = mergeDockerDaemonConfig(file, flags)
	assert.Equal(t, map[string]any{"crun": "/usr/libexec/crio/crun", "oci": "/usr/sbin/runc"}, dockerRuntimes(cfg))
	cfg = mergeDockerDaemonConfig(map[string]any{}, flags)
	assert.Equal(t, map[string]any{"oci": "/usr/sbin/runc"}, dockerRuntimes(cfg), "the flag's runtime alone")

	// dockerd refuses to start with a setting in both; should one still
	// appear in both, the file's value is the one reported
	cfg = mergeDockerDaemonConfig(map[string]any{"icc": true}, map[string]any{"icc": false, "debug": true})
	assert.Equal(t, true, cfg["icc"])
	assert.Equal(t, true, cfg["debug"])
}

func TestIsDockerdExecutable(t *testing.T) {
	assert.True(t, isDockerdExecutable("/usr/bin/dockerd"))
	assert.True(t, isDockerdExecutable(`C:\Program Files\Docker\dockerd.exe`))
	assert.True(t, isDockerdExecutable(`C:\Program Files\Docker\Docker\resources\DOCKERD.EXE`))
	assert.True(t, isDockerdExecutable("dockerd"))
	assert.False(t, isDockerdExecutable("/usr/bin/dockerd-rootless.sh"))
	assert.False(t, isDockerdExecutable(`C:\Program Files\Docker\docker.exe`))
	assert.False(t, isDockerdExecutable("/usr/bin/containerd"))
}

func dockerDaemonTestRuntime(t *testing.T, family []string, files map[string]string) *plugin.Runtime {
	t.Helper()
	mfs := afero.NewMemMapFs()
	for p, content := range files {
		writeMemFSFile(t, mfs, p, []byte(content))
	}
	asset := &inventory.Asset{Platform: &inventory.Platform{Name: family[0], Family: family}}
	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, asset, "", nil, mfs)
	require.NoError(t, err)
	return &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}
}

func newTestDockerDaemon(t *testing.T, rt *plugin.Runtime) *mqlDockerDaemon {
	t.Helper()
	r, err := NewResource(rt, "docker.daemon", map[string]*llx.RawData{})
	require.NoError(t, err)
	return r.(*mqlDockerDaemon)
}

// Without a dockerd on the target, dockerd's defaults say nothing about it:
// no listener, no default setting, while the configuration file it would
// read is still named.
func TestDockerDaemonNotInstalled(t *testing.T) {
	for name, family := range map[string][]string{
		"linux":   {"debian", "linux", "unix"},
		"windows": {"windows"},
	} {
		t.Run(name, func(t *testing.T) {
			d := newTestDockerDaemon(t, dockerDaemonTestRuntime(t, family, nil))

			hosts := d.GetHosts()
			require.NoError(t, hosts.Error)
			assert.True(t, hosts.IsNull())
			assert.Nil(t, hosts.Data)

			icc := d.GetIcc()
			require.NoError(t, icc.Error)
			assert.True(t, icc.IsNull())
			assert.True(t, d.GetTlsVerify().IsNull())
			assert.True(t, d.GetDataRoot().IsNull())
			assert.True(t, d.GetLogDriver().IsNull())

			cf := d.GetConfigFile()
			require.NoError(t, cf.Error)
			assert.Equal(t, dockerdPlatformFor(family[0]).configFile, cf.Data.Path.Data)
		})
	}
}

func TestDockerDaemonWindowsDefaults(t *testing.T) {
	rt := dockerDaemonTestRuntime(t, []string{"windows"}, map[string]string{
		`C:\Program Files\Docker\dockerd.exe`: "MZ",
	})
	d := newTestDockerDaemon(t, rt)
	assert.Equal(t, []any{"npipe:////./pipe/docker_engine"}, d.GetHosts().Data)
	assert.Equal(t, `C:\ProgramData\docker`, d.GetDataRoot().Data)
	assert.Equal(t, `C:\ProgramData\docker\config\daemon.json`, d.GetConfigFile().Data.Path.Data)
	icc := d.GetIcc()
	assert.False(t, icc.IsNull())
	assert.True(t, icc.Data)
}

func TestDockerDaemonConfigFileMeansInstalled(t *testing.T) {
	rt := dockerDaemonTestRuntime(t, []string{"windows"}, map[string]string{
		`C:\ProgramData\docker\config\daemon.json`: `{"hosts": ["tcp://0.0.0.0:2375"], "data-root": "D:\\docker"}`,
	})
	d := newTestDockerDaemon(t, rt)
	hosts := d.GetHosts()
	require.NoError(t, hosts.Error)
	assert.Equal(t, []any{"tcp://0.0.0.0:2375"}, hosts.Data)
	assert.Equal(t, `D:\docker`, d.GetDataRoot().Data)
	assert.False(t, d.GetTlsVerify().Data)
	assert.False(t, d.GetTlsVerify().IsNull())
}

func TestDockerDaemonLinuxBinaryMeansInstalled(t *testing.T) {
	rt := dockerDaemonTestRuntime(t, []string{"debian", "linux", "unix"}, map[string]string{
		"/usr/bin/dockerd": "ELF",
	})
	d := newTestDockerDaemon(t, rt)
	assert.Equal(t, []any{"unix:///var/run/docker.sock"}, d.GetHosts().Data)
	assert.Equal(t, "/var/lib/docker", d.GetDataRoot().Data)
}
