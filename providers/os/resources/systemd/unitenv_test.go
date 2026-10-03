// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package systemd

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testFs(files map[string]string) *afero.Afero {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	for p, content := range files {
		if err := afs.WriteFile(p, []byte(content), 0o644); err != nil {
			panic(err)
		}
	}
	return afs
}

// archUnit is /usr/lib/systemd/system/ollama.service as shipped by the Arch
// ollama package (0.32.14-1), copied verbatim. It is the reason the models
// directory cannot be assumed to be $HOME/.ollama/models.
const archUnit = `[Unit]
Description=Ollama Service
Wants=network-online.target
After=network.target network-online.target

[Service]
ExecStart=/usr/bin/ollama serve
WorkingDirectory=/var/lib/ollama
Environment="HOME=/var/lib/ollama"
Environment="OLLAMA_MODELS=/var/lib/ollama"
User=ollama
Group=ollama
Restart=on-failure
RestartSec=3
RestartPreventExitStatus=1
Type=simple
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes

[Install]
WantedBy=multi-user.target
`

func TestResolveUnitEnv_ArchPackagedUnit(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service": archUnit,
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, "/var/lib/ollama", env.Vars["OLLAMA_MODELS"])
	assert.Equal(t, "/var/lib/ollama", env.Vars["HOME"])
	assert.Equal(t, "/usr/lib/systemd/system/ollama.service", env.FragmentPath)
	assert.Equal(t, "/usr/lib/systemd/system/ollama.service", env.Sources["OLLAMA_MODELS"])
	// Directives outside [Service] and non-environment ones must not leak in.
	assert.NotContains(t, env.Vars, "Description")
	assert.NotContains(t, env.Vars, "User")
	assert.Equal(t, "ollama", env.User, "User= is read as a setting, not as a variable")
	assert.Equal(t, "/usr/bin/ollama serve", env.ExecStart)
}

func TestResolveUnitEnv_ExecStartModifiers(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service": "[Service]\nExecStart=-/usr/local/bin/ollama serve\n",
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)
	assert.Equal(t, "/usr/local/bin/ollama serve", env.ExecStart)
}

func TestResolveUnitEnv_NotInstalled(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/sshd.service": "[Service]\nEnvironment=X=1\n",
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	assert.False(t, ok)
	assert.Empty(t, env.Vars)
	assert.Empty(t, env.FragmentPath)
}

// The documented way to expose Ollama on a network is a drop-in that sets
// OLLAMA_HOST. It has to beat the packaged unit, or the resource reports the
// loopback default on a host that is listening on every interface.
func TestResolveUnitEnv_DropInOverridesFragment(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service": archUnit,
		"/etc/systemd/system/ollama.service.d/override.conf": `[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_MODELS=/srv/models"
`,
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, "0.0.0.0:11434", env.Vars["OLLAMA_HOST"])
	assert.Equal(t, "/srv/models", env.Vars["OLLAMA_MODELS"])
	assert.Equal(t, "/var/lib/ollama", env.Vars["HOME"], "untouched fragment settings survive")
	assert.Equal(t, []string{"/etc/systemd/system/ollama.service.d/override.conf"}, env.DropInPaths)
	assert.Equal(t, "/etc/systemd/system/ollama.service.d/override.conf", env.Sources["OLLAMA_MODELS"])
}

func TestResolveUnitEnv_DropInsApplyInLexicographicOrder(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service":         "[Service]\nEnvironment=OLLAMA_HOST=127.0.0.1\n",
		"/etc/systemd/system/ollama.service.d/20-b.conf": "[Service]\nEnvironment=OLLAMA_HOST=10.0.0.2\n",
		"/etc/systemd/system/ollama.service.d/10-a.conf": "[Service]\nEnvironment=OLLAMA_HOST=10.0.0.1\n",
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, "10.0.0.2", env.Vars["OLLAMA_HOST"], "20- is applied after 10-")
	assert.Equal(t, []string{
		"/etc/systemd/system/ollama.service.d/10-a.conf",
		"/etc/systemd/system/ollama.service.d/20-b.conf",
	}, env.DropInPaths)
}

// Equally named drop-ins: /etc wins over /run wins over /usr/lib, and only the
// winner is applied.
func TestResolveUnitEnv_DropInDirectoryPrecedence(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service":             "[Service]\nEnvironment=OLLAMA_HOST=127.0.0.1\n",
		"/usr/lib/systemd/system/ollama.service.d/10-x.conf": "[Service]\nEnvironment=OLLAMA_HOST=from-usr\n",
		"/run/systemd/system/ollama.service.d/10-x.conf":     "[Service]\nEnvironment=OLLAMA_HOST=from-run\n",
		"/etc/systemd/system/ollama.service.d/10-x.conf":     "[Service]\nEnvironment=OLLAMA_HOST=from-etc\n",
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, "from-etc", env.Vars["OLLAMA_HOST"])
	assert.Equal(t, []string{"/etc/systemd/system/ollama.service.d/10-x.conf"}, env.DropInPaths)
}

// A unit in /etc replaces the packaged one outright rather than merging with it.
func TestResolveUnitEnv_FragmentPrecedence(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service": archUnit,
		"/etc/systemd/system/ollama.service":     "[Service]\nEnvironment=OLLAMA_HOST=0.0.0.0\n",
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, "/etc/systemd/system/ollama.service", env.FragmentPath)
	assert.Equal(t, "0.0.0.0", env.Vars["OLLAMA_HOST"])
	assert.NotContains(t, env.Vars, "OLLAMA_MODELS", "the packaged unit is replaced, not merged")
}

func TestResolveUnitEnv_EmptyEnvironmentResets(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service": archUnit,
		"/etc/systemd/system/ollama.service.d/reset.conf": `[Service]
Environment=
Environment=OLLAMA_HOST=0.0.0.0
`,
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, "0.0.0.0", env.Vars["OLLAMA_HOST"])
	assert.NotContains(t, env.Vars, "OLLAMA_MODELS", "the reset drops the fragment's assignments")
	assert.NotContains(t, env.Vars, "HOME")
}

// systemd.exec(5): "Settings from these files override settings made with
// Environment=" — regardless of which appears first in the unit.
func TestResolveUnitEnv_EnvironmentFileOverridesInlineEnvironment(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service": `[Service]
EnvironmentFile=/etc/sysconfig/ollama
Environment=OLLAMA_HOST=127.0.0.1
Environment=OLLAMA_DEBUG=0
`,
		"/etc/sysconfig/ollama": "OLLAMA_HOST=0.0.0.0:11434\n",
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, "0.0.0.0:11434", env.Vars["OLLAMA_HOST"])
	assert.Equal(t, "0", env.Vars["OLLAMA_DEBUG"], "variables the file does not set keep the inline value")
	assert.Equal(t, "/etc/sysconfig/ollama", env.Sources["OLLAMA_HOST"])
	assert.Equal(t, []string{"/etc/sysconfig/ollama"}, env.EnvironmentFilePaths)
}

func TestResolveUnitEnv_LaterEnvironmentFileWins(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service": `[Service]
EnvironmentFile=/etc/default/ollama
EnvironmentFile=/etc/sysconfig/ollama
`,
		"/etc/default/ollama":   "OLLAMA_HOST=10.0.0.1\n",
		"/etc/sysconfig/ollama": "OLLAMA_HOST=10.0.0.2\n",
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, "10.0.0.2", env.Vars["OLLAMA_HOST"])
}

func TestResolveUnitEnv_MissingEnvironmentFile(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service": `[Service]
Environment=OLLAMA_HOST=127.0.0.1
EnvironmentFile=-/etc/default/ollama
`,
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, "127.0.0.1", env.Vars["OLLAMA_HOST"])
	assert.Empty(t, env.EnvironmentFilePaths, "a file that was never read is not reported as a source")
}

func TestResolveUnitEnv_EmptyEnvironmentFileResetsList(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service":          "[Service]\nEnvironmentFile=/etc/default/ollama\n",
		"/etc/systemd/system/ollama.service.d/reset.conf": "[Service]\nEnvironmentFile=\n",
		"/etc/default/ollama":                             "OLLAMA_HOST=0.0.0.0\n",
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.NotContains(t, env.Vars, "OLLAMA_HOST")
	assert.Empty(t, env.EnvironmentFilePaths)
}

func TestResolveUnitEnv_QuotingAndContinuation(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service": `[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434" "OLLAMA_ORIGINS=http://a.example,http://b.example"
Environment=OLLAMA_KV_CACHE_TYPE=q8_0 OLLAMA_NUM_PARALLEL=4
Environment="OLLAMA_LLM_LIBRARY=cpu avx2"
Environment="OLLAMA_MODELS=/srv/a" \
            "OLLAMA_KEEP_ALIVE=-1"
`,
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, "0.0.0.0:11434", env.Vars["OLLAMA_HOST"])
	assert.Equal(t, "http://a.example,http://b.example", env.Vars["OLLAMA_ORIGINS"])
	assert.Equal(t, "q8_0", env.Vars["OLLAMA_KV_CACHE_TYPE"])
	assert.Equal(t, "4", env.Vars["OLLAMA_NUM_PARALLEL"])
	assert.Equal(t, "cpu avx2", env.Vars["OLLAMA_LLM_LIBRARY"], "a quoted value keeps its interior space")
	assert.Equal(t, "/srv/a", env.Vars["OLLAMA_MODELS"])
	assert.Equal(t, "-1", env.Vars["OLLAMA_KEEP_ALIVE"], "a continuation line is part of the same directive")
}

func TestResolveUnitEnv_IgnoresOtherSections(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service": `[Unit]
Environment=OLLAMA_HOST=should-not-be-read

[Service]
Environment=OLLAMA_HOST=127.0.0.1

[Install]
Environment=OLLAMA_HOST=also-not-read
`,
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, "127.0.0.1", env.Vars["OLLAMA_HOST"])
}

func TestResolveUnitEnv_Files(t *testing.T) {
	afs := testFs(map[string]string{
		"/usr/lib/systemd/system/ollama.service":           "[Service]\nEnvironmentFile=/etc/default/ollama\n",
		"/etc/systemd/system/ollama.service.d/10-net.conf": "[Service]\nEnvironment=OLLAMA_HOST=0.0.0.0\n",
		"/etc/default/ollama":                              "OLLAMA_DEBUG=1\n",
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)

	assert.Equal(t, []string{
		"/usr/lib/systemd/system/ollama.service",
		"/etc/systemd/system/ollama.service.d/10-net.conf",
		"/etc/default/ollama",
	}, env.Files())
}

func TestParseEnvFile(t *testing.T) {
	got := ParseEnvFile(`# a comment
; another comment

OLLAMA_HOST=0.0.0.0:11434
OLLAMA_ORIGINS="http://a.example,http://b.example"
OLLAMA_LLM_LIBRARY='cpu avx2'
   OLLAMA_DEBUG=1
a line without an equals sign
OLLAMA_EMPTY=
`)

	assert.Equal(t, map[string]string{
		"OLLAMA_HOST":        "0.0.0.0:11434",
		"OLLAMA_ORIGINS":     "http://a.example,http://b.example",
		"OLLAMA_LLM_LIBRARY": "cpu avx2",
		"OLLAMA_DEBUG":       "1",
		"OLLAMA_EMPTY":       "",
	}, got)
}

// On a merged-usr system /lib is a symlink to /usr/lib, so a unit is visible
// under both. systemd reports the /usr/lib path, and so should this.
func TestResolveUnitEnv_PrefersUsrLibOverLib(t *testing.T) {
	afs := testFs(map[string]string{
		"/lib/systemd/system/ollama.service":     archUnit,
		"/usr/lib/systemd/system/ollama.service": archUnit,
	})

	env, ok := ResolveUnitEnv(afs, "ollama.service")
	require.True(t, ok)
	assert.Equal(t, "/usr/lib/systemd/system/ollama.service", env.FragmentPath)
}

// dropInProbe is the layout of a throwaway unit, mqlt-a-b.service, with
// clashing drop-ins at every level systemd reads: the unit's own directory,
// both dash prefixes (mqlt-a-.service.d, mqlt-.service.d) and the type-level
// service.d, spread over /etc, /run and /usr/lib. Each value names where it
// came from, so the winner of every clash is visible in the environment.
var dropInProbe = map[string]string{
	"/run/systemd/system/mqlt-a-b.service":                     "[Service]\nType=oneshot\nExecStart=/bin/true\n",
	"/etc/systemd/system/service.d/50-proxy.conf":              "[Service]\nEnvironment=HTTPS_PROXY=http://proxy.example.com:3128 NO_PROXY=localhost,127.0.0.1\n",
	"/etc/systemd/system/service.d/60-x.conf":                  "[Service]\nEnvironment=X60=etc-type\n",
	"/run/systemd/system/mqlt-a-b.service.d/60-x.conf":         "[Service]\nEnvironment=X60=run-unit\n",
	"/etc/systemd/system/service.d/61-y.conf":                  "[Service]\nEnvironment=X61=etc-type\n",
	"/usr/lib/systemd/system/mqlt-a-b.service.d/61-y.conf":     "[Service]\nEnvironment=X61=usr-unit\n",
	"/etc/systemd/system/mqlt-.service.d/62-z.conf":            "[Service]\nEnvironment=X62=etc-prefix1\n",
	"/etc/systemd/system/mqlt-a-b.service.d/62-z.conf":         "[Service]\nEnvironment=X62=etc-unit\n",
	"/etc/systemd/system/mqlt-.service.d/63-w.conf":            "[Service]\nEnvironment=X63=etc-prefix1\n",
	"/run/systemd/system/mqlt-a-.service.d/63-w.conf":          "[Service]\nEnvironment=X63=run-prefix2\n",
	"/etc/systemd/system/mqlt-a-.service.d/64-v.conf":          "[Service]\nEnvironment=X64=etc-prefix2\n",
	"/usr/lib/systemd/system/mqlt-a-b.service.d/64-v.conf":     "[Service]\nEnvironment=X64=usr-unit\n",
	"/run/systemd/system/mqlt-a-.service.d/70-p.conf":          "[Service]\nEnvironment=X70=run-prefix2\n",
	"/usr/lib/systemd/system/service.d/71-q.conf":              "[Service]\nEnvironment=X71=usr-type\n",
	"/usr/lib/systemd/system/socket.d/72-other-type.conf":      "[Service]\nEnvironment=X72=wrong-type\n",
	"/etc/systemd/system/mqlt-a-b.service.d/73-not-a-conf.txt": "[Service]\nEnvironment=X73=not-conf\n",
}

// TestResolveUnitEnv_TypeAndPrefixDropIns pins the result systemctl show
// reported for dropInProbe on systemd 239 (RHEL 8), 247 (Debian 11), 252
// (RHEL 9) and 259 (Fedora 44), which all agreed:
//
//	DropInPaths=/etc/systemd/system/service.d/50-proxy.conf
//	  /run/systemd/system/mqlt-a-b.service.d/60-x.conf
//	  /usr/lib/systemd/system/mqlt-a-b.service.d/61-y.conf
//	  /etc/systemd/system/mqlt-a-b.service.d/62-z.conf
//	  /etc/systemd/system/mqlt-.service.d/63-w.conf
//	  /etc/systemd/system/mqlt-a-.service.d/64-v.conf
//	  /run/systemd/system/mqlt-a-.service.d/70-p.conf
//	  /usr/lib/systemd/system/service.d/71-q.conf
//
// For a clashing file name the unit's own and its prefix directories rank by
// directory first (/etc, /run, /usr/lib) and by specificity within one
// directory, and all of them beat the type-level service.d.
func TestResolveUnitEnv_TypeAndPrefixDropIns(t *testing.T) {
	afs := testFs(dropInProbe)

	env, ok := ResolveUnitEnvWithDirs(afs, "mqlt-a-b.service", AllDropInDirs)
	require.True(t, ok)

	assert.Equal(t, []string{
		"/etc/systemd/system/service.d/50-proxy.conf",
		"/run/systemd/system/mqlt-a-b.service.d/60-x.conf",
		"/usr/lib/systemd/system/mqlt-a-b.service.d/61-y.conf",
		"/etc/systemd/system/mqlt-a-b.service.d/62-z.conf",
		"/etc/systemd/system/mqlt-.service.d/63-w.conf",
		"/etc/systemd/system/mqlt-a-.service.d/64-v.conf",
		"/run/systemd/system/mqlt-a-.service.d/70-p.conf",
		"/usr/lib/systemd/system/service.d/71-q.conf",
	}, env.DropInPaths)
	assert.Equal(t, map[string]string{
		"HTTPS_PROXY": "http://proxy.example.com:3128",
		"NO_PROXY":    "localhost,127.0.0.1",
		"X60":         "run-unit",
		"X61":         "usr-unit",
		"X62":         "etc-unit",
		"X63":         "etc-prefix1",
		"X64":         "etc-prefix2",
		"X70":         "run-prefix2",
		"X71":         "usr-type",
	}, env.Vars)
	assert.Equal(t, "/etc/systemd/system/service.d/50-proxy.conf", env.Sources["HTTPS_PROXY"])

	// Unknown version (systemctl not runnable, e.g. a mounted image) reads
	// drop-ins the way every supported systemd release does.
	unknown, ok := ResolveUnitEnv(afs, "mqlt-a-b.service")
	require.True(t, ok)
	assert.Equal(t, env.DropInPaths, unknown.DropInPaths)
}

// TestResolveUnitEnv_PrefixOnlySystemd pins systemd 241 (Debian 10) on the
// same layout: prefix directories count, the type-level service.d does not.
//
//	DropInPaths=/run/systemd/system/mqlt-a-b.service.d/60-x.conf
//	  /usr/lib/systemd/system/mqlt-a-b.service.d/61-y.conf
//	  /etc/systemd/system/mqlt-a-b.service.d/62-z.conf
//	  /etc/systemd/system/mqlt-.service.d/63-w.conf
//	  /etc/systemd/system/mqlt-a-.service.d/64-v.conf
//	  /run/systemd/system/mqlt-a-.service.d/70-p.conf
func TestResolveUnitEnv_PrefixOnlySystemd(t *testing.T) {
	afs := testFs(dropInProbe)

	env, ok := ResolveUnitEnvWithDirs(afs, "mqlt-a-b.service", DropInDirsForVersion(241, false))
	require.True(t, ok)
	assert.Equal(t, []string{
		"/run/systemd/system/mqlt-a-b.service.d/60-x.conf",
		"/usr/lib/systemd/system/mqlt-a-b.service.d/61-y.conf",
		"/etc/systemd/system/mqlt-a-b.service.d/62-z.conf",
		"/etc/systemd/system/mqlt-.service.d/63-w.conf",
		"/etc/systemd/system/mqlt-a-.service.d/64-v.conf",
		"/run/systemd/system/mqlt-a-.service.d/70-p.conf",
	}, env.DropInPaths)
	assert.NotContains(t, env.Vars, "HTTPS_PROXY")
	assert.Equal(t, "run-unit", env.Vars["X60"])
}

// TestResolveUnitEnv_LegacySystemdIgnoresTypeAndPrefixDropIns pins systemd 219
// (RHEL 7) and 232 (Debian 9) on the same layout: only the unit's own
// directories count.
//
//	DropInPaths=/run/systemd/system/mqlt-a-b.service.d/60-x.conf
//	  /usr/lib/systemd/system/mqlt-a-b.service.d/61-y.conf
//	  /etc/systemd/system/mqlt-a-b.service.d/62-z.conf
//	  /usr/lib/systemd/system/mqlt-a-b.service.d/64-v.conf
func TestResolveUnitEnv_LegacySystemdIgnoresTypeAndPrefixDropIns(t *testing.T) {
	afs := testFs(dropInProbe)

	for _, v := range []int{219, 232, 238} {
		env, ok := ResolveUnitEnvWithDirs(afs, "mqlt-a-b.service", DropInDirsForVersion(v, false))
		require.True(t, ok)
		assert.Equal(t, []string{
			"/run/systemd/system/mqlt-a-b.service.d/60-x.conf",
			"/usr/lib/systemd/system/mqlt-a-b.service.d/61-y.conf",
			"/etc/systemd/system/mqlt-a-b.service.d/62-z.conf",
			"/usr/lib/systemd/system/mqlt-a-b.service.d/64-v.conf",
		}, env.DropInPaths, v)
		assert.NotContains(t, env.Vars, "HTTPS_PROXY", v)
	}
}

// When systemd reports the drop-ins, they are the ones applied, even where the
// directory rules would pick others.
func TestResolveUnitEnvWithDropIns(t *testing.T) {
	afs := testFs(dropInProbe)

	reported := []string{
		"/run/systemd/system/mqlt-a-b.service.d/60-x.conf",
		"/etc/systemd/system/mqlt-.service.d/63-w.conf",
	}
	env, ok := ResolveUnitEnvWithDropIns(afs, "mqlt-a-b.service", reported)
	require.True(t, ok)
	assert.Equal(t, reported, env.DropInPaths)
	assert.Equal(t, map[string]string{"X60": "run-unit", "X63": "etc-prefix1"}, env.Vars)

	_, ok = ResolveUnitEnvWithDropIns(afs, "ollama.service", reported)
	assert.False(t, ok, "a unit with no unit file is not installed")
}

func TestParseDropInPaths(t *testing.T) {
	// Debian 11, systemd 247
	paths, ok := ParseDropInPaths("LoadState=loaded\nDropInPaths=/etc/systemd/system/service.d/50-proxy.conf /etc/systemd/system/ollama.service.d/override.conf\n")
	require.True(t, ok)
	assert.Equal(t, []string{
		"/etc/systemd/system/service.d/50-proxy.conf",
		"/etc/systemd/system/ollama.service.d/override.conf",
	}, paths)

	// Loaded without drop-ins: an authoritative empty list.
	paths, ok = ParseDropInPaths("LoadState=loaded\nDropInPaths=\n")
	assert.True(t, ok)
	assert.Empty(t, paths)

	// A unit systemd does not know (systemctl exits 0 for it).
	_, ok = ParseDropInPaths("LoadState=not-found\nDropInPaths=\n")
	assert.False(t, ok)

	_, ok = ParseDropInPaths("LoadState=masked\nDropInPaths=\n")
	assert.False(t, ok)

	_, ok = ParseDropInPaths("System has not been booted with systemd as init system (PID 1). Can't operate.\n")
	assert.False(t, ok)
}

func TestDropInDirsForVersion(t *testing.T) {
	cases := []struct {
		version  int
		backport bool
		want     DropInDirs
	}{
		{0, false, AllDropInDirs},
		{219, false, DropInDirs{}},
		{219, true, DropInDirs{}},
		{232, false, DropInDirs{}},
		{238, false, DropInDirs{}},
		{239, false, DropInDirs{Prefix: true}},
		{241, false, DropInDirs{Prefix: true}},
		// Type-level drop-ins arrived in 244 (NEWS: "CHANGES WITH 244"); Ubuntu
		// 20.04's 245 applies /etc/systemd/system/service.d.
		{243, false, DropInDirs{Prefix: true}},
		{244, false, AllDropInDirs},
		{245, false, AllDropInDirs},
		{239, true, AllDropInDirs},
		{246, false, AllDropInDirs},
		{247, false, AllDropInDirs},
		{259, false, AllDropInDirs},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, DropInDirsForVersion(c.version, c.backport), "%d backport=%v", c.version, c.backport)
	}
}

func TestInstalledVersion(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		want  int
	}{
		// Debian 9, before the /usr merge
		"debian9": {map[string]string{"/lib/systemd/libsystemd-shared-232.so": ""}, 232},
		// Debian 10 and 11 after the /usr merge: the same file under both paths
		"debian10": {map[string]string{
			"/lib/systemd/libsystemd-shared-241.so":     "",
			"/usr/lib/systemd/libsystemd-shared-241.so": "",
		}, 241},
		// Debian 12 and 13, multiarch directory
		"debian13": {map[string]string{"/usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-257.so": ""}, 257},
		// SLES 15 SP7 and SLES 16.0 put the library in /usr/lib64 and name it
		// with the full package version; Leap 15.6 uses the short name there
		"sles15": {map[string]string{"/usr/lib64/systemd/libsystemd-shared-254.27-150600.4.71.2.so": ""}, 254},
		"sles16": {map[string]string{"/usr/lib64/systemd/libsystemd-shared-257.13-160000.1.1.so": ""}, 257},
		"leap15": {map[string]string{"/usr/lib64/systemd/libsystemd-shared-254.so": ""}, 254},
		"none":   {map[string]string{"/usr/lib/systemd/system/ollama.service": ""}, 0},
	}
	for name, c := range cases {
		assert.Equal(t, c.want, InstalledVersion(testFs(c.files)), name)
	}
}
func TestUnitNamePrefixes(t *testing.T) {
	assert.Equal(t, []string{"foo-bar-.service", "foo-.service"}, unitNamePrefixes("foo-bar-baz.service"))
	assert.Empty(t, unitNamePrefixes("ollama.service"))
	assert.Empty(t, unitNamePrefixes("noext"))
	// A trailing dash names the prefix unit itself, which is not its own prefix.
	assert.Equal(t, []string{"foo-.service"}, unitNamePrefixes("foo-bar-.service"))
}
