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
