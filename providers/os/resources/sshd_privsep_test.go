// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// stderr of `sshd -T` on Ubuntu 24.04 (OpenSSH 9.6p1) after a boot, before
// the socket-activated ssh.service has run and created /run/sshd
const ubuntuMissingPrivsepStderr = "Missing privilege separation directory: /run/sshd\n"

func sshdUbuntuMockRuntime(t *testing.T, commands map[string]*mock.Command) *plugin.Runtime {
	t.Helper()
	asset := &inventory.Asset{Platform: &inventory.Platform{
		Name:    "ubuntu",
		Family:  []string{"debian", "linux", "unix", "os"},
		Version: "24.04",
	}}
	conn, err := mock.New(0, asset, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func TestSshdInPrivateRun(t *testing.T) {
	assert.Equal(t,
		`unshare --mount --propagation private sh -c 'mount -t tmpfs -o mode=0755 tmpfs /run && mkdir -m 0755 /run/sshd && exec sshd -T'`,
		sshdInPrivateRun("sshd -T", "/run/sshd"))
	assert.Equal(t,
		`unshare --mount --propagation private sh -c 'mount -t tmpfs -o mode=0755 tmpfs /run && mkdir -m 0755 /run/sshd && exec sshd -T -f '"'"'/etc/ssh/my config'"'"''`,
		sshdInPrivateRun("sshd -T -f '/etc/ssh/my config'", "/run/sshd"))
}

func TestMissingSshdPrivsepDir(t *testing.T) {
	dir, ok := missingSshdPrivsepDir(ubuntuMissingPrivsepStderr)
	assert.True(t, ok)
	assert.Equal(t, "/run/sshd", dir)

	dir, ok = missingSshdPrivsepDir("Missing privilege separation directory: /var/run/sshd\n")
	assert.True(t, ok)
	assert.Equal(t, "/var/run/sshd", dir)

	for _, stderr := range []string{
		"Missing privilege separation directory: /var/empty\n",
		"Missing privilege separation directory: /run/a/b\n",
		"Missing privilege separation directory: /run/../etc\n",
		"Missing privilege separation directory: /run/ssh$(id)\n",
		"/etc/ssh/sshd_config line 12: Bad configuration option: Ciphersx\n",
		"",
	} {
		_, ok := missingSshdPrivsepDir(stderr)
		assert.False(t, ok, stderr)
	}
}

// Without /run/sshd, sshd -T runs again in a private mount namespace with a
// temporary /run and reports the effective configuration.
func TestSshdConfigEffectiveMissingPrivsepDir(t *testing.T) {
	runtime := sshdUbuntuMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command:    sshdEffectiveConfigCommand,
			Stderr:     ubuntuMissingPrivsepStderr,
			ExitStatus: 255,
		},
		sshdInPrivateRun(sshdEffectiveConfigCommand, "/run/sshd"): {
			Stdout: "ciphers aes256-gcm@openssh.com,aes128-ctr\nmacs hmac-sha2-256,hmac-sha1\nkexalgorithms curve25519-sha256\n",
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	config := raw.(*mqlSshdConfig)

	macs := config.GetEffectiveMacs()
	require.NoError(t, macs.Error)
	assert.Equal(t, []any{"hmac-sha2-256", "hmac-sha1"}, macs.Data)

	ciphers := config.GetEffectiveCiphers()
	require.NoError(t, ciphers.Error)
	assert.Equal(t, []any{"aes256-gcm@openssh.com", "aes128-ctr"}, ciphers.Data)

	kexs := config.GetEffectiveKexs()
	require.NoError(t, kexs.Error)
	assert.Equal(t, []any{"curve25519-sha256"}, kexs.Data)
}

// When the namespace cannot be created (no unshare, no CAP_SYS_ADMIN), the
// original error is kept and says why the retry did not help.
func TestSshdConfigEffectiveMissingPrivsepDirNoNamespace(t *testing.T) {
	runtime := sshdUbuntuMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command:    sshdEffectiveConfigCommand,
			Stderr:     ubuntuMissingPrivsepStderr,
			ExitStatus: 255,
		},
		sshdInPrivateRun(sshdEffectiveConfigCommand, "/run/sshd"): {
			Stderr:     "unshare: unshare failed: Operation not permitted\n",
			ExitStatus: 1,
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	macs := raw.(*mqlSshdConfig).GetEffectiveMacs()
	require.Error(t, macs.Error)
	assert.Equal(t,
		"sshd -T failed (exit 255): Missing privilege separation directory: /run/sshd "+
			"(sshd creates this directory when the ssh service starts; running sshd -T in a private mount namespace "+
			"with a temporary /run failed too: unshare: unshare failed: Operation not permitted)",
		macs.Error.Error())
}

// unshare not installed: the mock answers unknown commands with exit 1.
func TestSshdConfigEffectiveMissingPrivsepDirNoUnshare(t *testing.T) {
	runtime := sshdUbuntuMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command:    sshdEffectiveConfigCommand,
			Stderr:     ubuntuMissingPrivsepStderr,
			ExitStatus: 255,
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	macs := raw.(*mqlSshdConfig).GetEffectiveMacs()
	require.Error(t, macs.Error)
	assert.Contains(t, macs.Error.Error(), "sshd -T failed (exit 255): Missing privilege separation directory: /run/sshd (")
	assert.Contains(t, macs.Error.Error(), "failed too: command not found: unshare")
}

// A fatal sshd error inside the namespace is sshd's answer, and the -C retry
// for Match blocks then runs in the namespace too.
func TestSshdConfigEffectiveMissingPrivsepDirThenConnectionSpec(t *testing.T) {
	withSpec := sshdEffectiveConfigCommand + " -C " + sshdTestConnectionSpec
	runtime := sshdUbuntuMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command:    sshdEffectiveConfigCommand,
			Stderr:     ubuntuMissingPrivsepStderr,
			ExitStatus: 255,
		},
		sshdInPrivateRun(sshdEffectiveConfigCommand, "/run/sshd"): {
			Stderr:     debian10MatchUserStderr,
			ExitStatus: 255,
		},
		sshdInPrivateRun(withSpec, "/run/sshd"): {
			Stdout: "macs hmac-sha2-512\n",
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	macs := raw.(*mqlSshdConfig).GetEffectiveMacs()
	require.NoError(t, macs.Error)
	assert.Equal(t, []any{"hmac-sha2-512"}, macs.Data)
}

// A directory outside /run is not worked around.
func TestSshdConfigEffectiveMissingPrivsepDirOutsideRun(t *testing.T) {
	runtime := sshdUbuntuMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command:    sshdEffectiveConfigCommand,
			Stderr:     "Missing privilege separation directory: /var/empty\n",
			ExitStatus: 255,
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	macs := raw.(*mqlSshdConfig).GetEffectiveMacs()
	require.Error(t, macs.Error)
	assert.Equal(t, "sshd -T failed (exit 255): Missing privilege separation directory: /var/empty", macs.Error.Error())
}

// Platforms other than Linux keep the original error.
func TestSshdConfigEffectiveMissingPrivsepDirNotLinux(t *testing.T) {
	asset := &inventory.Asset{Platform: &inventory.Platform{
		Name:   "freebsd",
		Family: []string{"bsd", "unix", "os"},
	}}
	conn, err := mock.New(0, asset, mock.WithData(&mock.TomlData{Commands: map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command:    sshdEffectiveConfigCommand,
			Stderr:     "Missing privilege separation directory: /var/run/sshd\n",
			ExitStatus: 255,
		},
		sshdInPrivateRun(sshdEffectiveConfigCommand, "/var/run/sshd"): {
			Stdout: "macs hmac-sha2-512\n",
		},
	}}))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	macs := raw.(*mqlSshdConfig).GetEffectiveMacs()
	require.Error(t, macs.Error)
	assert.Equal(t, "sshd -T failed (exit 255): Missing privilege separation directory: /var/run/sshd", macs.Error.Error())
}
