// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/sshd"
	"go.mondoo.com/mql/utils/syncx"
)

func sshdDaemonMockRuntime(t *testing.T, commands map[string]*mock.Command, files map[string]*mock.MockFileData) *plugin.Runtime {
	t.Helper()
	asset := &inventory.Asset{Platform: &inventory.Platform{
		Name:    "redhat",
		Family:  []string{"redhat", "linux", "unix", "os"},
		Version: "8.10",
	}}
	conn, err := mock.New(0, asset, mock.WithData(&mock.TomlData{
		Commands: commands,
		Files:    files,
	}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

// On RHEL 8, sshd.service starts `sshd -D $OPTIONS $CRYPTO_POLICY`: the
// crypto policy reaches the daemon as -o options, which override the
// Ciphers line in sshd_config. Bare `sshd -T` shows the sshd_config list,
// the daemon accepts aes128-cbc.
func TestSshdConfigEffectiveAlgorithmsRunningDaemonOptions(t *testing.T) {
	cmdline, err := os.ReadFile("sshd/testdata/cmdline-rhel8.bin")
	require.NoError(t, err)
	daemon, ok := sshd.ParseDaemonCommandLine(cmdline)
	require.True(t, ok)

	withPolicy := sshdCommandWithOptions(sshdEffectiveConfigCommand, daemon.Options)
	runtime := sshdDaemonMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command: sshdEffectiveConfigCommand,
			Stdout: `pidfile /var/run/sshd.pid
ciphers aes256-gcm@openssh.com,aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
`,
		},
		"cat /proc/2207/cmdline": {Command: "cat /proc/2207/cmdline", Stdout: string(cmdline)},
		withPolicy: {
			Command: withPolicy,
			Stdout: `pidfile /var/run/sshd.pid
ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes256-cbc,aes128-gcm@openssh.com,aes128-ctr,aes128-cbc
macs hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512
`,
		},
	}, map[string]*mock.MockFileData{
		"/var/run/sshd.pid": {Path: "/var/run/sshd.pid", Content: "2207\n"},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	config := raw.(*mqlSshdConfig)

	ciphers := config.GetEffectiveCiphers()
	require.NoError(t, ciphers.Error)
	assert.Contains(t, ciphers.Data, "aes128-cbc")
	assert.Contains(t, ciphers.Data, "aes256-cbc")

	macs := config.GetEffectiveMacs()
	require.NoError(t, macs.Error)
	assert.Contains(t, macs.Data, "hmac-sha1")
}

// A daemon started with -f for another file does not describe the default
// sshd_config, and a pid file that names some other process is ignored.
func TestSshdConfigEffectiveAlgorithmsIgnoresUnrelatedDaemon(t *testing.T) {
	base := func(cmdline string) map[string]*mock.Command {
		return map[string]*mock.Command{
			sshdEffectiveConfigCommand: {
				Command: sshdEffectiveConfigCommand,
				Stdout:  "ciphers aes256-ctr\n",
			},
			"cat /proc/77/cmdline": {Command: "cat /proc/77/cmdline", Stdout: cmdline},
		}
	}
	for name, cmdline := range map[string]string{
		"other config file": "/usr/sbin/sshd\x00-D\x00-f\x00/etc/ssh/sshd_config_alt\x00-oCiphers=aes128-cbc\x00",
		"pid reused":        "/usr/bin/sleep\x00-oCiphers=aes128-cbc\x00",
		"no options":        "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\x00",
	} {
		t.Run(name, func(t *testing.T) {
			runtime := sshdDaemonMockRuntime(t, base(cmdline), map[string]*mock.MockFileData{
				"/var/run/sshd.pid": {Path: "/var/run/sshd.pid", Content: "77\n"},
			})
			raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
			require.NoError(t, err)
			ciphers := raw.(*mqlSshdConfig).GetEffectiveCiphers()
			require.NoError(t, ciphers.Error)
			assert.Equal(t, []any{"aes256-ctr"}, ciphers.Data)
		})
	}

	t.Run("no pid file", func(t *testing.T) {
		runtime := sshdDaemonMockRuntime(t, base(""), map[string]*mock.MockFileData{})
		raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
		require.NoError(t, err)
		ciphers := raw.(*mqlSshdConfig).GetEffectiveCiphers()
		require.NoError(t, ciphers.Error)
		assert.Equal(t, []any{"aes256-ctr"}, ciphers.Data)
	})
}

// The daemon's options apply to sshd.config("<path>") when the daemon reads
// that path with -f.
func TestSshdConfigEffectiveAlgorithmsDaemonCustomPath(t *testing.T) {
	command := sshdEffectiveConfigCommand + " -f /etc/ssh/alt_config"
	withOpts := command + " -o Ciphers=aes128-cbc"
	runtime := sshdDaemonMockRuntime(t, map[string]*mock.Command{
		command:                {Command: command, Stdout: "pidfile /run/sshd-alt.pid\nciphers aes256-ctr\n"},
		withOpts:               {Command: withOpts, Stdout: "pidfile /run/sshd-alt.pid\nciphers aes128-cbc\n"},
		"cat /proc/88/cmdline": {Command: "cat /proc/88/cmdline", Stdout: "/usr/sbin/sshd\x00-D\x00-f\x00/etc/ssh/alt_config\x00-oCiphers=aes128-cbc\x00"},
	}, map[string]*mock.MockFileData{
		"/run/sshd-alt.pid": {Path: "/run/sshd-alt.pid", Content: "88\n"},
	})
	raw, err := NewResource(runtime, ResourceSshdConfig, map[string]*llx.RawData{
		"path": llx.StringData("/etc/ssh/alt_config"),
	})
	require.NoError(t, err)
	ciphers := raw.(*mqlSshdConfig).GetEffectiveCiphers()
	require.NoError(t, ciphers.Error)
	assert.Equal(t, []any{"aes128-cbc"}, ciphers.Data)
}

// A failing rerun with the daemon's options is an error, not the
// sshd_config view.
func TestSshdConfigEffectiveAlgorithmsDaemonOptionsRerunFails(t *testing.T) {
	withOpts := sshdEffectiveConfigCommand + " -o Ciphers=aes128-cbc"
	runtime := sshdDaemonMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {Command: sshdEffectiveConfigCommand, Stdout: "ciphers aes256-ctr\n"},
		withOpts:                   {Command: withOpts, Stderr: "command-line line 0: Bad SSH2 cipher spec", ExitStatus: 255},
		"cat /proc/99/cmdline":     {Command: "cat /proc/99/cmdline", Stdout: "/usr/sbin/sshd\x00-D\x00-oCiphers=aes128-cbc\x00"},
	}, map[string]*mock.MockFileData{
		"/var/run/sshd.pid": {Path: "/var/run/sshd.pid", Content: "99\n"},
	})
	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	ciphers := raw.(*mqlSshdConfig).GetEffectiveCiphers()
	require.ErrorContains(t, ciphers.Error, "Bad SSH2 cipher spec")
}

func TestSshdCommandWithOptions(t *testing.T) {
	assert.Equal(t,
		`sshd -T -o Ciphers=aes256-ctr,aes128-cbc -o 'AuthorizedKeysCommand /opt/aws/bin/eic_run_authorized_keys %u %f'`,
		sshdCommandWithOptions("sshd -T", []string{
			"Ciphers=aes256-ctr,aes128-cbc",
			"AuthorizedKeysCommand /opt/aws/bin/eic_run_authorized_keys %u %f",
		}))
	assert.Equal(t, "sshd -T", sshdCommandWithOptions("sshd -T", nil))
}
