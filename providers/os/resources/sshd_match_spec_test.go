// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// stderr of `sshd -T` on Debian 10 (OpenSSH 7.9p1) when sshd_config has a
// `Match User` block
const debian10MatchUserStderr = "'Match User' in configuration but 'user' not in connection test specification.\n"

func sshdDebianMockRuntime(t *testing.T, commands map[string]*mock.Command) *plugin.Runtime {
	t.Helper()
	asset := &inventory.Asset{Platform: &inventory.Platform{
		Name:    "debian",
		Family:  []string{"debian", "linux", "unix", "os"},
		Version: "10.13",
	}}
	conn, err := mock.New(0, asset, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func TestSshdConfigEffectiveRetriesWithConnectionSpec(t *testing.T) {
	withSpec := sshdEffectiveConfigCommand + " -C " + sshdTestConnectionSpec
	runtime := sshdDebianMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command:    sshdEffectiveConfigCommand,
			Stderr:     debian10MatchUserStderr,
			ExitStatus: 255,
		},
		withSpec: {
			Command: withSpec,
			Stdout:  "ciphers aes256-gcm@openssh.com,aes128-cbc\nmacs hmac-sha2-256\n",
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	config := raw.(*mqlSshdConfig)

	ciphers := config.GetEffectiveCiphers()
	require.NoError(t, ciphers.Error)
	assert.Equal(t, []any{"aes256-gcm@openssh.com", "aes128-cbc"}, ciphers.Data)
}

// Any other sshd -T failure is reported as it was, without a second run.
func TestSshdConfigEffectiveOtherFailureIsNotRetried(t *testing.T) {
	runtime := sshdDebianMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command:    sshdEffectiveConfigCommand,
			Stderr:     "/etc/ssh/sshd_config line 12: Bad configuration option: Ciphersx\n",
			ExitStatus: 255,
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	ciphers := raw.(*mqlSshdConfig).GetEffectiveCiphers()
	require.Error(t, ciphers.Error)
	assert.Equal(t, "sshd -T failed (exit 255): /etc/ssh/sshd_config line 12: Bad configuration option: Ciphersx", ciphers.Error.Error())
}

// A retry that fails too names the command that was retried.
func TestSshdConfigEffectiveRetryFailure(t *testing.T) {
	withSpec := sshdEffectiveConfigCommand + " -C " + sshdTestConnectionSpec
	runtime := sshdDebianMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command:    sshdEffectiveConfigCommand,
			Stderr:     debian10MatchUserStderr,
			ExitStatus: 255,
		},
		withSpec: {
			Command:    withSpec,
			Stderr:     "'Match RDomain' in configuration but 'rdomain' not in connection test specification.\n",
			ExitStatus: 255,
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	ciphers := raw.(*mqlSshdConfig).GetEffectiveCiphers()
	require.Error(t, ciphers.Error)
	assert.Contains(t, ciphers.Error.Error(), withSpec+" failed (exit 255)")
}

func TestSshdIncludeReadError(t *testing.T) {
	denied := &fs.PathError{Op: "open", Path: "/etc/ssh/sshd_config.d/00-local.conf", Err: fs.ErrPermission}

	t.Run("refusal is forbidden with structured errors", func(t *testing.T) {
		withStructuredErrors(t, true)
		err := sshdIncludeReadError(denied.Path, denied)
		assert.True(t, errors.Is(err, llx.ErrForbidden))
		assert.True(t, errors.Is(err, fs.ErrPermission))
		assert.Equal(t, "open /etc/ssh/sshd_config.d/00-local.conf: permission denied", err.Error())
	})

	t.Run("refusal without a path names the file", func(t *testing.T) {
		withStructuredErrors(t, true)
		err := sshdIncludeReadError("/etc/ssh/sshd_config.d/00-local.conf", fs.ErrPermission)
		assert.True(t, errors.Is(err, llx.ErrForbidden))
		assert.Equal(t, "/etc/ssh/sshd_config.d/00-local.conf: permission denied", err.Error())
	})

	t.Run("refusal stays unclassified without structured errors", func(t *testing.T) {
		withStructuredErrors(t, false)
		err := sshdIncludeReadError(denied.Path, denied)
		assert.False(t, errors.Is(err, llx.ErrForbidden))
	})

	t.Run("a missing file is not a refusal", func(t *testing.T) {
		withStructuredErrors(t, true)
		err := sshdIncludeReadError("/etc/ssh/sshd_config.d/00-local.conf", fs.ErrNotExist)
		assert.False(t, errors.Is(err, llx.ErrForbidden))
	})
}
