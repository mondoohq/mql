// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func TestExpandSshdGlob(t *testing.T) {
	fs := afero.NewMemMapFs()
	files := []string{
		"/etc/ssh/sshd_config",
		"/etc/ssh/decoy.conf",
		"/etc/ssh/sshd_config.d/10-a.conf",
		"/etc/ssh/sshd_config.d/20-b.conf",
		"/etc/ssh/sshd_config.d/nested/deep.conf",
	}
	for _, f := range files {
		require.NoError(t, afero.WriteFile(fs, f, []byte("Port 22\n"), 0o644))
	}
	afs := &afero.Afero{Fs: fs}

	tests := []struct {
		name string
		glob string
		want []string
	}{
		{
			name: "non-glob absolute path is returned as-is",
			glob: "/etc/ssh/sshd_config",
			want: []string{"/etc/ssh/sshd_config"},
		},
		{
			name: "non-glob relative path resolves from /etc/ssh",
			glob: "sshd_config",
			want: []string{"/etc/ssh/sshd_config"},
		},
		{
			name: "absolute glob in a subdirectory",
			glob: "/etc/ssh/sshd_config.d/*.conf",
			want: []string{"/etc/ssh/sshd_config.d/10-a.conf", "/etc/ssh/sshd_config.d/20-b.conf"},
		},
		{
			// Regression: a relative Include glob with a subdirectory must not
			// drop the subdirectory segment and glob one level too shallow.
			name: "relative glob in a subdirectory",
			glob: "sshd_config.d/*.conf",
			want: []string{"/etc/ssh/sshd_config.d/10-a.conf", "/etc/ssh/sshd_config.d/20-b.conf"},
		},
		{
			// Regression: a single-segment relative glob must expand within
			// /etc/ssh, not return the directory itself.
			name: "relative single-segment glob",
			glob: "*.conf",
			want: []string{"/etc/ssh/decoy.conf"},
		},
		{
			name: "glob does not descend into subdirectories",
			glob: "/etc/ssh/*.conf",
			want: []string{"/etc/ssh/decoy.conf"},
		},
		{
			name: "glob against a missing directory yields no matches",
			glob: "/etc/does-not-exist/*.conf",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandSshdGlob(afs, tt.glob)
			require.NoError(t, err)
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestSshdConfigEffectiveAlgorithms(t *testing.T) {
	runtime := sshdEffectiveConfigMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command: sshdEffectiveConfigCommand,
			Stdout: `ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256
kexalgorithms sntrup761x25519-sha512,mlkem768x25519-sha256,curve25519-sha256
`,
			ExitStatus: 0,
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)

	config := raw.(*mqlSshdConfig)
	ciphers := config.GetEffectiveCiphers()
	require.NoError(t, ciphers.Error)
	assert.Equal(t, []any{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"}, ciphers.Data)

	macs := config.GetEffectiveMacs()
	require.NoError(t, macs.Error)
	assert.Equal(t, []any{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256"}, macs.Data)

	kexs := config.GetEffectiveKexs()
	require.NoError(t, kexs.Error)
	assert.Equal(t, []any{"sntrup761x25519-sha512", "mlkem768x25519-sha256", "curve25519-sha256"}, kexs.Data)
}

func TestSshdConfigEffectiveAlgorithmsCustomPath(t *testing.T) {
	command := sshdEffectiveConfigCommand + " -f '/tmp/sshd config'"
	runtime := sshdEffectiveConfigMockRuntime(t, map[string]*mock.Command{
		command: {
			Command:    command,
			Stdout:     "ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com\n",
			ExitStatus: 0,
		},
	})

	raw, err := NewResource(runtime, ResourceSshdConfig, map[string]*llx.RawData{
		"path": llx.StringData("/tmp/sshd config"),
	})
	require.NoError(t, err)

	config := raw.(*mqlSshdConfig)
	ciphers := config.GetEffectiveCiphers()
	require.NoError(t, ciphers.Error)
	assert.Equal(t, []any{"aes256-gcm@openssh.com", "aes128-gcm@openssh.com"}, ciphers.Data)
}

func TestSshdConfigEffectiveAlgorithmsCommandFailure(t *testing.T) {
	runtime := sshdEffectiveConfigMockRuntime(t, map[string]*mock.Command{
		sshdEffectiveConfigCommand: {
			Command:    sshdEffectiveConfigCommand,
			Stderr:     "bad sshd configuration",
			ExitStatus: 255,
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)

	config := raw.(*mqlSshdConfig)
	ciphers := config.GetEffectiveCiphers()
	require.ErrorContains(t, ciphers.Error, "sshd -T failed (exit 255): bad sshd configuration")
}

func sshdEffectiveConfigMockRuntime(t *testing.T, commands map[string]*mock.Command) *plugin.Runtime {
	t.Helper()

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "linux",
			Family:  []string{"linux", "unix", "os"},
			Version: "test",
		},
	}
	conn, err := mock.New(0, asset, mock.WithData(&mock.TomlData{
		Commands: commands,
		Files:    map[string]*mock.MockFileData{},
	}))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

// windowsSshdConfig is the non-comment part of C:\ProgramData\ssh\sshd_config
// that Windows Server 2025 (OpenSSH_for_Windows_9.5p2) writes on the first
// start of the sshd service, plus an Include line to exercise resolution
// against %ProgramData%\ssh.
const windowsSshdConfig = `AuthorizedKeysFile	.ssh/authorized_keys
Subsystem	sftp	sftp-server.exe
AllowGroups administrators "openssh users"
Include sshd_config.d\hardening.conf

Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
`

func TestSshdConfigWindowsDefaultPath(t *testing.T) {
	runtime := sshdMockRuntime(t, windowsPlatform, nil, map[string]*mock.MockFileData{
		`C:\ProgramData\ssh\sshd_config`: {
			Path:    `C:\ProgramData\ssh\sshd_config`,
			Content: windowsSshdConfig,
		},
		`C:\ProgramData\ssh\sshd_config.d\hardening.conf`: {
			Path:    `C:\ProgramData\ssh\sshd_config.d\hardening.conf`,
			Content: "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com\n",
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	config := raw.(*mqlSshdConfig)

	file := config.GetFile()
	require.NoError(t, file.Error)
	assert.Equal(t, `C:\ProgramData\ssh\sshd_config`, file.Data.Path.Data)

	params := config.GetParams()
	require.NoError(t, params.Error)
	assert.Equal(t, ".ssh/authorized_keys", params.Data["AuthorizedKeysFile"])
	assert.Equal(t, "sftp sftp-server.exe", params.Data["Subsystem"])

	ciphers := config.GetCiphers()
	require.NoError(t, ciphers.Error)
	assert.Equal(t, []any{"aes256-gcm@openssh.com", "aes128-gcm@openssh.com"}, ciphers.Data)

	blocks := config.GetBlocks()
	require.NoError(t, blocks.Error)
	var criteria []string
	for _, b := range blocks.Data {
		criteria = append(criteria, b.(*mqlSshdConfigMatchBlock).Criteria.Data)
	}
	assert.Contains(t, criteria, "Group administrators")
}

func TestSshdConfigLinuxDefaultPath(t *testing.T) {
	runtime := sshdMockRuntime(t, linuxPlatform, nil, map[string]*mock.MockFileData{
		"/etc/ssh/sshd_config": {
			Path:    "/etc/ssh/sshd_config",
			Content: "Ciphers aes256-ctr\n",
		},
		`C:\ProgramData\ssh\sshd_config`: {
			Path:    `C:\ProgramData\ssh\sshd_config`,
			Content: "Ciphers aes128-ctr\n",
		},
	})

	raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
	require.NoError(t, err)
	config := raw.(*mqlSshdConfig)

	file := config.GetFile()
	require.NoError(t, file.Error)
	assert.Equal(t, "/etc/ssh/sshd_config", file.Data.Path.Data)

	ciphers := config.GetCiphers()
	require.NoError(t, ciphers.Error)
	assert.Equal(t, []any{"aes256-ctr"}, ciphers.Data)
}

func TestExpandWindowsSshdGlob(t *testing.T) {
	fs := afero.NewMemMapFs()
	for _, f := range []string{
		"C:/ProgramData/ssh/sshd_config",
		"C:/ProgramData/ssh/sshd_config.d/10-a.conf",
		"C:/ProgramData/ssh/sshd_config.d/20-b.conf",
		"C:/ProgramData/ssh/sshd_config.d/30-c.CONF",
		"D:/ssh/extra.conf",
	} {
		require.NoError(t, afero.WriteFile(fs, f, []byte("Port 22\n"), 0o644))
	}
	afs := &afero.Afero{Fs: fs}

	tests := []struct {
		name string
		glob string
		want []string
	}{
		{
			name: "relative path resolves from ProgramData",
			glob: `sshd_config.d\10-a.conf`,
			want: []string{`C:\ProgramData\ssh\sshd_config.d\10-a.conf`},
		},
		{
			name: "relative glob with forward slashes",
			glob: "sshd_config.d/*.conf",
			want: []string{`C:\ProgramData\ssh\sshd_config.d\10-a.conf`, `C:\ProgramData\ssh\sshd_config.d\20-b.conf`},
		},
		{
			name: "__PROGRAMDATA__ token is absolute",
			glob: "__PROGRAMDATA__/ssh/sshd_config.d/2*.conf",
			want: []string{`C:\ProgramData\ssh\sshd_config.d\20-b.conf`},
		},
		{
			name: "drive-letter glob",
			glob: `D:\ssh\*.conf`,
			want: []string{`D:\ssh\extra.conf`},
		},
		{
			name: "drive-letter path is not joined to ProgramData",
			glob: `D:\ssh\extra.conf`,
			want: []string{`D:\ssh\extra.conf`},
		},
		{
			name: "missing directory yields no matches",
			glob: `sshd_config.missing\*.conf`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandWindowsSshdGlob(afs, tt.glob)
			require.NoError(t, err)
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestSshdConfigEffectiveWindows(t *testing.T) {
	// `sshd -T` output from Windows Server 2025 (OpenSSH_for_Windows_9.5p2)
	// with the default configuration.
	stdout := `ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
macs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512
kexalgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256
`
	t.Run("default path runs sshd -T", func(t *testing.T) {
		runtime := sshdMockRuntime(t, windowsPlatform, map[string]*mock.Command{
			sshdEffectiveConfigCommand: {Command: sshdEffectiveConfigCommand, Stdout: stdout},
		}, map[string]*mock.MockFileData{
			`C:\ProgramData\ssh\sshd_config`: {Path: `C:\ProgramData\ssh\sshd_config`, Content: windowsSshdConfig},
		})
		raw, err := CreateResource(runtime, ResourceSshdConfig, nil)
		require.NoError(t, err)
		kexs := raw.(*mqlSshdConfig).GetEffectiveKexs()
		require.NoError(t, kexs.Error)
		assert.Len(t, kexs.Data, 9)
		assert.Equal(t, "curve25519-sha256", kexs.Data[0])
	})

	t.Run("custom path is double-quoted for cmd.exe", func(t *testing.T) {
		// cmd.exe passes single quotes through literally, and sshd then
		// fails with "'C:\...': Invalid argument" (observed on Windows
		// Server 2022 and 2025 over WinRM).
		command := sshdEffectiveConfigCommand + ` -f "C:\sshd test\sshd_config"`
		runtime := sshdMockRuntime(t, windowsPlatform, map[string]*mock.Command{
			command: {Command: command, Stdout: stdout},
		}, nil)
		raw, err := NewResource(runtime, ResourceSshdConfig, map[string]*llx.RawData{
			"path": llx.StringData(`C:\sshd test\sshd_config`),
		})
		require.NoError(t, err)
		ciphers := raw.(*mqlSshdConfig).GetEffectiveCiphers()
		require.NoError(t, ciphers.Error)
		assert.Equal(t, "chacha20-poly1305@openssh.com", ciphers.Data[0])
	})
}

func TestSshdConfigEffectiveWindowsRejectsExpandablePath(t *testing.T) {
	for _, path := range []string{`C:\%USERNAME%\sshd_config`, `C:\$(whoami)\sshd_config`, "C:\\a`b\\sshd_config"} {
		t.Run(path, func(t *testing.T) {
			runtime := sshdMockRuntime(t, windowsPlatform, nil, nil)
			raw, err := NewResource(runtime, ResourceSshdConfig, map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			require.NoError(t, err)
			ciphers := raw.(*mqlSshdConfig).GetEffectiveCiphers()
			require.ErrorContains(t, ciphers.Error, "Windows shell would expand")
		})
	}
}

func sshdMockRuntime(t *testing.T, pf *inventory.Platform, commands map[string]*mock.Command, files map[string]*mock.MockFileData) *plugin.Runtime {
	t.Helper()
	if files == nil {
		files = map[string]*mock.MockFileData{}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: pf}, mock.WithData(&mock.TomlData{
		Commands: commands,
		Files:    files,
	}))
	require.NoError(t, err)
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}
