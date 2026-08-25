// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVendorConfigCandidates(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "etc file",
			path: "/etc/login.defs",
			want: []string{"/etc/login.defs", "/usr/etc/login.defs"},
		},
		{
			name: "nested etc file",
			path: "/etc/ssh/sshd_config",
			want: []string{"/etc/ssh/sshd_config", "/usr/etc/ssh/sshd_config"},
		},
		{
			name: "etc directory",
			path: "/etc/security/limits.d",
			want: []string{"/etc/security/limits.d", "/usr/etc/security/limits.d"},
		},
		{
			name: "bare etc",
			path: "/etc",
			want: []string{"/etc", "/usr/etc"},
		},
		{
			name: "path outside etc is untouched",
			path: "/usr/local/etc/sudoers",
			want: []string{"/usr/local/etc/sudoers"},
		},
		{
			name: "etc prefix without separator is not an etc path",
			path: "/etcetera/conf",
			want: []string{"/etcetera/conf"},
		},
		{
			name: "relative path is untouched",
			path: "sshd_config",
			want: []string{"sshd_config"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, vendorConfigCandidates(test.path))
		})
	}
}

func TestResolveVendorConfigPath(t *testing.T) {
	t.Run("etc wins when both exist", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/etc/login.defs", []byte("UMASK 077\n"), 0o644))
		require.NoError(t, afero.WriteFile(fs, "/usr/etc/login.defs", []byte("UMASK 022\n"), 0o644))

		assert.Equal(t, "/etc/login.defs", resolveVendorConfigPath(fs, "/etc/login.defs"))
	})

	t.Run("falls back to usr etc", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/usr/etc/ssh/sshd_config", []byte("UsePAM yes\n"), 0o644))

		assert.Equal(t, "/usr/etc/ssh/sshd_config", resolveVendorConfigPath(fs, "/etc/ssh/sshd_config"))
	})

	t.Run("keeps the canonical path when nothing exists", func(t *testing.T) {
		fs := afero.NewMemMapFs()

		assert.Equal(t, "/etc/sudoers", resolveVendorConfigPath(fs, "/etc/sudoers"))
	})

	t.Run("nil filesystem keeps the canonical path", func(t *testing.T) {
		assert.Equal(t, "/etc/sudoers", resolveVendorConfigPath(nil, "/etc/sudoers"))
	})
}

func TestVendorConfigDirs(t *testing.T) {
	t.Run("returns both trees with etc first", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, fs.MkdirAll("/etc/logrotate.d", 0o755))
		require.NoError(t, fs.MkdirAll("/usr/etc/logrotate.d", 0o755))

		assert.Equal(t,
			[]string{"/etc/logrotate.d", "/usr/etc/logrotate.d"},
			vendorConfigDirs(fs, "/etc/logrotate.d"))
	})

	t.Run("returns only the tree that exists", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, fs.MkdirAll("/usr/etc/security/limits.d", 0o755))

		assert.Equal(t,
			[]string{"/usr/etc/security/limits.d"},
			vendorConfigDirs(fs, "/etc/security/limits.d"))
	})

	t.Run("ignores a regular file with the directory name", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/etc/logrotate.d", []byte("not a dir"), 0o644))

		assert.Empty(t, vendorConfigDirs(fs, "/etc/logrotate.d"))
	})

	t.Run("no directory anywhere", func(t *testing.T) {
		assert.Empty(t, vendorConfigDirs(afero.NewMemMapFs(), "/etc/logrotate.d"))
	})

	t.Run("nil filesystem", func(t *testing.T) {
		assert.Empty(t, vendorConfigDirs(nil, "/etc/logrotate.d"))
	})
}

func TestVendorConfigShadowed(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/logrotate.d/nginx", []byte("admin copy\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/usr/etc/logrotate.d/nginx", []byte("vendor copy\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/usr/etc/logrotate.d/chrony", []byte("vendor copy\n"), 0o644))

	t.Run("vendor drop-in overridden in etc", func(t *testing.T) {
		assert.True(t, vendorConfigShadowed(fs, "/usr/etc/logrotate.d/nginx"))
	})

	t.Run("vendor drop-in with no override", func(t *testing.T) {
		assert.False(t, vendorConfigShadowed(fs, "/usr/etc/logrotate.d/chrony"))
	})

	t.Run("etc drop-in is never shadowed", func(t *testing.T) {
		assert.False(t, vendorConfigShadowed(fs, "/etc/logrotate.d/nginx"))
	})

	t.Run("path outside the vendor tree", func(t *testing.T) {
		assert.False(t, vendorConfigShadowed(fs, "/opt/logrotate.d/nginx"))
	})

	t.Run("traversal is not resolved into an etc lookup", func(t *testing.T) {
		assert.False(t, vendorConfigShadowed(fs, "/usr/etc/logrotate.d/../logrotate.d/nginx"))
	})

	t.Run("nil filesystem", func(t *testing.T) {
		assert.False(t, vendorConfigShadowed(nil, "/usr/etc/logrotate.d/nginx"))
	})
}
