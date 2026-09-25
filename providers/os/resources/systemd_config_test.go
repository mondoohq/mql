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

func writeTestFiles(t *testing.T, fs afero.Fs, files map[string]string) {
	t.Helper()
	for p, content := range files {
		require.NoError(t, afero.WriteFile(fs, p, []byte(content), 0o644))
	}
}

func TestFindSystemdMainConfig(t *testing.T) {
	t.Run("first directory in precedence order wins", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		writeTestFiles(t, fs, map[string]string{
			"/usr/lib/systemd/coredump.conf": "",
			"/run/systemd/coredump.conf":     "",
		})
		p, err := findSystemdMainConfig(fs, "coredump.conf")
		require.NoError(t, err)
		assert.Equal(t, "/run/systemd/coredump.conf", p)
	})

	t.Run("vendor file is used when /etc has none", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		writeTestFiles(t, fs, map[string]string{"/usr/lib/systemd/coredump.conf": ""})
		p, err := findSystemdMainConfig(fs, "coredump.conf")
		require.NoError(t, err)
		assert.Equal(t, "/usr/lib/systemd/coredump.conf", p)
	})

	t.Run("absent", func(t *testing.T) {
		p, err := findSystemdMainConfig(afero.NewMemMapFs(), "coredump.conf")
		require.NoError(t, err)
		assert.Empty(t, p)
	})
}

func TestFindSystemdConfigDropins(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{
		"/usr/lib/systemd/coredump.conf.d/50-vendor.conf":       "",
		"/usr/lib/systemd/coredump.conf.d/90-late.conf":         "",
		"/usr/local/lib/systemd/coredump.conf.d/50-vendor.conf": "",
		"/run/systemd/coredump.conf.d/10-runtime.conf":          "",
		"/etc/systemd/coredump.conf.d/50-vendor.conf":           "",
		"/etc/systemd/coredump.conf.d/70-local.conf":            "",
		"/etc/systemd/coredump.conf.d/README":                   "",
		"/etc/systemd/journald.conf.d/00-other.conf":            "",
	})

	dropins, err := findSystemdConfigDropins(fs, "coredump.conf")
	require.NoError(t, err)
	// Sorted by file name across directories; 50-vendor.conf in /etc masks
	// the /usr/local/lib and /usr/lib copies; non-.conf files and other
	// daemons' drop-ins are not read.
	assert.Equal(t, []string{
		"/run/systemd/coredump.conf.d/10-runtime.conf",
		"/etc/systemd/coredump.conf.d/50-vendor.conf",
		"/etc/systemd/coredump.conf.d/70-local.conf",
		"/usr/lib/systemd/coredump.conf.d/90-late.conf",
	}, dropins)
}

func TestFindSystemdConfigDevNullMask(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"etc/systemd/coredump.conf.d", "usr/lib/systemd/coredump.conf.d"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr/lib/systemd/coredump.conf"), nil, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr/lib/systemd/coredump.conf.d/50-vendor.conf"), nil, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr/lib/systemd/coredump.conf.d/60-kept.conf"), nil, 0o644))
	require.NoError(t, os.Symlink("/dev/null", filepath.Join(root, "etc/systemd/coredump.conf.d/50-vendor.conf")))
	require.NoError(t, os.Symlink("/dev/null", filepath.Join(root, "etc/systemd/coredump.conf")))

	fs := afero.NewBasePathFs(afero.NewOsFs(), root)

	mainPath, err := findSystemdMainConfig(fs, "coredump.conf")
	require.NoError(t, err)
	assert.Empty(t, mainPath, "a /dev/null main file in /etc masks the vendor copy")

	dropins, err := findSystemdConfigDropins(fs, "coredump.conf")
	require.NoError(t, err)
	assert.Equal(t, []string{"/usr/lib/systemd/coredump.conf.d/60-kept.conf"}, dropins)
}
