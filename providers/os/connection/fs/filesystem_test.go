// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fs_test

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/fsutil"
	"go.mondoo.com/mql/providers/os/registry"
)

func TestOsDetection(t *testing.T) {
	conn, err := fs.NewConnection(0, &inventory.Config{
		Path: "./testdata/centos8",
	}, &inventory.Asset{})
	require.NoError(t, err)

	pf, detected := detector.DetectOS(conn)
	require.True(t, detected)

	assert.Equal(t, "centos", pf.Name)
	assert.Equal(t, "8.5.2111", pf.Version)
}

func TestMountedDirectoryFile(t *testing.T) {
	conn, err := fs.NewConnection(0, &inventory.Config{
		Path: "./testdata/centos8",
	}, &inventory.Asset{})
	require.NoError(t, err)

	f, err := conn.FileSystem().Open("/etc/os-release")
	assert.Nil(t, err, "should open without error")
	assert.NotNil(t, f)
	defer f.Close()

	afutil := afero.Afero{Fs: conn.FileSystem()}
	exists, err := afutil.Exists(f.Name())
	assert.NoError(t, err)
	assert.True(t, exists, "file should exist")

	p := f.Name()
	assert.Equal(t, "/etc/os-release", p, "path should be correct")

	stat, err := f.Stat()
	assert.Equal(t, int64(332), stat.Size(), "should read file size")
	assert.Nil(t, err, "should execute without error")

	content, err := afutil.ReadFile(f.Name())
	assert.Equal(t, nil, err, "should execute without error")
	assert.Equal(t, 332, len(content), "should read the full content")

	// reset reader
	_, _ = f.Seek(0, 0)
	sha, err := fsutil.Sha256(f)
	assert.Equal(t, "6c5f622e7011184134511fb18af399d5ba13164d1472e3df8dcfed346a376f70", sha, "sha256 output should be correct")
	assert.Nil(t, err, "should execute without error")

	// reset reader
	_, _ = f.Seek(0, 0)
	md5, err := fsutil.Md5(f)
	assert.Equal(t, "1c61d1e243561194a84bd1210c7f58ce", md5, "md5 output should be correct")
	assert.Nil(t, err, "should execute without error")
}

func TestRunCommandReturnsErr(t *testing.T) {
	conn, err := fs.NewConnection(0, &inventory.Config{
		Path: "./testdata/centos8",
	}, &inventory.Asset{})
	require.NoError(t, err)

	_, err = conn.RunCommand("aa-status")
	require.Error(t, err)
	assert.Equal(t, "provider does not implement RunCommand", err.Error())
}

// A Windows disk mounted on a POSIX scanner has the hives at
// Windows/System32/config. The registry path constants must find them through
// the connection, and the hive must then be readable.
func TestMountedWindowsRegistryHive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("loading a hive on windows needs the backup privilege")
	}
	mount := t.TempDir()
	dir := filepath.Join(mount, "Windows", "System32", "config")
	require.NoError(t, os.MkdirAll(dir, 0o755))

	in, err := os.Open(filepath.Join("..", "..", "registry", "testdata", "fixture.hiv.gz"))
	require.NoError(t, err)
	defer in.Close()
	zr, err := gzip.NewReader(in)
	require.NoError(t, err)
	out, err := os.Create(filepath.Join(dir, "SOFTWARE"))
	require.NoError(t, err)
	_, err = io.Copy(out, zr)
	require.NoError(t, err)
	require.NoError(t, out.Close())

	conn, err := fs.NewConnection(0, &inventory.Config{Path: mount}, &inventory.Asset{})
	require.NoError(t, err)

	fi, err := conn.FileInfo(registry.SoftwareRegPath)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(mount, "Windows", "System32", "config", "SOFTWARE"), fi.Path)

	_, err = conn.FileInfo(registry.SystemRegPath)
	assert.Error(t, err, "no SYSTEM hive on this disk")

	rh := registry.NewRegistryHandler()
	t.Cleanup(func() { assert.NoError(t, rh.UnloadSubkeys()) })
	require.NoError(t, rh.LoadSubkey(registry.Software, fi.Path))
	items, err := rh.GetNativeRegistryKeyItems(registry.Software, "Values")
	require.NoError(t, err)
	found := false
	for _, i := range items {
		if i.Key == "Sz" {
			found = true
			assert.Equal(t, "hello world", i.Value.String)
		}
	}
	assert.True(t, found, "value Sz not read")
}
