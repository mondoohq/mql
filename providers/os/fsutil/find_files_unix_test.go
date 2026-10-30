// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package fsutil

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindFilesPermissionFilter(t *testing.T) {
	fs := afero.NewMemMapFs()
	mkDir(t, fs, "root/a")
	mkDir(t, fs, "root/b")
	mkDir(t, fs, "root/c")
	mkDir(t, fs, "root/c/d")

	mkFile(t, fs, "root/file0")
	mkFile(t, fs, "root/a/file1")
	mkFile(t, fs, "root/a/file2")
	mkFile(t, fs, "root/b/file1")
	mkFile(t, fs, "root/c/file4")
	mkFile(t, fs, "root/c/d/file5")

	require.NoError(t, fs.Chmod("root/c/file4", 0o002))

	perm := uint32(0o002)
	permFiles, err := FindFiles(afero.NewIOFS(fs), "root", nil, "f", &perm, nil)
	require.NoError(t, err)
	assert.ElementsMatch(t, permFiles, []string{"root/c/file4"})

	// a mask of several bits needs every one of them, as `find -perm -0644`
	// and the documented "at least these permission bits" do; one shared
	// bit is not enough
	for name, mode := range map[string]os.FileMode{
		"root/file0":     0o600,
		"root/a/file1":   0o644,
		"root/a/file2":   0o640,
		"root/b/file1":   0o664,
		"root/c/d/file5": 0o004,
	} {
		require.NoError(t, fs.Chmod(name, mode))
	}
	perm = 0o644
	permFiles, err = FindFiles(afero.NewIOFS(fs), "root", nil, "f", &perm, nil)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"root/a/file1", "root/b/file1"}, permFiles)
}

// TestFindFilesZeroPermissionMatchesAll is a regression test for
// https://github.com/mondoohq/mql/issues/8467
//
// files.find built via CreateResource without a permissions argument reaches
// the native walker with a 0 mask (initFilesFind's 0o777 default only applies
// to MQL-instantiated resources). A 0 mask must mean "no permission filter"
// (like `find -perm -0`), not "match nothing" — otherwise the pam/sudoers/
// modprobe/rsyslog/... `*.d` discoveries return no files on filesystem/tar
// connections.
func TestFindFilesZeroPermissionMatchesAll(t *testing.T) {
	fs := afero.NewMemMapFs()
	mkDir(t, fs, "root")
	mkFile(t, fs, "root/a")
	mkFile(t, fs, "root/b")
	require.NoError(t, fs.Chmod("root/a", 0o644))
	require.NoError(t, fs.Chmod("root/b", 0o600))

	zero := uint32(0)
	files, err := FindFiles(afero.NewIOFS(fs), "root", nil, "f", &zero, nil)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"root/a", "root/b"}, files,
		"a 0 permission mask must match all files, not none")
}

// TestFindFilesFollowsSymlinks is a regression test for
// https://github.com/mondoohq/mql/issues/8467
//
// authselect manages key /etc/pam.d service files (system-auth, password-auth,
// ...) as symlinks into /etc/authselect. The command-based backend runs
// `find -L` and follows them, but the native walker reported lstat info and
// skipped symlinks, so type:"file" missed those service files and pam.module
// resolved to an empty husk. A real filesystem is needed here because afero's
// MemMapFs has no symlink support.
func TestFindFilesFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.conf"), []byte("x"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.Symlink("real.conf", filepath.Join(dir, "link.conf"))) // -> regular file
	require.NoError(t, os.Symlink("sub", filepath.Join(dir, "dirlink")))         // -> directory
	require.NoError(t, os.Symlink("missing", filepath.Join(dir, "broken")))      // dangling

	iofs := os.DirFS(dir)

	// type:"file" follows symlinks to regular files (mirrors `find -L`).
	files, err := FindFiles(iofs, ".", nil, "file", nil, nil)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"real.conf", "link.conf"}, files,
		"type:file must include a symlink that points at a regular file")

	// type:"link" still matches every symlink (additive), including the one
	// that resolves to a file/dir and the dangling one.
	links, err := FindFiles(iofs, ".", nil, "link", nil, nil)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"link.conf", "dirlink", "broken"}, links,
		"type:link must still match all symlinks")

	// type:"directory" follows a symlink that points at a directory.
	dirs, err := FindFiles(iofs, ".", nil, "directory", nil, nil)
	require.NoError(t, err)
	assert.Contains(t, dirs, "sub")
	assert.Contains(t, dirs, "dirlink",
		"type:directory must include a symlink that points at a directory")
}

// deviceFindFS models a mounted subtree using real stat device identifiers;
// it records directory reads so -xdev is proved to prune before descent.
type deviceFindFS struct {
	fs.FS
	reads []string
}
type deviceFindInfo struct {
	fs.FileInfo
	device uint64
}

func (i deviceFindInfo) Sys() any {
	stat := &syscall.Stat_t{}
	field := reflect.ValueOf(stat).Elem().FieldByName("Dev")
	if field.Kind() == reflect.Int32 || field.Kind() == reflect.Int64 {
		field.SetInt(int64(i.device))
	} else {
		field.SetUint(i.device)
	}
	return stat
}

type deviceFindEntry struct {
	fs.DirEntry
	info fs.FileInfo
}

func (e deviceFindEntry) Info() (fs.FileInfo, error) { return e.info, nil }
func (f *deviceFindFS) info(name string, info fs.FileInfo) fs.FileInfo {
	device := uint64(1)
	if name == "root/mount" || name == "root/mount/foreign" {
		device = 2
	}
	return deviceFindInfo{info, device}
}
func (f *deviceFindFS) Stat(name string) (fs.FileInfo, error) {
	info, err := fs.Stat(f.FS, name)
	if err != nil {
		return nil, err
	}
	return f.info(name, info), nil
}
func (f *deviceFindFS) ReadDir(name string) ([]fs.DirEntry, error) {
	f.reads = append(f.reads, name)
	entries, err := fs.ReadDir(f.FS, name)
	if err != nil {
		return nil, err
	}
	for i, e := range entries {
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		entries[i] = deviceFindEntry{e, f.info(name+"/"+e.Name(), info)}
	}
	return entries, nil
}
func TestFindFilesMountBoundary(t *testing.T) {
	for _, cross := range []bool{false, true} {
		t.Run(fmt.Sprint(cross), func(t *testing.T) {
			f := afero.NewMemMapFs()
			mkDir(t, f, "root/mount")
			mkFile(t, f, "root/local")
			mkFile(t, f, "root/mount/foreign")
			target := &deviceFindFS{FS: afero.NewIOFS(f)}
			found, err := FindFilesWithOptions(target, "root", nil, "file,directory", nil, nil, FindOptions{CrossFileSystems: cross})
			require.NoError(t, err)
			require.Contains(t, found, "root/mount", "the mount point itself is still reported")
			require.Contains(t, found, "root/local")
			if cross {
				require.Contains(t, found, "root/mount/foreign")
				require.Contains(t, target.reads, "root/mount")
			} else {
				require.NotContains(t, found, "root/mount/foreign")
				require.NotContains(t, target.reads, "root/mount")
			}
		})
	}
}

type deniedDeviceEntry struct{ fs.DirEntry }

func (e deniedDeviceEntry) Info() (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "stat", Path: e.Name(), Err: fs.ErrPermission}
}

type deniedDeviceFindFS struct{ *deviceFindFS }

func (f deniedDeviceFindFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := f.deviceFindFS.ReadDir(name)
	for i, entry := range entries {
		if entry.IsDir() {
			entries[i] = deniedDeviceEntry{entry}
		}
	}
	return entries, err
}

func TestFindFilesDeniedDeviceMetadata(t *testing.T) {
	f := afero.NewMemMapFs()
	mkDir(t, f, "root/mount")
	mkFile(t, f, "root/local")
	mkFile(t, f, "root/mount/foreign")
	deviceFS := &deviceFindFS{FS: afero.NewIOFS(f)}
	found, err := FindFilesWithOptions(deniedDeviceFindFS{deviceFS}, "root", nil, "file", nil, nil, FindOptions{})
	require.ErrorIs(t, err, fs.ErrPermission)
	require.ErrorContains(t, err, `filesystem boundary at "root/mount"`)
	require.Nil(t, found, "a strict search must not succeed without proving each boundary")
	require.NotContains(t, deviceFS.reads, "root/mount", "stat refusal does not imply ReadDir would also be denied")
}
