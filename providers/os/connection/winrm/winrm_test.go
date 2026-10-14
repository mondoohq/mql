// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package winrm

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return f.size }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

// statFs answers Stat from stat, as cat.Fs does: what a path points to.
type statFs struct {
	afero.Fs
	stat map[string]os.FileInfo
}

func (s statFs) Stat(name string) (os.FileInfo, error) {
	if fi, ok := s.stat[name]; ok {
		return fi, nil
	}
	return nil, &os.PathError{Op: "stat", Path: name, Err: os.ErrNotExist}
}

// lstatFs also answers LstatIfPossible from lstat: the link itself.
type lstatFs struct {
	statFs
	lstat map[string]os.FileInfo
}

func (l lstatFs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	if fi, ok := l.lstat[name]; ok {
		return fi, true, nil
	}
	return nil, true, &os.PathError{Op: "lstat", Path: name, Err: os.ErrNotExist}
}

func TestFileInfoReportsLinks(t *testing.T) {
	plain := fakeInfo{name: "plain.txt", size: 5, mode: 0o666}
	target := fakeInfo{name: "target.txt", size: 12, mode: 0o444}
	dir := fakeInfo{name: "dir", mode: os.ModeDir | 0o777}
	link := fakeInfo{name: "link", mode: os.ModeSymlink | 0o666}

	fs := lstatFs{
		statFs: statFs{Fs: afero.NewMemMapFs(), stat: map[string]os.FileInfo{
			`C:\t\plain.txt`: plain,
			`C:\t\link.txt`:  target,
			`C:\t\junction`:  dir,
		}},
		lstat: map[string]os.FileInfo{
			`C:\t\plain.txt`: plain,
			`C:\t\link.txt`:  link,
			`C:\t\junction`:  link,
			`C:\t\dangling`:  link,
		},
	}

	fi, err := fileInfo(fs, `C:\t\plain.txt`)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o666), fi.Mode.FileMode)
	assert.Equal(t, int64(5), fi.Size)
	assert.Equal(t, int64(-1), fi.Uid)
	assert.Equal(t, int64(-1), fi.Gid)

	fi, err = fileInfo(fs, `C:\t\link.txt`)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink|0o444, fi.Mode.FileMode, "the target's permissions, with the link bit")
	assert.Equal(t, int64(12), fi.Size, "the target's size")

	fi, err = fileInfo(fs, `C:\t\junction`)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink|os.ModeDir|0o777, fi.Mode.FileMode)

	fi, err = fileInfo(fs, `C:\t\dangling`)
	require.NoError(t, err)
	assert.Equal(t, link.mode, fi.Mode.FileMode)

	_, err = fileInfo(fs, `C:\t\missing`)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

func TestFileInfoWithoutLstat(t *testing.T) {
	fs := statFs{Fs: afero.NewMemMapFs(), stat: map[string]os.FileInfo{
		`C:\t\link.txt`: fakeInfo{name: "link.txt", size: 0, mode: 0o666},
	}}
	fi, err := fileInfo(fs, `C:\t\link.txt`)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o666), fi.Mode.FileMode)
}
