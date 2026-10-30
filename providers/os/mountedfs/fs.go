// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mountedfs

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/fsutil"
)

var _ shared.FileSearch = (*MountedFs)(nil)

var errNotSupported = errors.New("not supported")

type MountedFs struct {
	prefix string
}

func NewMountedFs(mountedDir string) afero.Fs {
	return &MountedFs{
		prefix: mountedDir,
	}
}

func (t *MountedFs) getPath(name string) string {
	// NOTE: this uses local os filepaths, so mounting a linux system on windows will not work yet
	return filepath.Join(t.prefix, name)
}

func (t *MountedFs) Name() string { return "Mounted Fs" }

func (t *MountedFs) Create(name string) (afero.File, error) {
	mountedPath := t.getPath(name)
	f, e := os.Create(mountedPath)
	if f == nil {
		// while this looks strange, we need to return a bare nil (of type nil) not
		// a nil value of type *os.File or nil won't be nil
		return nil, e
	}
	return NewMountedFile(name, f), e
}

func (t *MountedFs) Mkdir(name string, perm os.FileMode) error {
	return errNotSupported
}

func (t *MountedFs) MkdirAll(path string, perm os.FileMode) error {
	return errNotSupported
}

func (t *MountedFs) Open(name string) (afero.File, error) {
	mountedPath := t.getPath(name)
	f, e := os.Open(mountedPath)
	if f == nil {
		// while this looks strange, we need to return a bare nil (of type nil) not
		// a nil value of type *os.File or nil won't be nil
		return nil, e
	}
	return NewMountedFile(name, f), e
}

func (t *MountedFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	mountedPath := t.getPath(name)
	f, e := os.OpenFile(mountedPath, flag, perm)
	if f == nil {
		// while this looks strange, we need to return a bare nil (of type nil) not
		// a nil value of type *os.File or nil won't be nil
		return nil, e
	}
	return NewMountedFile(name, f), e
}

func (t *MountedFs) Remove(name string) error {
	return errNotSupported
}

func (t *MountedFs) RemoveAll(path string) error {
	return errNotSupported
}

func (t *MountedFs) Rename(oldname, newname string) error {
	return errNotSupported
}

func (t *MountedFs) Stat(name string) (os.FileInfo, error) {
	mountedPath := t.getPath(name)
	return os.Stat(mountedPath)
}

func (t *MountedFs) Chmod(name string, mode os.FileMode) error {
	return errNotSupported
}

func (t *MountedFs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return errNotSupported
}

func (t *MountedFs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	mountedPath := t.getPath(name)
	fi, err := os.Lstat(mountedPath)
	return fi, true, err
}

func (t *MountedFs) ReadlinkIfPossible(name string) (string, error) {
	mountedPath := t.getPath(name)
	return os.Readlink(mountedPath)
}

func (t *MountedFs) Chown(name string, uid, gid int) error {
	return errNotSupported
}

func (t *MountedFs) Find(from string, r *regexp.Regexp, typ string, perm *uint32, depth *int) ([]string, error) {
	iofs := afero.NewIOFS(t)
	return fsutil.FindFiles(iofs, from, r, typ, perm, depth)
}

func (t *MountedFs) FindWithOptions(from string, r *regexp.Regexp, typ string, perm *uint32, depth *int, options fsutil.FindOptions) ([]string, error) {
	return fsutil.FindFilesWithOptions(afero.NewIOFS(t), from, r, typ, perm, depth, options)
}
