// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mountedfs

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/fsutil"
)

var _ shared.FileSearch = (*MountedFs)(nil)

var errNotSupported = errors.New("not supported")

// MountedFs serves a directory on the scanning host as the root filesystem
// of the scanned target. Every path is resolved as if the directory were "/":
// symlinks are followed inside it, absolute link targets start over at it, and
// ".." never climbs above it. A link in the target can therefore never name a
// file on the scanning host.
type MountedFs struct {
	prefix string
}

func NewMountedFs(mountedDir string) afero.Fs {
	prefix := filepath.Clean(mountedDir)
	if abs, err := filepath.Abs(prefix); err == nil {
		prefix = abs
	}
	return &MountedFs{
		prefix: prefix,
	}
}

// getPath maps a path in the target to the host path it resolves to,
// following every symlink, the last component included, inside the mount.
func (t *MountedFs) getPath(name string) (string, error) {
	// NOTE: this uses local os filepaths, so mounting a linux system on windows will not work yet
	return securejoin.SecureJoin(t.prefix, name)
}

// getLinkPath maps a path in the target to a host path like getPath, but
// leaves the last component unresolved, for Lstat and Readlink.
func (t *MountedFs) getLinkPath(name string) (string, error) {
	dir, base := filepath.Split(name)
	if base == "" || base == "." || base == ".." {
		return t.getPath(name)
	}
	parent, err := t.getPath(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, base), nil
}

func (t *MountedFs) Name() string { return "Mounted Fs" }

func (t *MountedFs) Create(name string) (afero.File, error) {
	mountedPath, err := t.getPath(name)
	if err != nil {
		return nil, err
	}
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
	mountedPath, err := t.getPath(name)
	if err != nil {
		return nil, err
	}
	f, e := os.Open(mountedPath)
	if f == nil {
		// while this looks strange, we need to return a bare nil (of type nil) not
		// a nil value of type *os.File or nil won't be nil
		return nil, e
	}
	return NewMountedFile(name, f), e
}

func (t *MountedFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	mountedPath, err := t.getPath(name)
	if err != nil {
		return nil, err
	}
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
	mountedPath, err := t.getPath(name)
	if err != nil {
		return nil, err
	}
	return os.Stat(mountedPath)
}

func (t *MountedFs) Chmod(name string, mode os.FileMode) error {
	return errNotSupported
}

func (t *MountedFs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return errNotSupported
}

func (t *MountedFs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	mountedPath, err := t.getLinkPath(name)
	if err != nil {
		return nil, true, err
	}
	fi, err := os.Lstat(mountedPath)
	return fi, true, err
}

func (t *MountedFs) ReadlinkIfPossible(name string) (string, error) {
	mountedPath, err := t.getLinkPath(name)
	if err != nil {
		return "", err
	}
	return os.Readlink(mountedPath)
}

func (t *MountedFs) Chown(name string, uid, gid int) error {
	return errNotSupported
}

func (t *MountedFs) Find(from string, r *regexp.Regexp, typ string, perm *uint32, depth *int) ([]string, error) {
	iofs := afero.NewIOFS(t)
	return fsutil.FindFiles(iofs, from, r, typ, perm, depth)
}
