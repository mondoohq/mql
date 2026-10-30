// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar

import (
	"archive/tar"
	"io/fs"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestFs builds a filesystem holding one regular file and one symlink whose
// target is not in the archive, the way systemd masks a unit by pointing it at
// /dev/null.
func newTestFs() *FS {
	f := NewFs("test")
	f.FileMap["/etc/systemd/system/real.service"] = &tar.Header{
		Name:     "etc/systemd/system/real.service",
		Typeflag: tar.TypeReg,
		Size:     10,
	}
	f.FileMap["/etc/systemd/system/masked.service"] = &tar.Header{
		Name:     "etc/systemd/system/masked.service",
		Typeflag: tar.TypeSymlink,
		Linkname: "/dev/null",
	}
	return f
}

func TestFsImplementsLstaterAndLinkReader(t *testing.T) {
	var f afero.Fs = NewFs("test")

	_, isLstater := f.(afero.Lstater)
	assert.True(t, isLstater, "systemd unit lookup probes for afero.Lstater to tell a masked unit from a real one")

	_, isLinkReader := f.(afero.LinkReader)
	assert.True(t, isLinkReader, "reading the link target is how a masked unit is recognised")
}

func TestLstatDoesNotFollowSymlinks(t *testing.T) {
	f := newTestFs()

	info, wasLstat, err := f.LstatIfPossible("/etc/systemd/system/masked.service")
	require.NoError(t, err, "lstat of a dangling symlink must succeed: the link itself exists")
	assert.True(t, wasLstat)
	assert.NotZero(t, info.Mode()&fs.ModeSymlink, "the link must be reported as a symlink, not as its target")
}

func TestReadlinkReturnsTheTarget(t *testing.T) {
	f := newTestFs()

	target, err := f.ReadlinkIfPossible("/etc/systemd/system/masked.service")
	require.NoError(t, err)
	assert.Equal(t, "/dev/null", target)

	_, err = f.ReadlinkIfPossible("/etc/systemd/system/real.service")
	assert.Error(t, err, "a regular file is not a link")
}

// A symlink whose target is absent is a dangling symlink, which os.Stat reports
// as not-exist. Returning a bare error made callers that branch on
// os.IsNotExist treat it as fatal, and one masked unit aborted the whole
// systemd service list.
func TestStatOfDanglingSymlinkIsNotExist(t *testing.T) {
	f := newTestFs()

	_, err := f.Stat("/etc/systemd/system/masked.service")
	require.Error(t, err)
	assert.True(t, os.IsNotExist(err),
		"a dangling symlink must read as not-exist, got %v", err)
}
