// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// typedFs reports a file type for selected paths, the way the local
// filesystem reports a FIFO, a socket or a symlink in ~/.ssh. MemMapFs can
// only hold regular files and directories.
type typedFs struct {
	afero.Fs
	lstat map[string]os.FileMode // type bits Lstat reports
	stat  map[string]os.FileMode // type bits Stat reports (symlink target)
	size  map[string]int64
}

type typedInfo struct {
	os.FileInfo
	mode os.FileMode
	size int64
}

func (i typedInfo) Mode() os.FileMode { return i.mode }
func (i typedInfo) Size() int64       { return i.size }
func (i typedInfo) IsDir() bool       { return i.mode.IsDir() }

func (f *typedFs) wrap(name string, fi os.FileInfo, modes map[string]os.FileMode) os.FileInfo {
	mode := fi.Mode()
	if m, ok := modes[name]; ok {
		mode = m | 0o600
	}
	size := fi.Size()
	if s, ok := f.size[name]; ok {
		size = s
	}
	return typedInfo{FileInfo: fi, mode: mode, size: size}
}

func (f *typedFs) Stat(name string) (os.FileInfo, error) {
	fi, err := f.Fs.Stat(name)
	if err != nil {
		return nil, err
	}
	return f.wrap(name, fi, f.stat), nil
}

func (f *typedFs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	fi, err := f.Fs.Stat(name)
	if err != nil {
		return nil, true, err
	}
	return f.wrap(name, fi, f.lstat), true, nil
}

func TestSSHKeyCandidatesOnlyRegularFiles(t *testing.T) {
	dir := "/home/alice/.ssh"
	mem := afero.NewMemMapFs()
	for _, name := range []string{
		"id_ed25519", "fifo", "cm-socket", "link_to_key", "link_to_fifo", "dev", "huge",
	} {
		require.NoError(t, afero.WriteFile(mem, dir+"/"+name, []byte("x"), 0o600))
	}
	fs := &typedFs{
		Fs: mem,
		lstat: map[string]os.FileMode{
			dir + "/fifo":         os.ModeNamedPipe,
			dir + "/cm-socket":    os.ModeSocket,
			dir + "/link_to_key":  os.ModeSymlink,
			dir + "/link_to_fifo": os.ModeSymlink,
			dir + "/dev":          os.ModeDevice | os.ModeCharDevice,
		},
		stat: map[string]os.FileMode{
			dir + "/fifo":         os.ModeNamedPipe,
			dir + "/cm-socket":    os.ModeSocket,
			dir + "/link_to_fifo": os.ModeNamedPipe,
			dir + "/dev":          os.ModeDevice | os.ModeCharDevice,
		},
		size: map[string]int64{dir + "/huge": maxSSHKeyFileSize + 1},
	}

	got, err := sshKeyCandidates(fs, dir)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{dir + "/id_ed25519", dir + "/link_to_key"}, got)
}

// Over SSH --sudo the cat filesystem stats with `stat -L` and marks a symlink
// by adding ModeSymlink to the target's type, so a symlink to a regular file
// arrives as ModeSymlink alone and one to a FIFO as ModeSymlink|ModeNamedPipe.
func TestSSHKeyCandidatesCatFsSymlinks(t *testing.T) {
	dir := "/home/alice/.ssh"
	mem := afero.NewMemMapFs()
	for _, name := range []string{"link_to_key", "link_to_fifo"} {
		require.NoError(t, afero.WriteFile(mem, dir+"/"+name, []byte("x"), 0o600))
	}
	modes := map[string]os.FileMode{
		dir + "/link_to_key":  os.ModeSymlink,
		dir + "/link_to_fifo": os.ModeSymlink | os.ModeNamedPipe,
	}
	fs := &typedFs{Fs: mem, lstat: modes, stat: modes}

	got, err := sshKeyCandidates(fs, dir)
	require.NoError(t, err)
	assert.Equal(t, []string{dir + "/link_to_key"}, got)
}
