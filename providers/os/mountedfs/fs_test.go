// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package mountedfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newConfinementFixture lays out a scanned root next to a directory that
// stands in for the scanning host. Every file in the root reads "target",
// every file outside reads "host". The links mirror what a crafted image can
// ship: absolute targets naming host paths, relative targets climbing out
// with "..", directory links, and a loop.
func newConfinementFixture(t *testing.T) (root string, host string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	host = filepath.Join(base, "host")

	write := func(p, content string) {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}
	link := func(target, p string) {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.Symlink(target, p))
	}

	write(filepath.Join(host, "secret"), "host")
	write(filepath.Join(host, "etc", "passwd"), "host")
	write(filepath.Join(root, "etc", "passwd"), "target")
	write(filepath.Join(root, "usr", "bin", "tool"), "target")
	write(filepath.Join(root, "etc", "real", "in.conf"), "target")

	// absolute link naming a path that exists in the target: chroot semantics
	link("/etc/passwd", filepath.Join(root, "etc", "abs-inside"))
	// absolute link naming a path that only exists on the scanning host
	link(filepath.Join(host, "secret"), filepath.Join(root, "etc", "abs-escape"))
	// relative link climbing past the root
	link(strings.Repeat("../", 64)+filepath.Join(host, "secret")[1:], filepath.Join(root, "etc", "rel-escape"))
	// relative link to a sibling, which must keep working
	link("passwd", filepath.Join(root, "etc", "rel-inside"))
	// usr-merge style directory link, relative and absolute
	link("usr/bin", filepath.Join(root, "bin"))
	link("/etc/real", filepath.Join(root, "etc", "absdir"))
	// directory link onto the host, used as an intermediate component
	link(host, filepath.Join(root, "hostdir"))
	// directory link to "/", then climb with ".."
	link("/", filepath.Join(root, "slash"))
	// loop
	link("loop-b", filepath.Join(root, "etc", "loop-a"))
	link("loop-a", filepath.Join(root, "etc", "loop-b"))
	return root, host
}

func readString(t *testing.T, fs afero.Fs, name string) (string, error) {
	t.Helper()
	b, err := afero.ReadFile(fs, name)
	return string(b), err
}

func TestMountedFsResolvesLinksInsideRoot(t *testing.T) {
	root, _ := newConfinementFixture(t)
	fs := NewMountedFs(root)

	for _, name := range []string{
		"/etc/passwd",
		"/etc/abs-inside",
		"/etc/rel-inside",
		"/bin/tool",
		"/etc/absdir/in.conf",
		"/slash/etc/passwd",
		"/slash/../../../etc/passwd",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readString(t, fs, name)
			require.NoError(t, err)
			assert.Equal(t, "target", got)

			st, err := fs.Stat(name)
			require.NoError(t, err)
			assert.False(t, st.IsDir())
		})
	}
}

func TestMountedFsNeverReadsTheScanningHost(t *testing.T) {
	root, host := newConfinementFixture(t)
	fs := NewMountedFs(root)

	for _, name := range []string{
		"/etc/abs-escape",
		"/etc/rel-escape",
		"/hostdir/secret",
		"/slash/" + strings.Repeat("../", 64) + filepath.Join(host, "secret")[1:],
		"/" + strings.Repeat("../", 64) + filepath.Join(host, "secret")[1:],
		strings.Repeat("../", 64) + filepath.Join(host, "secret")[1:],
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readString(t, fs, name)
			assert.NotEqual(t, "host", got)
			assert.True(t, os.IsNotExist(err), "want not-exist, got %v", err)

			_, err = fs.Stat(name)
			assert.True(t, os.IsNotExist(err), "want not-exist, got %v", err)

			f, err := fs.OpenFile(name, os.O_RDONLY, 0)
			if err == nil {
				f.Close()
			}
			assert.True(t, os.IsNotExist(err), "want not-exist, got %v", err)
		})
	}
}

func TestMountedFsLstatAndReadlinkDoNotFollowTheLeaf(t *testing.T) {
	root, host := newConfinementFixture(t)
	lfs := NewMountedFs(root).(afero.Lstater)
	rfs := NewMountedFs(root).(afero.LinkReader)

	fi, _, err := lfs.LstatIfPossible("/etc/abs-escape")
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink, fi.Mode()&os.ModeSymlink)

	target, err := rfs.ReadlinkIfPossible("/etc/abs-escape")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(host, "secret"), target)

	// the parent directories are still resolved inside the root: /bin is a
	// link to usr/bin, so this is root/usr/bin/tool, a regular file
	fi, _, err = lfs.LstatIfPossible("/bin/tool")
	require.NoError(t, err)
	assert.True(t, fi.Mode().IsRegular())

	// a parent that links onto the host does not reach it
	_, _, err = lfs.LstatIfPossible("/hostdir/secret")
	assert.True(t, os.IsNotExist(err), "want not-exist, got %v", err)
	_, err = rfs.ReadlinkIfPossible("/hostdir/secret")
	assert.Error(t, err)
}

func TestMountedFsLinkLoopIsAnError(t *testing.T) {
	root, _ := newConfinementFixture(t)
	fs := NewMountedFs(root)

	_, err := fs.Open("/etc/loop-a")
	require.Error(t, err)
	_, err = fs.Stat("/etc/loop-a")
	require.Error(t, err)

	// the link itself is still there to lstat
	fi, _, err := fs.(afero.Lstater).LstatIfPossible("/etc/loop-a")
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink, fi.Mode()&os.ModeSymlink)
}

func TestMountedFsDirectoryListingThroughLinks(t *testing.T) {
	root, _ := newConfinementFixture(t)
	fs := NewMountedFs(root)

	names, err := afero.ReadDir(fs, "/bin")
	require.NoError(t, err)
	require.Len(t, names, 1)
	assert.Equal(t, "tool", names[0].Name())

	_, err = afero.ReadDir(fs, "/hostdir")
	assert.True(t, os.IsNotExist(err), "want not-exist, got %v", err)
}

func TestMountedFsFindStaysInsideRoot(t *testing.T) {
	root, _ := newConfinementFixture(t)
	fs := NewMountedFs(root).(*MountedFs)

	found, err := fs.Find("/hostdir", nil, "", nil, nil)
	if err == nil {
		assert.Empty(t, found)
	}

	found, err = fs.Find("/bin", nil, "f", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"/bin/tool"}, found)
}
