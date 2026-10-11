// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar_test

import (
	archivetar "archive/tar"
	"debug/elf"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

// deactivate test for now for speedier testing
// in contrast to alpine, the symlink on centos is pointing to a relative target and not an absolute one
func TestTarRelativeSymlinkFileCentos(t *testing.T) {
	err := cacheCentos()
	require.NoError(t, err, "should create tar without error")

	c, err := tar.NewConnection(0, &inventory.Config{
		Type: "tar",
		Options: map[string]string{
			tar.OPTION_FILE: centosContainerPath,
		},
	}, &inventory.Asset{})
	assert.Equal(t, nil, err, "should create tar without error")

	f, err := c.FileSystem().Open("/etc/redhat-release")
	require.NoError(t, err)

	if assert.NotNil(t, f) {
		assert.Equal(t, nil, err, "should execute without error")

		p := f.Name()
		assert.Equal(t, "/etc/redhat-release", p, "path should be correct")

		stat, err := f.Stat()
		assert.Equal(t, nil, err, "should stat without error")
		assert.Equal(t, int64(37), stat.Size(), "should read file size")

		content, err := io.ReadAll(f)
		assert.Equal(t, nil, err, "should execute without error")
		assert.Equal(t, 37, len(content), "should read the full content")
	}
}

func TestTarFileAlpine(t *testing.T) {
	err := cacheAlpine()
	require.NoError(t, err, "should create tar without error")

	c, err := tar.NewConnection(0, &inventory.Config{
		Type: "tar",
		Options: map[string]string{
			tar.OPTION_FILE: alpineContainerPath,
		},
	}, &inventory.Asset{})
	assert.Equal(t, nil, err, "should create tar without error")

	t.Run("test file content", func(t *testing.T) {
		f, err := c.FileSystem().Open("/etc/alpine-release")
		assert.Nil(t, err)
		if assert.NotNil(t, f) {
			assert.Equal(t, nil, err, "should execute without error")

			p := f.Name()
			assert.Equal(t, "/etc/alpine-release", p, "path should be correct")

			stat, err := f.Stat()
			assert.Equal(t, int64(8), stat.Size(), "should read file size")
			assert.Equal(t, nil, err, "should execute without error")

			content, err := io.ReadAll(f)
			assert.Equal(t, nil, err, "should execute without error")
			assert.Equal(t, 8, len(content), "should read the full content")
		}
	})

	t.Run("test file permissions", func(t *testing.T) {
		path := "/etc/alpine-release"
		details, err := c.FileInfo(path)
		require.NoError(t, err)
		assert.Equal(t, int64(0), details.Uid)
		assert.Equal(t, int64(0), details.Gid)
		assert.True(t, details.Size >= 0)
		assert.Equal(t, false, details.Mode.IsDir())
		assert.Equal(t, true, details.Mode.IsRegular())
		assert.Equal(t, "-rw-r--r--", details.Mode.String())
		assert.True(t, details.Mode.UserReadable())
		assert.True(t, details.Mode.UserWriteable())
		assert.False(t, details.Mode.UserExecutable())
		assert.True(t, details.Mode.GroupReadable())
		assert.False(t, details.Mode.GroupWriteable())
		assert.False(t, details.Mode.GroupExecutable())
		assert.True(t, details.Mode.OtherReadable())
		assert.False(t, details.Mode.OtherWriteable())
		assert.False(t, details.Mode.OtherExecutable())
		assert.False(t, details.Mode.Suid())
		assert.False(t, details.Mode.Sgid())
		assert.False(t, details.Mode.Sticky())

		path = "/etc"
		details, err = c.FileInfo(path)
		require.NoError(t, err)
		assert.Equal(t, int64(0), details.Uid)
		assert.Equal(t, int64(0), details.Gid)
		assert.True(t, details.Size >= 0)
		assert.True(t, details.Mode.IsDir())
		assert.False(t, details.Mode.IsRegular())
		assert.Equal(t, "drwxr-xr-x", details.Mode.String())
		assert.True(t, details.Mode.UserReadable())
		assert.True(t, details.Mode.UserWriteable())
		assert.True(t, details.Mode.UserExecutable())
		assert.True(t, details.Mode.GroupReadable())
		assert.False(t, details.Mode.GroupWriteable())
		assert.True(t, details.Mode.GroupExecutable())
		assert.True(t, details.Mode.OtherReadable())
		assert.False(t, details.Mode.OtherWriteable())
		assert.True(t, details.Mode.OtherExecutable())
		assert.False(t, details.Mode.Suid())
		assert.False(t, details.Mode.Sgid())
		assert.False(t, details.Mode.Sticky())
	})

	t.Run("test symlink", func(t *testing.T) {
		c, err := tar.NewConnection(0, &inventory.Config{
			Type: "tar",
			Options: map[string]string{
				tar.OPTION_FILE: alpineContainerPath,
			},
		}, &inventory.Asset{})
		assert.Equal(t, nil, err, "should create tar without error")

		f, err := c.FileSystem().Open("/bin/cat")
		assert.Nil(t, err)
		if assert.NotNil(t, f) {
			assert.Equal(t, nil, err, "should execute without error")

			p := f.Name()
			assert.Equal(t, "/bin/cat", p, "path should be correct")

			stat, err := f.Stat()
			assert.Equal(t, nil, err, "should stat without error")
			assert.Equal(t, int64(829000), stat.Size(), "should read file size")

			content, err := io.ReadAll(f)
			assert.Equal(t, nil, err, "should execute without error")
			assert.Equal(t, 829000, len(content), "should read the full content")
		}
	})

	t.Run("test file search", func(t *testing.T) {
		fs := c.FileSystem()
		fSearch := fs.(*tar.FS)
		infos, err := fSearch.Find("/", regexp.MustCompile(`alpine-release`), "file", nil, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, len(infos))
	})

	t.Run("test file readdirnames", func(t *testing.T) {
		fs := c.FileSystem()
		tarFs := fs.(*tar.FS)
		d, err := tarFs.Open("/etc/apk")
		require.NoError(t, err)
		defer d.Close()
		names, err := d.Readdirnames(-1)
		require.NoError(t, err)
		assert.Equal(t, 5, len(names))
		sort.Strings(names)
		assert.Equal(t, []string{"arch", "keys", "protected_paths.d", "repositories", "world"}, names)
	})
}

// Platform detection falls back to reading the ELF header of a binary on the
// target when there is no command capability to ask `uname -m`, which is every
// container image scan. elf.NewFile needs io.ReaderAt, so the tar filesystem
// has to provide one.
func TestTarFileReadAt(t *testing.T) {
	err := cacheAlpine()
	require.NoError(t, err, "should create tar without error")

	c, err := tar.NewConnection(0, &inventory.Config{
		Type: "tar",
		Options: map[string]string{
			tar.OPTION_FILE: alpineContainerPath,
		},
	}, &inventory.Asset{})
	require.NoError(t, err)

	t.Run("reads the bytes at an offset", func(t *testing.T) {
		f, err := c.FileSystem().Open("/etc/alpine-release")
		require.NoError(t, err)
		full, err := io.ReadAll(f)
		require.NoError(t, err)
		require.Greater(t, len(full), 6)

		f2, err := c.FileSystem().Open("/etc/alpine-release")
		require.NoError(t, err)
		ra, ok := f2.(io.ReaderAt)
		require.True(t, ok, "tar file must implement io.ReaderAt")

		buf := make([]byte, 4)
		n, err := ra.ReadAt(buf, 2)
		require.NoError(t, err)
		assert.Equal(t, 4, n)
		assert.Equal(t, full[2:6], buf)
	})

	t.Run("an ELF binary parses over the tar filesystem", func(t *testing.T) {
		f, err := c.FileSystem().Open("/bin/busybox")
		require.NoError(t, err)
		ra, ok := f.(io.ReaderAt)
		require.True(t, ok, "tar file must implement io.ReaderAt")

		ef, err := elf.NewFile(ra)
		require.NoError(t, err, "elf.NewFile must work over the tar filesystem")
		assert.NotEqual(t, elf.EM_NONE, ef.Machine, "ELF machine type must be readable")
	})
}

type tarEntry struct {
	name string
	typ  byte
	link string
	body string
}

func writeTar(t *testing.T, entries []tarEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	tw := archivetar.NewWriter(f)
	for _, e := range entries {
		h := &archivetar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: 0o644}
		switch e.typ {
		case archivetar.TypeDir:
			h.Mode = 0o755
		case archivetar.TypeSymlink:
			h.Mode = 0o777
		case archivetar.TypeReg:
			h.Size = int64(len(e.body))
		}
		require.NoError(t, tw.WriteHeader(h))
		if e.typ == archivetar.TypeReg {
			_, err := tw.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	return path
}

// usrMergedImage mirrors the layout of a `docker export` of debian:12 (and
// every other usr-merged image), plus the link fixtures the container sweep
// used. The names and link targets are the ones `ls -l` shows in the image.
func usrMergedImage(t *testing.T) *tar.Connection {
	return ostreeConn(t, writeTar(t, []tarEntry{
		{name: "bin", typ: archivetar.TypeSymlink, link: "usr/bin"},
		{name: "lib", typ: archivetar.TypeSymlink, link: "usr/lib"},
		{name: "sbin", typ: archivetar.TypeSymlink, link: "usr/sbin"},
		{name: "usr/", typ: archivetar.TypeDir},
		{name: "usr/bin/", typ: archivetar.TypeDir},
		{name: "usr/bin/dash", typ: archivetar.TypeReg, body: "dash-binary"},
		{name: "usr/bin/sh", typ: archivetar.TypeSymlink, link: "dash"},
		{name: "usr/sbin/", typ: archivetar.TypeDir},
		{name: "usr/sbin/sshd", typ: archivetar.TypeReg, body: "sshd-binary"},
		{name: "usr/lib/", typ: archivetar.TypeDir},
		{name: "usr/lib/systemd/system/ssh.service", typ: archivetar.TypeReg, body: "[Unit]\n"},
		// usr/share/doc/ and usr/share/zoneinfo/ deliberately have no entry of
		// their own, as in a layer tar that omits parent directories
		{name: "usr/share/", typ: archivetar.TypeDir},
		// Debian points the doc dir of a package built from another source
		// at that source's doc dir.
		{name: "usr/share/doc/gcc-12-base/copyright", typ: archivetar.TypeReg, body: "License: GPL-3\n"},
		{name: "usr/share/doc/libgcc-s1", typ: archivetar.TypeSymlink, link: "gcc-12-base"},
		{name: "usr/share/zoneinfo/UTC", typ: archivetar.TypeReg, body: "TZif"},
		{name: "etc/", typ: archivetar.TypeDir},
		{name: "etc/c3-links/", typ: archivetar.TypeDir},
		{name: "etc/c3-links/target.conf", typ: archivetar.TypeReg, body: "hello\n"},
		{name: "etc/c3-links/tofile", typ: archivetar.TypeSymlink, link: "target.conf"},
		{name: "etc/c3-links/broken", typ: archivetar.TypeSymlink, link: "/nonexistent/c3"},
		{name: "etc/c3-links/realdir/", typ: archivetar.TypeDir},
		{name: "etc/c3-links/realdir/in.conf", typ: archivetar.TypeReg, body: "inner\n"},
		{name: "etc/c3-links/todir", typ: archivetar.TypeSymlink, link: "realdir"},
		{name: "etc/c3-links/absdir", typ: archivetar.TypeSymlink, link: "/usr/share/zoneinfo"},
		{name: "etc/c3-links/loop1", typ: archivetar.TypeSymlink, link: "loop2"},
		{name: "etc/c3-links/loop2", typ: archivetar.TypeSymlink, link: "loop1"},
		// Alpine keeps the user crontabs in /etc/crontabs and links the spool
		// path to it.
		{name: "etc/crontabs/", typ: archivetar.TypeDir},
		{name: "etc/crontabs/root", typ: archivetar.TypeReg, body: "* * * * * true\n"},
		{name: "var/spool/cron/crontabs", typ: archivetar.TypeSymlink, link: "/etc/crontabs"},
	}))
}

func readAll(t *testing.T, fs afero.Fs, path string) string {
	t.Helper()
	f, err := fs.Open(path)
	require.NoError(t, err, path)
	defer f.Close()
	b, err := io.ReadAll(f)
	require.NoError(t, err, path)
	return string(b)
}

// A path whose directory part runs through a symlink resolves the way the
// kernel resolves it. Only the last component used to be followed, so every
// usr-merged image read /bin/sh, /sbin/sshd and /lib/systemd/... as absent.
func TestTarResolvesSymlinkedDirectories(t *testing.T) {
	fs := usrMergedImage(t).FileSystem()

	assert.Equal(t, "dash-binary", readAll(t, fs, "/bin/sh"), "bin -> usr/bin, then sh -> dash")
	assert.Equal(t, "sshd-binary", readAll(t, fs, "/sbin/sshd"))
	assert.Equal(t, "[Unit]\n", readAll(t, fs, "/lib/systemd/system/ssh.service"))
	assert.Equal(t, "inner\n", readAll(t, fs, "/etc/c3-links/todir/in.conf"))
	assert.Equal(t, "TZif", readAll(t, fs, "/etc/c3-links/absdir/UTC"), "absolute directory link")
	assert.Equal(t, "License: GPL-3\n", readAll(t, fs, "/usr/share/doc/libgcc-s1/copyright"))

	st, err := fs.Stat("/lib/systemd/system/ssh.service")
	require.NoError(t, err)
	assert.Equal(t, int64(7), st.Size())

	_, err = fs.Stat("/bin/nope")
	assert.True(t, os.IsNotExist(err), "a missing file behind a directory link is not-exist, got %v", err)
}

// Lstat follows the directory components but not the last one.
func TestTarLstatThroughSymlinkedDirectory(t *testing.T) {
	fs := usrMergedImage(t).FileSystem()
	lstater := fs.(afero.Lstater)

	info, _, err := lstater.LstatIfPossible("/bin/sh")
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "/bin/sh itself is a symlink")

	target, err := fs.(afero.LinkReader).ReadlinkIfPossible("/bin/sh")
	require.NoError(t, err)
	assert.Equal(t, "dash", target)
}

// Listing a directory reached through a symlink lists the target's direct
// children. It used to list the link entry itself, so Alpine's crontab spool
// read as one user named "crontabs".
func TestTarReadDirThroughSymlink(t *testing.T) {
	afs := &afero.Afero{Fs: usrMergedImage(t).FileSystem()}

	infos, err := afs.ReadDir("/var/spool/cron/crontabs")
	require.NoError(t, err)
	names := []string{}
	for _, i := range infos {
		names = append(names, i.Name())
	}
	assert.Equal(t, []string{"root"}, names)

	f, err := afs.Open("/var/spool/cron/crontabs")
	require.NoError(t, err)
	dirnames, err := f.Readdirnames(-1)
	require.NoError(t, err)
	assert.Equal(t, []string{"root"}, dirnames)

	// reading a directory is an error, as on a live system: the RHEL spool
	// walk of /var/spool/cron opens the crontabs link and must not parse it
	// as an empty crontab
	_, err = io.ReadAll(f)
	assert.Error(t, err)

	// direct children only, and no sibling that merely shares the prefix
	infos, err = afs.ReadDir("/etc/c3-links/realdir")
	require.NoError(t, err)
	require.Len(t, infos, 1)
	assert.Equal(t, "in.conf", infos[0].Name())

	infos, err = afs.ReadDir("/usr/share")
	require.NoError(t, err)
	names = names[:0]
	for _, i := range infos {
		names = append(names, i.Name())
	}
	sort.Strings(names)
	assert.Equal(t, []string{"doc", "zoneinfo"}, names, "implicit directories are listed, descendants are not")
}
