// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar_test

import (
	archivetar "archive/tar"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

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

// FileInfo reports links the way the local connection does: a link to a file
// is a symlink with its target's size, a dangling link exists as a link, and a
// link loop is an error rather than a missing file.
func TestTarFileInfoSymlinkSemantics(t *testing.T) {
	c := usrMergedImage(t)

	fi, err := c.FileInfo("/etc/c3-links/tofile")
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode.FileMode&os.ModeSymlink, "isSymlink")
	assert.Equal(t, int64(6), fi.Size, "the target's size")

	fi, err = c.FileInfo("/bin")
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode.FileMode&os.ModeSymlink, "/bin is a symlink")
	assert.True(t, fi.Mode.FileMode&os.ModeDir != 0, "to a directory")

	fi, err = c.FileInfo("/etc/c3-links/broken")
	require.NoError(t, err, "a dangling link exists, as on a live system")
	assert.NotZero(t, fi.Mode.FileMode&os.ModeSymlink)

	_, err = c.FileInfo("/etc/c3-links/loop1")
	require.Error(t, err)
	assert.False(t, os.IsNotExist(err), "a loop is an error, not a missing file: %v", err)

	fi, err = c.FileInfo("/usr/bin/dash")
	require.NoError(t, err)
	assert.Zero(t, fi.Mode.FileMode&os.ModeSymlink)
	assert.Equal(t, int64(11), fi.Size)
}
