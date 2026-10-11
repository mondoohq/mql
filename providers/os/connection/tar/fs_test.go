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
		infos, err := fSearch.Find("/", regexp.MustCompile(`.*/alpine-release`), "file", nil, nil)
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

type findEntry struct {
	name string
	typ  byte
	mode int64
	link string
}

// findFixtureFs is the sweep's /etc/c3-links fixture plus a slice of
// debian:12's /usr/bin, as `docker export` writes them: hard2 is a tar
// hardlink to hard1, su is setuid, and realdirx is a sibling of realdir that
// shares its name as a prefix. bin links to usr/bin, as on a usr-merged image.
func findFixtureFs(t *testing.T) *tar.FS {
	t.Helper()
	path := filepath.Join(t.TempDir(), "find.tar")
	f, err := os.Create(path)
	require.NoError(t, err)
	tw := archivetar.NewWriter(f)
	for _, e := range []findEntry{
		{name: "etc/c3-links/", typ: archivetar.TypeDir, mode: 0o755},
		{name: "etc/c3-links/target.conf", typ: archivetar.TypeReg, mode: 0o644},
		{name: "etc/c3-links/tofile", typ: archivetar.TypeSymlink, mode: 0o777, link: "target.conf"},
		{name: "etc/c3-links/broken", typ: archivetar.TypeSymlink, mode: 0o777, link: "/nonexistent/c3"},
		{name: "etc/c3-links/realdir/", typ: archivetar.TypeDir, mode: 0o755},
		{name: "etc/c3-links/realdir/in.conf", typ: archivetar.TypeReg, mode: 0o644},
		{name: "etc/c3-links/realdirx/", typ: archivetar.TypeDir, mode: 0o755},
		{name: "etc/c3-links/realdirx/x.conf", typ: archivetar.TypeReg, mode: 0o644},
		{name: "etc/c3-links/todir", typ: archivetar.TypeSymlink, mode: 0o777, link: "realdir"},
		{name: "etc/c3-links/hard1", typ: archivetar.TypeReg, mode: 0o644},
		{name: "etc/c3-links/hard2", typ: archivetar.TypeLink, mode: 0o644, link: "etc/c3-links/hard1"},
		{name: "usr/bin/", typ: archivetar.TypeDir, mode: 0o755},
		{name: "usr/bin/su", typ: archivetar.TypeReg, mode: 0o4755},
		{name: "usr/bin/ls", typ: archivetar.TypeReg, mode: 0o755},
		{name: "usr/bin/wall", typ: archivetar.TypeReg, mode: 0o2755},
		{name: "bin", typ: archivetar.TypeSymlink, mode: 0o777, link: "usr/bin"},
	} {
		require.NoError(t, tw.WriteHeader(&archivetar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link}))
	}
	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())

	return ostreeConn(t, path).FileSystem().(*tar.FS)
}

func find(t *testing.T, fs *tar.FS, from string, r *regexp.Regexp, typ string, perm *uint32) []string {
	t.Helper()
	res, err := fs.Find(from, r, typ, perm, nil)
	require.NoError(t, err)
	sort.Strings(res)
	return res
}

func TestTarFindPermissions(t *testing.T) {
	fs := findFixtureFs(t)
	suid := uint32(0o4000)
	assert.Equal(t, []string{"/usr/bin/su"}, find(t, fs, "/usr/bin", nil, "file", &suid),
		"only the setuid binary: the permission filter used to be ignored")

	zero := uint32(0)
	assert.Len(t, find(t, fs, "/usr/bin", nil, "file", &zero), 3, "a zero mask is no filter")
}

func TestTarFindTypes(t *testing.T) {
	fs := findFixtureFs(t)

	assert.Equal(t, []string{
		"/etc/c3-links/hard1",
		"/etc/c3-links/hard2",
		"/etc/c3-links/realdir/in.conf",
		"/etc/c3-links/realdirx/x.conf",
		"/etc/c3-links/target.conf",
		"/etc/c3-links/tofile",
	}, find(t, fs, "/etc/c3-links", nil, "file", nil), "a hardlink and a link to a file are files, as with find -L")

	assert.Equal(t, []string{
		"/etc/c3-links",
		"/etc/c3-links/realdir",
		"/etc/c3-links/realdirx",
		"/etc/c3-links/todir",
	}, find(t, fs, "/etc/c3-links", nil, "directory", nil))

	assert.Equal(t, []string{
		"/etc/c3-links/broken",
		"/etc/c3-links/todir",
		"/etc/c3-links/tofile",
	}, find(t, fs, "/etc/c3-links", nil, "link", nil))

	assert.Equal(t, find(t, fs, "/etc/c3-links", nil, "file", nil), find(t, fs, "/etc/c3-links", nil, "f", nil),
		"the one-letter find type is accepted, as the firefox and chrome lookups pass it")
}

func TestTarFindFromIsADirectory(t *testing.T) {
	fs := findFixtureFs(t)
	assert.Equal(t, []string{
		"/etc/c3-links/realdir",
		"/etc/c3-links/realdir/in.conf",
	}, find(t, fs, "/etc/c3-links/realdir", nil, "", nil), "the sibling realdirx is not under realdir")

	assert.Equal(t, find(t, fs, "/etc/c3-links/realdir", nil, "", nil), find(t, fs, "/etc/c3-links/realdir/", nil, "", nil))
}

func TestTarFindRegexIsAnchored(t *testing.T) {
	fs := findFixtureFs(t)
	assert.Empty(t, find(t, fs, "/etc/c3-links", regexp.MustCompile(`hard.*`), "", nil),
		"find -regex matches the whole path")
	assert.Equal(t, []string{"/etc/c3-links/hard1", "/etc/c3-links/hard2"},
		find(t, fs, "/etc/c3-links", regexp.MustCompile(`.*/hard.*`), "", nil))
}

func TestTarFindFromALinkedDirectory(t *testing.T) {
	fs := findFixtureFs(t)
	suid := uint32(0o4000)
	assert.Equal(t, []string{"/bin/su"}, find(t, fs, "/bin", nil, "file", &suid),
		"a start path that links to a directory is searched, as find -L does")
	assert.Equal(t, []string{"/bin", "/bin/ls", "/bin/su", "/bin/wall"}, find(t, fs, "/bin", nil, "", nil))
	assert.Equal(t, []string{"/bin/ls"}, find(t, fs, "/bin", regexp.MustCompile(`/bin/l.`), "", nil),
		"the regex sees the path below from")

	assert.Equal(t, []string{"/etc/c3-links/todir", "/etc/c3-links/todir/in.conf"}, find(t, fs, "/etc/c3-links/todir", nil, "", nil))
}
