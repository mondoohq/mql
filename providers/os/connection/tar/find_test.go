// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar_test

import (
	archivetar "archive/tar"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

type findEntry struct {
	name string
	typ  byte
	mode int64
	link string
}

// findFixtureFs is the sweep's /etc/c3-links fixture plus a slice of
// debian:12's /usr/bin, as `docker export` writes them: hard2 is a tar
// hardlink to hard1, su is setuid, and realdirx is a sibling of realdir that
// shares its name as a prefix.
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
