// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

// unlistableFs refuses to open the given directories, the way a non-root
// user sees /etc/polkit-1/rules.d (0750 root:polkitd on Ubuntu 24.04) or a
// ~/.ssh (0700) inside a world-readable home: the directory stats, but
// listing it fails with EACCES.
type unlistableFs struct {
	afero.Fs
	denied map[string]bool
}

func (f *unlistableFs) Open(name string) (afero.File, error) {
	if f.denied[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: os.ErrPermission}
	}
	return f.Fs.Open(name)
}

func newUnlistableFs(t *testing.T, files []string, denied ...string) *unlistableFs {
	t.Helper()
	mem := afero.NewMemMapFs()
	for _, f := range files {
		require.NoError(t, afero.WriteFile(mem, f, []byte("x"), 0o644))
	}
	d := map[string]bool{}
	for _, p := range denied {
		d[p] = true
	}
	return &unlistableFs{Fs: mem, denied: d}
}

// withStructuredErrors sets the process-wide StructuredErrors feature for the
// rest of the test and resets it on cleanup. It is not safe for tests that
// call t.Parallel().
func withStructuredErrors(t *testing.T, on bool) {
	t.Helper()
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
	if on {
		plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	} else {
		plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)}))
	}
}

func TestGlobDir(t *testing.T) {
	fsys := newUnlistableFs(t, []string{
		"/etc/polkit-1/rules.d/50-b.rules",
		"/etc/polkit-1/rules.d/40-a.rules",
		"/etc/polkit-1/rules.d/README",
		"/etc/polkit-1/localauthority/50-local.d/x.pkla",
		"/etc/polkit-1/localauthority/notadir.pkla",
	}, "/denied")
	require.NoError(t, fsys.MkdirAll("/denied", 0o750))

	got, err := globDir(fsys, "/etc/polkit-1/rules.d", "*.rules", false)
	require.NoError(t, err)
	assert.Equal(t, []string{"/etc/polkit-1/rules.d/40-a.rules", "/etc/polkit-1/rules.d/50-b.rules"}, got)

	got, err = globDir(fsys, "/etc/polkit-1/localauthority", "*", true)
	require.NoError(t, err)
	assert.Equal(t, []string{"/etc/polkit-1/localauthority/50-local.d"}, got)

	got, err = globDir(fsys, "/missing", "*.rules", false)
	require.NoError(t, err)
	assert.Empty(t, got)

	_, err = globDir(fsys, "/denied", "*.rules", false)
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden), "a refused listing is forbidden: %v", err)
}

func TestPolkitRuleFilesUnlistableDir(t *testing.T) {
	fsys := newUnlistableFs(t, []string{
		"/etc/polkit-1/rules.d/50-mqltest.rules",
		"/usr/share/polkit-1/rules.d/50-default.rules",
	}, "/etc/polkit-1/rules.d")

	withStructuredErrors(t, true)
	_, err := polkitRuleFiles(fsys)
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden))

	// v13: the unreadable directory is skipped, the readable one still listed
	withStructuredErrors(t, false)
	got, err := polkitRuleFiles(fsys)
	require.NoError(t, err)
	assert.Equal(t, [][]string{nil, nil, {"/usr/share/polkit-1/rules.d/50-default.rules"}}, got)
}

func TestPolkitRuleFilesReadable(t *testing.T) {
	fsys := newUnlistableFs(t, []string{
		"/etc/polkit-1/rules.d/50-mqltest.rules",
		"/usr/share/polkit-1/rules.d/50-default.rules",
	})
	withStructuredErrors(t, true)
	got, err := polkitRuleFiles(fsys)
	require.NoError(t, err)
	assert.Equal(t, [][]string{
		{"/etc/polkit-1/rules.d/50-mqltest.rules"}, nil, nil,
		{"/usr/share/polkit-1/rules.d/50-default.rules"},
	}, got)
}

func TestPolkitPklaFilesUnlistableDir(t *testing.T) {
	// Ubuntu 16.04 to 22.04: /etc/polkit-1/localauthority is 0700 root
	files := []string{
		"/etc/polkit-1/localauthority/50-local.d/mqltest.pkla",
		"/var/lib/polkit-1/localauthority/10-vendor.d/org.freedesktop.packagekit.pkla",
	}

	withStructuredErrors(t, true)
	got, err := polkitPklaFiles(newUnlistableFs(t, files))
	require.NoError(t, err)
	assert.Equal(t, files, got)

	_, err = polkitPklaFiles(newUnlistableFs(t, files, "/etc/polkit-1/localauthority"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden))

	// a numbered subdirectory that can't be listed fails too
	_, err = polkitPklaFiles(newUnlistableFs(t, files, "/var/lib/polkit-1/localauthority/10-vendor.d"))
	require.Error(t, err)

	withStructuredErrors(t, false)
	got, err = polkitPklaFiles(newUnlistableFs(t, files, "/etc/polkit-1/localauthority"))
	require.NoError(t, err)
	assert.Equal(t, files[1:], got)
}

func TestSSHKeyCandidatesUnlistableDir(t *testing.T) {
	files := []string{
		"/home/alice/.ssh/id_ed25519",
		"/home/alice/.ssh/id_ed25519.pub",
		"/home/alice/.ssh/known_hosts",
		"/home/alice/.ssh/config",
		"/home/alice/.ssh/sub/nested_key",
	}

	withStructuredErrors(t, true)
	got, err := sshKeyCandidates(newUnlistableFs(t, files), "/home/alice/.ssh")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"/home/alice/.ssh/id_ed25519", "/home/alice/.ssh/sub/nested_key"}, got)

	_, err = sshKeyCandidates(newUnlistableFs(t, files, "/home/alice/.ssh"), "/home/alice/.ssh")
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden))

	withStructuredErrors(t, false)
	got, err = sshKeyCandidates(newUnlistableFs(t, files, "/home/alice/.ssh"), "/home/alice/.ssh")
	require.NoError(t, err)
	assert.Empty(t, got)
}

// deniedDirFs refuses everything below the given directories, the way a
// non-root user sees /etc/cassandra or /etc/mysql at 0750 root:<service>:
// stat on any path inside fails with EACCES, so the scan cannot even tell
// whether a configuration file is there.
type deniedDirFs struct {
	afero.Fs
	dirs []string
}

func (f *deniedDirFs) denied(name string) error {
	for _, d := range f.dirs {
		if strings.HasPrefix(name, d+"/") {
			return &fs.PathError{Op: "stat", Path: name, Err: os.ErrPermission}
		}
	}
	return nil
}

func (f *deniedDirFs) Stat(name string) (os.FileInfo, error) {
	if err := f.denied(name); err != nil {
		return nil, err
	}
	return f.Fs.Stat(name)
}

func (f *deniedDirFs) Open(name string) (afero.File, error) {
	if err := f.denied(name); err != nil {
		return nil, err
	}
	return f.Fs.Open(name)
}

type deniedDirConn struct {
	*mock.Connection
	fs afero.Fs
}

func (c *deniedDirConn) FileSystem() afero.Fs { return c.fs }

func (c *deniedDirConn) FileInfo(path string) (shared.FileInfoDetails, error) {
	if err := c.fs.(*deniedDirFs).denied(path); err != nil {
		return shared.FileInfoDetails{}, err
	}
	return c.Connection.FileInfo(path)
}

func newDeniedDirRuntime(t *testing.T, data *mock.TomlData, dirs ...string) *plugin.Runtime {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "debian", Family: []string{"debian", "linux"}},
	}, mock.WithData(data))
	require.NoError(t, err)
	return &plugin.Runtime{
		Connection: &deniedDirConn{Connection: conn, fs: &deniedDirFs{Fs: conn.FileSystem(), dirs: dirs}},
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

func dirEntry(path string) *mock.MockFileData {
	return &mock.MockFileData{Path: path, StatData: mock.FileInfo{Mode: os.ModeDir | 0o750, IsDir: true}}
}

func fileEntry(path, content string) *mock.MockFileData {
	return &mock.MockFileData{Path: path, Content: content, StatData: mock.FileInfo{Mode: 0o644}}
}
