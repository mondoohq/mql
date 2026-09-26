// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"io/fs"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func chronyFs(t *testing.T, files map[string]string) *afero.Afero {
	t.Helper()
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for path, content := range files {
		require.NoError(t, afs.WriteFile(path, []byte(content), 0o644))
	}
	return afs
}

// leap16Chrony is the configuration openSUSE Leap 16 ships: chrony puts
// chrony.conf under /usr/etc, and chrony-pool-openSUSE adds the pool as a
// confdir drop-in. The pool line in chrony.conf itself is commented out.
var leap16Chrony = map[string]string{
	"/usr/etc/chrony.conf": "! pool pool.ntp.org iburst\n" +
		"driftfile /var/lib/chrony/drift\n" +
		"makestep 1.0 3\n" +
		"rtcsync\n" +
		"confdir /etc/chrony.d /usr/etc/chrony.d\n" +
		"sourcedir /run/chrony-dhcp\n",
	"/usr/etc/chrony.d/pool.conf": "pool 2.opensuse.pool.ntp.org iburst\n",
}

func chronySettings(lines ...string) []any {
	res := make([]any, len(lines))
	for i := range lines {
		res[i] = lines[i]
	}
	return res
}

func TestChronyDirectiveValues(t *testing.T) {
	settings := chronySettings(
		"server 0.pool.ntp.org iburst",
		"server 1.pool.ntp.org iburst",
		"pool 2.pool.ntp.org iburst maxsources 4",
		"allow 192.168.0.0/16",
		"deny all",
		"bindcmdaddress 127.0.0.1",
		"Server 3.pool.ntp.org", // case-insensitive directive match
	)

	require.Equal(t, []any{
		"0.pool.ntp.org iburst",
		"1.pool.ntp.org iburst",
		"3.pool.ntp.org",
	}, directiveValues(settings, "server"))

	require.Equal(t, []any{"2.pool.ntp.org iburst maxsources 4"}, directiveValues(settings, "pool"))
	require.Equal(t, []any{"192.168.0.0/16"}, directiveValues(settings, "allow"))
	require.Equal(t, []any{"all"}, directiveValues(settings, "deny"))
	require.Equal(t, []any{"127.0.0.1"}, directiveValues(settings, "bindcmdaddress"))
	require.Empty(t, directiveValues(settings, "peer"))
}

func TestChronyLastDirectiveValue(t *testing.T) {
	settings := chronySettings(
		"keyfile /etc/chrony.keys",
		"makestep 1.0 3",
		"keyfile /etc/chrony/override.keys", // last wins
	)

	require.Equal(t, "/etc/chrony/override.keys", lastDirectiveValue(settings, "keyfile"))
	require.Equal(t, "1.0 3", lastDirectiveValue(settings, "makestep"))
	require.Equal(t, "", lastDirectiveValue(settings, "leapsectz"))
}

func TestLoadChronyConfigFollowsConfdir(t *testing.T) {
	afs := chronyFs(t, leap16Chrony)

	cfg, err := loadChronyConfig(afs, "/usr/etc/chrony.conf")
	require.NoError(t, err)
	assert.Equal(t, []string{"/usr/etc/chrony.conf", "/usr/etc/chrony.d/pool.conf"}, cfg.files)
	assert.Equal(t, []any{"2.opensuse.pool.ntp.org iburst"},
		directiveValues(llxStrings(cfg.settings), "pool"))
	assert.Equal(t, "1.0 3", lastDirectiveValue(llxStrings(cfg.settings), "makestep"))
}

func TestLoadChronyConfigConfdirFirstDirWins(t *testing.T) {
	// A drop-in in /etc/chrony.d replaces the /usr/etc/chrony.d file of the
	// same name, and files are read in name order across both directories.
	files := map[string]string{
		"/etc/chrony.d/pool.conf":       "pool pool.example.com iburst\n",
		"/etc/chrony.d/zz-local.conf":   "server 10.0.0.1\n",
		"/etc/chrony.d/ignored.txt":     "server 10.9.9.9\n",
		"/run/chrony-dhcp/eth0.sources": "server 10.0.0.53 iburst\n",
	}
	for k, v := range leap16Chrony {
		files[k] = v
	}
	files["/usr/etc/chrony.d/aa-vendor.conf"] = "server 192.0.2.1\n"

	cfg, err := loadChronyConfig(chronyFs(t, files), "/usr/etc/chrony.conf")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"/usr/etc/chrony.conf",
		"/usr/etc/chrony.d/aa-vendor.conf",
		"/etc/chrony.d/pool.conf",
		"/etc/chrony.d/zz-local.conf",
		"/run/chrony-dhcp/eth0.sources",
	}, cfg.files)
	settings := llxStrings(cfg.settings)
	assert.Equal(t, []any{"pool.example.com iburst"}, directiveValues(settings, "pool"),
		"the shadowed vendor pool.conf is not read")
	assert.Equal(t, []any{"192.0.2.1", "10.0.0.1", "10.0.0.53 iburst"}, directiveValues(settings, "server"))
}

func TestLoadChronyConfigInclude(t *testing.T) {
	afs := chronyFs(t, map[string]string{
		"/etc/chrony.conf":          "include /etc/chrony/conf.d/*.conf\ninclude /etc/chrony/extra\nkeyfile /etc/chrony.keys\n",
		"/etc/chrony/conf.d/b.conf": "server b.example.com\n",
		"/etc/chrony/conf.d/a.conf": "server a.example.com\nkeyfile /etc/a.keys\n",
		"/etc/chrony/conf.d/c.txt":  "server c.example.com\n",
		"/etc/chrony/extra":         "; comment\n% comment\npeer p.example.com\n",
	})

	cfg, err := loadChronyConfig(afs, "/etc/chrony.conf")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"/etc/chrony.conf",
		"/etc/chrony/conf.d/a.conf",
		"/etc/chrony/conf.d/b.conf",
		"/etc/chrony/extra",
	}, cfg.files)
	settings := llxStrings(cfg.settings)
	assert.Equal(t, []any{"a.example.com", "b.example.com"}, directiveValues(settings, "server"))
	assert.Equal(t, []any{"p.example.com"}, directiveValues(settings, "peer"))
	assert.Equal(t, "/etc/chrony.keys", lastDirectiveValue(settings, "keyfile"),
		"a directive after the include overrides the included one")
	assert.NotContains(t, cfg.settings, "; comment")
	assert.NotContains(t, cfg.settings, "% comment")
}

func TestLoadChronyConfigIncludeGlobInDirectory(t *testing.T) {
	afs := chronyFs(t, map[string]string{
		"/etc/chrony.conf":              "include /etc/chrony/*.d/*.conf\n",
		"/etc/chrony/b.d/1.conf":        "server b.example.com\n",
		"/etc/chrony/a.d/1.conf":        "server a.example.com\n",
		"/etc/chrony/a.d/nested/x.conf": "server nested.example.com\n",
		"/etc/chrony/c.x/1.conf":        "server c.example.com\n",
	})

	cfg, err := loadChronyConfig(afs, "/etc/chrony.conf")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"/etc/chrony.conf",
		"/etc/chrony/a.d/1.conf",
		"/etc/chrony/b.d/1.conf",
	}, cfg.files)
}

// wrappedNotExistFs reports a missing path the way a remote connection's
// filesystem can: fs.ErrNotExist wrapped in its own error, not *os.PathError.
type wrappedNotExistFs struct{ afero.Fs }

func (w wrappedNotExistFs) wrap(err error) error {
	if err != nil && os.IsNotExist(err) {
		return fmt.Errorf("remote: %w", fs.ErrNotExist)
	}
	return err
}

func (w wrappedNotExistFs) Open(name string) (afero.File, error) {
	f, err := w.Fs.Open(name)
	return f, w.wrap(err)
}

func (w wrappedNotExistFs) Stat(name string) (os.FileInfo, error) {
	fi, err := w.Fs.Stat(name)
	return fi, w.wrap(err)
}

func TestLoadChronyConfigWrappedNotExist(t *testing.T) {
	// Leap 16 lists /etc/chrony.d in confdir although the directory does not
	// exist on a stock host, and /run/chrony-dhcp is absent in an image scan.
	mem := chronyFs(t, leap16Chrony)
	afs := &afero.Afero{Fs: wrappedNotExistFs{mem.Fs}}
	_, err := afs.ReadDir("/etc/chrony.d")
	require.Error(t, err)
	require.False(t, os.IsNotExist(err), "the wrapper must defeat os.IsNotExist")

	cfg, err := loadChronyConfig(afs, "/usr/etc/chrony.conf")
	require.NoError(t, err)
	assert.Equal(t, []string{"/usr/etc/chrony.conf", "/usr/etc/chrony.d/pool.conf"}, cfg.files)

	afs2 := &afero.Afero{Fs: wrappedNotExistFs{chronyFs(t, map[string]string{
		"/etc/chrony.conf": "include /etc/chrony/missing.conf\nserver a.example.com\n",
	}).Fs}}
	cfg, err = loadChronyConfig(afs2, "/etc/chrony.conf")
	require.NoError(t, err, "a missing include is skipped")
	assert.Equal(t, []string{"/etc/chrony.conf"}, cfg.files)
}

func TestLoadChronyConfigMissing(t *testing.T) {
	cfg, err := loadChronyConfig(chronyFs(t, nil), "/etc/chrony.conf")
	require.NoError(t, err)
	assert.Empty(t, cfg.files)
	assert.Empty(t, cfg.settings)
}

func TestLoadChronyConfigIncludeLoop(t *testing.T) {
	afs := chronyFs(t, map[string]string{
		"/etc/chrony.conf": "include /etc/chrony.conf\n",
	})
	_, err := loadChronyConfig(afs, "/etc/chrony.conf")
	assert.Error(t, err)
}

func TestChronyConfFallsBackToUsrEtc(t *testing.T) {
	files := map[string]*mock.MockFileData{}
	for path, content := range leap16Chrony {
		files[path] = &mock.MockFileData{Path: path, Content: content}
	}
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "opensuse-leap", Family: []string{"suse", "linux", "unix"}},
	}, mock.WithData(&mock.TomlData{Files: files}))
	require.NoError(t, err)
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	res, err := NewResource(rt, "chrony.conf", nil)
	require.NoError(t, err)
	conf := res.(*mqlChronyConf)
	file := conf.GetFile()
	require.NoError(t, file.Error)
	assert.Equal(t, "/usr/etc/chrony.conf", file.Data.Path.Data)
}

func llxStrings(in []string) []any {
	return chronySettings(in...)
}
