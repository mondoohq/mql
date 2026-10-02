// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

// A bare `crontab.entry` leaves `file` unset, so id() must report the missing
// file rather than dereferencing a nil *mqlFile.
func TestCrontabEntryID(t *testing.T) {
	e := &mqlCrontabEntry{}
	// GetFile short-circuits on an already-resolved field, so mark it set with a
	// nil value -- the shape the runtime produces for a bare entry.
	e.File.State = plugin.StateIsSet | plugin.StateIsNull

	id, err := e.id()
	require.Error(t, err)
	assert.Empty(t, id)
	assert.Contains(t, err.Error(), "missing file")
}

// SUSE stores per-user crontabs in /var/spool/cron/tabs, one directory below
// the RHEL location that was already scanned. Walking both layouts must find
// root's crontab exactly once, and the tabs directory itself must never be
// reported as a user named "tabs" while /var/spool/cron is walked.
func TestCollectUserCrontabFilesSUSE(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/var/spool/cron/tabs", 0o700))
	require.NoError(t, afs.WriteFile("/var/spool/cron/tabs/root",
		[]byte("0 5 * * * /usr/sbin/aide --check\n"), 0o600))

	got, err := collectUserCrontabFiles(afs, userCrontabDirs)
	require.NoError(t, err)

	assert.Equal(t, []userCrontabFile{
		{user: "root", path: "/var/spool/cron/tabs/root"},
	}, got)
}

// The other distro layouts keep working, and the editor / backup droppings
// that live beside a real crontab are not users.
func TestCollectUserCrontabFiles(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for _, path := range []string{
		"/var/spool/cron/crontabs/alice",
		"/var/spool/cron/crontabs/.hidden",
		"/var/spool/cron/crontabs/alice~",
		"/var/spool/cron/crontabs/alice.bak",
		"/var/spool/cron/bob",
		"/usr/lib/cron/tabs/carol",
	} {
		require.NoError(t, afs.WriteFile(path, []byte("@daily /bin/true\n"), 0o600))
	}

	got, err := collectUserCrontabFiles(afs, userCrontabDirs)
	require.NoError(t, err)

	// Directory order, then file name order within a directory.
	assert.Equal(t, []userCrontabFile{
		{user: "alice", path: "/var/spool/cron/crontabs/alice"},
		{user: "bob", path: "/var/spool/cron/bob"},
		{user: "carol", path: "/usr/lib/cron/tabs/carol"},
	}, got)
}

// FreeBSD's cron(8) reads per-user crontabs from /var/cron/tabs and package
// crontabs from /usr/local/etc/cron.d, next to /etc/crontab and /etc/cron.d.
// All four must be reported, and root's per-user crontab must carry the file
// name as its user.
func TestCrontabFreeBSD(t *testing.T) {
	fixturePath, err := filepath.Abs("testdata/crontab_freebsd.toml")
	require.NoError(t, err)

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "freebsd",
			Family: []string{"bsd", "unix"},
		},
	}
	conn, err := mock.New(0, asset, mock.WithPath(fixturePath))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
	raw, err := CreateResource(runtime, "crontab", nil)
	require.NoError(t, err)
	c := raw.(*mqlCrontab)

	files := c.GetFiles()
	require.NoError(t, files.Error)
	var paths []string
	for _, f := range files.Data {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	assert.ElementsMatch(t, []string{
		"/etc/crontab",
		"/etc/cron.d/at",
		"/usr/local/etc/cron.d/pkg-backup",
		"/var/cron/tabs/root",
	}, paths)

	entries := c.GetEntries()
	require.NoError(t, entries.Error)
	var rootAide bool
	for _, e := range entries.Data {
		entry := e.(*mqlCrontabEntry)
		if entry.Command.Data == "/usr/local/sbin/aide --check" {
			rootAide = entry.User.Data == "root"
		}
	}
	assert.True(t, rootAide, "root's /var/cron/tabs entry must be reported as user root")
}

// A host with no spool directories at all (a stripped container image) yields
// nothing rather than erroring the whole crontab.entries walk.
func TestCollectUserCrontabFilesMissingDirs(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	got, err := collectUserCrontabFiles(afs, userCrontabDirs)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// Which /etc/cron.d names each cron runs. The cronie cases were checked
// against crond on RHEL 7, RHEL 9 and Fedora 44: every file got a
// `* * * * *` job touching a marker, and the markers that appeared are the
// "runs" rows. Before, the Debian-style skip list was applied everywhere, so
// a job in /etc/cron.d/x.bak that cronie runs every minute was not reported.
func TestCronDFileIsSkipped(t *testing.T) {
	tests := []struct {
		name   string
		cronie bool // skipped by cronie
		debian bool // skipped by Debian cron
	}{
		{"0hourly", false, false},
		{"g04p_ok", false, false},
		{"php-sessionclean", false, false},
		{"g04p.bak", false, true},
		{"g04p.dpkg-old", false, true},
		{"g04p.swp", false, true},
		{"g04p.dotted", false, true},
		{".g04phidden", true, true},
		{"g04p~", true, true},
		{"#g04p", true, true},
		{"g04p.rpmsave", true, true},
		{"g04p.rpmnew", true, true},
		{"g04p.rpmorig", true, true},
	}
	for _, tt := range tests {
		assert.Equalf(t, tt.cronie, cronDFileIsSkipped(tt.name, cronFlavorCronie), "cronie %q", tt.name)
		assert.Equalf(t, tt.debian, cronDFileIsSkipped(tt.name, cronFlavorDebian), "debian %q", tt.name)
	}

	// platforms with neither keep the previous list
	assert.True(t, cronDFileIsSkipped("x.bak", cronFlavorDefault))
	assert.False(t, cronDFileIsSkipped("x.conf", cronFlavorDefault))
}

// Debian's cron skips a system crontab that is group or other writable
// ("INSECURE MODE") or not owned by root ("WRONG FILE OWNER"), whatever its
// name. Modes and owners are the Debian 13 fixtures cron refused live.
func TestDebianCronRefuses(t *testing.T) {
	info := func(mode os.FileMode, uid int64) shared.FileInfoDetails {
		return shared.FileInfoDetails{Mode: shared.FileModeDetails{FileMode: mode}, Uid: uid}
	}
	assert.False(t, debianCronRefuses(info(0o644, 0)), "g04")
	assert.False(t, debianCronRefuses(info(0o600, 0)))
	assert.True(t, debianCronRefuses(info(0o664, 0)), "g04badmode")
	assert.True(t, debianCronRefuses(info(0o646, 0)), "other writable")
	assert.True(t, debianCronRefuses(info(0o644, 1000)), "g04notroot")
	// a symlink is judged by the root-owned 0644 file it points to (g04symlink, loaded)
	assert.False(t, debianCronRefuses(info(os.ModeSymlink|0o644, 0)), "g04symlink")
	// an owner the connection could not read is not a wrong owner
	assert.False(t, debianCronRefuses(info(0o644, -1)))
}

// On Debian, crontab leaves out the cron.d files cron refuses for their mode
// or owner, and keeps the ones it loads.
func TestCrontabDebianRefusedModes(t *testing.T) {
	fixturePath, err := filepath.Abs("testdata/crontab_debian_modes.toml")
	require.NoError(t, err)

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "debian",
			Family: []string{"debian", "linux", "unix", "os"},
		},
	}
	conn, err := mock.New(0, asset, mock.WithPath(fixturePath))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
	raw, err := CreateResource(runtime, "crontab", nil)
	require.NoError(t, err)
	c := raw.(*mqlCrontab)

	files := c.GetFiles()
	require.NoError(t, files.Error)
	var paths []string
	for _, f := range files.Data {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	assert.ElementsMatch(t, []string{
		"/etc/crontab",
		"/etc/cron.d/g04",
		"/etc/cron.d/g04-ok_name",
	}, paths)
}

func TestCronFlavorOf(t *testing.T) {
	platform := func(family ...string) *inventory.Asset {
		return &inventory.Asset{Platform: &inventory.Platform{Family: family}}
	}
	assert.Equal(t, cronFlavorCronie, cronFlavorOf(platform("redhat", "linux", "unix", "os")))
	assert.Equal(t, cronFlavorCronie, cronFlavorOf(platform("suse", "linux", "unix", "os")))
	assert.Equal(t, cronFlavorDebian, cronFlavorOf(platform("debian", "linux", "unix", "os")))
	assert.Equal(t, cronFlavorDefault, cronFlavorOf(platform("bsd", "unix", "os")))
	assert.Equal(t, cronFlavorDefault, cronFlavorOf(nil))
}

// A non-root scan on RHEL cannot list /var/spool/cron (0700). With structured
// errors that is a refusal, not a host without user crontabs; without them it
// keeps the v13 skip.
func TestCollectUserCrontabFilesUnlistableSpool(t *testing.T) {
	fs := newUnlistableFs(t, []string{"/var/spool/cron/root"}, "/var/spool/cron")
	afs := &afero.Afero{Fs: fs}

	withStructuredErrors(t, true)
	_, err := collectUserCrontabFiles(afs, userCrontabDirs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden))

	withStructuredErrors(t, false)
	got, err := collectUserCrontabFiles(afs, userCrontabDirs)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// cronie refuses a system crontab unless (mode & 07533) == 0400 and root owns
// it. Modes and owners are the SLES 15 fixtures cron refused or loaded live.
func TestCronieRefuses(t *testing.T) {
	info := func(mode os.FileMode, uid int64) shared.FileInfoDetails {
		return shared.FileInfoDetails{Mode: shared.FileModeDetails{FileMode: mode}, Uid: uid}
	}
	assert.False(t, cronieRefuses(info(0o644, 0)), "g04")
	assert.False(t, cronieRefuses(info(0o600, 0)), "SUSE /etc/crontab")
	assert.False(t, cronieRefuses(info(0o400, 0)))
	assert.True(t, cronieRefuses(info(0o664, 0)), "g04badmode")
	assert.True(t, cronieRefuses(info(0o666, 0)), "g04worldw")
	assert.True(t, cronieRefuses(info(0o755, 0)), "g04exec: any execute bit")
	assert.True(t, cronieRefuses(info(0o744, 0)), "owner execute")
	assert.True(t, cronieRefuses(info(0o200, 0)), "owner cannot read")
	assert.True(t, cronieRefuses(info(os.ModeSetuid|0o644, 0)), "setuid")
	assert.True(t, cronieRefuses(info(0o644, 1000)), "g04notroot")
	// a symlink is judged by the root-owned 0644 file it points to (g04symlink, loaded)
	assert.False(t, cronieRefuses(info(os.ModeSymlink|0o644, 0)), "g04symlink")
	assert.False(t, cronieRefuses(info(0o644, -1)), "unknown owner")
}

func newCrontabOnFixture(t *testing.T, fixture string, family []string, wrap func(afero.Fs) afero.Fs) *mqlCrontab {
	t.Helper()
	fixturePath, err := filepath.Abs(fixture)
	require.NoError(t, err)
	asset := &inventory.Asset{Platform: &inventory.Platform{Name: family[0], Family: family}}
	mc, err := mock.New(0, asset, mock.WithPath(fixturePath))
	require.NoError(t, err)
	var conn shared.Connection = mc
	if wrap != nil {
		conn = &fsWrapConn{Connection: mc, fs: wrap(mc.FileSystem())}
	}
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	raw, err := CreateResource(runtime, "crontab", nil)
	require.NoError(t, err)
	return raw.(*mqlCrontab)
}

// fsWrapConn serves a connection's files through another filesystem, such as
// one that refuses some reads the way they are refused to a non-root scan.
type fsWrapConn struct {
	shared.Connection
	fs afero.Fs
}

func (c *fsWrapConn) FileSystem() afero.Fs { return c.fs }

// On SUSE, crontab reports the files cronie loads (names, mode and owner)
// and reads the "-" no-syslog prefix of /etc/crontab's run-crons line.
func TestCrontabSUSECronie(t *testing.T) {
	c := newCrontabOnFixture(t, "testdata/crontab_suse_cronie.toml", []string{"sles", "suse", "linux", "unix", "os"}, nil)

	files := c.GetFiles()
	require.NoError(t, files.Error)
	var paths []string
	for _, f := range files.Data {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	assert.ElementsMatch(t, []string{
		"/etc/crontab",
		"/etc/cron.d/g04",
		"/etc/cron.d/g04.bak",
		"/etc/cron.d/g04.dotted",
		"/etc/cron.d/g04.dpkg-old",
		"/etc/cron.d/g04-ok_name",
	}, paths)

	entries := c.GetEntries()
	require.NoError(t, entries.Error)
	minutes := map[string]string{}
	for _, e := range entries.Data {
		entry := e.(*mqlCrontabEntry)
		minutes[entry.Command.Data] = entry.Minute.Data
	}
	assert.Equal(t, "*/15", minutes["test -x /usr/lib/cron/run-crons && /usr/lib/cron/run-crons >/dev/null 2>&1"])
	assert.Equal(t, "*/10", minutes["/usr/bin/true g04-nolog"])
}

// SUSE's /etc/crontab is 0600. A non-root scan cannot read it: with
// structured errors that is a refusal, not a crontab without entries; without
// them the v13 skip stays.
func TestCrontabUnreadableSystemCrontab(t *testing.T) {
	deny := func(paths ...string) func(afero.Fs) afero.Fs {
		return func(fs afero.Fs) afero.Fs {
			d := map[string]bool{}
			for _, p := range paths {
				d[p] = true
			}
			return &unlistableFs{Fs: fs, denied: d}
		}
	}
	suse := []string{"sles", "suse", "linux", "unix", "os"}

	for _, denied := range []string{"/etc/crontab", "/etc/cron.d/g04", "/etc/cron.d"} {
		withStructuredErrors(t, true)
		c := newCrontabOnFixture(t, "testdata/crontab_suse_cronie.toml", suse, deny(denied))
		entries := c.GetEntries()
		require.Error(t, entries.Error, denied)
		assert.True(t, errors.Is(entries.Error, llx.ErrForbidden), denied)
		assert.Contains(t, entries.Error.Error(), denied)

		withStructuredErrors(t, false)
		c = newCrontabOnFixture(t, "testdata/crontab_suse_cronie.toml", suse, deny(denied))
		entries = c.GetEntries()
		require.NoError(t, entries.Error, denied)
		assert.NotEmpty(t, entries.Data, denied)
	}
}
