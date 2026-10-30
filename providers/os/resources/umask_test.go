// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/utils/syncx"
)

func newTestUmask(t *testing.T, mem afero.Fs) *mqlUmask {
	t.Helper()
	// pam.conf lists /etc/pam.d with files.find, which needs a platform
	asset := &inventory.Asset{Platform: &inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix", "os"}}}
	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, asset, "", nil, mem)
	require.NoError(t, err)
	rt := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}
	args, _, err := initUmask(rt, map[string]*llx.RawData{})
	require.NoError(t, err)
	raw, err := CreateResource(rt, "umask", args)
	require.NoError(t, err)
	return raw.(*mqlUmask)
}

// umaskSettingSummary is what a check reads from a setting.
type umaskSettingSummary struct {
	Source      string
	Path        string
	Line        int64
	Value       string
	Octal       string
	Conditional bool
}

func umaskSettings(t *testing.T, u *mqlUmask) []umaskSettingSummary {
	t.Helper()
	settings := u.GetSettings()
	require.NoError(t, settings.Error)
	var res []umaskSettingSummary
	for _, raw := range settings.Data {
		s := raw.(*mqlUmaskSetting)
		res = append(res, umaskSettingSummary{
			Source:      s.Source.Data,
			Path:        s.File.Data.Path.Data,
			Line:        s.Line.Data,
			Value:       s.Value.Data,
			Octal:       s.Octal.Data,
			Conditional: s.Conditional.Data,
		})
	}
	return res
}

func TestUmaskSettings(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeMemFSFile(t, mem, "/etc/login.defs", []byte("# UMASK 000\nUMASK\t\t022\nPASS_MAX_DAYS 90\nUMASK 027\n"))
	writeMemFSFile(t, mem, "/etc/default/login", []byte("UMASK=077\n"))
	writeMemFSFile(t, mem, "/etc/profile", []byte("export PATH\n#umask 022\n"))
	writeMemFSFile(t, mem, "/etc/profile.d/b.sh", []byte("umask u=rwx,g=rx,o=\n"))
	writeMemFSFile(t, mem, "/etc/profile.d/a.sh", []byte("umask 0027\n"))
	writeMemFSFile(t, mem, "/etc/profile.d/c.csh", []byte("umask 000\n"))
	writeMemFSFile(t, mem, "/etc/profile.d/sh.local", []byte("umask 077\n"))
	writeMemFSFile(t, mem, "/etc/bashrc", []byte("if [ $UID -gt 199 ]; then\n  umask 002\nfi\n[ `umask` -eq 0 ] && umask 022\n"))
	writeMemFSFile(t, mem, "/etc/pam.d/common-session", []byte("session optional pam_umask.so umask=0077 usergroups\n"))
	u := newTestUmask(t, mem)

	assert.Equal(t, []umaskSettingSummary{
		{Source: "login.defs", Path: "/etc/login.defs", Line: 2, Value: "022", Octal: "0022"},
		{Source: "login.defs", Path: "/etc/login.defs", Line: 4, Value: "027", Octal: "0027"},
		{Source: "default-login", Path: "/etc/default/login", Line: 1, Value: "077", Octal: "0077"},
		{Source: "pam", Path: "/etc/pam.d/common-session", Line: 1, Value: "0077", Octal: "0077"},
		// /etc/profile.d in name order, then sh.local; not the csh file
		{Source: "shell", Path: "/etc/profile.d/a.sh", Line: 1, Value: "0027", Octal: "0027"},
		{Source: "shell", Path: "/etc/profile.d/b.sh", Line: 1, Value: "u=rwx,g=rx,o=", Octal: "0027"},
		{Source: "shell", Path: "/etc/profile.d/sh.local", Line: 1, Value: "077", Octal: "0077"},
		{Source: "shell", Path: "/etc/bashrc", Line: 2, Value: "002", Octal: "0002", Conditional: true},
		{Source: "shell", Path: "/etc/bashrc", Line: 4, Value: "022", Octal: "0022", Conditional: true},
	}, umaskSettings(t, u))

	files := u.GetFiles()
	require.NoError(t, files.Error)
	var paths []string
	for _, f := range files.Data {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	assert.Equal(t, []string{
		"/etc/login.defs", "/etc/default/login", "/etc/profile",
		"/etc/profile.d/a.sh", "/etc/profile.d/b.sh", "/etc/profile.d/sh.local", "/etc/bashrc",
	}, paths, "the files that exist, without the PAM service files")

	ld := u.GetLoginDefs()
	require.NoError(t, ld.Error)
	require.NotNil(t, ld.Data)
	assert.Equal(t, int64(4), ld.Data.Line.Data, "the last UMASK line wins")
	assert.Equal(t, int64(0o027), ld.Data.Mode.Data)
	assert.True(t, ld.Data.UserWriteable.Data)
	assert.True(t, ld.Data.GroupReadable.Data)
	assert.False(t, ld.Data.GroupWriteable.Data)
	assert.False(t, ld.Data.OtherReadable.Data)
	assert.False(t, ld.Data.OtherExecutable.Data)
}

func TestUmaskSettingFields(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeMemFSFile(t, mem, "/etc/profile", []byte("umask g=rx,o=\numask $UMASK\n"))
	u := newTestUmask(t, mem)

	settings := u.GetSettings()
	require.NoError(t, settings.Error)
	require.Len(t, settings.Data, 2)

	relative := settings.Data[0].(*mqlUmaskSetting)
	assert.True(t, relative.Relative.Data, "g=rx,o= keeps the user bits of the umask before it")
	assert.Equal(t, int64(0o027), relative.Mode.Data)
	assert.True(t, relative.UserReadable.Data)

	unknown := settings.Data[1].(*mqlUmaskSetting)
	assert.Equal(t, "$UMASK", unknown.Value.Data)
	assert.True(t, unknown.Mode.IsNull(), "an expanded value is not a known mask")
	assert.True(t, unknown.Octal.IsNull())
	assert.True(t, unknown.Relative.IsNull(), "an unknown mask is neither relative nor absolute")
	assert.True(t, unknown.GroupWriteable.IsNull())
	assert.True(t, unknown.OtherReadable.IsNull())
}

func TestUmaskPam(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeMemFSFile(t, mem, "/etc/login.defs", []byte("UMASK 027\n"))
	writeMemFSFile(t, mem, "/etc/pam.d/common-session", []byte("session optional pam_umask.so umask=0077 usergroups\n"))
	writeMemFSFile(t, mem, "/etc/pam.d/postlogin", []byte("auth optional pam_umask.so\nsession optional pam_umask.so silent usergroups nousergroups\n"))
	u := newTestUmask(t, mem)

	pam := u.GetPam()
	require.NoError(t, pam.Error)
	require.Len(t, pam.Data, 2, "session lines only")

	withArg := pam.Data[0].(*mqlUmaskPamModule)
	assert.Equal(t, "/etc/pam.d/common-session", withArg.Service.Data)
	assert.True(t, withArg.Usergroups.Data)
	assert.Equal(t, "pam", withArg.Setting.Data.Source.Data)
	assert.Equal(t, "0077", withArg.Setting.Data.Octal.Data)

	fallback := pam.Data[1].(*mqlUmaskPamModule)
	assert.Equal(t, "/etc/pam.d/postlogin", fallback.Service.Data)
	assert.Equal(t, int64(1), fallback.LineNumber.Data)
	assert.False(t, fallback.Usergroups.Data, "the later nousergroups wins")
	assert.Equal(t, "login.defs", fallback.Setting.Data.Source.Data, "without umask= pam_umask reads login.defs")
	assert.Equal(t, "0027", fallback.Setting.Data.Octal.Data)
}

func TestUmaskPamFallbacks(t *testing.T) {
	t.Run("default/login", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		writeMemFSFile(t, mem, "/etc/login.defs", []byte("PASS_MAX_DAYS 90\n"))
		writeMemFSFile(t, mem, "/etc/default/login", []byte("UMASK=077\n"))
		writeMemFSFile(t, mem, "/etc/pam.d/common-session", []byte("session optional pam_umask.so\n"))
		u := newTestUmask(t, mem)

		ld := u.GetLoginDefs()
		require.NoError(t, ld.Error)
		assert.True(t, ld.IsNull(), "login.defs sets no UMASK")

		pam := u.GetPam()
		require.NoError(t, pam.Error)
		require.Len(t, pam.Data, 1)
		setting := pam.Data[0].(*mqlUmaskPamModule).Setting.Data
		require.NotNil(t, setting)
		assert.Equal(t, "default-login", setting.Source.Data)
	})

	t.Run("none", func(t *testing.T) {
		// Debian 13: no UMASK in login.defs, so pam_umask leaves the umask alone
		mem := afero.NewMemMapFs()
		writeMemFSFile(t, mem, "/etc/login.defs", []byte("PASS_MAX_DAYS 90\n"))
		writeMemFSFile(t, mem, "/etc/pam.d/common-session", []byte("session optional\t\t\tpam_umask.so\n"))
		u := newTestUmask(t, mem)

		pam := u.GetPam()
		require.NoError(t, pam.Error)
		require.Len(t, pam.Data, 1)
		mod := pam.Data[0].(*mqlUmaskPamModule)
		assert.True(t, mod.Setting.IsNull())
	})

	t.Run("no PAM", func(t *testing.T) {
		mem := afero.NewMemMapFs()
		writeMemFSFile(t, mem, "/etc/profile", []byte("umask 022\n"))
		u := newTestUmask(t, mem)

		pam := u.GetPam()
		require.NoError(t, pam.Error)
		assert.Empty(t, pam.Data)
	})
}

// SUSE reads the packaged /usr/etc/profile.d files unless /etc/profile.d has
// one of the same name, and /usr/etc/bash.bashrc when /etc has none.
func TestUmaskVendorFiles(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeMemFSFile(t, mem, "/usr/etc/login.defs", []byte("UMASK 022\n"))
	writeMemFSFile(t, mem, "/usr/etc/profile.d/a.sh", []byte("umask 022\n"))
	writeMemFSFile(t, mem, "/usr/etc/profile.d/b.sh", []byte("umask 002\n"))
	writeMemFSFile(t, mem, "/etc/profile.d/b.sh", []byte("umask 077\n"))
	writeMemFSFile(t, mem, "/usr/etc/bash.bashrc", []byte("umask 027\n"))
	u := newTestUmask(t, mem)

	assert.Equal(t, []umaskSettingSummary{
		{Source: "login.defs", Path: "/usr/etc/login.defs", Line: 1, Value: "022", Octal: "0022"},
		{Source: "shell", Path: "/usr/etc/profile.d/a.sh", Line: 1, Value: "022", Octal: "0022"},
		{Source: "shell", Path: "/etc/profile.d/b.sh", Line: 1, Value: "077", Octal: "0077"},
		{Source: "shell", Path: "/usr/etc/bash.bashrc", Line: 1, Value: "027", Octal: "0027"},
	}, umaskSettings(t, u))
}

func TestUmaskPamOptions(t *testing.T) {
	value, usergroups := umaskPamOptions([]string{"debug", "umask=0022", "UserGroups", "umask=0077"})
	assert.Equal(t, "0077", value, "the last umask= wins")
	assert.True(t, usergroups, "options are case-insensitive")

	value, usergroups = umaskPamOptions([]string{"silent"})
	assert.Equal(t, "", value)
	assert.False(t, usergroups)
}

func TestIsUmaskModule(t *testing.T) {
	assert.True(t, isUmaskModule("pam_umask.so"))
	assert.True(t, isUmaskModule("/lib/x86_64-linux-gnu/security/pam_umask.so"))
	assert.False(t, isUmaskModule("pam_unix.so"))
	assert.False(t, isUmaskModule("pam_umask.so.bak"))
}
