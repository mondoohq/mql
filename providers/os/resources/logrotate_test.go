// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// A bare `logrotate.entry` leaves `file` unset, so id() must report the missing
// file rather than dereferencing a nil *mqlFile.
func TestLogrotateEntryID(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		id, err := (&mqlLogrotateEntry{}).id()
		require.Error(t, err)
		assert.Empty(t, id)
		assert.Contains(t, err.Error(), "missing file")
	})

	t.Run("with file", func(t *testing.T) {
		f := &mqlFile{}
		f.Path.Data = "/etc/logrotate.conf"
		f.Path.State = plugin.StateIsSet

		e := &mqlLogrotateEntry{}
		e.File.Data = f
		e.File.State = plugin.StateIsSet
		e.LineNumber.Data = 7
		e.LineNumber.State = plugin.StateIsSet
		e.Path.Data = "/var/log/syslog"
		e.Path.State = plugin.StateIsSet

		id, err := e.id()
		require.NoError(t, err)
		assert.Equal(t, "/etc/logrotate.conf:7:/var/log/syslog", id)
	})
}

func TestLogrotateLocations(t *testing.T) {
	write := func(t *testing.T, fs afero.Fs, path string) {
		t.Helper()
		require.NoError(t, afero.WriteFile(fs, path, []byte("weekly\n"), 0o644))
	}

	// Layout of the logrotate 3.22.0 package on FreeBSD 14.5: no /etc copy,
	// the configuration and its drop-in directory under /usr/local/etc.
	t.Run("the FreeBSD port layout", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(t, fs, "/usr/local/etc/logrotate.conf")
		write(t, fs, "/usr/local/etc/logrotate.d/mysqlrouter")

		conf, dirs := logrotateLocations(fs)
		assert.Equal(t, "/usr/local/etc/logrotate.conf", conf)
		assert.Equal(t, []string{"/usr/local/etc/logrotate.d"}, dirs)
	})

	t.Run("the FreeBSD port layout without a drop-in directory", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(t, fs, "/usr/local/etc/logrotate.conf")

		conf, dirs := logrotateLocations(fs)
		assert.Equal(t, "/usr/local/etc/logrotate.conf", conf)
		assert.Empty(t, dirs)
	})

	t.Run("/etc wins over /usr/local/etc", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(t, fs, "/etc/logrotate.conf")
		write(t, fs, "/etc/logrotate.d/nginx")
		write(t, fs, "/usr/local/etc/logrotate.conf")
		write(t, fs, "/usr/local/etc/logrotate.d/other")

		conf, dirs := logrotateLocations(fs)
		assert.Equal(t, "/etc/logrotate.conf", conf)
		assert.Equal(t, []string{"/etc/logrotate.d"}, dirs)
	})

	t.Run("the /usr/etc vendor copy wins over /usr/local/etc", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(t, fs, "/usr/etc/logrotate.conf")
		write(t, fs, "/usr/local/etc/logrotate.conf")

		conf, _ := logrotateLocations(fs)
		assert.Equal(t, "/usr/etc/logrotate.conf", conf)
	})

	t.Run("nothing installed names the canonical path", func(t *testing.T) {
		conf, dirs := logrotateLocations(afero.NewMemMapFs())
		assert.Equal(t, "/etc/logrotate.conf", conf)
		assert.Empty(t, dirs)
	})
}

// `logrotate -d /etc/logrotate.conf` on SLE 15 SP7 and openSUSE Leap 15.6
// (logrotate 3.18.1) reads g04 and g04.old and ignores g04.bak, g04.rpmnew
// and g04.disabled ("Ignoring g04.bak, because of *.bak pattern match").
// Hidden .g04hidden and .g04.bak are read too: fnmatch(FNM_PERIOD) never lets
// `*` match a leading dot.
func TestLogrotateTabooMatchSLE15(t *testing.T) {
	exts := logrotateTabooExts("3.18.1")

	for _, name := range []string{"g04", "g04.old", ".g04hidden", ".g04.bak", "chrony", "zypp-history.lr", "syslog"} {
		assert.False(t, logrotateTabooMatch(exts, name), name)
	}
	for _, name := range []string{"g04.bak", "g04.rpmnew", "g04.disabled", "g04.rpmsave", "g04~", "g04,v", "g04.dpkg-tmp", "g04.rhn-cfg-tmp-1234"} {
		assert.True(t, logrotateTabooMatch(exts, name), name)
	}
}

func TestLogrotateTabooExtsByVersion(t *testing.T) {
	// .bak became taboo in 3.17; .old, .new and .orig in 3.22
	assert.False(t, logrotateTabooMatch(logrotateTabooExts("3.16.0"), "g04.bak"))
	assert.True(t, logrotateTabooMatch(logrotateTabooExts("3.17.0"), "g04.bak"))
	assert.False(t, logrotateTabooMatch(logrotateTabooExts("3.21.0"), "g04.old"))
	assert.True(t, logrotateTabooMatch(logrotateTabooExts("3.22.0"), "g04.old"))
	assert.True(t, logrotateTabooMatch(logrotateTabooExts("3.22.0"), "g04.orig"))
	// .dpkg-bak in 3.13, .dpkg-tmp in 3.14
	assert.False(t, logrotateTabooMatch(logrotateTabooExts("3.12.3"), "g04.dpkg-bak"))
	assert.True(t, logrotateTabooMatch(logrotateTabooExts("3.13.0"), "g04.dpkg-bak"))
	assert.False(t, logrotateTabooMatch(logrotateTabooExts("3.13.0"), "g04.dpkg-tmp"))
	assert.True(t, logrotateTabooMatch(logrotateTabooExts("3.14.0"), "g04.dpkg-tmp"))
	// an unknown version reads as SLE 15's 3.18
	assert.Equal(t, logrotateTabooExts("3.18.1"), logrotateTabooExts(""))
}

func TestParseLogrotateVersion(t *testing.T) {
	// SLE 15 SP7
	out := "logrotate 3.18.1\n\n    Default mail command:       /bin/mail\n    Default compress command:   /bin/gzip\n"
	assert.Equal(t, "3.18.1", parseLogrotateVersion(out))
	assert.Equal(t, "3.22.0", parseLogrotateVersion("logrotate 3.22.0\n"))
	assert.Equal(t, "", parseLogrotateVersion("bash: logrotate: command not found\n"))
	assert.Equal(t, "", parseLogrotateVersion(""))
}

// The logrotate.service SLE 16 and openSUSE Leap 16 ship.
const sle16LogrotateService = `[Unit]
Description=Rotate log files
Documentation=man:logrotate(8) man:logrotate.conf(5)
RequiresMountsFor=/var/log
ConditionACPower=true

[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate-all

# performance options
Nice=19
`

// The logrotate.service of SLE 15 SP7 and Leap 15.6.
const sle15LogrotateService = `[Unit]
Description=Rotate log files
Documentation=man:logrotate(8) man:logrotate.conf(5)
RequiresMountsFor=/var/log
ConditionACPower=true

[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate /etc/logrotate.conf
`

func TestLogrotateAllDrivesRotation(t *testing.T) {
	write := func(t *testing.T, fs afero.Fs, path, content string) {
		t.Helper()
		require.NoError(t, afero.WriteFile(fs, path, []byte(content), 0o644))
	}

	t.Run("SLE 16 runs logrotate-all", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(t, fs, "/usr/sbin/logrotate-all", "#!/bin/sh\n")
		write(t, fs, "/usr/lib/systemd/system/logrotate.service", sle16LogrotateService)
		assert.True(t, logrotateAllDrivesRotation(fs))
	})

	t.Run("SLE 15 runs logrotate with its configuration", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(t, fs, "/usr/lib/systemd/system/logrotate.service", sle15LogrotateService)
		assert.False(t, logrotateAllDrivesRotation(fs))
	})

	t.Run("an /etc unit that runs logrotate directly wins", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(t, fs, "/usr/sbin/logrotate-all", "#!/bin/sh\n")
		write(t, fs, "/usr/lib/systemd/system/logrotate.service", sle16LogrotateService)
		write(t, fs, "/etc/systemd/system/logrotate.service", sle15LogrotateService)
		assert.False(t, logrotateAllDrivesRotation(fs))
	})

	t.Run("the unit names a wrapper that is not installed", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(t, fs, "/usr/lib/systemd/system/logrotate.service", sle16LogrotateService)
		assert.False(t, logrotateAllDrivesRotation(fs))
	})
}

// Outside SUSE the suffix list stays as it was.
func TestLogrotateLegacySkip(t *testing.T) {
	for _, name := range []string{"apt.bak", "apt.old", "apt.dpkg-old", "apt.dpkg-dist", "apt~"} {
		assert.True(t, logrotateLegacySkip(name), name)
	}
	assert.False(t, logrotateLegacySkip("apt"))
}
