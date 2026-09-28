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
