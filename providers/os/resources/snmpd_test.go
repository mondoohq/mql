// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestSnmpdConfigPath(t *testing.T) {
	write := func(t *testing.T, fs afero.Fs, path string) {
		t.Helper()
		require.NoError(t, afero.WriteFile(fs, path, []byte("rocommunity public 127.0.0.1\n"), 0o644))
	}

	t.Run("Linux packages use /etc/snmp", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(t, fs, "/etc/snmp/snmpd.conf")
		write(t, fs, "/usr/local/share/snmp/snmpd.conf")
		assert.Equal(t, "/etc/snmp/snmpd.conf", snmpdConfigPath(fs))
	})

	// net-snmp 5.9.5.2 on FreeBSD 14.5: `net-snmp-config --snmpconfpath`
	// starts with /usr/local/etc/snmp:/usr/local/share/snmp.
	t.Run("the FreeBSD rc.d default", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(t, fs, "/usr/local/share/snmp/snmpd.conf")
		assert.Equal(t, "/usr/local/share/snmp/snmpd.conf", snmpdConfigPath(fs))
	})

	t.Run("/usr/local/etc/snmp comes first in the FreeBSD search path", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(t, fs, "/usr/local/etc/snmp/snmpd.conf")
		write(t, fs, "/usr/local/share/snmp/snmpd.conf")
		assert.Equal(t, "/usr/local/etc/snmp/snmpd.conf", snmpdConfigPath(fs))
	})

	t.Run("nothing installed names the default path", func(t *testing.T) {
		assert.Equal(t, "/etc/snmp/snmpd.conf", snmpdConfigPath(afero.NewMemMapFs()))
	})
}

// snmpd.config("/nonexistent") used to resolve to empty lists, so
// roCommunities.none(_ == "public") passed against a file that is not there.
// An explicit path that does not exist is an error; a missing default
// location still means snmpd is not configured and reads as empty.
func TestSnmpdConfigMissingExplicitPath(t *testing.T) {
	newConfig := func(t *testing.T, files map[string]*mock.MockFileData, path string) *mqlSnmpdConfig {
		t.Helper()
		// tomcatMockRuntime is a plain mock Linux connection serving files;
		// nothing in it is specific to Tomcat.
		runtime := tomcatMockRuntime(t, files)
		raw, err := NewResource(runtime, "snmpd.config", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		require.NoError(t, err)
		return raw.(*mqlSnmpdConfig)
	}

	t.Run("a missing explicit path is an error", func(t *testing.T) {
		cfg := newConfig(t, map[string]*mock.MockFileData{}, "/opt/snmp/custom.conf")
		files := cfg.GetFiles()
		require.Error(t, files.Error)
		assert.Contains(t, files.Error.Error(), "/opt/snmp/custom.conf")
		require.Error(t, cfg.GetRoCommunities().Error)
	})

	t.Run("a missing default path reads as not configured", func(t *testing.T) {
		cfg := newConfig(t, map[string]*mock.MockFileData{}, defaultSnmpdConfig)
		require.NoError(t, cfg.GetFiles().Error)
		ro := cfg.GetRoCommunities()
		require.NoError(t, ro.Error)
		assert.Empty(t, ro.Data)
	})

	t.Run("an existing explicit path is read", func(t *testing.T) {
		cfg := newConfig(t, map[string]*mock.MockFileData{
			"/opt/snmp/custom.conf": {StatData: mock.FileInfo{Mode: 0o644}, Content: "rocommunity public 127.0.0.1\n"},
		}, "/opt/snmp/custom.conf")
		ro := cfg.GetRoCommunities()
		require.NoError(t, ro.Error)
		assert.Equal(t, []any{"public"}, ro.Data)
	})
}
