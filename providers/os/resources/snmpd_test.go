// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
