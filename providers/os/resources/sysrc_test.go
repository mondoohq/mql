// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSysrc(t *testing.T) {
	t.Run("standard rc.conf", func(t *testing.T) {
		content := `# System configuration
hostname="freebsd-host"
ifconfig_em0="DHCP"
sshd_enable="YES"
dumpdev="NO"
`
		entries := ParseSysrc(content)
		require.Len(t, entries, 4)

		require.Equal(t, SysrcEntry{Name: "hostname", Value: "freebsd-host"}, entries[0])
		require.Equal(t, SysrcEntry{Name: "ifconfig_em0", Value: "DHCP"}, entries[1])
		require.Equal(t, SysrcEntry{Name: "sshd_enable", Value: "YES"}, entries[2])
		require.Equal(t, SysrcEntry{Name: "dumpdev", Value: "NO"}, entries[3])
	})

	t.Run("single quotes", func(t *testing.T) {
		entries := ParseSysrc(`syslogd_flags='-s -s'`)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "syslogd_flags", Value: "-s -s"}, entries[0])
	})

	t.Run("unquoted value", func(t *testing.T) {
		entries := ParseSysrc(`savecore_enable=NO`)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "savecore_enable", Value: "NO"}, entries[0])
	})

	t.Run("empty lines and comments", func(t *testing.T) {
		content := `# comment

hostname="test"

# another comment
`
		entries := ParseSysrc(content)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "hostname", Value: "test"}, entries[0])
	})

	t.Run("empty value", func(t *testing.T) {
		entries := ParseSysrc(`gateway_enable=""`)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "gateway_enable", Value: ""}, entries[0])
	})

	t.Run("value with equals sign", func(t *testing.T) {
		entries := ParseSysrc(`ifconfig_em0="inet 10.0.0.1 netmask=255.255.255.0"`)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "ifconfig_em0", Value: "inet 10.0.0.1 netmask=255.255.255.0"}, entries[0])
	})

	t.Run("empty content", func(t *testing.T) {
		entries := ParseSysrc("")
		require.Nil(t, entries)
	})

	t.Run("duplicate keys last wins", func(t *testing.T) {
		content := `sshd_enable="NO"
sshd_enable="YES"
`
		entries := ParseSysrc(content)
		require.Len(t, entries, 1)
		require.Equal(t, SysrcEntry{Name: "sshd_enable", Value: "YES"}, entries[0])
	})
}

// The parser reads a whole file already held in memory. A line over 64 KiB
// must not end the parse and drop the settings after it.
func TestParseSysrcAfterLongLine(t *testing.T) {
	entries := ParseSysrc("ifconfig_em0_aliases=\"" + strings.Repeat("x", 70000) + "\"\nsshd_enable=\"YES\"\n")
	require.Len(t, entries, 2)
	assert.Equal(t, SysrcEntry{Name: "sshd_enable", Value: "YES"}, entries[1])
}
