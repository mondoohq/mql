// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// The fixtures are freebsdServiceStatusScript's output on a FreeBSD 14.5 host,
// run as root (sudo) and as an unprivileged member of wheel.
func freebsdStatusFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("./testdata/" + name)
	require.NoError(t, err)
	return string(data)
}

func servicesByName(list []*Service) map[string]*Service {
	res := make(map[string]*Service, len(list))
	for _, s := range list {
		res[s.Name] = s
	}
	return res
}

func TestParseFreeBSDServiceStatusRoot(t *testing.T) {
	list := ParseFreeBSDServiceStatus(strings.NewReader(freebsdStatusFixture(t, "freebsd14-service-status-root.txt")))
	require.Len(t, list, 46)
	byName := servicesByName(list)

	// `service <name> status` exits 0: "<name> is running as pid N"
	for _, name := range []string{"sshd", "cron", "syslogd", "ntpd", "nginx", "mysql-server", "devd", "auditd", "rtsold"} {
		s := byName[name]
		require.NotNil(t, s, name)
		assert.True(t, s.Running, name)
		assert.Equal(t, ServiceRunning, s.State, name)
	}
	// enabled in rc.conf but "snmpd is not running"
	assert.False(t, byName["snmpd"].Running, "snmpd")
	assert.Equal(t, ServiceStopped, byName["snmpd"].State, "snmpd")
	// one-shot boot scripts without a status directive
	for _, name := range []string{"growfs", "hostid", "cleanvar", "kldxref", "newsyslog"} {
		assert.False(t, byName[name].Running, name)
	}

	sshd := byName["sshd"]
	assert.Equal(t, "/etc/rc.d/sshd", sshd.Path)
	assert.True(t, sshd.Enabled)
	assert.True(t, sshd.Installed)
	assert.Equal(t, "bsd", sshd.Type)
	assert.Equal(t, "/usr/local/etc/rc.d/nginx", byName["nginx"].Path)
}

func TestParseFreeBSDServiceStatusUnprivileged(t *testing.T) {
	list := ParseFreeBSDServiceStatus(strings.NewReader(freebsdStatusFixture(t, "freebsd14-service-status-user.txt")))
	byName := servicesByName(list)
	// cron, syslogd and mysql keep root-only pidfiles; their status reads
	// "Permission denied" and must not turn into a stopped daemon.
	for _, name := range []string{"cron", "syslogd", "mysql-server"} {
		assert.True(t, byName[name].Running, name)
	}
	assert.True(t, byName["sshd"].Running)
	assert.False(t, byName["snmpd"].Running)
	assert.False(t, byName["growfs"].Running)
}

func TestParseFreeBSDServiceStatusSkipsMalformed(t *testing.T) {
	list := ParseFreeBSDServiceStatus(strings.NewReader("\n0\nsudo: lecture\nWarning: /etc/rc.conf\n127 /etc/rc.d/motd\n"))
	require.Len(t, list, 1)
	assert.Equal(t, "motd", list[0].Name)
	assert.False(t, list[0].Running)
}

func TestManagerFreeBSDChecksStatus(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "freebsd", Family: []string{"bsd", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{Commands: map[string]*mock.Command{
		"sh -c " + shared.ShellEscape(freebsdServiceStatusScript): {
			Stdout: freebsdStatusFixture(t, "freebsd14-service-status-root.txt"),
		},
	}}))
	require.NoError(t, err)

	mm, err := ResolveManager(conn)
	require.NoError(t, err)
	list, err := mm.List()
	require.NoError(t, err)
	byName := servicesByName(list)
	assert.Len(t, list, 46)
	assert.True(t, byName["sshd"].Running)
	assert.False(t, byName["snmpd"].Running)

	s, err := mm.Get("growfs")
	require.NoError(t, err)
	assert.False(t, s.Running)
}
