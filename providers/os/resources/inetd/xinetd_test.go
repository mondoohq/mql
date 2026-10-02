// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inetd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdata/leap-15.6-xinetd is /etc/xinetd.conf and /etc/xinetd.d from an
// openSUSE Leap 15.6 host (xinetd 2.3.15.4, identical on Leap 16.0) with the
// echo and daytime TCP services switched to `disable = no`. xinetd listened on
// ports 7 and 13 only.
func readLeapXinetd(t *testing.T) (XinetdFile, []XinetdFile) {
	t.Helper()
	main, err := os.ReadFile("testdata/leap-15.6-xinetd/xinetd.conf")
	require.NoError(t, err)
	names, err := filepath.Glob("testdata/leap-15.6-xinetd/xinetd.d/*")
	require.NoError(t, err)
	require.Len(t, names, 12)
	files := []XinetdFile{}
	for _, n := range names {
		data, err := os.ReadFile(n)
		require.NoError(t, err)
		files = append(files, ParseXinetd(string(data)))
	}
	return ParseXinetd(string(main)), files
}

func TestIsXinetd(t *testing.T) {
	main, err := os.ReadFile("testdata/leap-15.6-xinetd/xinetd.conf")
	require.NoError(t, err)
	assert.True(t, IsXinetd(string(main)))
	echo, err := os.ReadFile("testdata/leap-15.6-xinetd/xinetd.d/echo")
	require.NoError(t, err)
	assert.True(t, IsXinetd(string(echo)))

	freebsd, err := os.ReadFile("testdata/freebsd-14.5-inetd.conf")
	require.NoError(t, err)
	assert.False(t, IsXinetd(string(freebsd)))
	assert.False(t, IsXinetd("ftp stream tcp nowait root /usr/sbin/tcpd in.ftpd\n127.0.0.1:\n\t/usr/libexec/ftpd ftpd -l\n"))
}

// The stock xinetd.conf holds only a defaults block and an includedir. Its
// attribute lines (`cps = 50 10`, `groups = yes`) are not services.
func TestParseXinetdStockMainFile(t *testing.T) {
	main, _ := readLeapXinetd(t)
	assert.Empty(t, main.Services)
	assert.Equal(t, []string{"/etc/xinetd.d"}, main.IncludeDirs)
	assert.Equal(t, []string{"50", "10"}, main.Defaults["cps"])
	assert.Equal(t, []string{"SYSLOG", "daemon", "info"}, main.Defaults["log_type"])
	_, hasEnabled := main.Defaults["enabled"]
	assert.False(t, hasEnabled, "commented-out enabled must not count")
	assert.Empty(t, main.Entries(MergeXinetdDefaults([]XinetdFile{main})))
}

func TestXinetdEntriesLeap(t *testing.T) {
	main, files := readLeapXinetd(t)
	all := append([]XinetdFile{main}, files...)
	defaults := MergeXinetdDefaults(all)

	entries := []Entry{}
	for _, f := range all {
		entries = append(entries, f.Entries(defaults)...)
	}
	require.Len(t, entries, 2)

	byName := map[string]Entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	echo := byName["echo"]
	assert.Equal(t, Entry{
		Name: "echo", SocketType: "stream", Protocol: "tcp", Wait: "nowait",
		User: "root", Server: "internal", Line: 4,
	}, echo)
	assert.Equal(t, "tcp", byName["daytime"].Protocol)
}

func TestXinetdDefaultsEnabledDisabled(t *testing.T) {
	svc := ParseXinetd(`service telnet
{
	socket_type = stream
	wait        = no
	user        = root
	server      = /usr/sbin/in.telnetd
	server_args = -h -L /bin/login
	bind        = 192.0.2.10
}
service ftp
{
	id          = ftp-main
	socket_type = stream
	wait        = no
	user        = root
	server      = /usr/sbin/vsftpd
}
service tftp
{
	socket_type = dgram
	protocol    = udp
	wait        = yes
	user        = root
	server      = /usr/sbin/in.tftpd
	server_args = -s /srv/tftp
	server_args += -v
}
`)
	names := func(defaultsBlock string) []string {
		d := ParseXinetd(defaultsBlock)
		res := []string{}
		for _, e := range svc.Entries(MergeXinetdDefaults([]XinetdFile{d, svc})) {
			res = append(res, e.Name)
		}
		return res
	}

	assert.Equal(t, []string{"telnet", "ftp", "tftp"}, names(""))
	// disabled and enabled name service ids, and ftp's id is ftp-main
	assert.Equal(t, []string{"telnet", "tftp"}, names("defaults\n{\n\tdisabled = ftp-main\n}\n"))
	assert.Equal(t, []string{"telnet", "ftp", "tftp"}, names("defaults\n{\n\tdisabled = ftp\n}\n"))
	assert.Equal(t, []string{"tftp"}, names("defaults {\n\tenabled = tftp\n}\n"))
	assert.Equal(t, []string{"telnet"}, names("defaults\n{\n\tenabled = tftp telnet\n\tenabled -= tftp\n}\n"))

	entries := svc.Entries(nil)
	assert.Equal(t, "192.0.2.10", entries[0].Address)
	assert.Equal(t, "-h -L /bin/login", entries[0].Arguments)
	assert.Equal(t, "/usr/sbin/in.telnetd", entries[0].Server)
	assert.Equal(t, "wait", entries[2].Wait)
	assert.Equal(t, "-s /srv/tftp -v", entries[2].Arguments)
	assert.Equal(t, "", entries[1].Address)
	assert.Equal(t, "192.0.2.20", svc.Entries(map[string][]string{"bind": {"192.0.2.20"}})[1].Address)
}

func TestXinetdIncludesFile(t *testing.T) {
	assert.True(t, XinetdIncludesFile("echo-udp"))
	assert.False(t, XinetdIncludesFile("echo.rpmnew"))
	assert.False(t, XinetdIncludesFile("echo~"))
	assert.False(t, XinetdIncludesFile(".echo"))
}
