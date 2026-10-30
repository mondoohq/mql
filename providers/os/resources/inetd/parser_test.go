// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inetd

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	content := `# /etc/inetd.conf example
#
# <service> <socket> <proto> <wait> <user> <server> <args>
ftp     stream  tcp     nowait  root    /usr/sbin/tcpd  in.ftpd
telnet  stream  tcp     nowait  root    /usr/sbin/tcpd  in.telnetd
#shell  stream  tcp     nowait  root    /usr/sbin/tcpd  in.rshd
daytime stream  tcp     nowait  root    internal

   # indented comment is still a comment
tftp    dgram   udp     wait    nobody  /usr/sbin/tcpd  in.tftpd /srv/tftp
ftp     stream  tcp6    nowait  root    /usr/sbin/tcpd  in.ftpd
`

	entries := Parse(content)
	require.Len(t, entries, 5)

	t.Run("first active entry maps all columns", func(t *testing.T) {
		ftp := entries[0]
		assert.Equal(t, "ftp", ftp.Name)
		assert.Equal(t, "stream", ftp.SocketType)
		assert.Equal(t, "tcp", ftp.Protocol)
		assert.Equal(t, "nowait", ftp.Wait)
		assert.Equal(t, "root", ftp.User)
		assert.Equal(t, "/usr/sbin/tcpd", ftp.Server)
		assert.Equal(t, "in.ftpd", ftp.Arguments)
		assert.Equal(t, 4, ftp.Line)
	})

	t.Run("commented-out entries are excluded", func(t *testing.T) {
		for _, e := range entries {
			assert.NotEqual(t, "shell", e.Name)
		}
	})

	t.Run("internal servers have no arguments", func(t *testing.T) {
		daytime := entries[2]
		assert.Equal(t, "daytime", daytime.Name)
		assert.Equal(t, "internal", daytime.Server)
		assert.Equal(t, "", daytime.Arguments)
	})

	t.Run("multiple arguments are joined", func(t *testing.T) {
		tftp := entries[3]
		assert.Equal(t, "tftp", tftp.Name)
		assert.Equal(t, "in.tftpd /srv/tftp", tftp.Arguments)
	})

	t.Run("same service over different protocols both kept", func(t *testing.T) {
		assert.Equal(t, "ftp", entries[4].Name)
		assert.Equal(t, "tcp6", entries[4].Protocol)
	})
}

func TestParseEmpty(t *testing.T) {
	assert.Empty(t, Parse(""))
	assert.Empty(t, Parse("# only comments\n#ftp stream tcp nowait root internal\n"))
}

func TestParseRPCAndSuffixes(t *testing.T) {
	content := `rstatd/1-3      dgram   rpc/udp wait    root    /usr/sbin/rpc.rstatd    rpc.rstatd
echo            stream  tcp     nowait.400      root    internal
finger          stream  tcp     nowait  nobody.nogroup  /usr/sbin/tcpd  in.fingerd`

	entries := Parse(content)
	require.Len(t, entries, 3)

	assert.Equal(t, "rstatd/1-3", entries[0].Name)
	assert.Equal(t, "rpc/udp", entries[0].Protocol)

	// nowait.max suffix is preserved verbatim
	assert.Equal(t, "nowait.400", entries[1].Wait)

	// user.group suffix is preserved verbatim
	assert.Equal(t, "nobody.nogroup", entries[2].User)
}

func TestParseMalformedLinesSkipped(t *testing.T) {
	content := `ftp stream tcp nowait root
ftp stream tcp nowait root /usr/sbin/in.ftpd`

	entries := Parse(content)
	require.Len(t, entries, 1)
	assert.Equal(t, "/usr/sbin/in.ftpd", entries[0].Server)
	assert.Equal(t, 2, entries[0].Line)
}

// testdata/freebsd-14.5-inetd.conf is /etc/inetd.conf as shipped by the
// FreeBSD 14.5-RELEASE amd64 AMI, copied verbatim.
func readFreeBSDConfig(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/freebsd-14.5-inetd.conf")
	require.NoError(t, err)
	return string(data)
}

func TestParseFreeBSDStockConfig(t *testing.T) {
	// FreeBSD ships every service commented out, including the #@ IPsec
	// policy lines, so the stock file has no active entries.
	assert.Empty(t, Parse(readFreeBSDConfig(t)))
}

func TestParseFreeBSDStockConfigUncommented(t *testing.T) {
	// Enabling every service the way the file header describes (removing the
	// leading #) must yield exactly one entry per service line.
	stock := readFreeBSDConfig(t)
	serviceLine := regexp.MustCompile(`(?m)^#([a-z/])`)
	want := len(serviceLine.FindAllString(stock, -1))
	require.Equal(t, 67, want)

	entries := Parse(serviceLine.ReplaceAllString(stock, "$1"))
	require.Len(t, entries, want)

	byName := map[string]Entry{}
	for _, e := range entries {
		assert.Empty(t, e.Address, "entry %s on line %d", e.Name, e.Line)
		if _, ok := byName[e.Name]; !ok {
			byName[e.Name] = e
		}
	}

	finger := byName["finger"]
	assert.Equal(t, "nowait/3/10", finger.Wait)
	assert.Equal(t, "nobody", finger.User)
	assert.Equal(t, "fingerd -k -s", finger.Arguments)

	assert.Equal(t, "tty:tty", byName["comsat"].User)
	assert.Equal(t, "nowait/400", byName["swat"].Wait)

	echo := byName["/var/run/echo"]
	assert.Equal(t, "unix", echo.Protocol)
	assert.Equal(t, "internal", echo.Server)

	assert.Equal(t, "rpc/udp", byName["rstatd/1-3"].Protocol)
	assert.Equal(t, "guest", byName["tcpmux/+date"].User)
	assert.Equal(t, "cvs --allow-root=/your/cvsroot/here pserver", byName["cvspserver"].Arguments)

	// The service after the "#@ ipsec ah/require" policy line is read, the
	// policy line itself is not an entry.
	last := entries[len(entries)-1]
	assert.Equal(t, "chargen", last.Name)
	assert.Equal(t, 147, last.Line)
}

func TestParseFreeBSDUnixSocketOwnership(t *testing.T) {
	// FreeBSD sets a unix socket's owner, group, and mode with a
	// :user:group:mode: prefix on the path. It is not a listen address.
	entries := Parse(":root:wheel:0600:/var/run/echo stream unix nowait root internal\n")
	require.Len(t, entries, 1)
	assert.Equal(t, "/var/run/echo", entries[0].Name)
	assert.Empty(t, entries[0].Address)
}

func TestParseAddressPrefix(t *testing.T) {
	content := `127.0.0.1:ftp  stream tcp  nowait root /usr/sbin/tcpd in.ftpd
[::1]:telnet   stream tcp6 nowait root /usr/sbin/tcpd in.telnetd
*:echo         stream tcp  nowait root internal
:daytime       stream tcp  nowait root internal
192.0.2.10:
finger         stream tcp  nowait nobody /usr/sbin/tcpd in.fingerd
tftp           dgram  udp  wait   nobody /usr/sbin/tcpd in.tftpd
*:
discard        stream tcp  nowait root internal
`

	entries := Parse(content)
	require.Len(t, entries, 7)

	got := [][2]string{}
	for _, e := range entries {
		got = append(got, [2]string{e.Address, e.Name})
	}
	assert.Equal(t, [][2]string{
		{"127.0.0.1", "ftp"},
		{"::1", "telnet"},
		{"", "echo"},
		{"", "daytime"},
		{"192.0.2.10", "finger"},
		{"192.0.2.10", "tftp"},
		{"", "discard"},
	}, got)
}

func TestParserDefaultAddressCarriesAcrossFiles(t *testing.T) {
	// GNU inetutils binds a drop-in under /etc/inetd.d to the address that
	// /etc/inetd.conf left in effect. Verified live on Ubuntu 24.04: chargen
	// from the drop-in listened on 127.0.0.1:19.
	p := &Parser{}
	main := p.Parse("127.0.0.1:\ndiscard stream tcp nowait root internal\n")
	dropin := p.Parse("chargen stream tcp nowait root \"internal\"\n")

	require.Len(t, main, 1)
	require.Len(t, dropin, 1)
	assert.Equal(t, "127.0.0.1", dropin[0].Address)
	assert.Equal(t, "internal", dropin[0].Server)

	// The package-level Parse starts from a clean state every time.
	assert.Empty(t, Parse("chargen stream tcp nowait root internal\n")[0].Address)
}

func TestParseContinuationLines(t *testing.T) {
	content := "ftp\tstream\ttcp\tnowait\troot\n" +
		"\t/usr/libexec/ftpd\tftpd -l\n" +
		"telnet stream tcp nowait root\n" +
		"\n" +
		"    /usr/libexec/telnetd telnetd\n" +
		"echo stream tcp nowait root internal\n" +
		"  discard stream tcp nowait root internal\n"

	entries := Parse(content)
	require.Len(t, entries, 3)

	// A wrapped entry is read as one, numbered by its first line.
	assert.Equal(t, "ftp", entries[0].Name)
	assert.Equal(t, "/usr/libexec/ftpd", entries[0].Server)
	assert.Equal(t, "ftpd -l", entries[0].Arguments)
	assert.Equal(t, 1, entries[0].Line)

	// An empty line ends the entry, so the incomplete telnet line is dropped
	// and the indented line after it doesn't make an entry either.
	assert.Equal(t, "echo", entries[1].Name)
	assert.Equal(t, "", entries[1].Arguments)

	// An indented line after a complete entry is its own entry, not more
	// arguments, so it can't hide a service.
	assert.Equal(t, "discard", entries[2].Name)
	assert.Equal(t, 7, entries[2].Line)
}

func TestParseQuotedTokens(t *testing.T) {
	entries := Parse(`svc stream tcp nowait root "/opt/my server/bin/svc" svc --motd 'hello world'` + "\n")
	require.Len(t, entries, 1)
	assert.Equal(t, "/opt/my server/bin/svc", entries[0].Server)
	assert.Equal(t, "svc --motd hello world", entries[0].Arguments)
}
