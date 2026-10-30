// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lsof

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func TestParseLsofWithoutFileDescriptors(t *testing.T) {
	s := `p388
g388
R1
cloginwindow
u501
f10
au
l 
tIPv4
G0x3;0x0
d0x6949610f649739df
o0t0
PUDP
n*:*
`

	processes, err := Parse(strings.NewReader(s))
	require.NoError(t, err)
	assert.Equal(t, 1, len(processes))

	process := processes[0]
	assert.Equal(t, "388", process.PID)
	assert.Equal(t, "loginwindow", process.Command)
	assert.Equal(t, "501", process.UID)
}

func TestParseLsofWithFileDescriptors(t *testing.T) {
	s := `p37224
g678
R678
cHyper Helper
u501
f24
au
l 
tIPv4
G0x10007;0x0
d0x6949610a99d53797
o0t0
PTCP
n10.184.10.188:64647->76.76.21.61:443
TST=ESTABLISHED
TQR=0
TQS=0
f25
au
l 
tIPv4
G0x10007;0x0
d0x6949610a9a1bec8f
o0t0
PTCP
n10.184.10.188:64645->76.76.21.241:443
TST=ESTABLISHED
TQR=0
TQS=0
p38266
g38266
R1
cMail
u501
f68
au
l 
tIPv4
G0x10007;0x1
d0x6949610a99a77797
o0t0
PTCP
n10.184.10.188:59637->142.251.163.108:993
TST=ESTABLISHED
TQR=0
TQS=0
`

	processes, err := Parse(strings.NewReader(s))
	require.NoError(t, err)

	assert.Equal(t, 2, len(processes))

	process := processes[0]
	assert.Equal(t, "37224", process.PID)
	assert.Equal(t, "Hyper Helper", process.Command)
	assert.Equal(t, "501", process.UID)

	assert.Equal(t, 2, len(process.FileDescriptors))

	fd := process.FileDescriptors[0]
	assert.Equal(t, "24", fd.FileDescriptor)
	assert.Equal(t, FileTypeIPv4, fd.Type)
	assert.Equal(t, "10.184.10.188:64647->76.76.21.61:443", fd.Name)

	fd = process.FileDescriptors[1]
	assert.Equal(t, "25", fd.FileDescriptor)
	assert.Equal(t, FileTypeIPv4, fd.Type)
	assert.Equal(t, "10.184.10.188:64645->76.76.21.241:443", fd.Name)
}

func TestParseLsofFileDescriptorsWithoutOffsetField(t *testing.T) {
	// lsof does not always emit an "o" (file offset) field — many socket
	// file types omit it. With two descriptors and no offset line, the
	// descriptors must not be duplicated.
	s := `p37224
cHyper Helper
u501
f24
tIPv4
PTCP
n10.184.10.188:64647->76.76.21.61:443
f25
tIPv4
PTCP
n10.184.10.188:64645->76.76.21.241:443
`

	processes, err := Parse(strings.NewReader(s))
	require.NoError(t, err)
	require.Equal(t, 1, len(processes))

	process := processes[0]
	require.Equal(t, 2, len(process.FileDescriptors))
	assert.Equal(t, "24", process.FileDescriptors[0].FileDescriptor)
	assert.Equal(t, "25", process.FileDescriptors[1].FileDescriptor)
}

func TestParseLsofTcpStateKeys(t *testing.T) {
	// lsof spells these states SYN_RCVD and FIN_WAIT2 (no underscore before the
	// digit); the mapping keys must match exactly or TcpState falls back to 0.
	cases := map[string]int64{
		"ESTABLISHED": 1,
		"SYN_RCVD":    3,
		"FIN_WAIT1":   4,
		"FIN_WAIT2":   5,
		"LISTEN":      10,
	}
	for state, want := range cases {
		s := "p1\ncFoo\nu0\nf3\nPTCP\nn1.2.3.4:1->5.6.7.8:2\nTST=" + state + "\n"
		processes, err := Parse(strings.NewReader(s))
		require.NoError(t, err)
		require.Len(t, processes, 1)
		require.Len(t, processes[0].FileDescriptors, 1)
		assert.Equal(t, want, processes[0].FileDescriptors[0].TcpState(), "state %q", state)
	}
}

func TestParseLsofMalformedTcpField(t *testing.T) {
	// A T-field without `key=value` form must be skipped, not panic.
	s := "p1\ncFoo\nu0\nf3\nPTCP\nnname\nTmalformed\n"
	require.NotPanics(t, func() {
		processes, err := Parse(strings.NewReader(s))
		require.NoError(t, err)
		require.Len(t, processes, 1)
	})
}

func TestNetworkFileEstablished(t *testing.T) {
	// Established connections are "<local>-><remote>". IPv6 endpoints are
	// bracketed and contain colons, so the local/remote host and port must be
	// split on "->" and parsed per-endpoint rather than with a naive
	// host:port regex.
	cases := []struct {
		name       string
		fdName     string
		localHost  string
		localPort  int64
		remoteHost string
		remotePort int64
	}{
		{
			name:       "ipv4",
			fdName:     "10.184.10.188:64647->76.76.21.61:443",
			localHost:  "10.184.10.188",
			localPort:  64647,
			remoteHost: "76.76.21.61",
			remotePort: 443,
		},
		{
			name:       "ipv6",
			fdName:     "[fe80::1]:8080->[fe80::2]:9090",
			localHost:  "fe80::1",
			localPort:  8080,
			remoteHost: "fe80::2",
			remotePort: 9090,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := FileDescriptor{Name: tc.fdName}
			localHost, localPort, remoteHost, remotePort, err := fd.NetworkFile()
			require.NoError(t, err)
			assert.Equal(t, tc.localHost, localHost)
			assert.Equal(t, tc.localPort, localPort)
			assert.Equal(t, tc.remoteHost, remoteHost)
			assert.Equal(t, tc.remotePort, remotePort)
		})
	}
}

func TestNetworkFileListening(t *testing.T) {
	// The listening branch (no "->") must keep working for bracketed IPv6.
	fd := FileDescriptor{Name: "[::1]:17223"}
	host, port, remoteHost, remotePort, err := fd.NetworkFile()
	require.NoError(t, err)
	assert.Equal(t, "::1", host)
	assert.Equal(t, int64(17223), port)
	assert.Equal(t, "", remoteHost)
	assert.Equal(t, int64(0), remotePort)
}

func TestParseEmpty(t *testing.T) {
	processes, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 0 {
		t.Fatal("Failed parsing empty")
	}
}
