// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleFirewalldOutput = `block
  target: %%REJECT%%
  icmp-block-inversion: no
  interfaces:
  sources:
  services:
  ports:
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:

dmz
  target: default
  icmp-block-inversion: no
  interfaces:
  sources:
  services: ssh
  ports:
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:

public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0 eth1
  sources:
  services: cockpit dhcpv6-client ssh
  ports: 8080/tcp 443/tcp
  protocols: icmp
  forward: yes
  masquerade: yes
  forward-ports: port=80:proto=tcp:toport=8080:toaddr=
  source-ports:
  icmp-blocks: echo-reply
  rich rules:
	rule family="ipv4" source address="10.0.0.0/8" accept
	rule family="ipv4" source address="192.168.1.0/24" destination address="10.0.0.0/8" reject
`

func TestParseFirewalldZones(t *testing.T) {
	zones := parseFirewalldZones(sampleFirewalldOutput)
	require.Len(t, zones, 3)

	// block zone
	block := zones[0]
	assert.Equal(t, "block", block.name)
	assert.Equal(t, "%%REJECT%%", block.target)
	assert.False(t, block.active)
	assert.False(t, block.icmpBlockInversion)
	assert.Nil(t, block.interfaces)
	assert.Nil(t, block.services)
	assert.False(t, block.masquerade)

	// dmz zone
	dmz := zones[1]
	assert.Equal(t, "dmz", dmz.name)
	assert.Equal(t, "default", dmz.target)
	assert.False(t, dmz.active)
	assert.Equal(t, []string{"ssh"}, dmz.services)

	// public zone (active)
	pub := zones[2]
	assert.Equal(t, "public", pub.name)
	assert.True(t, pub.active)
	assert.Equal(t, "default", pub.target)
	assert.Equal(t, []string{"eth0", "eth1"}, pub.interfaces)
	assert.Equal(t, []string{"cockpit", "dhcpv6-client", "ssh"}, pub.services)
	assert.Equal(t, []string{"8080/tcp", "443/tcp"}, pub.ports)
	assert.Equal(t, []string{"icmp"}, pub.protocols)
	assert.True(t, pub.masquerade)
	assert.Equal(t, []string{"port=80:proto=tcp:toport=8080:toaddr="}, pub.forwardPorts)
	assert.Equal(t, []string{"echo-reply"}, pub.icmpBlocks)
	require.Len(t, pub.richRules, 2)
	assert.Equal(t, `rule family="ipv4" source address="10.0.0.0/8" accept`, pub.richRules[0])
	assert.Equal(t, `rule family="ipv4" source address="192.168.1.0/24" destination address="10.0.0.0/8" reject`, pub.richRules[1])
}

func TestParseFirewalldZonesEmpty(t *testing.T) {
	zones := parseFirewalldZones("")
	assert.Empty(t, zones)
}

func TestParseFirewalldRichRule(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected parsedRichRule
	}{
		{
			name:  "accept with source",
			input: `rule family="ipv4" source address="10.0.0.0/8" accept`,
			expected: parsedRichRule{
				family: "ipv4",
				source: "10.0.0.0/8",
				action: "accept",
			},
		},
		{
			name:  "reject with source and destination",
			input: `rule family="ipv4" source address="192.168.1.0/24" destination address="10.0.0.0/8" reject`,
			expected: parsedRichRule{
				family:      "ipv4",
				source:      "192.168.1.0/24",
				destination: "10.0.0.0/8",
				action:      "reject",
			},
		},
		{
			name:  "ipv6 drop",
			input: `rule family="ipv6" source address="fd00::/8" drop`,
			expected: parsedRichRule{
				family: "ipv6",
				source: "fd00::/8",
				action: "drop",
			},
		},
		{
			name:  "no family",
			input: `rule source address="10.0.0.0/8" accept`,
			expected: parsedRichRule{
				source: "10.0.0.0/8",
				action: "accept",
			},
		},
		{
			name:  "service name containing action keyword",
			input: `rule family="ipv4" service name="acceptor" drop`,
			expected: parsedRichRule{
				family: "ipv4",
				action: "drop",
			},
		},
		{
			name:  "log with accept",
			input: `rule family="ipv4" source address="10.0.0.0/8" log prefix="test" level="info" accept`,
			expected: parsedRichRule{
				family: "ipv4",
				source: "10.0.0.0/8",
				action: "accept",
			},
		},
		{
			name:  "ipv4 anti-spoofing with destination NOT address",
			input: `rule family="ipv4" source address="127.0.0.1" destination NOT address="127.0.0.1" drop`,
			expected: parsedRichRule{
				family:              "ipv4",
				source:              "127.0.0.1",
				destination:         "127.0.0.1",
				destinationInverted: true,
				action:              "drop",
			},
		},
		{
			name:  "ipv6 anti-spoofing with destination NOT address",
			input: `rule family="ipv6" source address="::1" destination NOT address="::1" drop`,
			expected: parsedRichRule{
				family:              "ipv6",
				source:              "::1",
				destination:         "::1",
				destinationInverted: true,
				action:              "drop",
			},
		},
		{
			name:  "source NOT address inverted",
			input: `rule family="ipv4" source NOT address="10.0.0.0/8" drop`,
			expected: parsedRichRule{
				family:         "ipv4",
				source:         "10.0.0.0/8",
				sourceInverted: true,
				action:         "drop",
			},
		},
		// The rules below are as firewall-cmd --list-all-zones printed them on
		// RHEL 7 (firewalld 0.6.3) and RHEL 9 (1.3.4).
		{
			name:  "accept followed by a limit option",
			input: `rule family="ipv4" source address="198.51.100.200" accept limit value="2/m"`,
			expected: parsedRichRule{
				family: "ipv4",
				source: "198.51.100.200",
				action: "accept",
			},
		},
		{
			name:  "reject followed by a type option",
			input: `rule family="ipv4" source address="203.0.113.0/24" reject type="icmp-host-prohibited"`,
			expected: parsedRichRule{
				family: "ipv4",
				source: "203.0.113.0/24",
				action: "reject",
			},
		},
		{
			name:  "log prefix with a trailing space and a limit",
			input: `rule family="ipv4" source address="198.51.100.0/24" service name="ftp" log prefix="ftp " level="info" limit value="1/m" accept`,
			expected: parsedRichRule{
				family: "ipv4",
				source: "198.51.100.0/24",
				action: "accept",
			},
		},
		{
			name:  "firewalld 0.6 prints an inverted destination in lower case",
			input: `rule family="ipv4" destination not address="192.0.2.1" service name="dns" log prefix="dnsx" level="warning" drop`,
			expected: parsedRichRule{
				family:              "ipv4",
				destination:         "192.0.2.1",
				destinationInverted: true,
				action:              "drop",
			},
		},
		{
			name:  "action keyword inside a quoted value",
			input: `rule family="ipv4" source address="10.0.0.0/8" log prefix=" drop " level="info"`,
			expected: parsedRichRule{
				family: "ipv4",
				source: "10.0.0.0/8",
				action: "log",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseFirewalldRichRule(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitNonEmpty(t *testing.T) {
	assert.Nil(t, splitNonEmpty(""))
	assert.Equal(t, []string{"ssh"}, splitNonEmpty("ssh"))
	assert.Equal(t, []string{"ssh", "http", "https"}, splitNonEmpty("ssh http https"))
	assert.Equal(t, []string{"a", "b"}, splitNonEmpty("  a   b  "))
}

// firewall-cmd exits non-zero both when the firewall is stopped and when polkit
// refuses to answer an unprivileged caller. Only the second must be treated as
// "we could not determine"; conflating them reports a running firewall as off.
func TestIsFirewalldAuthzError(t *testing.T) {
	authz := []string{
		// verbatim from an unprivileged `firewall-cmd --state` on CentOS Stream 9
		"Authorization failed.\n    Make sure polkit agent is running or run the application as superuser.",
		"Authorization failed.",
		"Error: NOT_AUTHORIZED",
		"Failed to query polkit authority",
		"dbus.exceptions.DBusException: Permission denied",
		"Access denied",
		// case must not matter
		"AUTHORIZATION FAILED",
	}
	for _, s := range authz {
		t.Run("authz/"+s[:min(len(s), 28)], func(t *testing.T) {
			assert.True(t, isFirewalldAuthzError(s), "should be recognised as an authorization failure")
		})
	}

	notAuthz := []string{
		// what firewall-cmd prints when the daemon really is stopped
		"firewall-cmd: error: Failed to connect to bus: No such file or directory",
		"FirewallD is not running",
		"Error: COMMAND_FAILED",
		"command not found",
		"",
	}
	for _, s := range notAuthz {
		name := s
		if name == "" {
			name = "empty"
		}
		t.Run("stopped/"+name[:min(len(name), 28)], func(t *testing.T) {
			assert.False(t, isFirewalldAuthzError(s),
				"a genuinely stopped firewall must still report as not running")
		})
	}
}

func TestParseFirewalldZonesForwardPorts(t *testing.T) {
	read := func(name string) []parsedZone {
		data, err := os.ReadFile("testdata/firewalld/" + name)
		require.NoError(t, err)
		zones := parseFirewalldZones(string(data))
		require.NotEmpty(t, zones)
		return zones
	}
	public := func(zones []parsedZone) parsedZone {
		for _, z := range zones {
			if z.name == "public" {
				return z
			}
		}
		t.Fatal("no public zone")
		return parsedZone{}
	}

	t.Run("firewalld 1.3 lists forward ports below the key", func(t *testing.T) {
		z := public(read("list-all-zones-1.3.4.txt"))
		assert.Equal(t, []string{"port=2022:proto=tcp:toport=22:toaddr="}, z.forwardPorts)
		// the block must end at the next key
		assert.Equal(t, []string{"1234/udp"}, z.sourcePorts)
		assert.Equal(t, []string{"timestamp-request"}, z.icmpBlocks)
		assert.Len(t, z.richRules, 9)
	})

	t.Run("firewalld 0.6 lists forward ports on the key line", func(t *testing.T) {
		z := public(read("list-all-zones-0.6.3.txt"))
		assert.Equal(t, []string{"port=2022:proto=tcp:toport=22:toaddr="}, z.forwardPorts)
		assert.Equal(t, []string{"1234/udp"}, z.sourcePorts)
		assert.Len(t, z.richRules, 9)
	})

	t.Run("zone without forward ports", func(t *testing.T) {
		for _, z := range read("list-all-zones-1.3.4.txt") {
			if z.name == "dmz" {
				assert.Empty(t, z.forwardPorts)
				return
			}
		}
		t.Fatal("no dmz zone")
	})
}

func TestIsFirewalldFailedState(t *testing.T) {
	// firewall-cmd --state on AlmaLinux 10 with firewalld 2.4.3 in the FAILED
	// state: empty stdout, "failed" on stderr, exit code 251
	assert.True(t, isFirewalldFailedState("failed\n"))
	assert.False(t, isFirewalldFailedState("not running\n"))
	assert.False(t, isFirewalldFailedState("Waiting on dbus connection...\nnot running\n"))
	assert.False(t, isFirewalldFailedState(""))
	// firewall-cmd colors its warnings when it writes to a terminal
	assert.True(t, isFirewalldFailedState("\x1b[91mfailed\x1b[00m\n"))
	// firewalld 0.4.4 (Debian 9) has no FAILED state
	assert.False(t, isFirewalldFailedState("\x1b[91mnot running\x1b[00m\n"))
}

// firewalld 0.4.4 (Debian 9) whose ruleset failed to apply: --state prints
// "not running" and exits 252, while --get-default-zone answers "public". A
// stopped daemon makes --get-default-zone exit 252 as well.
func TestFirewalldDefaultZoneAnswered(t *testing.T) {
	assert.True(t, firewalldDefaultZoneAnswered(0, "public\n"))
	assert.False(t, firewalldDefaultZoneAnswered(firewalldNotRunningExit, "\x1b[91mFirewallD is not running\x1b[00m\n"))
	assert.False(t, firewalldDefaultZoneAnswered(firewalldNotRunningExit, "FirewallD is not running\n"))
	assert.False(t, firewalldDefaultZoneAnswered(0, "\n"))
}
