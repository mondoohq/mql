// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLoggingConfig_Full(t *testing.T) {
	cfg := `!
logging on
logging host 192.168.100.201
logging host 192.168.100.202 514
logging host 192.168.100.203 601 protocol tcp
logging vrf MGMT host 10.9.9.9 514
logging trap informational
logging console errors
logging monitor debugging
logging buffered 10000 informational
logging persistent 32768
logging source-interface Management1
logging facility local6
logging format timestamp high-resolution
logging format hostname fqdn
logging format rfc5424
logging synchronous
!
`
	c := ParseLoggingConfig(cfg)
	assert.True(t, c.Enabled)
	assert.Equal(t, "informational", c.TrapSeverity)
	assert.Equal(t, "errors", c.ConsoleSeverity)
	assert.Equal(t, "debugging", c.MonitorSeverity)
	assert.Equal(t, "informational", c.BufferedSeverity)
	assert.Equal(t, 10000, c.BufferedSize)
	assert.True(t, c.PersistentEnabled)
	assert.Equal(t, 32768, c.PersistentSize)
	assert.Equal(t, "Management1", c.SourceInterface)
	assert.Equal(t, "local6", c.Facility)
	assert.Equal(t, "high-resolution", c.TimestampFormat)
	assert.Equal(t, "fqdn", c.HostnameFormat)
	assert.True(t, c.Rfc5424Format)
	assert.True(t, c.Synchronous)

	require.Len(t, c.Hosts, 4)
	// Port and protocol fall back to what EOS uses when the line omits them.
	assert.Equal(t, LoggingHost{Host: "192.168.100.201", Port: 514, Protocol: "udp"}, c.Hosts[0])
	assert.Equal(t, LoggingHost{Host: "192.168.100.202", Port: 514, Protocol: "udp"}, c.Hosts[1])
	assert.Equal(t, LoggingHost{Host: "192.168.100.203", Port: 601, Protocol: "tcp"}, c.Hosts[2])
	assert.Equal(t, LoggingHost{Host: "10.9.9.9", Port: 514, Protocol: "udp", VRF: "MGMT"}, c.Hosts[3])
}

func TestParseLoggingConfig_NoConfig(t *testing.T) {
	// A device with no logging lines still logs (EOS default), but ships
	// nothing off-box — which is the finding callers care about.
	c := ParseLoggingConfig("")
	assert.True(t, c.Enabled)
	assert.Empty(t, c.Hosts)
	// Severities stay empty rather than being filled with a guessed default.
	assert.Empty(t, c.TrapSeverity)
	assert.Empty(t, c.ConsoleSeverity)
	assert.False(t, c.PersistentEnabled)
}

func TestParseLoggingConfig_Disabled(t *testing.T) {
	cfg := `no logging on
no logging console
no logging monitor
no logging buffered
`
	c := ParseLoggingConfig(cfg)
	assert.False(t, c.Enabled)
	assert.Equal(t, "disabled", c.ConsoleSeverity)
	assert.Equal(t, "disabled", c.MonitorSeverity)
	assert.Equal(t, "disabled", c.BufferedSeverity)
}

func TestParseLoggingConfig_ExplicitDisabledKeyword(t *testing.T) {
	// EOS also accepts `disabled` as the severity token itself.
	cfg := `logging trap disabled
logging buffered disabled
`
	c := ParseLoggingConfig(cfg)
	assert.Equal(t, "disabled", c.TrapSeverity)
	assert.Equal(t, "disabled", c.BufferedSeverity)
	assert.Equal(t, 0, c.BufferedSize)
}

func TestParseLoggingConfig_NegatedHostIsRemoved(t *testing.T) {
	// A config diff can add then remove a collector; the removal must win so
	// we never report a collector the device no longer ships to.
	cfg := `logging host 10.0.0.1
logging host 10.0.0.2
no logging host 10.0.0.1
`
	c := ParseLoggingConfig(cfg)
	require.Len(t, c.Hosts, 1)
	assert.Equal(t, "10.0.0.2", c.Hosts[0].Host)
}

func TestParseLoggingConfig_BufferedSeverityWithoutSize(t *testing.T) {
	cfg := `logging buffered warnings
`
	c := ParseLoggingConfig(cfg)
	assert.Equal(t, "warnings", c.BufferedSeverity)
	assert.Equal(t, 0, c.BufferedSize)
}

func TestParseLoggingConfig_VrfSourceInterface(t *testing.T) {
	cfg := `logging vrf MGMT source-interface Management1
`
	c := ParseLoggingConfig(cfg)
	assert.Equal(t, "Management1", c.SourceInterface)
}

func TestParseLoggingConfig_IgnoresInterfaceLoggingCommands(t *testing.T) {
	// `logging event ...` is a valid interface sub-command. Only top-level
	// lines are syslog configuration, so an indented block must not be able
	// to contribute a collector or a severity.
	cfg := `interface Ethernet1
   logging event link-status
   logging event congestion-drops
   logging host 10.6.6.6
   logging trap debugging
logging host 10.0.0.1
`
	c := ParseLoggingConfig(cfg)
	require.Len(t, c.Hosts, 1)
	assert.Equal(t, "10.0.0.1", c.Hosts[0].Host)
	assert.Empty(t, c.TrapSeverity)
}

func TestParseLoggingConfig_IgnoresUnrelatedLines(t *testing.T) {
	// "logging" appears inside other config contexts (ACL rules, BGP). Only
	// top-level `logging ...` lines belong to the syslog configuration.
	cfg := `router bgp 65001
   bgp log-neighbor-changes
ip access-list standard MGMT
   10 permit 10.0.0.0/8 log
logging host 10.0.0.1
`
	c := ParseLoggingConfig(cfg)
	require.Len(t, c.Hosts, 1)
	assert.Equal(t, "10.0.0.1", c.Hosts[0].Host)
}
