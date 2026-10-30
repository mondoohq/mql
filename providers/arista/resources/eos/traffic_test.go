// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMonitorSessions_LocalAndTunnel(t *testing.T) {
	cfg := `!
monitor session SPAN1 source Ethernet1
monitor session SPAN1 source Ethernet2 rx
monitor session SPAN1 destination Ethernet48
monitor session SPAN1 truncate size 160
monitor session ERSPAN1 source Ethernet3 both
monitor session ERSPAN1 destination tunnel mode gre destination 10.0.0.1 source 10.0.0.2
!
`
	sessions := ParseMonitorSessions(cfg)
	require.Len(t, sessions, 2)

	byName := map[string]MonitorSession{}
	for _, s := range sessions {
		byName[s.Name] = s
	}

	span := byName["SPAN1"]
	require.Len(t, span.Sources, 2)
	// A source line with no direction mirrors both.
	assert.Equal(t, MonitorSource{Interface: "Ethernet1", Direction: "both"}, span.Sources[0])
	assert.Equal(t, MonitorSource{Interface: "Ethernet2", Direction: "rx"}, span.Sources[1])
	assert.Equal(t, []string{"Ethernet48"}, span.DestinationInterfaces)
	assert.Empty(t, span.TunnelDestinations)
	assert.True(t, span.TruncateEnabled)
	assert.Equal(t, 160, span.TruncateSize)

	// The encapsulated session sends traffic off the device entirely.
	erspan := byName["ERSPAN1"]
	assert.Equal(t, []string{"10.0.0.1"}, erspan.TunnelDestinations)
	assert.Empty(t, erspan.DestinationInterfaces)
}

func TestParseMonitorSessions_None(t *testing.T) {
	assert.Empty(t, ParseMonitorSessions("interface Ethernet1\n   description X\n"))
}

func TestParseMonitorSessions_TruncatedLineDoesNotPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		ParseMonitorSessions("monitor session S1\nmonitor session S1 source\nmonitor session S1 destination\n")
	})
}

func TestParseSflowConfig_Full(t *testing.T) {
	cfg := `!
sflow sample 16384
sflow polling-interval 30
sflow destination 10.0.0.50
sflow destination 10.0.0.51 6344
sflow vrf MGMT destination 10.0.0.52
sflow source-interface Management1
sflow run
!
`
	c := ParseSflowConfig(cfg)
	assert.True(t, c.Enabled)
	assert.Equal(t, 16384, c.SampleRate)
	assert.Equal(t, 30, c.PollingInterval)
	assert.Equal(t, "Management1", c.SourceInterface)

	require.Len(t, c.Destinations, 3)
	assert.Equal(t, SflowDestination{Address: "10.0.0.50", Port: 6343}, c.Destinations[0])
	assert.Equal(t, SflowDestination{Address: "10.0.0.51", Port: 6344}, c.Destinations[1])
	assert.Equal(t, SflowDestination{Address: "10.0.0.52", Port: 6343, VRF: "MGMT"}, c.Destinations[2])
}

func TestParseSflowConfig_NotRunning(t *testing.T) {
	// Collectors can be configured while sampling is off; both matter.
	cfg := `sflow destination 10.0.0.50
`
	c := ParseSflowConfig(cfg)
	assert.False(t, c.Enabled)
	assert.Len(t, c.Destinations, 1)
}

func TestParseSflowConfig_NegatedDestination(t *testing.T) {
	cfg := `sflow destination 10.0.0.50
sflow destination 10.0.0.51
no sflow destination 10.0.0.50
no sflow run
`
	c := ParseSflowConfig(cfg)
	assert.False(t, c.Enabled)
	require.Len(t, c.Destinations, 1)
	assert.Equal(t, "10.0.0.51", c.Destinations[0].Address)
}

func TestParseSflowConfig_None(t *testing.T) {
	c := ParseSflowConfig("interface Ethernet1\n")
	assert.False(t, c.Enabled)
	assert.Empty(t, c.Destinations)
}

func TestParseInterfaceHardening(t *testing.T) {
	cfg := `!
interface Ethernet1
   description UPLINK
   ip proxy-arp
   ip verify unicast source reachable-via rx
!
interface Ethernet2
   no ip redirects
!
interface Vlan100
   description SVI
!
`
	hardening := ParseInterfaceHardening(cfg)
	require.Len(t, hardening, 3)

	byName := map[string]InterfaceHardening{}
	for _, h := range hardening {
		byName[h.Interface] = h
	}

	e1 := byName["Ethernet1"]
	assert.True(t, e1.ProxyArpEnabled)
	assert.Equal(t, "rx", e1.UnicastRpfMode)
	// Nothing said about redirects, so the device default applies.
	assert.True(t, e1.IcmpRedirectsEnabled)

	assert.False(t, byName["Ethernet2"].IcmpRedirectsEnabled)

	// An interface that configures none of this still has a posture, and it
	// is reported rather than omitted.
	v100 := byName["Vlan100"]
	assert.False(t, v100.ProxyArpEnabled)
	assert.True(t, v100.IcmpRedirectsEnabled)
	assert.Empty(t, v100.UnicastRpfMode)
}

func TestParseInterfaceHardening_ExplicitNegationWins(t *testing.T) {
	cfg := `interface Ethernet1
   ip proxy-arp
   no ip proxy-arp
   ip verify unicast source reachable-via any
   no ip verify unicast
`
	hardening := ParseInterfaceHardening(cfg)
	require.Len(t, hardening, 1)
	assert.False(t, hardening[0].ProxyArpEnabled)
	assert.Empty(t, hardening[0].UnicastRpfMode)
}

// EOS accepts options after the uRPF mode. Only the mode belongs in the field,
// or a policy testing for "rx" silently misses an interface that also carries
// allow-default or an ACL name.
func TestParseInterfaceHardening_UnicastRpfModeIgnoresTrailingOptions(t *testing.T) {
	cfg := `interface Ethernet1
   ip verify unicast source reachable-via rx allow-default
!
interface Ethernet2
   ip verify unicast source reachable-via any allow-default ACL-SPOOF
!
interface Ethernet3
   ip verify unicast source reachable-via rx
!
`
	byName := map[string]InterfaceHardening{}
	for _, h := range ParseInterfaceHardening(cfg) {
		byName[h.Interface] = h
	}

	assert.Equal(t, "rx", byName["Ethernet1"].UnicastRpfMode)
	assert.Equal(t, "any", byName["Ethernet2"].UnicastRpfMode)
	assert.Equal(t, "rx", byName["Ethernet3"].UnicastRpfMode)
}

func TestParseInterfaceHardening_None(t *testing.T) {
	assert.Empty(t, ParseInterfaceHardening("hostname switch\n"))
}
