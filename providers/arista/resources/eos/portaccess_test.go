// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDot1xConfig_Full(t *testing.T) {
	cfg := `!
dot1x system-auth-control
dot1x dynamic-authorization
dot1x mac based authentication hold period 300
!
interface Ethernet1
   description ACCESS-PORT
   dot1x pae authenticator
   dot1x port-control auto
   dot1x host-mode single-host
   dot1x reauthentication
   dot1x timeout reauth-period 3600
   dot1x timeout tx-period 30
   dot1x timeout quiet-period 60
!
interface Ethernet2
   dot1x pae authenticator
   dot1x port-control force-authorized
   dot1x mac based authentication
   dot1x eapol disabled
!
interface Ethernet3
   description UPLINK-NO-DOT1X
!
`
	c := ParseDot1xConfig(cfg)
	assert.True(t, c.SystemAuthControl)
	assert.True(t, c.DynamicAuthorization)
	assert.Equal(t, 300, c.MacBasedAuthHoldPeriod)

	// Ethernet3 has no 802.1X configuration and is left out.
	require.Len(t, c.Interfaces, 2)

	e1 := c.Interfaces[0]
	assert.Equal(t, "Ethernet1", e1.Interface)
	assert.Equal(t, "authenticator", e1.PaeMode)
	assert.Equal(t, "auto", e1.PortControl)
	assert.Equal(t, "single-host", e1.HostMode)
	assert.True(t, e1.Reauthentication)
	assert.Equal(t, 3600, e1.ReauthPeriod)
	assert.Equal(t, 30, e1.TxPeriod)
	assert.Equal(t, 60, e1.QuietPeriod)
	assert.False(t, e1.MacBasedAuth)

	e2 := c.Interfaces[1]
	assert.Equal(t, "Ethernet2", e2.Interface)
	// force-authorized hands access to whatever plugs in.
	assert.Equal(t, "force-authorized", e2.PortControl)
	assert.True(t, e2.MacBasedAuth)
	assert.True(t, e2.EapolDisabled)
	assert.False(t, e2.Reauthentication)
}

func TestParseDot1xConfig_PortsConfiguredButMasterSwitchOff(t *testing.T) {
	// Without `dot1x system-auth-control` the per-interface configuration is
	// inert. A device can look like it enforces port authentication while
	// enforcing nothing, so the two must be reported separately.
	cfg := `interface Ethernet1
   dot1x pae authenticator
   dot1x port-control auto
`
	c := ParseDot1xConfig(cfg)
	assert.False(t, c.SystemAuthControl)
	require.Len(t, c.Interfaces, 1)
	assert.Equal(t, "auto", c.Interfaces[0].PortControl)
}

func TestParseDot1xConfig_None(t *testing.T) {
	c := ParseDot1xConfig("interface Ethernet1\n   description NOTHING\n")
	assert.False(t, c.SystemAuthControl)
	assert.Empty(t, c.Interfaces)
}

func TestParseDot1xConfig_Negated(t *testing.T) {
	cfg := `dot1x system-auth-control
no dot1x system-auth-control
`
	c := ParseDot1xConfig(cfg)
	assert.False(t, c.SystemAuthControl)
}

func TestParseDot1xConfig_BareKeywordDoesNotPanic(t *testing.T) {
	// A truncated line must not index past an empty token slice: a panic in a
	// parser takes down the whole scan, not just this query.
	assert.NotPanics(t, func() {
		c := ParseDot1xConfig("interface Ethernet1\n   dot1x \n")
		assert.Empty(t, c.Interfaces)
	})
}

func TestParseDhcpSnooping_Full(t *testing.T) {
	cfg := `!
ip dhcp snooping
ip dhcp snooping vlan 100,200,300-310
ip dhcp snooping information option
!
interface Ethernet1
   ip dhcp snooping trust
!
interface Ethernet2
   description ACCESS
!
interface Ethernet48
   ip dhcp snooping trust
!
`
	c := ParseDhcpSnooping(cfg)
	assert.True(t, c.Enabled)
	// Range tokens stay as written rather than being expanded.
	assert.Equal(t, []string{"100", "200", "300-310"}, c.Vlans)
	assert.True(t, c.InsertOption82)
	assert.False(t, c.Bridging)
	assert.Equal(t, []string{"Ethernet1", "Ethernet48"}, c.TrustedInterfaces)
}

func TestParseDhcpSnooping_VlanCoverageAccumulates(t *testing.T) {
	// A device that renders one line per VLAN must not have all but the last
	// silently dropped. A VLAN repeated across lines is reported once.
	cfg := `ip dhcp snooping
ip dhcp snooping vlan 100
ip dhcp snooping vlan 200,300
ip dhcp snooping vlan 200
`
	c := ParseDhcpSnooping(cfg)
	assert.Equal(t, []string{"100", "200", "300"}, c.Vlans)
}

func TestParseArpInspection_VlanCoverageAccumulates(t *testing.T) {
	cfg := `ip arp inspection vlan 100
ip arp inspection vlan 200 logging acl-match matchlog
ip arp inspection vlan 100
`
	c := ParseArpInspection(cfg)
	assert.True(t, c.Enabled)
	assert.Equal(t, []string{"100", "200"}, c.Vlans)
}

func TestParseDhcpSnooping_None(t *testing.T) {
	c := ParseDhcpSnooping("interface Ethernet1\n   description X\n")
	assert.False(t, c.Enabled)
	assert.Empty(t, c.Vlans)
	assert.Empty(t, c.TrustedInterfaces)
}

func TestParseDhcpSnooping_Negated(t *testing.T) {
	cfg := `ip dhcp snooping
ip dhcp snooping information option
no ip dhcp snooping
no ip dhcp snooping information option
`
	c := ParseDhcpSnooping(cfg)
	assert.False(t, c.Enabled)
	assert.False(t, c.InsertOption82)
}

func TestParseArpInspection_Full(t *testing.T) {
	cfg := `!
ip arp inspection vlan 100,200 logging acl-match matchlog
!
interface Ethernet49
   ip arp inspection trust
!
interface Ethernet1
   description ACCESS
!
`
	c := ParseArpInspection(cfg)
	assert.True(t, c.Enabled)
	// The trailing logging clause is not part of the VLAN list.
	assert.Equal(t, []string{"100", "200"}, c.Vlans)
	assert.Equal(t, []string{"Ethernet49"}, c.TrustedInterfaces)
}

func TestParseArpInspection_None(t *testing.T) {
	// DAI has no global switch: with no VLAN covered it is simply off.
	c := ParseArpInspection("ip dhcp snooping\n")
	assert.False(t, c.Enabled)
	assert.Empty(t, c.Vlans)
}

func TestParseArpInspection_TruncatedLineDoesNotPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		c := ParseArpInspection("ip arp inspection vlan \n")
		assert.False(t, c.Enabled)
	})
}

func TestPortAccessParsers_IgnoreIndentedGlobalKeywords(t *testing.T) {
	// The same keywords appear indented inside interface blocks with a
	// per-port meaning. An indented line must never set global state.
	cfg := `interface Ethernet1
   ip dhcp snooping trust
   dot1x port-control auto
`
	dhcp := ParseDhcpSnooping(cfg)
	assert.False(t, dhcp.Enabled)
	assert.Equal(t, []string{"Ethernet1"}, dhcp.TrustedInterfaces)

	d1x := ParseDot1xConfig(cfg)
	assert.False(t, d1x.SystemAuthControl)
	require.Len(t, d1x.Interfaces, 1)
}
