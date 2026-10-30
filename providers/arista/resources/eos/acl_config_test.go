// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// aclConfig mirrors the lab configuration in TESTING.MD, which is the shape
// the device actually renders.
const aclConfig = `!
ip access-list standard MGMT-ACCESS
   10 permit 192.168.100.0/24
   20 deny any log
!
ip access-list extended UPLINK-IN
   10 permit tcp 10.0.0.0/8 any eq 443
   20 permit tcp 10.0.0.0/8 any eq 22
   30 permit icmp any any
   40 deny ip any any log
!
ipv6 access-list V6-MGMT
   10 permit ipv6 fc00::/7 any
   20 deny ipv6 any any log
!
`

func TestParseAccessLists_AllThreeForms(t *testing.T) {
	acls := ParseAccessLists(aclConfig)
	require.Len(t, acls, 3)

	byName := map[string]AccessList{}
	for _, a := range acls {
		byName[a.Name] = a
	}

	std := byName["MGMT-ACCESS"]
	assert.Equal(t, "ipv4", std.Family)
	assert.Equal(t, "standard", std.Type)
	require.Len(t, std.Entries, 2)
	assert.Equal(t, 10, std.Entries[0].SequenceNumber)
	assert.Equal(t, "permit", std.Entries[0].Action)
	assert.Equal(t, "192.168.100.0", std.Entries[0].SrcAddress)
	assert.Equal(t, 24, std.Entries[0].SrcPrefixLen)
	assert.Equal(t, "any", std.Entries[1].SrcAddress)
	assert.True(t, std.Entries[1].Log)

	// The extended list is the one the SDK could not see at all.
	ext := byName["UPLINK-IN"]
	assert.Equal(t, "ipv4", ext.Family)
	assert.Equal(t, "extended", ext.Type)
	require.Len(t, ext.Entries, 4)

	e10 := ext.Entries[0]
	assert.Equal(t, "permit", e10.Action)
	assert.Equal(t, "tcp", e10.Protocol)
	assert.Equal(t, "10.0.0.0", e10.SrcAddress)
	assert.Equal(t, 8, e10.SrcPrefixLen)
	assert.Equal(t, "any", e10.DstAddress)
	assert.Equal(t, "eq", e10.DstPortOperator)
	assert.Equal(t, []string{"443"}, e10.DstPorts)
	assert.Equal(t, "permit tcp 10.0.0.0/8 any eq 443", e10.Text)

	e40 := ext.Entries[3]
	assert.Equal(t, "deny", e40.Action)
	assert.Equal(t, "ip", e40.Protocol)
	assert.Equal(t, "any", e40.SrcAddress)
	assert.Equal(t, "any", e40.DstAddress)
	assert.True(t, e40.Log)

	v6 := byName["V6-MGMT"]
	assert.Equal(t, "ipv6", v6.Family)
	require.Len(t, v6.Entries, 2)
	assert.Equal(t, "ipv6", v6.Entries[0].Protocol)
	assert.Equal(t, "fc00::", v6.Entries[0].SrcAddress)
	assert.Equal(t, 7, v6.Entries[0].SrcPrefixLen)
}

func TestParseAccessLists_HostAndPortForms(t *testing.T) {
	cfg := `ip access-list extended PORTS
   10 permit tcp host 10.1.1.1 eq 1024 host 10.2.2.2 eq 80 443 log
   20 permit udp any range 5000 6000 any
   30 permit tcp any any established
   40 deny tcp any gt 1023 any
`
	acls := ParseAccessLists(cfg)
	require.Len(t, acls, 1)
	entries := acls[0].Entries
	require.Len(t, entries, 4)

	e10 := entries[0]
	assert.Equal(t, "10.1.1.1", e10.SrcAddress)
	assert.Equal(t, 32, e10.SrcPrefixLen)
	assert.Equal(t, "eq", e10.SrcPortOperator)
	assert.Equal(t, []string{"1024"}, e10.SrcPorts)
	assert.Equal(t, "10.2.2.2", e10.DstAddress)
	// A port list ends where the next address operand begins.
	assert.Equal(t, []string{"80", "443"}, e10.DstPorts)
	assert.True(t, e10.Log)

	e20 := entries[1]
	assert.Equal(t, "range", e20.SrcPortOperator)
	assert.Equal(t, []string{"5000", "6000"}, e20.SrcPorts)
	assert.Equal(t, "any", e20.DstAddress)

	assert.True(t, entries[2].Established)

	e40 := entries[3]
	assert.Equal(t, "gt", e40.SrcPortOperator)
	assert.Equal(t, []string{"1023"}, e40.SrcPorts)
}

func TestParseAccessLists_SameNameAcrossFamilies(t *testing.T) {
	// IPv4 and IPv6 access-lists are separate namespaces and can share a
	// name. Both must survive as distinct lists with their own rules.
	cfg := `ip access-list extended MGMT
   10 permit tcp 10.0.0.0/8 any eq 22
!
ipv6 access-list MGMT
   10 permit ipv6 fc00::/7 any
   20 deny ipv6 any any
!
`
	acls := ParseAccessLists(cfg)
	require.Len(t, acls, 2)

	byFamily := map[string]AccessList{}
	for _, a := range acls {
		assert.Equal(t, "MGMT", a.Name)
		byFamily[a.Family] = a
	}
	require.Len(t, byFamily, 2)
	assert.Len(t, byFamily["ipv4"].Entries, 1)
	assert.Len(t, byFamily["ipv6"].Entries, 2)
}

func TestParseAccessLists_WildcardMask(t *testing.T) {
	// The inverse-mask form is equivalent to a prefix length and must convert.
	cfg := `ip access-list extended WILDCARD
   10 permit ip 10.0.0.0 0.0.0.255 any
   20 permit ip 172.16.0.0 0.15.255.255 any
`
	acls := ParseAccessLists(cfg)
	require.Len(t, acls, 1)
	assert.Equal(t, "10.0.0.0", acls[0].Entries[0].SrcAddress)
	assert.Equal(t, 24, acls[0].Entries[0].SrcPrefixLen)
	assert.Equal(t, 12, acls[0].Entries[1].SrcPrefixLen)
}

func TestParseAccessLists_RemarkAndUntypedList(t *testing.T) {
	// A list declared with no keyword is extended, which is what the device
	// creates.
	cfg := `ip access-list NO-KEYWORD
   10 remark blocks the guest range
   20 deny ip 192.168.50.0/24 any
`
	acls := ParseAccessLists(cfg)
	require.Len(t, acls, 1)
	assert.Equal(t, "extended", acls[0].Type)
	require.Len(t, acls[0].Entries, 2)
	assert.Equal(t, "remark", acls[0].Entries[0].Action)
	assert.Equal(t, "blocks the guest range", acls[0].Entries[0].Remark)
}

func TestParseAccessLists_EntriesSortedBySequence(t *testing.T) {
	cfg := `ip access-list extended OUT-OF-ORDER
   30 deny ip any any
   10 permit ip 10.0.0.0/8 any
   20 permit ip 172.16.0.0/12 any
`
	acls := ParseAccessLists(cfg)
	require.Len(t, acls, 1)
	require.Len(t, acls[0].Entries, 3)
	assert.Equal(t, 10, acls[0].Entries[0].SequenceNumber)
	assert.Equal(t, 20, acls[0].Entries[1].SequenceNumber)
	assert.Equal(t, 30, acls[0].Entries[2].SequenceNumber)
}

func TestParseAccessLists_BlockSettingsAreNotRules(t *testing.T) {
	// Block-level settings sit at the same indentation as the rules and must
	// not be mistaken for one.
	cfg := `ip access-list extended WITH-SETTINGS
   counters per-entry
   statistics per-entry
   10 permit ip any any
`
	acls := ParseAccessLists(cfg)
	require.Len(t, acls, 1)
	require.Len(t, acls[0].Entries, 1)
	assert.Equal(t, 10, acls[0].Entries[0].SequenceNumber)
}

func TestParseAccessLists_None(t *testing.T) {
	assert.Empty(t, ParseAccessLists("interface Ethernet1\n   description X\n"))
}

func TestParseAccessLists_TruncatedRuleDoesNotPanic(t *testing.T) {
	cfg := `ip access-list extended TRUNCATED
   10 permit
   20 permit tcp
   30 permit tcp any eq
`
	assert.NotPanics(t, func() {
		acls := ParseAccessLists(cfg)
		require.Len(t, acls, 1)
		assert.Len(t, acls[0].Entries, 3)
	})
}

func TestParseAclBindings_AllTargets(t *testing.T) {
	cfg := `!
interface Ethernet1
   description UPLINK
   ip access-group UPLINK-IN in
   ip access-group UPLINK-OUT out
!
interface Vlan100
   ipv6 access-group V6-MGMT in
!
management ssh
   ip access-group MGMT-ACCESS in
   no shutdown
!
management telnet
   ip access-group TELNET-ACL in
   shutdown
!
management api http-commands
   ip access-group API-ACL in
   no shutdown
!
control-plane
   ip access-group COPP-IN in
!
`
	bindings := ParseAclBindings(cfg)
	require.Len(t, bindings, 7)

	assert.Equal(t, AclBinding{
		Target: "interface", TargetName: "Ethernet1", Direction: "in",
		Family: "ipv4", AclName: "UPLINK-IN",
	}, bindings[0])
	assert.Equal(t, "out", bindings[1].Direction)
	assert.Equal(t, AclBinding{
		Target: "interface", TargetName: "Vlan100", Direction: "in",
		Family: "ipv6", AclName: "V6-MGMT",
	}, bindings[2])
	assert.Equal(t, "managementSsh", bindings[3].Target)
	assert.Empty(t, bindings[3].TargetName)
	assert.Equal(t, "managementTelnet", bindings[4].Target)
	assert.Equal(t, "managementApi", bindings[5].Target)
	assert.Equal(t, "controlPlane", bindings[6].Target)
}

func TestParseAclBindings_DirectionDefaultsToInbound(t *testing.T) {
	cfg := `management ssh
   ip access-group MGMT in
!
interface Ethernet1
   ip access-group NO-DIRECTION
`
	bindings := ParseAclBindings(cfg)
	require.Len(t, bindings, 2)
	assert.Equal(t, "in", bindings[1].Direction)
}

func TestParseAclBindings_NegatedLineIsNotABinding(t *testing.T) {
	cfg := `control-plane
   no ip access-group COPP-IN in
`
	assert.Empty(t, ParseAclBindings(cfg))
}

func TestParseAclBindings_None(t *testing.T) {
	assert.Empty(t, ParseAclBindings("interface Ethernet1\n   description X\n"))
}

// TestParseAclBindings_DirectionIsNotPositional covers the management-service
// form, where the direction is not the token straight after the list name.
// Reading a fixed position reported an outbound binding as inbound, which
// inverts what the ACL is understood to protect.
func TestParseAclBindings_DirectionIsNotPositional(t *testing.T) {
	bindings := ParseAclBindings(`management ssh
   ip access-group MGMT-ACL vrf MGMT out
!
`)
	require.Len(t, bindings, 1)
	assert.Equal(t, "out", bindings[0].Direction)
	assert.Equal(t, "MGMT", bindings[0].VRF)
	assert.Equal(t, "MGMT-ACL", bindings[0].AclName)
}

// TestParseAclBindings_VrfIsCaptured pins the instance qualifier. A list bound
// only in the management instance leaves the service unrestricted in every
// other instance, including the one carrying production traffic; dropping the
// qualifier reported that as a device-wide restriction.
func TestParseAclBindings_VrfIsCaptured(t *testing.T) {
	bindings := ParseAclBindings(`management ssh
   ip access-group MGMT-ACL vrf MGMT in
!
`)
	require.Len(t, bindings, 1)
	assert.Equal(t, "MGMT", bindings[0].VRF)
	assert.Equal(t, "in", bindings[0].Direction)
}

// TestParseAclBindings_UnqualifiedBindingHasNoVrf keeps the ordinary interface
// form reporting no instance rather than a made-up one.
func TestParseAclBindings_UnqualifiedBindingHasNoVrf(t *testing.T) {
	bindings := ParseAclBindings(`interface Ethernet1
   ip access-group EDGE-IN in
   ip access-group EDGE-OUT out
!
`)
	require.Len(t, bindings, 2)
	for _, b := range bindings {
		assert.Empty(t, b.VRF)
		assert.Equal(t, "interface", b.Target)
		assert.Equal(t, "Ethernet1", b.TargetName)
	}
	assert.Equal(t, "in", bindings[0].Direction)
	assert.Equal(t, "out", bindings[1].Direction)
}
