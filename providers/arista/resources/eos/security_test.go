// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAaaConfig_TacacsThenLocal(t *testing.T) {
	cfg := `!
aaa authentication login default group tacacs+ local
aaa authentication enable default group tacacs+
aaa authorization commands all default group tacacs+ local
aaa authorization exec default group tacacs+ none
aaa accounting commands all default start-stop group tacacs+
aaa accounting exec default start-stop group tacacs+
tacacs-server host 10.0.0.1
tacacs-server host 10.0.0.2
radius-server host 10.0.0.5
!
`
	a := ParseAaaConfig(cfg)
	assert.Equal(t, []string{"group", "tacacs+", "local"}, a.AuthenticationLogin["default"])
	assert.Equal(t, []string{"group", "tacacs+"}, a.AuthenticationEnable["default"])
	assert.Equal(t, []string{"group", "tacacs+", "local"}, a.AuthorizationCommands["all/default"])
	assert.Equal(t, []string{"group", "tacacs+", "none"}, a.AuthorizationExec["default"])
	assert.Equal(t, []string{"group", "tacacs+"}, a.AccountingCommands["all/default"])
	assert.Equal(t, []string{"group", "tacacs+"}, a.AccountingExec["default"])
	// Local is a fallback after group, not the only option.
	assert.False(t, a.DefaultLoginPermitsLocalOnly)
}

func TestParseAaaConfig_LocalOnly(t *testing.T) {
	cfg := `aaa authentication login default local
`
	a := ParseAaaConfig(cfg)
	assert.True(t, a.DefaultLoginPermitsLocalOnly)
}

func TestParseAaaConfig_LocalBeforeGroup(t *testing.T) {
	// "local" precedes "group", so local authenticates without a working
	// remote source (the worse hardening posture). Order matters: presence of
	// a group token alone must not clear the flag.
	cfg := `aaa authentication login default local group tacacs+
`
	a := ParseAaaConfig(cfg)
	assert.Equal(t, []string{"local", "group", "tacacs+"}, a.AuthenticationLogin["default"])
	assert.True(t, a.DefaultLoginPermitsLocalOnly)
}

func TestParseAaaConfig_NoConfig(t *testing.T) {
	a := ParseAaaConfig("")
	assert.Empty(t, a.AuthenticationLogin)
	assert.False(t, a.DefaultLoginPermitsLocalOnly)
}

func TestParseAaaConfig_AccountingNone(t *testing.T) {
	// `none` is a valid action with no methods following it.
	cfg := `aaa accounting commands all default none
aaa accounting exec default none
`
	a := ParseAaaConfig(cfg)
	cmds, ok := a.AccountingCommands["all/default"]
	assert.True(t, ok, "accounting commands list should be recorded even with action=none")
	assert.Empty(t, cmds)
	exec, ok := a.AccountingExec["default"]
	assert.True(t, ok, "accounting exec list should be recorded even with action=none")
	assert.Empty(t, exec)
}

func TestParseSshSettings_Full(t *testing.T) {
	cfg := `! comment
management ssh
   ip access-group MGMT in
   idle-timeout 30
   server-port 22
   no shutdown
   authentication mode keyboard-interactive
   protocol version 2
   cipher aes256-gcm@openssh.com aes256-ctr
   key-exchange curve25519-sha256 ecdh-sha2-nistp521
   mac hmac-sha2-512-etm@openssh.com
   hostkey rsa key-size 4096
   fips restrictions
!
end
`
	s := ParseSshSettings(cfg)
	assert.True(t, s.Enabled)
	assert.Equal(t, "2", s.ProtocolVersion)
	assert.Equal(t, 30, s.IdleTimeout)
	assert.Equal(t, 22, s.ServerPort)
	assert.Equal(t, "keyboard-interactive", s.AuthenticationMode)
	assert.Equal(t, []string{"aes256-gcm@openssh.com", "aes256-ctr"}, s.Ciphers)
	assert.Equal(t, []string{"curve25519-sha256", "ecdh-sha2-nistp521"}, s.KeyExchange)
	assert.Equal(t, []string{"hmac-sha2-512-etm@openssh.com"}, s.Macs)
	assert.Contains(t, s.HostkeyAlgorithms, "rsa key-size 4096")
	assert.True(t, s.FipsRestrictions)
}

func TestParseSshSettings_Shutdown(t *testing.T) {
	cfg := `management ssh
   shutdown
!
`
	s := ParseSshSettings(cfg)
	assert.False(t, s.Enabled)
}

func TestParseSshSettings_AbsentDefaultsEnabled(t *testing.T) {
	s := ParseSshSettings("hostname switch1\n")
	// SSH is enabled by default on EOS even without an explicit block
	assert.True(t, s.Enabled)
	assert.Empty(t, s.Ciphers)
}

func TestParseSnmpCommunities(t *testing.T) {
	cfg := `snmp-server community public ro
snmp-server community ops ro IPV4-MGMT
snmp-server community admin rw
snmp-server community readonly
snmp-server community viewed view restricted ro IPV4-MGMT
snmp-server community v6only ro ipv6 IPV6-MGMT
snmp-server engineID local 800000110300010203040506
`
	cs := ParseSnmpCommunities(cfg)
	assert.Len(t, cs, 6)

	byName := map[string]SnmpCommunity{}
	for _, c := range cs {
		byName[c.Name] = c
	}
	assert.Equal(t, "ro", byName["public"].Access)
	assert.Equal(t, "", byName["public"].ACL)
	assert.False(t, byName["public"].IPv6)
	assert.Equal(t, "ro", byName["ops"].Access)
	assert.Equal(t, "IPV4-MGMT", byName["ops"].ACL)
	assert.False(t, byName["ops"].IPv6)
	assert.Equal(t, "rw", byName["admin"].Access)
	assert.Equal(t, "ro", byName["readonly"].Access)
	// view <view-name> clause shouldn't be captured as access mode or ACL
	assert.Equal(t, "ro", byName["viewed"].Access)
	assert.Equal(t, "IPV4-MGMT", byName["viewed"].ACL)
	assert.False(t, byName["viewed"].IPv6)
	// ipv6 keyword should set IPv6=true and the trailing token is the ACL
	assert.Equal(t, "ro", byName["v6only"].Access)
	assert.Equal(t, "IPV6-MGMT", byName["v6only"].ACL)
	assert.True(t, byName["v6only"].IPv6)
}

func TestParseTelnetService_Shutdown(t *testing.T) {
	cfg := `management telnet
   shutdown
   idle-timeout 0
   session-limit 20
   session-limit per-host 20
!
`
	t1 := ParseTelnetService(cfg)
	assert.True(t, t1.Configured)
	assert.False(t, t1.Enabled)
	assert.Equal(t, 0, t1.IdleTimeout)
	assert.Equal(t, 20, t1.SessionLimit)
	assert.Equal(t, 20, t1.PerHostLimit)
}

func TestParseTelnetService_NoShutdown(t *testing.T) {
	cfg := `management telnet
   no shutdown
   ip access-group MGMT in
!
`
	t1 := ParseTelnetService(cfg)
	assert.True(t, t1.Configured)
	assert.True(t, t1.Enabled)
	assert.Equal(t, "MGMT", t1.IPAccessGroup)
}

func TestParseTelnetService_Absent(t *testing.T) {
	t1 := ParseTelnetService("hostname sw\n")
	assert.False(t, t1.Configured)
	assert.False(t, t1.Enabled)
}

func TestParsePasswordPolicy_Full(t *testing.T) {
	cfg := `aaa authentication policy lockout failure 5 window 60 duration 300
aaa authentication policy on-failure log
aaa authentication policy on-success log
aaa authentication policy local allow-nopassword-remote-login
password policy strict
   minimum length 12
   minimum digits 1
   minimum upper 1
   minimum lower 1
   minimum special 1
   maximum repetitive 2
   maximum sequential 3
!
`
	p := ParsePasswordPolicy(cfg)
	assert.Equal(t, 5, p.LockoutFailure)
	assert.Equal(t, 60, p.LockoutWindowSeconds)
	assert.Equal(t, 300, p.LockoutDurationSeconds)
	assert.True(t, p.AllowNopasswordRemoteLogin)
	assert.True(t, p.LogOnFailure)
	assert.True(t, p.LogOnSuccess)
	assert.Equal(t, "strict", p.PolicyName)
	assert.Equal(t, 12, p.MinimumLength)
	assert.Equal(t, 1, p.MinimumDigits)
	assert.Equal(t, 1, p.MinimumUppercase)
	assert.Equal(t, 1, p.MinimumLowercase)
	assert.Equal(t, 1, p.MinimumSpecial)
	assert.Equal(t, 2, p.MaximumRepetitive)
	assert.Equal(t, 3, p.MaximumSequential)
}

func TestParsePasswordPolicy_Empty(t *testing.T) {
	p := ParsePasswordPolicy("hostname sw\n")
	assert.Equal(t, 0, p.LockoutFailure)
	assert.Equal(t, "", p.PolicyName)
	assert.False(t, p.AllowNopasswordRemoteLogin)
	assert.Equal(t, 0, p.MinimumLength)
}

func TestParsePasswordPolicy_LockoutOrderIndependent(t *testing.T) {
	// EOS does not enforce token order on lockout clauses.
	cfg := `aaa authentication policy lockout duration 300 window 60 failure 5
`
	p := ParsePasswordPolicy(cfg)
	assert.Equal(t, 5, p.LockoutFailure)
	assert.Equal(t, 60, p.LockoutWindowSeconds)
	assert.Equal(t, 300, p.LockoutDurationSeconds)
}

func TestParsePasswordPolicy_PrefersDefaultPolicy(t *testing.T) {
	// When multiple `password policy <name>` blocks exist we prefer one
	// named "default" over the first declared.
	cfg := `password policy strict
   minimum length 16
!
password policy default
   minimum length 12
!
`
	p := ParsePasswordPolicy(cfg)
	assert.Equal(t, "default", p.PolicyName)
	assert.Equal(t, 12, p.MinimumLength)
}

func TestParsePasswordPolicy_MultipleNonDefaultFallsBackToFirst(t *testing.T) {
	cfg := `password policy strict
   minimum length 16
!
password policy lax
   minimum length 8
!
`
	p := ParsePasswordPolicy(cfg)
	assert.Equal(t, "strict", p.PolicyName)
	assert.Equal(t, 16, p.MinimumLength)
}

func TestParseNtpAuth(t *testing.T) {
	cfg := `ntp authenticate
ntp authentication-key 1 sha1 7 abc123
ntp authentication-key 2 md5 7 def456
ntp authentication-key 3 sha256 7 ghi789
ntp trusted-key 1 3
`
	state := ParseNtpAuth(cfg)
	assert.True(t, state.AuthenticationEnabled)
	assert.Len(t, state.Keys, 3)
	assert.Equal(t, []int{1, 3}, state.TrustedKeyIDs)

	byID := map[int]NtpAuthKey{}
	for _, k := range state.Keys {
		byID[k.ID] = k
	}
	assert.Equal(t, "sha1", byID[1].HashAlgo)
	assert.True(t, byID[1].Trusted)
	assert.Equal(t, "md5", byID[2].HashAlgo)
	assert.False(t, byID[2].Trusted)
	assert.Equal(t, "sha256", byID[3].HashAlgo)
	assert.True(t, byID[3].Trusted)
}

func TestParseNtpAuth_Disabled(t *testing.T) {
	state := ParseNtpAuth("ntp server 1.2.3.4\n")
	assert.False(t, state.AuthenticationEnabled)
	assert.Empty(t, state.Keys)
	assert.Empty(t, state.TrustedKeyIDs)
}

func TestParseControlPlanePolicer_Configured(t *testing.T) {
	cfg := `control-plane
   ip access-group COPP-IN in
   ipv6 access-group COPP6-IN in
   service-policy input copp-system-policy
!
`
	c := ParseControlPlanePolicer(cfg)
	assert.True(t, c.Configured)
	assert.True(t, c.PolicyApplied)
	assert.Equal(t, "copp-system-policy", c.PolicyName)
	assert.Equal(t, "COPP-IN", c.IPAccessGroup)
	assert.Equal(t, "COPP6-IN", c.IP6AccessGroup)
}

func TestParseControlPlanePolicer_Absent(t *testing.T) {
	c := ParseControlPlanePolicer("hostname sw\n")
	assert.False(t, c.Configured)
	assert.False(t, c.PolicyApplied)
}

func TestParseControlPlanePolicer_NoPolicy(t *testing.T) {
	cfg := `control-plane
   no service-policy input copp-system-policy
!
`
	c := ParseControlPlanePolicer(cfg)
	assert.True(t, c.Configured)
	assert.False(t, c.PolicyApplied)
	assert.Empty(t, c.PolicyName)
}

func TestParseControlPlanePolicer_NoPolicyAfterApplied(t *testing.T) {
	// A `no service-policy input` line must override an earlier
	// `service-policy input` line in the same block.
	cfg := `control-plane
   service-policy input copp-system-policy
   no service-policy input copp-system-policy
!
`
	c := ParseControlPlanePolicer(cfg)
	assert.True(t, c.Configured)
	assert.False(t, c.PolicyApplied)
	assert.Empty(t, c.PolicyName)
}

func TestParsePortSecurity(t *testing.T) {
	cfg := `interface Ethernet1
   switchport mode access
   switchport port-security
   switchport port-security maximum 2
   switchport port-security violation restrict
   switchport port-security mac-address sticky
!
interface Ethernet2
   switchport mode trunk
!
interface Ethernet3
   switchport port-security
   switchport port-security violation shutdown
!
end
`
	ports := ParsePortSecurity(cfg)
	assert.Len(t, ports, 2)

	byIface := map[string]PortSecurityConfig{}
	for _, p := range ports {
		byIface[p.Interface] = p
	}

	e1 := byIface["Ethernet1"]
	assert.True(t, e1.Enabled)
	assert.Equal(t, 2, e1.MaximumMacAddresses)
	assert.Equal(t, "restrict", e1.ViolationAction)
	assert.True(t, e1.StickyLearning)

	e3 := byIface["Ethernet3"]
	assert.True(t, e3.Enabled)
	assert.Equal(t, 0, e3.MaximumMacAddresses)
	assert.Equal(t, "shutdown", e3.ViolationAction)
	assert.False(t, e3.StickyLearning)

	_, ok := byIface["Ethernet2"]
	assert.False(t, ok, "Ethernet2 has no port-security; should be excluded")
}

func TestGetSection_StopsAtNextSection(t *testing.T) {
	cfg := `management ssh
   no shutdown
   protocol version 2
!
management telnet
   shutdown
!
`
	body := GetSection(strings.NewReader(cfg), "management ssh")
	assert.Contains(t, body, "no shutdown")
	assert.Contains(t, body, "protocol version 2")
	assert.NotContains(t, body, "telnet")
}
