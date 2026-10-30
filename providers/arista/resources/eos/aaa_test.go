// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTacacsServers_Full(t *testing.T) {
	cfg := `!
tacacs-server host 10.0.0.1 key 7 042B0F1C
tacacs-server host 10.0.0.2 vrf MGMT port 4949 timeout 10 single-connection
tacacs-server host 10.0.0.3 key 0 plaintextsecret
!
`
	servers := ParseTacacsServers(cfg)
	require.Len(t, servers, 3)

	assert.Equal(t, "10.0.0.1", servers[0].Host)
	assert.Equal(t, 49, servers[0].Port)
	assert.True(t, servers[0].KeyConfigured)
	assert.Equal(t, "7", servers[0].KeyEncryptionType)
	assert.False(t, servers[0].SingleConnection)

	assert.Equal(t, "MGMT", servers[1].VRF)
	assert.Equal(t, 4949, servers[1].Port)
	assert.Equal(t, 10, servers[1].Timeout)
	assert.True(t, servers[1].SingleConnection)
	assert.False(t, servers[1].KeyConfigured)

	// Type 0 is the finding: the shared secret sits in the running-config in
	// the clear.
	assert.Equal(t, "0", servers[2].KeyEncryptionType)
}

func TestParseTacacsServers_GlobalDefaultsApply(t *testing.T) {
	// A host line that omits the key and timeout inherits the global setting,
	// so reporting only what is on the host line would call a keyed server
	// unkeyed.
	cfg := `tacacs-server key 7 042B0F1C
tacacs-server timeout 5
tacacs-server host 10.0.0.1
tacacs-server host 10.0.0.2 timeout 20 key 8a hashvalue
`
	servers := ParseTacacsServers(cfg)
	require.Len(t, servers, 2)

	assert.True(t, servers[0].KeyConfigured)
	assert.Equal(t, "7", servers[0].KeyEncryptionType)
	assert.Equal(t, 5, servers[0].Timeout)

	// A per-host setting wins over the global one.
	assert.Equal(t, 20, servers[1].Timeout)
	assert.Equal(t, "8a", servers[1].KeyEncryptionType)
}

func TestParseTacacsServers_KeyWithoutEncodingSelector(t *testing.T) {
	// Without an explicit selector the secret is stored in the clear.
	cfg := `tacacs-server host 10.0.0.1 key mysecret
`
	servers := ParseTacacsServers(cfg)
	require.Len(t, servers, 1)
	assert.True(t, servers[0].KeyConfigured)
	assert.Equal(t, "0", servers[0].KeyEncryptionType)
}

func TestParseTacacsServers_None(t *testing.T) {
	assert.Empty(t, ParseTacacsServers("aaa authentication login default local\n"))
}

func TestParseRadiusServers_Full(t *testing.T) {
	cfg := `radius-server host 10.0.0.5 key 7 042B0F1C
radius-server host 10.0.0.6 vrf MGMT auth-port 1645 acct-port 1646 timeout 8 retransmit 5
`
	servers := ParseRadiusServers(cfg)
	require.Len(t, servers, 2)

	assert.Equal(t, "10.0.0.5", servers[0].Host)
	assert.Equal(t, 1812, servers[0].AuthPort)
	assert.Equal(t, 1813, servers[0].AcctPort)
	assert.True(t, servers[0].KeyConfigured)
	assert.Equal(t, "7", servers[0].KeyEncryptionType)

	assert.Equal(t, "MGMT", servers[1].VRF)
	assert.Equal(t, 1645, servers[1].AuthPort)
	assert.Equal(t, 1646, servers[1].AcctPort)
	assert.Equal(t, 8, servers[1].Timeout)
	assert.Equal(t, 5, servers[1].Retransmit)
	assert.False(t, servers[1].KeyConfigured)
}

func TestParseRadiusServers_GlobalKeyApplies(t *testing.T) {
	cfg := `radius-server key 0 sharedsecret
radius-server host 10.0.0.5
`
	servers := ParseRadiusServers(cfg)
	require.Len(t, servers, 1)
	assert.True(t, servers[0].KeyConfigured)
	assert.Equal(t, "0", servers[0].KeyEncryptionType)
}

func TestParseAaaServerGroups(t *testing.T) {
	cfg := `!
aaa group server tacacs+ TACACS-GROUP
   server 192.168.100.200
   server 192.168.100.201 vrf MGMT
!
aaa group server radius RADIUS-GROUP
   server 10.0.0.5
!
aaa authentication login default group TACACS-GROUP local
`
	groups := ParseAaaServerGroups(cfg)
	require.Len(t, groups, 2)

	assert.Equal(t, "TACACS-GROUP", groups[0].Name)
	assert.Equal(t, "tacacs+", groups[0].Protocol)
	assert.Equal(t, []string{"192.168.100.200", "192.168.100.201"}, groups[0].Servers)

	assert.Equal(t, "RADIUS-GROUP", groups[1].Name)
	assert.Equal(t, "radius", groups[1].Protocol)
	assert.Equal(t, []string{"10.0.0.5"}, groups[1].Servers)
}

func TestParseAaaServerGroups_EmptyGroup(t *testing.T) {
	// A group with no members is worth surfacing: method lists pointing at it
	// authenticate against nothing.
	cfg := `aaa group server tacacs+ EMPTY-GROUP
tacacs-server host 10.0.0.1
`
	groups := ParseAaaServerGroups(cfg)
	require.Len(t, groups, 1)
	assert.Equal(t, "EMPTY-GROUP", groups[0].Name)
	assert.Empty(t, groups[0].Servers)
}

func TestParseAaaServerGroups_IndentedServerOutsideGroupIgnored(t *testing.T) {
	// `server ...` appears inside other blocks (NTP, management api). Only
	// lines nested under a group header are members.
	cfg := `router bgp 65001
   server 1.2.3.4
aaa group server radius R1
   server 10.0.0.5
`
	groups := ParseAaaServerGroups(cfg)
	require.Len(t, groups, 1)
	assert.Equal(t, []string{"10.0.0.5"}, groups[0].Servers)
}

func TestParseRootAccount_Disabled(t *testing.T) {
	// Absent `aaa root` is the shipped default: the account is disabled.
	state := ParseRootAccount("aaa authentication login default local\n")
	assert.False(t, state.Enabled)
	assert.False(t, state.NoPassword)
	assert.Empty(t, state.SecretFormat)
}

func TestParseRootAccount_Secret(t *testing.T) {
	state := ParseRootAccount("aaa root secret sha512 $6$salt$hash\n")
	assert.True(t, state.Enabled)
	assert.False(t, state.NoPassword)
	assert.Equal(t, "sha512", state.SecretFormat)
}

func TestParseRootAccount_NoPassword(t *testing.T) {
	// Root reachable with no password at all.
	state := ParseRootAccount("aaa root nopassword\n")
	assert.True(t, state.Enabled)
	assert.True(t, state.NoPassword)
	assert.Empty(t, state.SecretFormat)
}

func TestParseRootAccount_ExplicitlyDisabledAfterSecret(t *testing.T) {
	cfg := `aaa root secret 5 $1$salt$hash
no aaa root
`
	state := ParseRootAccount(cfg)
	assert.False(t, state.Enabled)
	assert.Empty(t, state.SecretFormat)
}

func TestParseAaaConfig_ConsoleAuthorization(t *testing.T) {
	// Console command authorization is configured separately from the remote
	// method list, so a device can authorize SSH commands and leave the
	// console unauthorized.
	cfg := `aaa authorization commands all default group tacacs+ local
aaa authorization console commands all default local
aaa authorization serial-console
`
	a := ParseAaaConfig(cfg)
	assert.Equal(t, []string{"group", "tacacs+", "local"}, a.AuthorizationCommands["all/default"])
	assert.Equal(t, []string{"local"}, a.AuthorizationConsoleCommands["all/default"])
	assert.True(t, a.SerialConsoleAuthorization)
}

func TestParseAaaConfig_ConsoleAuthorizationAbsent(t *testing.T) {
	a := ParseAaaConfig("aaa authorization commands all default group tacacs+\n")
	assert.Empty(t, a.AuthorizationConsoleCommands)
	assert.False(t, a.SerialConsoleAuthorization)
}

// TestParseRootAccount_BareFormIsCleartextAndHidesThePassword pins the closed
// selector set. The selector is optional on `aaa root secret`, so reading the
// first token positionally as the format published the root account's password
// in arista.eos.aaa.rootSecretFormat, a field every consumer reads as safe
// metadata. The sibling `enable secret` line has had this guard from the start.
func TestParseRootAccount_BareFormIsCleartextAndHidesThePassword(t *testing.T) {
	const password = "ExamplePassphraseValue"
	got := ParseRootAccount("aaa root secret " + password + "\n")
	assert.True(t, got.Enabled)
	assert.False(t, got.NoPassword)
	assert.Equal(t, "0", got.SecretFormat)
	assert.NotContains(t, got.SecretFormat, password)
}

func TestParseRootAccount_NeverCarriesTheHash(t *testing.T) {
	const hash = "$6$Zx1ExampleSalt$ExampleHashValueOnly"
	got := ParseRootAccount("aaa root secret sha512 " + hash + "\n")
	assert.True(t, got.Enabled)
	assert.Equal(t, "sha512", got.SecretFormat)
	assert.NotContains(t, got.SecretFormat, hash)
}

// TestPasswordSecretSelectors covers every selector EOS accepts on a password
// secret. Type 7 was missing from the set, so a reversibly-obfuscated secret
// and a genuinely cleartext one were both reported as "0" and a check for
// "the enable password must not be stored in cleartext" failed on a device
// that does not store it in cleartext.
func TestPasswordSecretSelectors(t *testing.T) {
	for _, selector := range []string{"0", "5", "7", "sha512"} {
		t.Run("root "+selector, func(t *testing.T) {
			got := ParseRootAccount("aaa root secret " + selector + " SecretValue\n")
			assert.Equal(t, selector, got.SecretFormat)
		})
		t.Run("enable "+selector, func(t *testing.T) {
			got := ParseEnableSecret("enable secret " + selector + " SecretValue\n")
			assert.True(t, got.Configured)
			assert.Equal(t, selector, got.Format)
		})
	}
}
