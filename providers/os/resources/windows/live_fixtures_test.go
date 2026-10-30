// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures exercised here were captured from live Windows Server hosts by
// running the provider's own command constants, so they are the exact bytes
// the parsers see in the field rather than a hand-written approximation of
// them. Hostnames are replaced with a synthetic name; nothing else is altered.
//
// Server 2016, 2019, 2022 and 2025 are all covered.
var liveWindowsVersions = []string{"2016", "2019", "2022", "2025"}

// liveFirewallRuleNames is the set of rules captured on every host. They are
// chosen for the decode shapes they carry rather than for their own sake: a
// well-known-name protocol and a bare numeric one, an ICMP rule whose type is
// a number, a rule with a distinct remote port, a multi-valued address that
// PowerShell wraps in {"value":[...],"Count":n}, and a disabled rule.
var liveFirewallRuleNames = []string{
	"NETDIS-LLMNR-In-UDP",
	"WINRM-HTTP-In-TCP",
	"RemoteDesktop-UserMode-In-TCP",
	"RRAS-GRE-In",
	"CoreNet-ICMP6-RS-Out",
	"CoreNet-IGMP-Out",
	"CoreNet-DHCP-Out",
	"FPS-ICMP4-ERQ-In",
}

// The Remote Desktop inbound rule is not scoped the same way on every host.
// 2016 through 2022 scope it to Domain and Private; the 2025 host captured also
// carries Public. Both are real readings, and pinning a single value would turn
// a genuine difference between hosts into a test failure.
var rdpProfilesByVersion = map[string]PSFlagList{
	"2016": {"Domain", "Private"},
	"2019": {"Domain", "Private"},
	"2022": {"Domain", "Private"},
	"2025": {"Domain", "Private", "Public"},
}

func openFixture(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open("./testdata/" + name)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

// The rule list arrives in a different order on each Windows version, so every
// assertion here keys on InstanceID. A test that indexed into the slice would
// pass on one version and fail on the next for no reason worth reporting.
func rulesByID(rules []WindowsFirewallRule) map[string]WindowsFirewallRule {
	res := make(map[string]WindowsFirewallRule, len(rules))
	for _, r := range rules {
		res[r.InstanceID] = r
	}
	return res
}

func TestLiveFirewallRules(t *testing.T) {
	for _, version := range liveWindowsVersions {
		t.Run(version, func(t *testing.T) {
			rules, err := ParseWindowsFirewallRules(openFixture(t, "firewall-rules-"+version+".json"))
			require.NoError(t, err)
			require.Len(t, rules, len(liveFirewallRuleNames))

			byID := rulesByID(rules)
			for _, name := range liveFirewallRuleNames {
				require.Contains(t, byID, name)
			}

			// Enabled and Direction are CIM enums that arrive as numbers: 1 is
			// enabled and 2 is disabled, 1 is inbound and 2 is outbound. They
			// are asserted against a rule known to be in each state so a decode
			// that silently zeroed them could not pass.
			rdp := byID["RemoteDesktop-UserMode-In-TCP"]
			assert.Equal(t, int64(1), rdp.Enabled)
			assert.Equal(t, int64(1), rdp.Direction)
			assert.Equal(t, int64(2), rdp.Action)
			assert.Equal(t, rdpProfilesByVersion[version], rdp.Profiles)

			dhcp := byID["CoreNet-DHCP-Out"]
			assert.Equal(t, int64(1), dhcp.Enabled)
			assert.Equal(t, int64(2), dhcp.Direction, "CoreNet-DHCP-Out is an outbound rule")

			// A disabled rule. Enabled is 2, not 0: a parser that mapped the
			// enum onto a bool would report this rule as enabled.
			assert.Equal(t, int64(2), byID["FPS-ICMP4-ERQ-In"].Enabled)

			// Every stock rule is in the persistent store. PolicyStoreSourceType
			// 1 is Local.
			for _, r := range rules {
				assert.Equal(t, "PersistentStore", r.PolicyStoreSource, r.InstanceID)
				assert.Equal(t, int64(1), r.PolicyStoreSourceType, r.InstanceID)
			}
		})
	}
}

// The Profile flags enum reaches the parser as the string PowerShell rendered
// it to. A rule scoped to two profiles must split into both, or a policy
// matching on "Public" silently misses a rule that carries it alongside
// another flag.
func TestLiveFirewallRuleProfileFlagsSplit(t *testing.T) {
	for _, version := range liveWindowsVersions {
		t.Run(version, func(t *testing.T) {
			rules, err := ParseWindowsFirewallRules(openFixture(t, "firewall-rules-"+version+".json"))
			require.NoError(t, err)
			byID := rulesByID(rules)

			assert.Equal(t, PSFlagList{"Domain", "Private"}, byID["WINRM-HTTP-In-TCP"].Profiles)
			assert.Equal(t, PSFlagList{"Any"}, byID["CoreNet-IGMP-Out"].Profiles)

			// The Remote Desktop rule is the one that moved: the 2025 host
			// captured scopes it to all three profiles, so the split has to
			// produce three flags there and two everywhere else. A test that
			// pinned one value would have read the drift as a decode failure.
			assert.Equal(t, rdpProfilesByVersion[version], byID["RemoteDesktop-UserMode-In-TCP"].Profiles)
		})
	}
}

func TestLiveFirewallRuleFilters(t *testing.T) {
	for _, version := range liveWindowsVersions {
		t.Run(version, func(t *testing.T) {
			filters, err := ParseWindowsFirewallRuleFilters(openFixture(t, "firewall-rule-filters-"+version+".json"))
			require.NoError(t, err)

			// Every captured rule joins to all six filter collections. This is
			// the shape a healthy host returns: the NetSecurity module keeps one
			// filter object of each kind per rule.
			for _, name := range liveFirewallRuleNames {
				f := filters[name]
				require.NotNil(t, f, "no filters joined for %s", name)
				assert.NotNil(t, f.Port, "%s port filter", name)
				assert.NotNil(t, f.Address, "%s address filter", name)
				assert.NotNil(t, f.Application, "%s application filter", name)
				assert.NotNil(t, f.Service, "%s service filter", name)
				assert.NotNil(t, f.InterfaceType, "%s interface type filter", name)
				assert.NotNil(t, f.Security, "%s security filter", name)
			}

			// A protocol with a well-known name.
			rdp := filters["RemoteDesktop-UserMode-In-TCP"]
			assert.Equal(t, PSFlexString("TCP"), rdp.Port.Protocol)
			assert.Equal(t, PSStringArray{"3389"}, rdp.Port.LocalPort)
			assert.Equal(t, PSFlexString("termservice"), rdp.Service.Service)

			// A protocol with no well-known name arrives as a bare JSON number.
			// It has to keep its literal text: a plain string tag fails the
			// decode of the whole payload, and reporting "" would state that the
			// rule matches no protocol.
			assert.Equal(t, PSFlexString("47"), filters["RRAS-GRE-In"].Port.Protocol)
			assert.Equal(t, PSFlexString("2"), filters["CoreNet-IGMP-Out"].Port.Protocol)

			// An ICMP rule carries its type as a number, and its LocalPort is
			// the string "RPC" rather than a port.
			icmp4 := filters["FPS-ICMP4-ERQ-In"]
			assert.Equal(t, PSFlexString("ICMPv4"), icmp4.Port.Protocol)
			assert.Equal(t, PSStringArray{"8"}, icmp4.Port.IcmpType)
			assert.Equal(t, PSStringArray{"RPC"}, icmp4.Port.LocalPort)

			icmp6 := filters["CoreNet-ICMP6-RS-Out"]
			assert.Equal(t, PSFlexString("ICMPv6"), icmp6.Port.Protocol)
			assert.Equal(t, PSStringArray{"133"}, icmp6.Port.IcmpType)

			// A multi-valued address arrives wrapped as {"value":[...],"Count":n}
			// rather than as a JSON array. A plain []string tag decodes that to
			// empty and reports the rule as scoped to nothing.
			assert.Equal(t,
				PSStringArray{"LocalSubnet6", "ff02::2", "fe80::/64"},
				icmp6.Address.RemoteAddress)

			// A single-valued address is a bare string, not a one-element array.
			assert.Equal(t, PSStringArray{"LocalSubnet"}, filters["NETDIS-LLMNR-In-UDP"].Address.RemoteAddress)

			// Distinct local and remote ports on the same rule.
			dhcp := filters["CoreNet-DHCP-Out"]
			assert.Equal(t, PSStringArray{"68"}, dhcp.Port.LocalPort)
			assert.Equal(t, PSStringArray{"67"}, dhcp.Port.RemotePort)
			assert.Equal(t, PSFlexString("dhcp"), dhcp.Service.Service)

			// An unscoped condition is the string "Any", which is a fact about
			// the rule and must not be confused with an absent filter.
			assert.Equal(t, PSFlexString("Any"), rdp.Security.RemoteUser)
			assert.Equal(t, PSFlexString("Any"), rdp.Security.RemoteMachine)
			assert.Equal(t, PSFlagList{"Any"}, rdp.InterfaceType.InterfaceType)
		})
	}
}

// The program a rule is scoped to differs between Windows versions for the
// same rule: 2016 through 2022 report an expanded path for Remote Desktop and
// an unexpanded one for DHCP. Both are real values and neither is empty.
func TestLiveFirewallRuleApplicationFilter(t *testing.T) {
	for _, version := range liveWindowsVersions {
		t.Run(version, func(t *testing.T) {
			filters, err := ParseWindowsFirewallRuleFilters(openFixture(t, "firewall-rule-filters-"+version+".json"))
			require.NoError(t, err)

			for _, name := range liveFirewallRuleNames {
				assert.NotEmpty(t, filters[name].Application.Program,
					"%s reported an empty program, which would read as scoped to no executable", name)
			}

			assert.Equal(t, PSFlexString("System"), filters["WINRM-HTTP-In-TCP"].Application.Program)
		})
	}
}

func TestLiveFirewallProfiles(t *testing.T) {
	for _, version := range liveWindowsVersions {
		t.Run(version, func(t *testing.T) {
			profiles, err := ParseWindowsFirewallProfiles(openFixture(t, "firewall-profiles-"+version+".json"))
			require.NoError(t, err)
			require.Len(t, profiles, 3, "Windows always reports Domain, Private and Public")

			byName := map[string]WindowsFirewallProfile{}
			for _, p := range profiles {
				byName[p.Name] = p
			}
			require.Contains(t, byName, "Domain")
			require.Contains(t, byName, "Private")
			require.Contains(t, byName, "Public")

			for name, p := range byName {
				// 1 is enabled. The firewall is on for every profile on a stock
				// Windows Server install.
				assert.Equal(t, int64(1), p.Enabled, "%s profile enabled", name)

				// 0 is NotConfigured, and it is what a stock host really
				// reports for both default actions. It does NOT mean the
				// firewall has no default: netsh on the same hosts reports the
				// effective policy as BlockInbound,AllowOutbound. The value is
				// the configured GPO-level action, and when it is unset the
				// firewall's own built-in default applies instead. Asserting
				// Block (4) here would encode a value no default host returns.
				assert.Equal(t, int64(0), p.DefaultInboundAction, "%s default inbound action", name)
				assert.Equal(t, int64(0), p.DefaultOutboundAction, "%s default outbound action", name)

				assert.NotEmpty(t, p.LogFileName, "%s log file name", name)
				assert.NotEmpty(t, p.InstanceID, "%s instance id", name)
			}
		})
	}
}

func TestLiveFirewallSettings(t *testing.T) {
	for _, version := range liveWindowsVersions {
		t.Run(version, func(t *testing.T) {
			settings, err := ParseWindowsFirewallSettings(openFixture(t, "firewall-settings-"+version+".json"))
			require.NoError(t, err)
			// 65535 is the "all profiles" sentinel the setting object carries.
			assert.Equal(t, int64(65535), settings.ActiveProfile)
			assert.NotEmpty(t, settings.InstanceID)
		})
	}
}

// The share list is byte-identical on 2016, 2019, 2022 and 2025, so one fixture
// covers them all. It is the stock set of administrative shares.
func TestLiveSmbShares(t *testing.T) {
	shares, err := ParseWindowsSmbShares(openFixture(t, "smb-shares.json"))
	require.NoError(t, err)
	require.Len(t, shares, 3)

	byName := map[string]WindowsSmbShare{}
	for _, s := range shares {
		byName[s.Name] = s
	}

	require.Contains(t, byName, "ADMIN$")
	require.Contains(t, byName, "C$")
	require.Contains(t, byName, "IPC$")

	assert.Equal(t, "C:\\", byName["C$"].Path)
	assert.Equal(t, "FileSystemDirectory", byName["C$"].ShareType)
	assert.Equal(t, "*", byName["C$"].ScopeName)

	// IPC$ is not a directory share and has no path. ShareType is forced to its
	// enum label on the host; a numeric value here would mean the calculated
	// property stopped working.
	assert.Equal(t, "InterprocessCommunication", byName["IPC$"].ShareType)
	assert.Empty(t, byName["IPC$"].Path)
}

func TestLiveWinRMListeners(t *testing.T) {
	listeners, err := ParseWinRMListeners(openFixture(t, "winrm-listeners.json"))
	require.NoError(t, err)
	require.Len(t, listeners, 1, "a stock host carries exactly one HTTP listener")

	l := listeners[0]
	assert.Equal(t, PSScalar("*"), l.Address)
	assert.Equal(t, PSScalar("HTTP"), l.Transport)
	assert.Equal(t, int64(5985), l.PortNumber())
	assert.True(t, l.IsEnabled())
	assert.Empty(t, l.CertificateThumbprint, "an HTTP listener carries no certificate")
	assert.Equal(t, "windows.winrm.listener/*+HTTP", l.ID())
}

func TestLiveWinRMConfig(t *testing.T) {
	config, err := ParseWinRMConfig(openFixture(t, "winrm-config.json"))
	require.NoError(t, err)

	// TrustedHosts is unset on a stock host. Empty here means "no host is
	// trusted", which is the secure state and a real reading, not a failure.
	assert.Empty(t, config.Client.TrustedHosts)

	// The address filters default to "*". Reporting "" would read as a filter
	// that admits nothing, which is the opposite of what "*" means.
	assert.Equal(t, PSScalar("*"), config.Service.IPv4Filter)
	assert.Equal(t, PSScalar("*"), config.Service.IPv6Filter)
}
