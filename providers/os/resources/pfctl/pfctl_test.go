// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pfctl

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The freebsd14_* fixtures were captured as root on a FreeBSD 14.5-RELEASE
// EC2 instance after loading a test ruleset. The host's private address in
// the rules fixture was replaced with 192.0.2.15.

func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return string(data)
}

func TestParseInfo(t *testing.T) {
	enabled, err := ParseInfo(readFixture(t, "freebsd14_info_enabled.txt"))
	require.NoError(t, err)
	assert.True(t, enabled)

	enabled, err = ParseInfo(readFixture(t, "freebsd14_info_disabled.txt"))
	require.NoError(t, err)
	assert.False(t, enabled)

	_, err = ParseInfo("")
	assert.Error(t, err)

	_, err = ParseInfo("Status: Unknown for 0 days")
	assert.Error(t, err)
}

func TestParseRulesFreeBSD(t *testing.T) {
	services := Services{"ssh/tcp": "22", "domain/udp": "53", "http/tcp": "80", "https/tcp": "443"}
	rules := ParseRules(readFixture(t, "freebsd14_rules.txt"), services)
	require.Len(t, rules, 17)

	assert.Equal(t, Rule{
		Raw:    "scrub in all fragment reassemble",
		Action: "scrub", Direction: "in", From: "any", To: "any",
	}, rules[0])

	assert.Equal(t, Rule{
		Raw:    "block return log all",
		Action: "block", BlockPolicy: "return", Log: true, From: "any", To: "any",
	}, rules[1])

	assert.Equal(t, Rule{
		Raw:    "block drop in quick from <bruteforce> to any",
		Action: "block", BlockPolicy: "drop", Direction: "in", Quick: true,
		From: "<bruteforce>", To: "any",
	}, rules[2])

	assert.Equal(t, Rule{
		Raw:    `pass in quick on ena0 inet proto tcp from any to any port = ssh flags S/SA keep state (if-bound) label "ssh"`,
		Action: "pass", Direction: "in", Quick: true, Interface: "ena0",
		AddressFamily: "inet", Protocol: "tcp", From: "any", To: "any", ToPort: "22",
		State: "keep state", Label: "ssh",
	}, rules[3])

	assert.Equal(t, "(ena0)", rules[4].To)
	assert.Equal(t, "<trusted>", rules[4].From)
	assert.Equal(t, "80", rules[4].ToPort)
	assert.Equal(t, "modulate state", rules[4].State)
	assert.Equal(t, "443", rules[5].ToPort)

	assert.Equal(t, "ipv6-icmp", rules[6].Protocol)
	assert.Equal(t, "any", rules[6].From)

	// `from any port 53 to self no state`: pfctl expands self per address
	assert.Equal(t, Rule{
		Raw:    "pass in inet6 proto udp from any port = domain to ::1 no state",
		Action: "pass", Direction: "in", AddressFamily: "inet6", Protocol: "udp",
		From: "any", FromPort: "53", To: "::1", State: "no state",
	}, rules[7])
	assert.Equal(t, "lo0", rules[8].Interface)
	assert.Equal(t, "192.0.2.15", rules[9].To)

	assert.Equal(t, "out", rules[11].Direction)
	assert.True(t, rules[11].Quick)

	assert.Equal(t, Rule{
		Raw:    "block return-rst in quick on ! ena0 proto tcp from any to any port 6000:6010",
		Action: "block", BlockPolicy: "return-rst", Direction: "in", Quick: true,
		Interface: "! ena0", Protocol: "tcp", From: "any", To: "any", ToPort: "6000:6010",
	}, rules[12])

	assert.Equal(t, "> 1024", rules[13].ToPort)
	assert.Equal(t, "synproxy state", rules[13].State)

	assert.Equal(t, Rule{
		Raw:    `pass in log (all) quick inet proto tcp from ! 192.0.2.0/24 to any port 8080:8090 flags S/SA keep state (if-bound) label "web alt"`,
		Action: "pass", Direction: "in", Quick: true, Log: true, AddressFamily: "inet",
		Protocol: "tcp", From: "! 192.0.2.0/24", To: "any", ToPort: "8080:8090",
		State: "keep state", Label: "web alt",
	}, rules[14])
	assert.Equal(t, "udp", rules[15].Protocol)

	assert.Equal(t, Rule{
		Raw:    `anchor "test/*" all`,
		Action: "anchor", Anchor: "test/*", From: "any", To: "any",
	}, rules[16])
}

func TestParseRulesSkipsCounters(t *testing.T) {
	// `pfctl -s rules -v` on the same FreeBSD 14.5 host
	out := "block return log all\n" +
		"  [ Evaluations: 0         Packets: 0         Bytes: 0           States: 0     ]\n" +
		"  [ Inserted: uid 0 pid 1772 State Creations: 0     ]\n"
	rules := ParseRules(out, nil)
	require.Len(t, rules, 1)
	assert.Equal(t, "block", rules[0].Action)
}

func TestParseRulesEmpty(t *testing.T) {
	assert.Empty(t, ParseRules("", nil))
}

func TestParseTables(t *testing.T) {
	assert.Equal(t, []string{"bruteforce", "trusted"}, ParseTables(readFixture(t, "freebsd14_tables.txt")))
	assert.Equal(t, []string{"192.0.2.10", "198.51.100.0/24"}, ParseTableAddresses(readFixture(t, "freebsd14_table_show.txt")))
	assert.Empty(t, ParseTables(""))
}

func TestParseSkipInterfaces(t *testing.T) {
	assert.Equal(t, []string{"lo0"}, ParseSkipInterfaces(readFixture(t, "freebsd14_interfaces.txt")))
	assert.Empty(t, ParseSkipInterfaces("all\nena0\n"))
}

func TestClassifyError(t *testing.T) {
	// FreeBSD 14.5 as nobody, and macOS as a regular user
	assert.Equal(t, ErrorRefused, ClassifyError("pfctl: /dev/pf: Permission denied\n"))
	// FreeBSD 14.5 before pf.ko is loaded
	assert.Equal(t, ErrorNotLoaded, ClassifyError("pfctl: /dev/pf: No such file or directory\n"))
	assert.Equal(t, ErrorOther, ClassifyError("pfctl: Syntax error"))
	assert.Equal(t, ErrorOther, ClassifyError(""))
}

// The solaris114_* fixtures were captured as root on Oracle Solaris 11.4.86
// with a test ruleset loaded. Solaris's pfctl derives from OpenBSD's: it
// prints ports as numbers and no keep state on a pass rule without state
// options, since keeping state is the default.
func TestParseRulesSolaris(t *testing.T) {
	rules := ParseRules(readFixture(t, "solaris114_rules.txt"), nil)
	require.Len(t, rules, 17)

	assert.Equal(t, Rule{
		Raw:    "block return all",
		Action: "block", BlockPolicy: "return", From: "any", To: "any",
	}, rules[0])

	assert.Equal(t, Rule{
		Raw:    "block drop in log (to pflog0) quick from <bruteforce> to any",
		Action: "block", BlockPolicy: "drop", Direction: "in", Log: true, Quick: true,
		From: "<bruteforce>", To: "any",
	}, rules[1])

	assert.Equal(t, Rule{
		Raw:    "pass in proto tcp from any to any port = 22 flags S/SA",
		Action: "pass", Direction: "in", Protocol: "tcp", From: "any", To: "any",
		ToPort: "22", State: "keep state",
	}, rules[5])

	assert.Equal(t, "546", rules[4].ToPort)
	assert.Equal(t, "547", rules[4].FromPort)

	assert.Equal(t, Rule{
		Raw:    "block return out quick inet proto tcp from any to 169.254.0.2 port = 3260 user > 0",
		Action: "block", BlockPolicy: "return", Direction: "out", Quick: true,
		AddressFamily: "inet", Protocol: "tcp", From: "any", To: "169.254.0.2", ToPort: "3260",
	}, rules[7])

	assert.Equal(t, "modulate state", rules[10].State)
	assert.Equal(t, "web", rules[10].Label)
	assert.Equal(t, "no state", rules[12].State)

	assert.True(t, rules[13].Log)
	assert.True(t, rules[13].Quick)
	assert.Equal(t, "keep state", rules[13].State)
	assert.Equal(t, "web alt", rules[13].Label)

	assert.Equal(t, Rule{
		Raw:    "match in on net0 inet proto tcp from 198.51.100.0/24 to any port = 25 scrub (max-mss 1440)",
		Action: "match", Direction: "in", Interface: "net0", AddressFamily: "inet",
		Protocol: "tcp", From: "198.51.100.0/24", To: "any", ToPort: "25",
	}, rules[14])

	assert.Equal(t, "out", rules[15].Direction)
	assert.Equal(t, "keep state", rules[15].State)
	assert.Equal(t, "test/*", rules[16].Anchor)
}

func TestParseInfoSolaris(t *testing.T) {
	enabled, err := ParseInfo(readFixture(t, "solaris114_info_enabled.txt"))
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestParseSkipInterfacesSolaris(t *testing.T) {
	// Solaris prints the ALTQ notice on stdout ahead of the list
	assert.Equal(t, []string{"lo0"}, ParseSkipInterfaces(readFixture(t, "solaris114_interfaces.txt")))
}
