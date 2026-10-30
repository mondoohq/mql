// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireRule fetches one rule from the parsed dump or fails the test loudly.
// Centralised so individual test cases stay focused on what they actually assert.
func requireRule(t *testing.T, dump *SavedDump, table, chain string, idx int) SavedRule {
	t.Helper()
	for _, tbl := range dump.Tables {
		if tbl.Name != table {
			continue
		}
		for _, ch := range tbl.Chains {
			if ch.Name != chain {
				continue
			}
			require.Greater(t, len(ch.Rules), idx, "chain %s/%s has only %d rules", table, chain, len(ch.Rules))
			return ch.Rules[idx]
		}
		t.Fatalf("chain %s not found in table %s", chain, table)
	}
	t.Fatalf("table %s not found", table)
	return SavedRule{}
}

func TestParseIptablesSave_Empty(t *testing.T) {
	dump, err := ParseIptablesSave("")
	require.NoError(t, err)
	assert.Empty(t, dump.Tables)
}

func TestParseIptablesSave_MinimalFilterTable(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [10:1234]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [5:678]
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	require.Len(t, dump.Tables, 1)
	require.Equal(t, "filter", dump.Tables[0].Name)
	require.Len(t, dump.Tables[0].Chains, 3)

	chains := map[string]*SavedChain{}
	for _, ch := range dump.Tables[0].Chains {
		chains[ch.Name] = ch
	}
	assert.Equal(t, "ACCEPT", chains["INPUT"].Policy)
	assert.True(t, chains["INPUT"].Builtin)
	assert.Equal(t, "DROP", chains["FORWARD"].Policy)
	assert.Equal(t, "ACCEPT", chains["OUTPUT"].Policy)
	assert.Empty(t, chains["INPUT"].Rules)
}

func TestParseIptablesSave_UserDefinedChain(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
:DOCKER - [0:0]
:f2b-ssh - [0:0]
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	require.Len(t, dump.Tables[0].Chains, 3)

	chains := map[string]*SavedChain{}
	for _, ch := range dump.Tables[0].Chains {
		chains[ch.Name] = ch
	}
	assert.True(t, chains["INPUT"].Builtin)
	assert.False(t, chains["DOCKER"].Builtin, "user-defined chain should not be marked builtin")
	assert.Empty(t, chains["DOCKER"].Policy, "user-defined chain has no default policy")
	assert.False(t, chains["f2b-ssh"].Builtin)
}

func TestParseIptablesSave_CounterPrefix(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[42:8400] -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.EqualValues(t, 42, rule.Packets)
	assert.EqualValues(t, 8400, rule.Bytes)
	assert.Equal(t, "tcp", rule.Protocol)
	assert.True(t, rule.HasDport)
	assert.Equal(t, 22, rule.Dport)
	assert.Equal(t, "ACCEPT", rule.Target)
}

func TestParseIptablesSave_NoCounterPrefix(t *testing.T) {
	// `iptables-save` without `-c` omits the counter prefix; verify we still
	// parse the rule and just leave counters at zero.
	input := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -p icmp -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.EqualValues(t, 0, rule.Packets)
	assert.EqualValues(t, 0, rule.Bytes)
	assert.Equal(t, "icmp", rule.Protocol)
	assert.Equal(t, "ACCEPT", rule.Target)
}

func TestParseIptablesSave_ProtocolDefaultsToAll(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -i lo -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, "all", rule.Protocol, "missing -p should render as 'all' to match -L output")
	assert.Equal(t, "lo", rule.In)
}

func TestParseIptablesSave_InOutInterfaces(t *testing.T) {
	input := `*filter
:FORWARD ACCEPT [0:0]
[0:0] -A FORWARD -i eth0 -o eth1 -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "FORWARD", 0)
	assert.Equal(t, "eth0", rule.In)
	assert.Equal(t, "eth1", rule.Out)
}

func TestParseIptablesSave_SourceDestination(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -s 10.0.0.0/8 -d 192.168.1.5 -j DROP
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, "10.0.0.0/8", rule.Source)
	assert.Equal(t, "192.168.1.5", rule.Destination)
	assert.Equal(t, "DROP", rule.Target)
}

func TestParseIptablesSave_DportSingle(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.True(t, rule.HasDport)
	assert.Equal(t, 443, rule.Dport)
	assert.Empty(t, rule.DportRange)
}

func TestParseIptablesSave_DportRange(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -p tcp -m tcp --dport 1024:65535 -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.True(t, rule.HasDport)
	assert.Equal(t, 0, rule.Dport, "range should not populate the integer port")
	assert.Equal(t, "1024:65535", rule.DportRange)
}

func TestParseIptablesSave_MultiportDports(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -p tcp -m multiport --dports 80,443,8080:8090 -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, []string{"80", "443", "8080:8090"}, rule.Dports)
}

func TestParseIptablesSave_SportSingleAndRange(t *testing.T) {
	input := `*filter
:OUTPUT ACCEPT [0:0]
[0:0] -A OUTPUT -p tcp -m tcp --sport 32768 -j ACCEPT
[0:0] -A OUTPUT -p udp -m udp --sport 1000:2000 -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	r0 := requireRule(t, dump, "filter", "OUTPUT", 0)
	assert.True(t, r0.HasSport)
	assert.Equal(t, 32768, r0.Sport)
	r1 := requireRule(t, dump, "filter", "OUTPUT", 1)
	assert.True(t, r1.HasSport)
	assert.Equal(t, "1000:2000", r1.SportRange)
}

func TestParseIptablesSave_MultiportSports(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -p tcp -m multiport --sports 22,80 -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, []string{"22", "80"}, rule.Sports)
}

func TestParseIptablesSave_State(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, []string{"RELATED", "ESTABLISHED"}, rule.Ctstate)
}

func TestParseIptablesSave_Conntrack(t *testing.T) {
	// -m conntrack --ctstate is the modern replacement for -m state.
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -m conntrack --ctstate NEW,RELATED -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, []string{"NEW", "RELATED"}, rule.Ctstate)
}

func TestParseIptablesSave_TCPFlags(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, []string{"FIN,SYN,RST,ACK", "SYN"}, rule.TCPFlags)
}

func TestParseIptablesSave_Comment(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -p tcp -m tcp --dport 22 -m comment --comment "allow ssh from admins" -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, "allow ssh from admins", rule.Comment)
}

func TestParseIptablesSave_CommentWithEscapedQuote(t *testing.T) {
	// Comments may contain escaped quotes — make sure tokenize handles them.
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -m comment --comment "say \"hi\"" -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, `say "hi"`, rule.Comment)
}

func TestParseIptablesSave_MatchSet(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -m set --match-set blacklisted src -j DROP
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, "blacklisted", rule.MatchSet)
	assert.Contains(t, rule.Options, "match-set blacklisted src")
}

func TestParseIptablesSave_RejectWith(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -j REJECT --reject-with icmp-port-unreachable
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, "REJECT", rule.Target)
	assert.Equal(t, "icmp-port-unreachable", rule.RejectWith)
}

func TestParseIptablesSave_GotoTarget(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
:DOCKER - [0:0]
[0:0] -A INPUT -g DOCKER
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, "DOCKER", rule.Target, "-g should populate target the same way -j does")
}

func TestParseIptablesSave_Negation(t *testing.T) {
	// Rules captured from `iptables-save -c` on Ubuntu 16.04 through 26.04.
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -d 127.0.0.0/8 ! -i lo -j DROP
[0:0] -A INPUT -s 198.51.100.7/32 -p tcp -m tcp ! --dport 2424 -j DROP
[0:0] -A INPUT ! -s 192.168.0.0/16 -p tcp -m tcp --dport 2323 -j DROP
[0:0] -A INPUT ! -d 10.0.0.0/8 -p udp -m udp ! --sport 53 -j ACCEPT
[0:0] -A INPUT -p tcp -m conntrack ! --ctstate ESTABLISHED,RELATED -m multiport ! --dports 80,443 -j DROP
[0:0] -A INPUT -m set ! --match-set allowlist src -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m multiport ! --sports 1000:2000 -j DROP
COMMIT
*nat
:POSTROUTING ACCEPT [0:0]
[2:198] -A POSTROUTING ! -o lo -j MASQUERADE
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)

	r := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, "!lo", r.In, "! -i lo matches every interface except lo")
	assert.Equal(t, "127.0.0.0/8", r.Destination)

	r = requireRule(t, dump, "filter", "INPUT", 1)
	assert.Equal(t, "198.51.100.7/32", r.Source)
	assert.True(t, r.HasDport)
	assert.Equal(t, 0, r.Dport, "a negated port is not a single-port match")
	assert.Equal(t, "!2424", r.DportRange)

	r = requireRule(t, dump, "filter", "INPUT", 2)
	assert.Equal(t, "!192.168.0.0/16", r.Source)
	assert.Equal(t, 2323, r.Dport)
	assert.Empty(t, r.DportRange)

	r = requireRule(t, dump, "filter", "INPUT", 3)
	assert.Equal(t, "!10.0.0.0/8", r.Destination)
	assert.Equal(t, 0, r.Sport)
	assert.Equal(t, "!53", r.SportRange)

	r = requireRule(t, dump, "filter", "INPUT", 4)
	assert.Equal(t, []string{"!ESTABLISHED", "!RELATED"}, r.Ctstate)
	assert.Equal(t, []string{"!80", "!443"}, r.Dports)

	r = requireRule(t, dump, "filter", "INPUT", 5)
	assert.Equal(t, "!allowlist", r.MatchSet)
	assert.Equal(t, []string{"!FIN,SYN,RST,ACK", "SYN"}, r.TCPFlags)
	assert.Equal(t, []string{"!1000:2000"}, r.Sports)

	r = requireRule(t, dump, "nat", "POSTROUTING", 0)
	assert.Equal(t, "!lo", r.Out)
	assert.Empty(t, r.In)
}

func TestParseIptablesSave_NegatedProtocol(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT ! -p tcp -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, "!tcp", rule.Protocol)
}

func TestParseIptablesSave_NATTable(t *testing.T) {
	input := `*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
[0:0] -A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.0.5:8080
[0:0] -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	require.Len(t, dump.Tables, 1)
	assert.Equal(t, "nat", dump.Tables[0].Name)

	pre := requireRule(t, dump, "nat", "PREROUTING", 0)
	assert.Equal(t, "DNAT", pre.Target)
	assert.True(t, pre.HasDport)
	assert.Equal(t, 80, pre.Dport)

	post := requireRule(t, dump, "nat", "POSTROUTING", 0)
	assert.Equal(t, "MASQUERADE", post.Target)
	assert.Equal(t, "10.0.0.0/24", post.Source)
	assert.Equal(t, "eth0", post.Out)
}

func TestParseIptablesSave_MultipleTables(t *testing.T) {
	input := `# Generated by iptables-save
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
[0:0] -A POSTROUTING -j MASQUERADE
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
COMMIT
*filter
:INPUT DROP [0:0]
:OUTPUT ACCEPT [0:0]
[5:200] -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	require.Len(t, dump.Tables, 3)

	names := []string{}
	for _, tbl := range dump.Tables {
		names = append(names, tbl.Name)
	}
	assert.Equal(t, []string{"nat", "mangle", "filter"}, names)

	// Filter table INPUT should have DROP policy.
	for _, tbl := range dump.Tables {
		if tbl.Name != "filter" {
			continue
		}
		for _, ch := range tbl.Chains {
			if ch.Name == "INPUT" {
				assert.Equal(t, "DROP", ch.Policy)
			}
		}
	}
}

func TestParseIptablesSave_IPv6Addresses(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -s 2001:db8::/32 -p tcp -m tcp --dport 80 -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, "2001:db8::/32", rule.Source)
	assert.True(t, rule.HasDport)
	assert.Equal(t, 80, rule.Dport)
}

func TestParseIptablesSave_BlankLinesAndComments(t *testing.T) {
	// iptables-save output can include shell-style comments and blank lines
	// between blocks; the parser must tolerate both.
	input := `# generated by some tool

*filter
# the filter table

:INPUT ACCEPT [0:0]

[0:0] -A INPUT -p icmp -j ACCEPT

COMMIT

`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	require.Len(t, dump.Tables, 1)
	require.Len(t, dump.Tables[0].Chains, 1)
	require.Len(t, dump.Tables[0].Chains[0].Rules, 1)
}

func TestParseIptablesSave_DataBeforeTableHeaderErrors(t *testing.T) {
	// A `-A` line before any *table header is malformed; the parser should
	// surface a clear error rather than silently dropping the rule.
	input := `:INPUT ACCEPT [0:0]
COMMIT
`
	_, err := ParseIptablesSave(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "before any *table header")
}

func TestParseIptablesSave_BadCounterPrefix(t *testing.T) {
	// `[abc:def]` is not a valid `[pkts:bytes]` counter — surface the
	// parse error rather than silently mis-counting.
	input := `*filter
:INPUT ACCEPT [0:0]
[abc:def] -A INPUT -j ACCEPT
COMMIT
`
	_, err := ParseIptablesSave(input)
	require.Error(t, err)
}

func TestParseIptablesSave_RulesBeforeChainDecl(t *testing.T) {
	// Defensive: some hand-edited dumps put rules before the chain
	// declaration. We auto-create the chain so we don't drop rules.
	input := `*filter
[0:0] -A CUSTOM -j ACCEPT
:CUSTOM - [0:0]
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	require.Len(t, dump.Tables[0].Chains, 1)
	assert.Equal(t, "CUSTOM", dump.Tables[0].Chains[0].Name)
	require.Len(t, dump.Tables[0].Chains[0].Rules, 1)
}

func TestParseIptablesSave_CRLFLineEndings(t *testing.T) {
	// Some tools emit CRLF line endings; the parser should tolerate them.
	input := "*filter\r\n:INPUT ACCEPT [0:0]\r\n[0:0] -A INPUT -p icmp -j ACCEPT\r\nCOMMIT\r\n"
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Equal(t, "icmp", rule.Protocol)
}

func TestParseIptablesSave_LineNumbersInOptions(t *testing.T) {
	// Unrecognized options should still appear in the options blob so users
	// can grep for things we haven't pulled into structured fields yet.
	input := `*filter
:INPUT ACCEPT [0:0]
[0:0] -A INPUT -p tcp -m tcp --dport 22 --tcp-option 4 -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.Contains(t, rule.Options, "tcp-option:4")
}

func TestParseIptablesSave_RawPreservedWithoutCounter(t *testing.T) {
	// `raw` should be the rule text minus the counter prefix.
	input := `*filter
:INPUT ACCEPT [0:0]
[7:300] -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	rule := requireRule(t, dump, "filter", "INPUT", 0)
	assert.True(t, strings.HasPrefix(rule.Raw, "-A INPUT"), "raw should start with -A CHAIN (counter prefix stripped); got %q", rule.Raw)
	assert.NotContains(t, rule.Raw, "[7:300]")
}

func TestParseIptablesSave_RealWorldDump(t *testing.T) {
	// A representative dump from a typical Linux host running Docker +
	// fail2ban + a simple firewall. Exercises every parser branch in
	// combination.
	input := `# Generated by iptables-save v1.8.7
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
[10:520] -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
[5:300] -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
COMMIT
*filter
:INPUT DROP [3:120]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [100:8000]
:DOCKER - [0:0]
:f2b-sshd - [0:0]
[150:9000] -A INPUT -i lo -j ACCEPT
[200:14000] -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
[12:600] -A INPUT -p tcp -m tcp --dport 22 -j f2b-sshd
[7:280] -A INPUT -p tcp -m tcp --dport 22 -m comment --comment "allow ssh" -j ACCEPT
[2:80] -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
[1:40] -A INPUT -p icmp -j ACCEPT
[0:0] -A INPUT -j REJECT --reject-with icmp-port-unreachable
[0:0] -A f2b-sshd -j RETURN
COMMIT
`
	dump, err := ParseIptablesSave(input)
	require.NoError(t, err)
	require.Len(t, dump.Tables, 2)

	// nat table — PREROUTING with addrtype, POSTROUTING with negated -o.
	pre := requireRule(t, dump, "nat", "PREROUTING", 0)
	assert.Equal(t, "DOCKER", pre.Target)
	assert.EqualValues(t, 10, pre.Packets)
	post := requireRule(t, dump, "nat", "POSTROUTING", 0)
	assert.Equal(t, "MASQUERADE", post.Target)
	assert.Equal(t, "172.17.0.0/16", post.Source)
	assert.Equal(t, "!docker0", post.Out, "! -o docker0 matches every interface except docker0")

	// filter table — verify the ssh rule has the comment, the multiport rule
	// has both ports, and the REJECT rule populates rejectWith.
	ssh := requireRule(t, dump, "filter", "INPUT", 3)
	assert.Equal(t, "allow ssh", ssh.Comment)
	assert.Equal(t, 22, ssh.Dport)

	multi := requireRule(t, dump, "filter", "INPUT", 4)
	assert.Equal(t, []string{"80", "443"}, multi.Dports)

	reject := requireRule(t, dump, "filter", "INPUT", 6)
	assert.Equal(t, "REJECT", reject.Target)
	assert.Equal(t, "icmp-port-unreachable", reject.RejectWith)

	// User-defined chains.
	var f2b *SavedChain
	for _, tbl := range dump.Tables {
		if tbl.Name != "filter" {
			continue
		}
		for _, ch := range tbl.Chains {
			if ch.Name == "f2b-sshd" {
				f2b = ch
			}
		}
	}
	require.NotNil(t, f2b)
	assert.False(t, f2b.Builtin)
	assert.Empty(t, f2b.Policy)
	require.Len(t, f2b.Rules, 1)
	assert.Equal(t, "RETURN", f2b.Rules[0].Target)
}

func TestTokenize_BasicSplit(t *testing.T) {
	tokens, err := tokenize("-A INPUT -p tcp")
	require.NoError(t, err)
	assert.Equal(t, []string{"-A", "INPUT", "-p", "tcp"}, tokens)
}

func TestTokenize_QuotedString(t *testing.T) {
	tokens, err := tokenize(`-A INPUT -m comment --comment "hello world" -j ACCEPT`)
	require.NoError(t, err)
	assert.Equal(t, []string{"-A", "INPUT", "-m", "comment", "--comment", "hello world", "-j", "ACCEPT"}, tokens)
}

func TestTokenize_EscapedQuoteInside(t *testing.T) {
	tokens, err := tokenize(`--comment "a\"b"`)
	require.NoError(t, err)
	assert.Equal(t, []string{"--comment", `a"b`}, tokens)
}

func TestTokenize_BackslashOutsideQuote(t *testing.T) {
	// Backslashes outside of quotes are not treated as escapes; iptables-save
	// never emits them in that context, but be tolerant if a hand-written
	// dump does.
	tokens, err := tokenize(`-A INPUT -j ACC\PT`)
	require.NoError(t, err)
	assert.Equal(t, []string{"-A", "INPUT", "-j", `ACC\PT`}, tokens)
}

func TestTokenize_UnterminatedQuoteErrors(t *testing.T) {
	_, err := tokenize(`--comment "missing close`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unterminated")
}

func TestTokenize_MultipleSpaces(t *testing.T) {
	tokens, err := tokenize("-A   INPUT    -j   ACCEPT")
	require.NoError(t, err)
	assert.Equal(t, []string{"-A", "INPUT", "-j", "ACCEPT"}, tokens)
}

func TestSplitCSV(t *testing.T) {
	assert.Nil(t, splitCSV(""), "empty input should return nil, not []string{\"\"}")
	assert.Equal(t, []string{"a"}, splitCSV("a"))
	assert.Equal(t, []string{"a", "b", "c"}, splitCSV("a,b,c"))
	assert.Equal(t, []string{"a", "b"}, splitCSV("a, b ,"), "whitespace and trailing commas should be trimmed")
}
