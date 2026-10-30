// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// These tests cover the cases the exposure predicates used to get wrong. Every
// one of them is a failed-open verdict: the resource is reachable and the
// provider reported that it was not, so a policy asserting "not reachable from
// the internet" passed over an exposed resource.

func TestIsInternetOpenSourcePrefixParsesRatherThanCompares(t *testing.T) {
	open := []string{
		"*", "any", "Any", "internet", "Internet", " INTERNET ",
		"0.0.0.0/0", " 0.0.0.0/0 ",
		"::/0",
		// the same zero-length IPv6 prefix written out in full -- a string
		// compare recognized only the short spelling
		"0000:0000:0000:0000:0000:0000:0000:0000/0",
	}
	for _, p := range open {
		assert.True(t, isInternetOpenSourcePrefix(p), "%q should be internet-open", p)
	}

	closed := []string{
		"", "10.0.0.0/8", "0.0.0.0/1", "128.0.0.0/1", "2001:db8::/32",
		"VirtualNetwork", "AzureLoadBalancer", "not-a-prefix", "0.0.0.0",
	}
	for _, p := range closed {
		assert.False(t, isInternetOpenSourcePrefix(p), "%q should not be internet-open on its own", p)
	}
}

// TestPrefixesCoverInternetSplitHalves is the case a per-entry check cannot
// see: neither 0.0.0.0/1 nor 128.0.0.0/1 is a zero-length prefix, but together
// they are all of IPv4. It is a common way to write "any", and an NSG opened
// this way used to read as closed.
func TestPrefixesCoverInternet(t *testing.T) {
	for _, tc := range []struct {
		name     string
		prefixes []string
		want     bool
	}{
		{"the two IPv4 halves", []string{"0.0.0.0/1", "128.0.0.0/1"}, true},
		{"halves in either order", []string{"128.0.0.0/1", "0.0.0.0/1"}, true},
		{"quarters", []string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"}, true},
		{"halves with unrelated entries mixed in", []string{"10.0.0.0/8", "0.0.0.0/1", "203.0.113.0/24", "128.0.0.0/1"}, true},
		{"a single zero-length prefix still counts", []string{"0.0.0.0/0"}, true},
		{"a named tag still counts", []string{"10.0.0.0/8", "Internet"}, true},

		{"one half alone leaves the other half unreachable", []string{"0.0.0.0/1"}, false},
		{"the upper half alone does not start at zero", []string{"128.0.0.0/1"}, false},
		{"a gap in the middle is not full coverage", []string{"0.0.0.0/2", "192.0.0.0/2"}, false},
		{"ordinary allowlist", []string{"10.0.0.0/8", "203.0.113.0/24"}, false},
		{"empty list", nil, false},
		{"unparseable entries are ignored, not assumed open", []string{"garbage", "also-garbage"}, false},

		// The aggregation is IPv4 only, and these two pin that boundary so a
		// later change has to move both the behavior and the doc comment.
		{"a zero-length IPv6 prefix counts on its own", []string{"::/0"}, true},
		{"IPv6 halves are not summed against each other", []string{"::/1", "8000::/1"}, false},
		{"IPv6 entries do not complete an IPv4 half", []string{"0.0.0.0/1", "8000::/1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, prefixesCoverInternet(tc.prefixes))
		})
	}
}

// TestFirewallRuleAllowsAnyInternetSpans covers the database firewall rule
// forms that a string compare on the start address got wrong in both
// directions.
func TestFirewallRuleAllowsAnyInternetSpans(t *testing.T) {
	for _, tc := range []struct {
		name       string
		start, end string
		want       bool
	}{
		{"the whole address space", "0.0.0.0", "255.255.255.255", true},
		{"starts at 1.0.0.0 -- the whole routable internet", "1.0.0.0", "255.255.255.255", true},
		{"off by one at the bottom", "0.0.0.1", "255.255.255.255", true},
		{"the documented wide-partial case", "0.0.0.0", "128.255.255.255", true},

		{"the allow-all-Azure-services rule is not internet-open", "0.0.0.0", "0.0.0.0", false},
		{"two addresses is not the internet", "0.0.0.0", "0.0.0.1", false},
		{"an office allowlist", "203.0.113.0", "203.0.113.255", false},
		{"a private range", "10.0.0.0", "10.255.255.255", false},
		{"an inverted range admits nothing", "255.255.255.255", "0.0.0.0", false},
		{"unparseable input is not assumed open", "", "255.255.255.255", false},
		{"a missing end is not assumed open", "0.0.0.0", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, firewallRuleAllowsAnyInternet(tc.start, tc.end))
		})
	}
}

// TestAksApiServerAllowlistMustActuallyRestrict pins the AKS case. Treating any
// non-empty authorized-IP list as a restriction meant a cluster allowlisted to
// 0.0.0.0/0 -- which is what several Terraform modules emit when the field
// cannot be left empty -- reported its API server as unreachable.
func TestAksApiServerAllowlistMustActuallyRestrict(t *testing.T) {
	for _, tc := range []struct {
		name    string
		private bool
		pna     string
		ranges  []string
		want    bool
	}{
		{"public cluster, no allowlist", false, "Enabled", nil, true},
		{"allowlisted to the whole internet", false, "Enabled", []string{"0.0.0.0/0"}, true},
		{"allowlisted to the two IPv4 halves", false, "Enabled", []string{"0.0.0.0/1", "128.0.0.0/1"}, true},

		{"a real allowlist restricts", false, "Enabled", []string{"203.0.113.0/24"}, false},
		{"a real allowlist with several entries restricts", false, "Enabled", []string{"203.0.113.0/24", "198.51.100.0/24"}, false},
		{"private clusters are never reachable", true, "Enabled", nil, false},
		{"private wins even over an open allowlist", true, "Enabled", []string{"0.0.0.0/0"}, false},
		{"public network access disabled closes it", false, "Disabled", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, aksApiServerInternetReachable(tc.private, tc.pna, tc.ranges))
		})
	}
}

// TestSecurityRuleSplitHalvesSource checks the set-level reasoning reaches the
// NSG rule predicates, not just the standalone helper.
func TestSecurityRuleSplitHalvesSource(t *testing.T) {
	assert.True(t, securityRuleAllowsInternetIngress("Inbound", "Allow", "",
		[]string{"0.0.0.0/1", "128.0.0.0/1"}),
		"a rule whose source list covers all of IPv4 is internet-open")

	assert.False(t, securityRuleAllowsInternetIngress("Inbound", "Allow", "",
		[]string{"0.0.0.0/1"}),
		"half the address space is not the whole internet")

	assert.True(t, ruleSourceIsInternet(map[string]any{
		"sourceAddressPrefixes": []any{"0.0.0.0/1", "128.0.0.0/1"},
	}))

	assert.False(t, ruleSourceIsInternet(map[string]any{
		"sourceAddressPrefixes": []any{"10.0.0.0/8", "203.0.113.0/24"},
	}))
}

func TestRangesCoverAllIPv4(t *testing.T) {
	full := []ipRange{{0, 4294967295}}
	assert.True(t, rangesCoverAllIPv4(full))

	halves := []ipRange{{0, 2147483647}, {2147483648, 4294967295}}
	assert.True(t, rangesCoverAllIPv4(halves), "adjacent ranges must join")

	gap := []ipRange{{0, 2147483646}, {2147483648, 4294967295}}
	assert.False(t, rangesCoverAllIPv4(gap), "a one-address gap is still a gap")

	notFromZero := []ipRange{{1, 4294967295}}
	assert.False(t, rangesCoverAllIPv4(notFromZero))

	assert.False(t, rangesCoverAllIPv4(nil))
}
