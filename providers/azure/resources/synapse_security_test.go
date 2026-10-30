// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIpv4RangeSpansAll(t *testing.T) {
	t.Run("the all-IPv4 rule", func(t *testing.T) {
		assert.True(t, ipv4RangeSpansAll("0.0.0.0", "255.255.255.255"))
	})
	t.Run("the allow-Azure-services rule is not all-IPv4", func(t *testing.T) {
		// Both ranges start at 0.0.0.0, which is exactly why these two are
		// confused; only the end address distinguishes them.
		assert.False(t, ipv4RangeSpansAll("0.0.0.0", "0.0.0.0"))
	})
	t.Run("narrower ranges", func(t *testing.T) {
		assert.False(t, ipv4RangeSpansAll("10.0.0.0", "10.0.0.255"))
		assert.False(t, ipv4RangeSpansAll("0.0.0.0", "10.255.255.255"))
		assert.False(t, ipv4RangeSpansAll("1.0.0.0", "255.255.255.255"))
	})
	t.Run("unparseable addresses are not treated as open", func(t *testing.T) {
		assert.False(t, ipv4RangeSpansAll("", ""))
		assert.False(t, ipv4RangeSpansAll("not-an-ip", "255.255.255.255"))
		assert.False(t, ipv4RangeSpansAll("0.0.0.0", "also-not-an-ip"))
	})
}

func TestIsAzureServicesRule(t *testing.T) {
	t.Run("the 0.0.0.0 to 0.0.0.0 rule", func(t *testing.T) {
		assert.True(t, isAzureServicesRule("0.0.0.0", "0.0.0.0"))
	})
	t.Run("the all-IPv4 rule is not the Azure-services rule", func(t *testing.T) {
		assert.False(t, isAzureServicesRule("0.0.0.0", "255.255.255.255"))
	})
	t.Run("an ordinary single host is not the Azure-services rule", func(t *testing.T) {
		assert.False(t, isAzureServicesRule("203.0.113.4", "203.0.113.4"))
	})
	t.Run("unparseable addresses", func(t *testing.T) {
		assert.False(t, isAzureServicesRule("", ""))
	})
}

func TestSynapseFirewallFlagsAreMutuallyExclusive(t *testing.T) {
	// The two flags describe different rules and must never both be true, since
	// a query that treats allowsAllIpv4 as "internet open" would otherwise also
	// fire on the far narrower Azure-services rule.
	cases := [][2]string{
		{"0.0.0.0", "255.255.255.255"},
		{"0.0.0.0", "0.0.0.0"},
		{"10.0.0.1", "10.0.0.9"},
		{"", ""},
	}
	for _, c := range cases {
		all := ipv4RangeSpansAll(c[0], c[1])
		azure := isAzureServicesRule(c[0], c[1])
		assert.Falsef(t, all && azure, "range %s-%s reported as both", c[0], c[1])
	}
}
