// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sql "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
)

// TestFirewallRuleAllowsAnyInternetIPv6 pins the family this check used to
// ignore outright.
//
// firewallRuleAllowsAnyInternet parsed both endpoints and bailed unless they
// were IPv4, so an Azure SQL server whose only wide rule was an IPv6 one --
// :: through ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff, every address on the IPv6
// internet -- was scored as if the rule did not exist and reported
// internetReachable: false.
func TestFirewallRuleAllowsAnyInternetIPv6(t *testing.T) {
	cases := []struct {
		name       string
		start, end string
		want       bool
	}{
		{"full IPv6 span", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"full IPv6 span, expanded spelling", "0000:0000:0000:0000:0000:0000:0000:0000", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"lower half of IPv6", "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"upper half of IPv6", "8000::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		// One address short of half the space. Pins the boundary from the side
		// that must stay closed, and exercises the borrow across the 64-bit
		// word split that made big.Int worth using.
		{"one short of half", "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:fffd", false},
		{"documentation prefix range", "2001:db8::", "2001:db8::ffff", false},
		{"single IPv6 address", "2001:db8::1", "2001:db8::1", false},
		{"unspecified address alone", "::", "::", false},
		{"reversed endpoints", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::", false},
		{"trimmed", " :: ", " ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ", true},
		// A rule cannot span two families; neither endpoint pair describes a
		// coherent range, so neither is treated as open.
		{"mixed families, v4 start", "0.0.0.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"mixed families, v6 start", "::", "255.255.255.255", false},
		// An IPv4-mapped IPv6 address describes IPv4 space, not the IPv6
		// internet, and must not be measured against the 128-bit threshold.
		{"IPv4-mapped range is not the IPv6 internet", "::ffff:0.0.0.0", "::ffff:255.255.255.255", false},
		{"empty", "", "", false},
		{"open start but no end", "::", "", false},
		{"garbage", "not-an-address", "also-not", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, firewallRuleAllowsAnyInternet(c.start, c.end))
		})
	}
}

// TestFirewallRuleAllowsAnyInternetIPv4Unchanged re-pins the IPv4 answers after
// the function grew a family switch, so the widened check cannot regress the
// behaviour it already had.
func TestFirewallRuleAllowsAnyInternetIPv4Unchanged(t *testing.T) {
	assert.True(t, firewallRuleAllowsAnyInternet("0.0.0.0", "255.255.255.255"))
	assert.True(t, firewallRuleAllowsAnyInternet("0.0.0.0", "128.255.255.255"))
	assert.False(t, firewallRuleAllowsAnyInternet("0.0.0.0", "0.0.0.0"))
	assert.False(t, firewallRuleAllowsAnyInternet("203.0.113.1", "203.0.113.10"))
}

// TestDatabaseInternetReachableIPv6 covers the combined judgement: an IPv6 rule
// alone is enough to make a server internet-reachable, and the
// publicNetworkAccess gate still overrides it.
func TestDatabaseInternetReachableIPv6(t *testing.T) {
	openV6 := [2]string{"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}
	scopedV4 := [2]string{"203.0.113.1", "203.0.113.10"}

	t.Run("IPv6 rule alone opens the server", func(t *testing.T) {
		assert.True(t, databaseInternetReachable("Enabled", [][2]string{scopedV4, openV6}))
	})
	t.Run("public access disabled still wins", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Disabled", [][2]string{openV6}))
	})
	t.Run("scoped rules in both families stay closed", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Enabled", [][2]string{
			scopedV4, {"2001:db8::", "2001:db8::ffff"},
		}))
	})
}

// TestIPv6FirewallRuleArgs pins the decode of the SDK record. The endpoints
// live on a nullable Properties pointer under IPv6-specific names, so a
// mistyped field or an unguarded nil would produce empty endpoints -- which
// parse to no address and score the rule as admitting nothing, restoring the
// same false negative through a different route.
func TestIPv6FirewallRuleArgs(t *testing.T) {
	t.Run("maps the IPv6 endpoints", func(t *testing.T) {
		args := ipv6FirewallRuleArgs(&sql.IPv6FirewallRule{
			ID:   new("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/srv/ipv6FirewallRules/AllowAll"),
			Name: new("AllowAll"),
			Type: new("Microsoft.Sql/servers/ipv6FirewallRules"),
			Properties: &sql.IPv6ServerFirewallRuleProperties{
				StartIPv6Address: new("::"),
				EndIPv6Address:   new("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
			},
		})

		assert.Equal(t, "AllowAll", args["name"].Value)
		assert.Equal(t, "Microsoft.Sql/servers/ipv6FirewallRules", args["type"].Value)
		assert.Equal(t, "::", args["startIpAddress"].Value)
		assert.Equal(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", args["endIpAddress"].Value)
		assert.Equal(t, args["id"].Value, args["__id"].Value)

		// the decoded endpoints must actually score as open
		assert.True(t, firewallRuleAllowsAnyInternet(
			args["startIpAddress"].Value.(string), args["endIpAddress"].Value.(string)))
	})

	t.Run("nil properties does not panic and yields empty endpoints", func(t *testing.T) {
		args := ipv6FirewallRuleArgs(&sql.IPv6FirewallRule{
			ID:   new("/subscriptions/s/.../ipv6FirewallRules/empty"),
			Name: new("empty"),
		})
		assert.Empty(t, args["startIpAddress"].Value)
		assert.Empty(t, args["endIpAddress"].Value)
	})
}

// TestSqlIPv6FirewallRanges pins the collection step that feeds
// internetReachable. It only picks up the IPv6 rule resource, so a rule that
// reached it as some other type is dropped rather than silently mis-scored.
func TestSqlIPv6FirewallRanges(t *testing.T) {
	runtime := cacheIDTestRuntime()

	rule, err := CreateResource(runtime, "azure.subscription.sqlService.server.ipv6FirewallRule",
		ipv6FirewallRuleArgs(&sql.IPv6FirewallRule{
			ID:   new("/subscriptions/s/.../ipv6FirewallRules/AllowAll"),
			Name: new("AllowAll"),
			Properties: &sql.IPv6ServerFirewallRuleProperties{
				StartIPv6Address: new("::"),
				EndIPv6Address:   new("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
			},
		}))
	require.NoError(t, err)

	ranges := sqlIPv6FirewallRanges([]any{rule})
	require.Len(t, ranges, 1)
	assert.Equal(t, [2]string{"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}, ranges[0])
	assert.True(t, databaseInternetReachable("Enabled", ranges))

	t.Run("nil and foreign entries are skipped", func(t *testing.T) {
		assert.Empty(t, sqlIPv6FirewallRanges([]any{nil, "not-a-rule"}))
		assert.Empty(t, sqlIPv6FirewallRanges(nil))
	})
}
