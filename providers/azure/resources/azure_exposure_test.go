// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestIsInternetOpenSourcePrefix(t *testing.T) {
	cases := []struct {
		prefix string
		want   bool
	}{
		{"*", true},
		{"0.0.0.0/0", true},
		{"::/0", true},
		{"Internet", true},
		{"internet", true},
		{" * ", true},
		{"10.0.0.0/8", false},
		{"VirtualNetwork", false},
		{"203.0.113.4", false},
		{"", false},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, isInternetOpenSourcePrefix(c.prefix), "prefix %q", c.prefix)
	}
}

func TestSecurityRuleAllowsInternetIngress(t *testing.T) {
	t.Run("inbound allow from any is open", func(t *testing.T) {
		assert.True(t, securityRuleAllowsInternetIngress("Inbound", "Allow", "0.0.0.0/0", nil))
	})
	t.Run("inbound allow via service tag is open", func(t *testing.T) {
		assert.True(t, securityRuleAllowsInternetIngress("Inbound", "Allow", "Internet", nil))
	})
	t.Run("inbound allow via prefix list is open", func(t *testing.T) {
		assert.True(t, securityRuleAllowsInternetIngress("Inbound", "Allow", "10.0.0.0/8", []string{"VirtualNetwork", "*"}))
	})
	t.Run("outbound is not ingress", func(t *testing.T) {
		assert.False(t, securityRuleAllowsInternetIngress("Outbound", "Allow", "*", nil))
	})
	t.Run("deny is not open", func(t *testing.T) {
		assert.False(t, securityRuleAllowsInternetIngress("Inbound", "Deny", "*", nil))
	})
	t.Run("scoped source is not open", func(t *testing.T) {
		assert.False(t, securityRuleAllowsInternetIngress("Inbound", "Allow", "10.0.0.0/8", []string{"172.16.0.0/12"}))
	})
	t.Run("case insensitive direction/access", func(t *testing.T) {
		assert.True(t, securityRuleAllowsInternetIngress("inbound", "allow", "*", nil))
	})
}

func TestEffectiveRuleAllowsInternetIngress(t *testing.T) {
	t.Run("inbound allow from any prefix is open", func(t *testing.T) {
		assert.True(t, effectiveRuleAllowsInternetIngress(map[string]any{
			"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "0.0.0.0/0",
		}))
	})
	t.Run("inbound allow via Internet service tag is open", func(t *testing.T) {
		assert.True(t, effectiveRuleAllowsInternetIngress(map[string]any{
			"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "Internet",
		}))
	})
	t.Run("inbound allow via expanded prefixes is open", func(t *testing.T) {
		assert.True(t, effectiveRuleAllowsInternetIngress(map[string]any{
			"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "VirtualNetwork",
			"expandedSourceAddressPrefix": []any{"10.0.0.0/8", "*"},
		}))
	})
	t.Run("outbound is not ingress", func(t *testing.T) {
		assert.False(t, effectiveRuleAllowsInternetIngress(map[string]any{
			"direction": "Outbound", "access": "Allow", "sourceAddressPrefix": "*",
		}))
	})
	t.Run("deny is not open", func(t *testing.T) {
		assert.False(t, effectiveRuleAllowsInternetIngress(map[string]any{
			"direction": "Inbound", "access": "Deny", "sourceAddressPrefix": "*",
		}))
	})
	t.Run("scoped source is not open", func(t *testing.T) {
		assert.False(t, effectiveRuleAllowsInternetIngress(map[string]any{
			"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "10.0.0.0/8",
		}))
	})
	t.Run("missing keys are not open", func(t *testing.T) {
		assert.False(t, effectiveRuleAllowsInternetIngress(map[string]any{}))
	})
}

func TestPublicNetworkAccessEnabled(t *testing.T) {
	assert.True(t, publicNetworkAccessEnabled("Enabled"))
	assert.True(t, publicNetworkAccessEnabled(""), "empty defaults to enabled")
	assert.True(t, publicNetworkAccessEnabled("enabled"))
	assert.False(t, publicNetworkAccessEnabled("Disabled"))
	assert.False(t, publicNetworkAccessEnabled("disabled"))
}

func TestFirewallRuleAllowsAnyInternet(t *testing.T) {
	cases := []struct {
		start, end string
		want       bool
	}{
		{"0.0.0.0", "0.0.0.0", false},            // allow-all-Azure-services rule, not the public internet
		{"0.0.0.0", "255.255.255.255", true},     // full IPv4 span
		{"0.0.0.0", "128.255.255.255", true},     // wide partial span starting at 0.0.0.0
		{"203.0.113.1", "203.0.113.10", false},   // scoped range
		{"10.0.0.0", "10.255.255.255", false},    // private span
		{"", "", false},                          // empty
		{"0.0.0.0", "", false},                   // open start but no end
		{" 0.0.0.0 ", " 255.255.255.255 ", true}, // trimmed
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, firewallRuleAllowsAnyInternet(c.start, c.end), "%s-%s", c.start, c.end)
	}
}

func TestDatabaseInternetReachable(t *testing.T) {
	t.Run("public access disabled is never reachable", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Disabled", [][2]string{{"0.0.0.0", "255.255.255.255"}}))
	})
	t.Run("public access enabled with open rule is reachable", func(t *testing.T) {
		assert.True(t, databaseInternetReachable("Enabled", [][2]string{{"0.0.0.0", "255.255.255.255"}}))
	})
	t.Run("allow-all-Azure-services rule alone is not reachable", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Enabled", [][2]string{{"0.0.0.0", "0.0.0.0"}}))
	})
	t.Run("public access enabled but only scoped rules is not reachable", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Enabled", [][2]string{{"203.0.113.1", "203.0.113.10"}}))
	})
	t.Run("no firewall rules is not reachable", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Enabled", nil))
	})
}

func TestAksApiServerInternetReachable(t *testing.T) {
	t.Run("public cluster with no allowlist is reachable", func(t *testing.T) {
		assert.True(t, aksApiServerInternetReachable(false, "Enabled", nil))
	})
	t.Run("private cluster is not reachable", func(t *testing.T) {
		assert.False(t, aksApiServerInternetReachable(true, "Enabled", nil))
	})
	t.Run("disabled public access is not reachable", func(t *testing.T) {
		assert.False(t, aksApiServerInternetReachable(false, "Disabled", nil))
	})
	t.Run("authorized IP ranges close exposure", func(t *testing.T) {
		assert.False(t, aksApiServerInternetReachable(false, "Enabled", []string{"203.0.113.0/24"}))
	})
	t.Run("empty publicNetworkAccess defaults to reachable", func(t *testing.T) {
		assert.True(t, aksApiServerInternetReachable(false, "", nil))
	})
}

func TestStorageAccountIsPublic(t *testing.T) {
	t.Run("all gates open is public", func(t *testing.T) {
		assert.True(t, storageAccountIsPublic("Enabled", "Allow", true))
	})
	t.Run("blob public access off is not public", func(t *testing.T) {
		assert.False(t, storageAccountIsPublic("Enabled", "Allow", false))
	})
	t.Run("deny default action is not public", func(t *testing.T) {
		assert.False(t, storageAccountIsPublic("Enabled", "Deny", true))
	})
	t.Run("disabled public network access is not public", func(t *testing.T) {
		assert.False(t, storageAccountIsPublic("Disabled", "Allow", true))
	})
	t.Run("empty default action is treated as not Allow", func(t *testing.T) {
		assert.False(t, storageAccountIsPublic("Enabled", "", true))
	})
}

func TestRuleSourceIsInternet(t *testing.T) {
	assert.True(t, ruleSourceIsInternet(map[string]any{"sourceAddressPrefix": "*"}))
	assert.True(t, ruleSourceIsInternet(map[string]any{"sourceAddressPrefix": "Internet"}))
	assert.True(t, ruleSourceIsInternet(map[string]any{"sourceAddressPrefixes": []any{"10.0.0.0/8", "0.0.0.0/0"}}))
	assert.True(t, ruleSourceIsInternet(map[string]any{"expandedSourceAddressPrefix": []any{"*"}}))
	assert.False(t, ruleSourceIsInternet(map[string]any{"sourceAddressPrefix": "VirtualNetwork"}))
	assert.False(t, ruleSourceIsInternet(map[string]any{"sourceAddressPrefixes": []any{"10.0.0.0/8"}}))
	assert.False(t, ruleSourceIsInternet(map[string]any{}))
}

func TestRuleInt(t *testing.T) {
	v, ok := ruleInt(map[string]any{"priority": float64(100)}, "priority")
	assert.True(t, ok)
	assert.Equal(t, 100, v)
	v, ok = ruleInt(map[string]any{"priority": 200}, "priority")
	assert.True(t, ok)
	assert.Equal(t, 200, v)
	_, ok = ruleInt(map[string]any{"priority": "300"}, "priority")
	assert.False(t, ok, "string priority is not accepted")
	_, ok = ruleInt(map[string]any{}, "priority")
	assert.False(t, ok)
}

func TestRulePortIntervals(t *testing.T) {
	assert.Equal(t, []portInterval{{0, 65535}}, rulePortIntervals(map[string]any{"destinationPortRange": "*"}))
	assert.Equal(t, []portInterval{{22, 22}}, rulePortIntervals(map[string]any{"destinationPortRange": "22"}))
	assert.Equal(t, []portInterval{{80, 443}}, rulePortIntervals(map[string]any{"destinationPortRange": "80-443"}))
	assert.Equal(t, []portInterval{{22, 22}, {443, 443}}, rulePortIntervals(map[string]any{"destinationPortRanges": []any{"22", "443"}}))
	assert.Equal(t, []portInterval{{0, 65535}}, rulePortIntervals(map[string]any{}), "absent ports means all ports")
}

func TestPortsCover(t *testing.T) {
	all := []portInterval{{0, 65535}}
	assert.True(t, portsCover(all, []portInterval{{22, 22}}))
	assert.True(t, portsCover([]portInterval{{20, 30}}, []portInterval{{22, 25}}))
	assert.False(t, portsCover([]portInterval{{20, 30}}, []portInterval{{22, 40}}))
	assert.False(t, portsCover([]portInterval{{80, 80}}, []portInterval{{22, 22}}))
	// allow spanning two deny intervals is not covered (must fall within one)
	assert.False(t, portsCover([]portInterval{{20, 25}, {26, 30}}, []portInterval{{22, 28}}))
}

func TestProtocolCovers(t *testing.T) {
	assert.True(t, protocolCovers("*", "Tcp"))
	assert.True(t, protocolCovers("Any", "Tcp"))
	assert.True(t, protocolCovers("", "Tcp"))
	assert.True(t, protocolCovers("Tcp", "tcp"))
	assert.False(t, protocolCovers("Udp", "Tcp"))
}

func TestDestCovers(t *testing.T) {
	assert.True(t, destCovers(map[string]any{"destinationAddressPrefix": "*"}, map[string]any{"destinationAddressPrefix": "10.0.0.4"}))
	assert.True(t, destCovers(map[string]any{"destinationAddressPrefix": "0.0.0.0/0"}, map[string]any{"destinationAddressPrefix": "10.0.0.4"}))
	assert.True(t, destCovers(map[string]any{"destinationAddressPrefix": "10.0.0.4"}, map[string]any{"destinationAddressPrefix": "10.0.0.4"}))
	assert.True(t, destCovers(map[string]any{"destinationAddressPrefixes": []any{"10.0.0.4"}}, map[string]any{"destinationAddressPrefix": "10.0.0.4"}))
	assert.False(t, destCovers(map[string]any{"destinationAddressPrefix": "10.0.0.5"}, map[string]any{"destinationAddressPrefix": "10.0.0.4"}))
	// allow rule using the plural destination form is read on the allow side too
	assert.True(t, destCovers(map[string]any{"destinationAddressPrefix": "10.0.0.4"}, map[string]any{"destinationAddressPrefixes": []any{"10.0.0.4"}}))
	// every allow destination must be covered; a deny covering only one is not enough
	assert.False(t, destCovers(map[string]any{"destinationAddressPrefix": "10.0.0.4"}, map[string]any{"destinationAddressPrefixes": []any{"10.0.0.4", "10.0.0.5"}}))
	assert.True(t, destCovers(map[string]any{"destinationAddressPrefix": "*"}, map[string]any{"destinationAddressPrefixes": []any{"10.0.0.4", "10.0.0.5"}}))
	// a narrow deny cannot cover an allow that targets all addresses
	assert.False(t, destCovers(map[string]any{"destinationAddressPrefix": "10.0.0.4"}, map[string]any{"destinationAddressPrefix": "*"}))
}

func TestDenyDominatesAllow(t *testing.T) {
	denyAll := map[string]any{"protocol": "*", "destinationPortRange": "*", "destinationAddressPrefix": "*"}
	allowSsh := map[string]any{"protocol": "Tcp", "destinationPortRange": "22", "destinationAddressPrefix": "*"}
	assert.True(t, denyDominatesAllow(denyAll, allowSsh))

	denyOtherPort := map[string]any{"protocol": "*", "destinationPortRange": "80", "destinationAddressPrefix": "*"}
	assert.False(t, denyDominatesAllow(denyOtherPort, allowSsh), "deny on a different port does not shadow")

	denyOtherProto := map[string]any{"protocol": "Udp", "destinationPortRange": "*", "destinationAddressPrefix": "*"}
	assert.False(t, denyDominatesAllow(denyOtherProto, allowSsh), "deny on a different protocol does not shadow")

	denyOtherDest := map[string]any{"protocol": "*", "destinationPortRange": "*", "destinationAddressPrefix": "10.0.0.5"}
	assert.False(t, denyDominatesAllow(denyOtherDest, allowSsh), "deny on a different destination does not shadow")
}

func TestNsgAllowsInternetIngress(t *testing.T) {
	allowSsh := map[string]any{
		"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "*",
		"protocol": "Tcp", "destinationPortRange": "22", "priority": float64(300),
		"destinationAddressPrefix": "*",
	}
	denyAllHigh := map[string]any{
		"direction": "Inbound", "access": "Deny", "sourceAddressPrefix": "*",
		"protocol": "*", "destinationPortRange": "*", "priority": float64(100),
		"destinationAddressPrefix": "*",
	}
	denyAllLow := map[string]any{
		"direction": "Inbound", "access": "Deny", "sourceAddressPrefix": "*",
		"protocol": "*", "destinationPortRange": "*", "priority": float64(4000),
		"destinationAddressPrefix": "*",
	}

	t.Run("allow with no deny is open", func(t *testing.T) {
		open, surviving := nsgAllowsInternetIngress([]map[string]any{allowSsh})
		assert.True(t, open)
		assert.Len(t, surviving, 1)
	})
	t.Run("higher-priority deny-all shadows the allow", func(t *testing.T) {
		open, surviving := nsgAllowsInternetIngress([]map[string]any{allowSsh, denyAllHigh})
		assert.False(t, open)
		assert.Empty(t, surviving)
	})
	t.Run("lower-priority deny-all does not shadow the allow", func(t *testing.T) {
		open, surviving := nsgAllowsInternetIngress([]map[string]any{allowSsh, denyAllLow})
		assert.True(t, open)
		assert.Len(t, surviving, 1)
	})
	t.Run("deny on a different port leaves the allow open", func(t *testing.T) {
		denyHttp := map[string]any{
			"direction": "Inbound", "access": "Deny", "sourceAddressPrefix": "*",
			"protocol": "Tcp", "destinationPortRange": "80", "priority": float64(100),
			"destinationAddressPrefix": "*",
		}
		open, _ := nsgAllowsInternetIngress([]map[string]any{allowSsh, denyHttp})
		assert.True(t, open)
	})
	t.Run("no internet-source rule admits nothing", func(t *testing.T) {
		vnetAllow := map[string]any{
			"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "VirtualNetwork",
			"protocol": "*", "destinationPortRange": "*", "priority": float64(100),
		}
		open, surviving := nsgAllowsInternetIngress([]map[string]any{vnetAllow})
		assert.False(t, open)
		assert.Empty(t, surviving)
	})
	t.Run("deny-internet only admits nothing", func(t *testing.T) {
		open, _ := nsgAllowsInternetIngress([]map[string]any{denyAllHigh})
		assert.False(t, open)
	})
	t.Run("one allow shadowed, another open", func(t *testing.T) {
		allowHttp := map[string]any{
			"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "*",
			"protocol": "Tcp", "destinationPortRange": "443", "priority": float64(200),
			"destinationAddressPrefix": "*",
		}
		denySshHigh := map[string]any{
			"direction": "Inbound", "access": "Deny", "sourceAddressPrefix": "*",
			"protocol": "Tcp", "destinationPortRange": "22", "priority": float64(150),
			"destinationAddressPrefix": "*",
		}
		open, surviving := nsgAllowsInternetIngress([]map[string]any{allowSsh, allowHttp, denySshHigh})
		assert.True(t, open)
		assert.Len(t, surviving, 1, "only the HTTPS allow survives")
	})
}

// --- Exposure verdicts: a read that did not happen reports null ---

// TestResolveExposureVerdicts pins the verdict that a deallocated VM used to
// get wrong. Azure computes effective NSG rules only for a NIC attached to a
// running VM and answers 400 otherwise, so stopping a machine flipped
// internetReachable from true to false while its NSG still allowed 22/tcp from
// anywhere -- and a policy asserting "not reachable from the internet" started
// passing on it. The same 400 comes back for a scanner running as Reader, which
// does not hold the effectiveNetworkSecurityGroups action.
func TestResolveExposureVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  exposureObservations
		want exposureVerdicts
	}{
		{
			name: "unread NSGs on a machine with a public IP leaves reachability unknown",
			obs: exposureObservations{
				hasPublicIp: true, loadBalancersEvaluated: true,
				sgAllowsIngress: false, nsgsEvaluated: false,
			},
			want: exposureVerdicts{
				internetReachable:          exposureVerdict{value: false, known: false},
				behindPublicLoadBalancer:   exposureVerdict{value: false, known: true},
				securityGroupAllowsIngress: exposureVerdict{value: false, known: false},
			},
		},
		{
			name: "evaluated NSGs that admit ingress on a machine with a public IP is reachable",
			obs: exposureObservations{
				hasPublicIp: true, loadBalancersEvaluated: true,
				sgAllowsIngress: true, nsgsEvaluated: true,
			},
			want: exposureVerdicts{
				internetReachable:          exposureVerdict{value: true, known: true},
				behindPublicLoadBalancer:   exposureVerdict{value: false, known: true},
				securityGroupAllowsIngress: exposureVerdict{value: true, known: true},
			},
		},
		{
			name: "evaluated NSGs that deny ingress on a machine with a public IP is not reachable",
			obs: exposureObservations{
				hasPublicIp: true, loadBalancersEvaluated: true,
				sgAllowsIngress: false, nsgsEvaluated: true,
			},
			want: exposureVerdicts{
				internetReachable:          exposureVerdict{value: false, known: true},
				behindPublicLoadBalancer:   exposureVerdict{value: false, known: true},
				securityGroupAllowsIngress: exposureVerdict{value: false, known: true},
			},
		},
		{
			// The NSGs went unread, but nothing can reach the machine in the
			// first place, so the answer is settled without them.
			name: "no public IP and no load balancer is a determined false even with unread NSGs",
			obs: exposureObservations{
				hasPublicIp: false, loadBalancersEvaluated: true,
				sgAllowsIngress: false, nsgsEvaluated: false,
			},
			want: exposureVerdicts{
				internetReachable:          exposureVerdict{value: false, known: true},
				behindPublicLoadBalancer:   exposureVerdict{value: false, known: true},
				securityGroupAllowsIngress: exposureVerdict{value: false, known: false},
			},
		},
		{
			// securityGroupAllowsIngress is an OR across the NICs: one NIC that
			// admits internet ingress settles it however many went unread.
			name: "one NIC admitting ingress settles the OR even with another unread",
			obs: exposureObservations{
				hasPublicIp: true, loadBalancersEvaluated: true,
				sgAllowsIngress: true, nsgsEvaluated: false,
			},
			want: exposureVerdicts{
				internetReachable:          exposureVerdict{value: true, known: true},
				behindPublicLoadBalancer:   exposureVerdict{value: false, known: true},
				securityGroupAllowsIngress: exposureVerdict{value: true, known: true},
			},
		},
		{
			name: "a public load balancer in front of open NSGs is reachable without a public IP",
			obs: exposureObservations{
				hasPublicIp: false, behindPublicLb: true, loadBalancersEvaluated: true,
				sgAllowsIngress: true, nsgsEvaluated: true,
			},
			want: exposureVerdicts{
				internetReachable:          exposureVerdict{value: true, known: true},
				behindPublicLoadBalancer:   exposureVerdict{value: true, known: true},
				securityGroupAllowsIngress: exposureVerdict{value: true, known: true},
			},
		},
		{
			// The load-balancer listing failed, so whether traffic can arrive is
			// unknown and the open NSGs cannot settle it either way.
			name: "unreadable load balancers with no public IP leaves reachability unknown",
			obs: exposureObservations{
				hasPublicIp: false, loadBalancersEvaluated: false,
				sgAllowsIngress: true, nsgsEvaluated: true,
			},
			want: exposureVerdicts{
				internetReachable:          exposureVerdict{value: false, known: false},
				behindPublicLoadBalancer:   exposureVerdict{value: false, known: false},
				securityGroupAllowsIngress: exposureVerdict{value: true, known: true},
			},
		},
		{
			name: "unreadable load balancers with closed NSGs is still a determined false",
			obs: exposureObservations{
				hasPublicIp: false, loadBalancersEvaluated: false,
				sgAllowsIngress: false, nsgsEvaluated: true,
			},
			want: exposureVerdicts{
				internetReachable:          exposureVerdict{value: false, known: true},
				behindPublicLoadBalancer:   exposureVerdict{value: false, known: false},
				securityGroupAllowsIngress: exposureVerdict{value: false, known: true},
			},
		},
		{
			name: "nothing readable at all on a machine with a public IP is unknown",
			obs: exposureObservations{
				hasPublicIp: true, loadBalancersEvaluated: false,
				sgAllowsIngress: false, nsgsEvaluated: false,
			},
			want: exposureVerdicts{
				internetReachable:          exposureVerdict{value: false, known: false},
				behindPublicLoadBalancer:   exposureVerdict{value: false, known: false},
				securityGroupAllowsIngress: exposureVerdict{value: false, known: false},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveExposureVerdicts(tc.obs))
		})
	}
}

// TestRawVerdict pins the rendering, which is where a null verdict either
// reaches the user as null or collapses back into the false this whole change
// exists to remove.
func TestRawVerdict(t *testing.T) {
	t.Run("a determined verdict renders its boolean", func(t *testing.T) {
		assert.Equal(t, true, rawVerdict(exposureVerdict{value: true, known: true}).Value)
		assert.Equal(t, false, rawVerdict(exposureVerdict{value: false, known: true}).Value)
	})

	t.Run("an undetermined verdict renders null", func(t *testing.T) {
		assert.Nil(t, rawVerdict(exposureVerdict{value: false, known: false}).Value)

		// and the runtime reads that as set-and-null rather than as false
		tv, ok := plugin.RawToTValue[bool](rawVerdict(exposureVerdict{}).Value, nil)
		require.True(t, ok)
		assert.True(t, tv.IsSet(), "an unset field is a different failure mode from null")
		assert.True(t, tv.IsNull())
		assert.False(t, tv.Data)
	})
}

// --- Effective rules: an unevaluated NIC reports null, not an empty list ---

func newTestNic(runtime *plugin.Runtime, evaluated bool, groups []effectiveNsgGroup) *mqlAzureSubscriptionNetworkServiceInterface {
	nic := &mqlAzureSubscriptionNetworkServiceInterface{
		MqlRuntime: runtime,
		Id:         plugin.TValue[string]{Data: "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic", State: plugin.StateIsSet},
	}
	nic.effNsgLoaded = true
	nic.effNsgEvaluated = evaluated
	nic.effNsgGroups = groups
	return nic
}

// TestEffectiveRulesNullWhenNotEvaluated pins the degrade. Both accessors used
// to discard the "evaluated" flag, and an unset nil slice renders as an empty
// list -- so `effectiveRules.none(access == "Allow" && direction == "Inbound"
// && sourceAddressPrefix == "*")` passed vacuously on every stopped VM and in
// every subscription where the scanning identity cannot read effective NSGs.
func TestEffectiveRulesNullWhenNotEvaluated(t *testing.T) {
	t.Run("raw rules", func(t *testing.T) {
		nic := newTestNic(nil, false, nil)
		res, err := nic.effectiveSecurityRules()
		require.NoError(t, err)
		assert.Nil(t, res)
		assert.True(t, nic.EffectiveSecurityRules.IsSet())
		assert.True(t, nic.EffectiveSecurityRules.IsNull())
	})

	t.Run("typed rules", func(t *testing.T) {
		nic := newTestNic(nil, false, nil)
		res, err := nic.effectiveRules()
		require.NoError(t, err)
		assert.Nil(t, res)
		assert.True(t, nic.EffectiveRules.IsSet())
		assert.True(t, nic.EffectiveRules.IsNull())
	})
}

// TestEffectiveRulesEmptyWhenEvaluated is the other half of the same contract:
// Azure answering with no rules is a real empty list, and must not be reported
// as null. Null and empty mean different things and both have to survive.
func TestEffectiveRulesEmptyWhenEvaluated(t *testing.T) {
	t.Run("raw rules", func(t *testing.T) {
		nic := newTestNic(nil, true, nil)
		res, err := nic.effectiveSecurityRules()
		require.NoError(t, err)
		assert.Equal(t, []any{}, res)
		assert.False(t, nic.EffectiveSecurityRules.IsNull())
	})

	t.Run("typed rules", func(t *testing.T) {
		nic := newTestNic(cacheIDTestRuntime(), true, nil)
		res, err := nic.effectiveRules()
		require.NoError(t, err)
		assert.Equal(t, []any{}, res)
		assert.False(t, nic.EffectiveRules.IsNull())
	})
}

// TestEffectiveRulesReturnedWhenEvaluated pins that the degrade guard did not
// swallow the ordinary path.
func TestEffectiveRulesReturnedWhenEvaluated(t *testing.T) {
	groups := []effectiveNsgGroup{{
		nsgID: "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg",
		rules: []map[string]any{{
			"name": "AllowSshFromAnywhere", "direction": "Inbound", "access": "Allow",
			"protocol": "Tcp", "destinationPortRange": "22", "sourceAddressPrefix": "*",
			"priority": float64(300),
		}},
	}}

	t.Run("raw rules", func(t *testing.T) {
		nic := newTestNic(nil, true, groups)
		res, err := nic.effectiveSecurityRules()
		require.NoError(t, err)
		require.Len(t, res, 1)
		assert.Equal(t, "AllowSshFromAnywhere", res[0].(map[string]any)["name"])
		assert.False(t, nic.EffectiveSecurityRules.IsNull())
	})

	t.Run("typed rules", func(t *testing.T) {
		nic := newTestNic(cacheIDTestRuntime(), true, groups)
		res, err := nic.effectiveRules()
		require.NoError(t, err)
		require.Len(t, res, 1)
		rule := res[0].(*mqlAzureSubscriptionNetworkServiceInterfaceEffectiveSecurityRule)
		assert.Equal(t, "AllowSshFromAnywhere", rule.Name.Data)
		assert.Equal(t, "*", rule.SourceAddressPrefix.Data)
		assert.False(t, nic.EffectiveRules.IsNull())
	})
}

// --- Database firewall rules are judged as a union ---

// TestNonRoutableIPv4Blocks pins the discount table the coverage measure is
// built on. The entries are parsed from strings, and a typo drops one silently
// -- which moves the threshold without touching any of the logic around it.
func TestNonRoutableIPv4Blocks(t *testing.T) {
	assert.Len(t, nonRoutableIPv4Blocks, 15, "an entry that fails to parse is dropped, not reported")
	assert.Equal(t, uint64(3702258432), routableIPv4Total)

	for i := 1; i < len(nonRoutableIPv4Blocks); i++ {
		assert.Greaterf(t, nonRoutableIPv4Blocks[i].lo, nonRoutableIPv4Blocks[i-1].hi,
			"blocks must be ascending and disjoint, or the total double-counts at index %d", i)
	}
}

func TestMergeIPv4Ranges(t *testing.T) {
	t.Run("the two halves coalesce into the whole space", func(t *testing.T) {
		assert.Equal(t, []ipRange{{0, math.MaxUint32}}, mergeIPv4Ranges([]ipRange{
			{0, 2147483647}, {2147483648, math.MaxUint32},
		}))
	})
	t.Run("touching ranges merge", func(t *testing.T) {
		assert.Equal(t, []ipRange{{10, 30}}, mergeIPv4Ranges([]ipRange{{10, 20}, {21, 30}}))
	})
	t.Run("a one-address gap does not merge", func(t *testing.T) {
		assert.Equal(t, []ipRange{{10, 20}, {22, 30}}, mergeIPv4Ranges([]ipRange{{22, 30}, {10, 20}}))
	})
	t.Run("a contained range is absorbed", func(t *testing.T) {
		assert.Equal(t, []ipRange{{10, 100}}, mergeIPv4Ranges([]ipRange{{10, 100}, {20, 30}}))
	})
	t.Run("inverted ranges admit nothing and are dropped", func(t *testing.T) {
		assert.Nil(t, mergeIPv4Ranges([]ipRange{{30, 10}}))
		assert.Empty(t, mergeIPv4Ranges(nil))
	})
	t.Run("the caller's slice is not reordered", func(t *testing.T) {
		in := []ipRange{{10, 20}, {0, 5}}
		mergeIPv4Ranges(in)
		assert.Equal(t, []ipRange{{10, 20}, {0, 5}}, in, "the input is often a resource's own rule list")
	})
}

func TestIPv4RoutableCoverage(t *testing.T) {
	whole := []ipRange{{0, math.MaxUint32}}
	assert.Equal(t, routableIPv4Total, ipv4RoutableCoverage(whole))

	// 10.0.0.0/8 is private: a rule spanning it admits nothing on the internet
	assert.Equal(t, uint64(0), ipv4RoutableCoverage([]ipRange{{167772160, 184549375}}))

	// 20.10.0.0/24, an ordinary public /24
	assert.Equal(t, uint64(256), ipv4RoutableCoverage([]ipRange{{336855040, 336855295}}))

	assert.Equal(t, uint64(0), ipv4RoutableCoverage(nil))
}

// TestDatabaseFirewallRangesJudgedAsUnion is the case that was live-confirmed
// on an Azure SQL server: five rules, no catch-all, and between them every
// address on the internet. Each rule was judged on its own, none of them
// reached the threshold, and the server reported internetReachable: false.
func TestDatabaseFirewallRangesJudgedAsUnion(t *testing.T) {
	thirds := [][2]string{
		{"0.0.0.0", "84.255.255.255"},
		{"85.0.0.0", "169.255.255.255"},
		{"170.0.0.0", "255.255.255.255"},
	}

	t.Run("no single third is open on its own", func(t *testing.T) {
		for _, r := range thirds {
			assert.Falsef(t, firewallRuleAllowsAnyInternet(r[0], r[1]), "%s-%s", r[0], r[1])
		}
	})
	t.Run("the three together are the whole internet", func(t *testing.T) {
		assert.True(t, databaseInternetReachable("Enabled", thirds))
	})
	t.Run("the live rule set, sentinel and overlap included", func(t *testing.T) {
		live := append([][2]string{}, thirds...)
		live = append(live,
			[2]string{"1.0.0.0", "127.255.255.255"}, // overlaps the first two thirds
			[2]string{"0.0.0.0", "0.0.0.0"},         // the allow-all-Azure-services sentinel
		)
		assert.True(t, databaseInternetReachable("Enabled", live))
	})
	t.Run("public network access disabled still wins over the union", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Disabled", thirds))
	})

	t.Run("two adjacent halves are the whole internet", func(t *testing.T) {
		assert.True(t, databaseInternetReachable("Enabled", [][2]string{
			{"0.0.0.0", "127.255.255.255"}, {"128.0.0.0", "255.255.255.255"},
		}))
	})
	t.Run("the upper half alone is not", func(t *testing.T) {
		assert.False(t, firewallRuleAllowsAnyInternet("128.0.0.0", "255.255.255.255"))
	})

	// half the internet written without touching 0.0.0.0/8, which a raw
	// half-of-IPv4 threshold scored as an allowlist by 16.7 million addresses
	t.Run("1.0.0.0 to 127.255.255.255 alone is open", func(t *testing.T) {
		assert.True(t, firewallRuleAllowsAnyInternet("1.0.0.0", "127.255.255.255"))
		assert.True(t, databaseInternetReachable("Enabled", [][2]string{{"1.0.0.0", "127.255.255.255"}}))
	})

	t.Run("the allow-all-Azure-services sentinel alone is not exposure", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Enabled", [][2]string{{"0.0.0.0", "0.0.0.0"}}))
	})
	t.Run("an office allowlist is not exposure", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Enabled", [][2]string{
			{"20.10.0.0", "20.10.0.255"}, {"52.1.2.0", "52.1.2.255"},
		}))
	})
	t.Run("private ranges do not accumulate into exposure", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Enabled", [][2]string{
			{"10.0.0.0", "10.255.255.255"},
			{"172.16.0.0", "172.31.255.255"},
			{"192.168.0.0", "192.168.255.255"},
			{"127.0.0.0", "127.255.255.255"},
		}))
	})
}

// TestFirewallRangeSets pins the split that feeds the union, including the
// pairs that describe no coherent range at all. A pair that survived
// mis-classified would be summed into the coverage measure.
func TestFirewallRangeSets(t *testing.T) {
	v4, v6 := firewallRangeSets([][2]string{
		{"1.2.3.4", "1.2.3.5"},
		{"::", "::ffff"},
		{"0.0.0.0", ""},                      // unparseable end
		{"not-an-address", "1.2.3.4"},        // unparseable start
		{"1.2.3.5", "1.2.3.4"},               // inverted
		{"::2", "::1"},                       // inverted, IPv6
		{"0.0.0.0", "ffff::"},                // mixed families
		{"::ffff:0.0.0.0", "::ffff:1.2.3.4"}, // IPv4-mapped is not the IPv6 internet
	})
	assert.Equal(t, []ipRange{{16909060, 16909061}}, v4)
	require.Len(t, v6, 1)
	assert.Equal(t, "0", v6[0].lo.String())
	assert.Equal(t, "65535", v6[0].hi.String())
}

// TestMergeIPv6RangesSkipsNilBounds guards against a panic, not a wrong answer.
// big.Int methods dereference their receiver, so a zero-value ipv6Range reaching
// the Cmp in mergeIPv6Ranges would panic, and a panic in provider code takes down
// the entire scan rather than one field. Every production range is built by
// firewallRangeSets with non-nil bounds, so this pins the precondition for any
// future caller.
func TestMergeIPv6RangesSkipsNilBounds(t *testing.T) {
	full := ipv6Range{lo: big.NewInt(0), hi: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))}

	cases := []struct {
		name   string
		ranges []ipv6Range
	}{
		{"zero value", []ipv6Range{{}}},
		{"nil lo only", []ipv6Range{{lo: nil, hi: big.NewInt(10)}}},
		{"nil hi only", []ipv6Range{{lo: big.NewInt(10), hi: nil}}},
		{"nil beside a real range", []ipv6Range{{}, full}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() { mergeIPv6Ranges(tc.ranges) })
			require.NotPanics(t, func() { ipv6RangesAdmitInternet(tc.ranges) })
		})
	}

	// A malformed neighbour must not swallow a range that is genuinely there:
	// the full-space range still has to be merged and still has to read as open.
	merged := mergeIPv6Ranges([]ipv6Range{{}, full})
	require.Len(t, merged, 1)
	assert.Equal(t, 0, merged[0].lo.Cmp(full.lo))
	assert.Equal(t, 0, merged[0].hi.Cmp(full.hi))
	assert.True(t, ipv6RangesAdmitInternet([]ipv6Range{{}, full}))

	// A list with nothing usable in it admits nothing.
	assert.False(t, ipv6RangesAdmitInternet([]ipv6Range{{}}))
}

// TestIPv6RangesAdmitInternet mirrors the IPv4 union for the family Azure keeps
// in a rule list of its own.
func TestIPv6RangesAdmitInternet(t *testing.T) {
	halves := [][2]string{
		{"::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"8000::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}
	t.Run("the two IPv6 halves together are open", func(t *testing.T) {
		assert.True(t, databaseInternetReachable("Enabled", halves))
	})
	t.Run("a documentation prefix is not", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Enabled", [][2]string{{"2001:db8::", "2001:db8::ffff"}}))
	})
	t.Run("quarters of the space sum to half", func(t *testing.T) {
		assert.True(t, databaseInternetReachable("Enabled", [][2]string{
			{"::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
			{"4000::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		}))
	})
	t.Run("one quarter alone is not half", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Enabled", [][2]string{
			{"::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		}))
	})
	t.Run("overlapping ranges are not double counted", func(t *testing.T) {
		assert.False(t, databaseInternetReachable("Enabled", [][2]string{
			{"::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
			{"::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
			{"1000::", "2fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		}))
	})
}

// TestRawOpenIngressRules pins the list form of the same rule. An empty
// openIngressRules on a VM whose NICs could not be read says "nothing admits
// internet traffic here", which is the claim a `.none(...)` check passes on.
func TestRawOpenIngressRules(t *testing.T) {
	rule := map[string]any{"name": "AllowSshFromAnywhere", "access": "Allow"}

	t.Run("nothing evaluated and nothing found is null", func(t *testing.T) {
		assert.Nil(t, rawOpenIngressRules([]any{}, false).Value)
		assert.Nil(t, rawOpenIngressRules(nil, false).Value)
	})
	t.Run("rules found on a readable NIC survive an unreadable sibling", func(t *testing.T) {
		assert.Equal(t, []any{rule}, rawOpenIngressRules([]any{rule}, false).Value)
	})
	t.Run("evaluated and empty is a real empty list", func(t *testing.T) {
		assert.Equal(t, []any{}, rawOpenIngressRules([]any{}, true).Value)
	})
	t.Run("evaluated with rules is the list", func(t *testing.T) {
		assert.Equal(t, []any{rule}, rawOpenIngressRules([]any{rule}, true).Value)
	})
}
