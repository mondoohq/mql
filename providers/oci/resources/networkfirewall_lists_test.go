// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/networkfirewall"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// namedItem stands in for a policy collection member so the selector can be
// tested without building MQL resources.
type namedItem struct{ name string }

func nameOfNamedItem(item any) (string, bool) {
	n, ok := item.(namedItem)
	if !ok {
		return "", false
	}
	return n.name, true
}

func TestOciFirewallSelectByName(t *testing.T) {
	items := []any{
		namedItem{name: "corp"},
		namedItem{name: "vpn"},
		namedItem{name: "guest"},
		"not a named item",
	}

	t.Run("selects the named members in collection order", func(t *testing.T) {
		got := ociFirewallSelectByName(items, []string{"guest", "corp"}, nameOfNamedItem)
		assert.Equal(t, []any{namedItem{name: "corp"}, namedItem{name: "guest"}}, got)
	})

	t.Run("no names selects nothing", func(t *testing.T) {
		assert.Empty(t, ociFirewallSelectByName(items, nil, nameOfNamedItem))
	})

	t.Run("matching is case insensitive", func(t *testing.T) {
		got := ociFirewallSelectByName(items, []string{"CORP"}, nameOfNamedItem)
		assert.Equal(t, []any{namedItem{name: "corp"}}, got)
	})

	t.Run("a name with no member selects nothing", func(t *testing.T) {
		assert.Empty(t, ociFirewallSelectByName(items, []string{"absent"}, nameOfNamedItem))
	})

	t.Run("members of an unexpected type are skipped, not asserted on", func(t *testing.T) {
		// A bare type assertion here would panic inside a builtin and take the
		// whole scan down with it.
		assert.NotPanics(t, func() {
			ociFirewallSelectByName(items, []string{"corp"}, nameOfNamedItem)
		})
	})
}

func TestOciOptionalInt(t *testing.T) {
	t.Run("absent stays null", func(t *testing.T) {
		// Zero is a real ICMP code (echo reply), so an absent code rendered as
		// 0 would be both wrong and entirely plausible.
		assert.Nil(t, ociOptionalInt(nil).Value)
	})

	t.Run("zero is preserved as zero", func(t *testing.T) {
		zero := 0
		assert.Equal(t, int64(0), ociOptionalInt(&zero).Value)
	})

	t.Run("a value is carried through", func(t *testing.T) {
		code := 3
		assert.Equal(t, int64(3), ociOptionalInt(&code).Value)
	})
}

func TestOciFirewallApplicationFields(t *testing.T) {
	code := 3

	t.Run("ICMP", func(t *testing.T) {
		fields := ociFirewallApplicationFields(networkfirewall.IcmpApplicationSummary{
			Name:     new("ping"),
			IcmpType: new(8),
			IcmpCode: &code,
		})
		require.NotNil(t, fields)
		assert.Equal(t, "ping", fields["name"].Value)
		assert.Equal(t, "ICMP", fields["type"].Value)
		assert.Equal(t, int64(8), fields["icmpType"].Value)
		assert.Equal(t, int64(3), fields["icmpCode"].Value)
	})

	t.Run("ICMP6", func(t *testing.T) {
		fields := ociFirewallApplicationFields(networkfirewall.Icmp6ApplicationSummary{
			Name:     new("ping6"),
			IcmpType: new(128),
		})
		require.NotNil(t, fields)
		assert.Equal(t, "ICMP6", fields["type"].Value)
		assert.Nil(t, fields["icmpCode"].Value, "an absent code must not become code 0")
	})

	t.Run("an unknown member is not classified", func(t *testing.T) {
		// nil is how the flattener reports "I do not know this member". The
		// caller turns that into an error rather than dropping the application,
		// which would leave a rule naming it resolving to nothing.
		assert.Nil(t, ociFirewallApplicationFields(nil))
	})
}

// ----- SDK union drift -----
//
// A member added by an SDK upgrade keeps compiling. The flatteners now error
// on one rather than dropping it, so it is loud at runtime - but an error found
// during a scan is still worse than one found at build time. These tests drive
// the discriminators from the SDK's own enum helpers, so a new member fails the
// build without anyone having to remember to update them.

func TestNetworkFirewallServiceUnionMembers(t *testing.T) {
	// portRanges names TcpService and UdpService explicitly and errors on
	// anything else. If the SDK grows a third transport, this fails and the
	// switch needs the new arm.
	handled := map[string]bool{
		"TCP_SERVICE": true,
		"UDP_SERVICE": true,
	}

	values := networkfirewall.GetServiceTypeEnumStringValues()
	require.NotEmpty(t, values, "the SDK enum helper returned nothing; the drift check would pass vacuously")

	for _, value := range values {
		assert.Truef(t, handled[value],
			"networkfirewall.ServiceType %q is not handled by portRanges; add it to the switch", value)
	}
}

func TestNetworkFirewallNatRuleUnionMembers(t *testing.T) {
	// natRules asserts NatV4NatSummary and errors on anything else.
	handled := map[string]bool{"NATV4": true}

	values := networkfirewall.GetNatTypeEnumStringValues()
	require.NotEmpty(t, values, "the SDK enum helper returned nothing; the drift check would pass vacuously")

	for _, value := range values {
		assert.Truef(t, handled[value],
			"networkfirewall.NatType %q is not handled by natRules; add it to the type switch", value)
	}
}

func TestNetworkFirewallTunnelInspectionUnionMembers(t *testing.T) {
	// tunnelInspectionRules asserts VxlanInspectionRuleSummary and hardcodes
	// the protocol string, so a second protocol needs both changed.
	handled := map[string]bool{"VXLAN": true}

	values := networkfirewall.GetTunnelInspectionProtocolEnumStringValues()
	require.NotEmpty(t, values, "the SDK enum helper returned nothing; the drift check would pass vacuously")

	for _, value := range values {
		assert.Truef(t, handled[value],
			"networkfirewall.TunnelInspectionProtocol %q is not handled by tunnelInspectionRules", value)
	}
}

func TestNetworkFirewallApplicationUnionMembers(t *testing.T) {
	// Unlike the three unions above, ApplicationSummary has no discriminator
	// enum in the SDK: it is an interface whose polymorphic unmarshaller
	// switches on a bare string, and Go cannot enumerate an interface's
	// implementations at runtime. So this set is pinned, not derived.
	//
	// That means the test proves each known member is classified, and does NOT
	// prove the SDK has not added a third. It is a regression guard, not a
	// drift guard. The drift check for this union is manual: re-read
	// application_summary.go's UnmarshalPolymorphicJSON on an SDK bump.
	members := map[string]networkfirewall.ApplicationSummary{
		"ICMP":    networkfirewall.IcmpApplicationSummary{Name: new("a"), IcmpType: new(8)},
		"ICMP_V6": networkfirewall.Icmp6ApplicationSummary{Name: new("b"), IcmpType: new(128)},
	}

	for discriminator, member := range members {
		t.Run(discriminator, func(t *testing.T) {
			fields := ociFirewallApplicationFields(member)
			require.NotNilf(t, fields,
				"member for discriminator %q is not classified by the flattener", discriminator)
			assert.NotEmpty(t, fields["type"].Value, "a classified member must report its type")
		})
	}
}
