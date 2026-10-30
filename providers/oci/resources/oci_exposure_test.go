// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/stretchr/testify/assert"
)

func TestOciCidrIsAny(t *testing.T) {
	cases := []struct {
		cidr string
		want bool
	}{
		{"0.0.0.0/0", true},
		{"::/0", true},
		{" 0.0.0.0/0 ", true},
		{"10.0.0.0/8", false},
		{"0.0.0.0", false}, // bare wildcard is not a CIDR route
		{"", false},
	}
	for _, c := range cases {
		if got := ociCidrIsAny(c.cidr); got != c.want {
			t.Errorf("ociCidrIsAny(%q) = %v, want %v", c.cidr, got, c.want)
		}
	}
}

func TestOciNsgRuleOpensIngress(t *testing.T) {
	cases := []struct {
		name string
		rule map[string]any
		want bool
	}{
		{"ingress cidr any", map[string]any{"direction": "INGRESS", "sourceType": "CIDR_BLOCK", "source": "0.0.0.0/0"}, true},
		{"ingress cidr any v6", map[string]any{"direction": "INGRESS", "sourceType": "CIDR_BLOCK", "source": "::/0"}, true},
		{"ingress cidr specific", map[string]any{"direction": "INGRESS", "sourceType": "CIDR_BLOCK", "source": "1.2.3.4/32"}, false},
		{"egress cidr any", map[string]any{"direction": "EGRESS", "sourceType": "CIDR_BLOCK", "source": "0.0.0.0/0"}, false},
		{"ingress nsg source", map[string]any{"direction": "INGRESS", "sourceType": "NETWORK_SECURITY_GROUP", "source": "ocid1.nsg"}, false},
		{"ingress service source", map[string]any{"direction": "INGRESS", "sourceType": "SERVICE_CIDR_BLOCK", "source": "all-services"}, false},
		{"missing sourceType but any cidr", map[string]any{"direction": "INGRESS", "source": "0.0.0.0/0"}, true},
		{"empty", map[string]any{}, false},

		// The dict list mirrors the security rule resources, so it has to agree
		// with them about which protocols reach a service port.
		{"ingress tcp any", map[string]any{"direction": "INGRESS", "source": "0.0.0.0/0", "protocol": "6"}, true},
		{"ingress udp any", map[string]any{"direction": "INGRESS", "source": "0.0.0.0/0", "protocol": "17"}, true},
		{"ingress all protocols any", map[string]any{"direction": "INGRESS", "source": "0.0.0.0/0", "protocol": "all"}, true},
		{"ingress icmp any", map[string]any{"direction": "INGRESS", "source": "0.0.0.0/0", "protocol": "1"}, false},
		{"ingress icmpv6 any", map[string]any{"direction": "INGRESS", "source": "0.0.0.0/0", "protocol": "58"}, false},
		{"ingress unknown protocol any", map[string]any{"direction": "INGRESS", "source": "0.0.0.0/0", "protocol": "not-a-protocol"}, true},
	}
	for _, c := range cases {
		if got := ociNsgRuleOpensIngress(c.rule); got != c.want {
			t.Errorf("ociNsgRuleOpensIngress(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOciNsgIngressVerdict(t *testing.T) {
	open := map[string]any{"direction": "INGRESS", "sourceType": "CIDR_BLOCK", "source": "0.0.0.0/0"}
	specific := map[string]any{"direction": "INGRESS", "sourceType": "CIDR_BLOCK", "source": "1.2.3.4/32"}

	cases := []struct {
		name          string
		sets          [][]map[string]any
		wantAllows    bool
		wantOpenCount int
	}{
		{"no NSG attached is open", nil, true, 0},
		{"empty outer slice is open", [][]map[string]any{}, true, 0},
		{"one NSG with empty rule list is closed", [][]map[string]any{{}}, false, 0},
		{"one NSG only specific rules is closed", [][]map[string]any{{specific}}, false, 0},
		{"one NSG with an any-address rule is open", [][]map[string]any{{open}}, true, 1},
		{"two NSGs one empty one open is open", [][]map[string]any{{}, {open}}, true, 1},
		{"two NSGs both closed is closed", [][]map[string]any{{specific}, {}}, false, 0},
	}
	for _, c := range cases {
		openRules, allows := ociNsgIngressVerdict(c.sets)
		if allows != c.wantAllows {
			t.Errorf("ociNsgIngressVerdict(%s) allows = %v, want %v", c.name, allows, c.wantAllows)
		}
		if len(openRules) != c.wantOpenCount {
			t.Errorf("ociNsgIngressVerdict(%s) openRules len = %d, want %d", c.name, len(openRules), c.wantOpenCount)
		}
	}
}

func TestOciSecurityListRuleOpensIngress(t *testing.T) {
	cases := []struct {
		name string
		rule map[string]any
		want bool
	}{
		{"any cidr", map[string]any{"sourceType": "CIDR_BLOCK", "source": "0.0.0.0/0"}, true},
		{"any cidr v6", map[string]any{"sourceType": "CIDR_BLOCK", "source": "::/0"}, true},
		{"specific cidr", map[string]any{"sourceType": "CIDR_BLOCK", "source": "1.2.3.4/32"}, false},
		{"service source", map[string]any{"sourceType": "SERVICE_CIDR_BLOCK", "source": "all-services"}, false},
		{"missing sourceType but any cidr", map[string]any{"source": "0.0.0.0/0"}, true},
		{"empty", map[string]any{}, false},

		// OCI's default VCN security list ships an SSH rule and an ICMP type 3
		// code 4 rule, both from 0.0.0.0/0. Only the first opens a port.
		{"default ssh rule", map[string]any{"sourceType": "CIDR_BLOCK", "source": "0.0.0.0/0", "protocol": "6"}, true},
		{"default path mtu discovery rule", map[string]any{"sourceType": "CIDR_BLOCK", "source": "0.0.0.0/0", "protocol": "1"}, false},
		{"every protocol", map[string]any{"sourceType": "CIDR_BLOCK", "source": "0.0.0.0/0", "protocol": "all"}, true},
	}
	for _, c := range cases {
		if got := ociSecurityListRuleOpensIngress(c.rule); got != c.want {
			t.Errorf("ociSecurityListRuleOpensIngress(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOciCollectOpenSecurityListRulesEmptyIsOpen(t *testing.T) {
	// No security list resolvable falls back to OCI's default open posture,
	// mirroring the network security group "no firewall == open" convention.
	typedOpen, dictOpen, allows, err := ociCollectOpenSecurityListRules(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allows {
		t.Errorf("empty security list set should admit ingress (absent == open)")
	}
	if len(typedOpen) != 0 {
		t.Errorf("empty security list set should surface no open rules, got %d", len(typedOpen))
	}
	if len(dictOpen) != 0 {
		t.Errorf("empty security list set should surface no open rule dicts, got %d", len(dictOpen))
	}
}

func TestOciIngressOpen(t *testing.T) {
	cases := []struct {
		name           string
		nsgOpenRules   int
		securityListOK bool
		want           bool
	}{
		{"nsg opens", 2, false, true},
		{"security list opens", 0, true, true},
		{"both open", 1, true, true},
		{"neither opens", 0, false, false},
	}
	for _, c := range cases {
		if got := ociIngressOpen(c.nsgOpenRules, c.securityListOK); got != c.want {
			t.Errorf("ociIngressOpen(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOciAnySubnetReachable(t *testing.T) {
	cases := []struct {
		name  string
		gates []ociSubnetGate
		want  bool
	}{
		{"no subnets", nil, false},
		{"single subnet permits and routes", []ociSubnetGate{{prohibitsIngress: false, routesToInternet: true}}, true},
		{"single subnet permits but no route", []ociSubnetGate{{prohibitsIngress: false, routesToInternet: false}}, false},
		{"single subnet routes but prohibits", []ociSubnetGate{{prohibitsIngress: true, routesToInternet: true}}, false},
		// Regression: independent aggregation would have combined subnet A's
		// ingress with subnet B's route into a false positive. The conjunction is
		// per subnet, so neither subnet alone makes the resource reachable.
		{
			"permit-only subnet plus route-only subnet is not reachable",
			[]ociSubnetGate{
				{prohibitsIngress: false, routesToInternet: false},
				{prohibitsIngress: true, routesToInternet: true},
			},
			false,
		},
		{
			"one fully reachable subnet among others is reachable",
			[]ociSubnetGate{
				{prohibitsIngress: true, routesToInternet: true},
				{prohibitsIngress: false, routesToInternet: true},
			},
			true,
		},
	}
	for _, c := range cases {
		if got := ociAnySubnetReachable(c.gates); got != c.want {
			t.Errorf("ociAnySubnetReachable(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOciWhitelistOpensInternet(t *testing.T) {
	cases := []struct {
		name   string
		ranges []any
		want   bool
	}{
		{"contains any cidr", []any{"1.2.3.4", "0.0.0.0/0"}, true},
		{"contains bare wildcard", []any{"0.0.0.0"}, true},
		{"contains v6 any", []any{"::/0"}, true},
		{"only specific", []any{"1.2.3.4", "10.0.0.0/8"}, false},
		{"empty denies (ACL on)", []any{}, false},
		{"non-string entries ignored", []any{42, "1.2.3.4"}, false},
	}
	for _, c := range cases {
		if got := ociWhitelistOpensInternet(c.ranges); got != c.want {
			t.Errorf("ociWhitelistOpensInternet(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestOciProtocolOpensServicePort pins which protocols count as an opening.
//
// The bug: the ingress predicate never read the protocol at all. OCI's default
// VCN security list ships two 0.0.0.0/0 ingress rules, TCP 22 and ICMP type 3
// code 4 for Path MTU Discovery, and Oracle documents keeping the ICMP one on
// hardened subnets. A subnet with SSH removed therefore reported
// securityListAllowsIngress true on the strength of the ICMP rule alone, so the
// field could not distinguish it from a subnet with SSH open to the world.
func TestOciProtocolOpensServicePort(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		want     bool
	}{
		{"tcp", "6", true},
		{"udp", "17", true},
		{"every protocol", "all", true},
		{"every protocol in capitals", "ALL", true},

		// ICMP carries no port, so it exposes no service to reach.
		{"icmp", "1", false},
		{"icmpv6", "58", false},
		{"icmp with surrounding space", " 1 ", false},

		// A protocol that could not be read is an unknown, and an unknown must
		// fail toward reachable. Reading it as closed would report a resource
		// as protected on the strength of a value nobody understood.
		{"absent", "", true},
		{"unparseable", "not-a-protocol", true},
		{"a number that is not a protocol we name", "47", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ociProtocolOpensServicePort(c.protocol))
		})
	}
}

// TestOciRuleValuesOpenIngressProtocolAndPorts covers the predicate over rules
// adapted from the SDK shapes, so the port options a real rule carries are part
// of the input rather than assumed away.
func TestOciRuleValuesOpenIngressProtocolAndPorts(t *testing.T) {
	// ingress builds a security list ingress rule the way the adapter does.
	ingress := func(protocol, source string, ports *core.PortRange) ociIngressRuleValues {
		rule := core.IngressSecurityRule{
			Protocol:   new(protocol),
			Source:     new(source),
			SourceType: core.IngressSecurityRuleSourceTypeCidrBlock,
		}
		if ports != nil {
			rule.TcpOptions = &core.TcpOptions{DestinationPortRange: ports}
		}
		return ociIngressValuesOf(securityRuleFromIngress(rule))
	}
	port := func(min, max int) *core.PortRange {
		return &core.PortRange{Min: new(min), Max: new(max)}
	}

	t.Run("ssh from anywhere is an opening", func(t *testing.T) {
		assert.True(t, ociRuleValuesOpenIngress(ingress("6", "0.0.0.0/0", port(22, 22))))
	})

	t.Run("a tcp rule stating no port range is an opening", func(t *testing.T) {
		// An absent range covers every port. It is wider than any explicit
		// range, so reading it as "no ports" would clear the widest rules
		// there are.
		assert.True(t, ociRuleValuesOpenIngress(ingress("6", "0.0.0.0/0", nil)))
	})

	t.Run("udp from anywhere is an opening", func(t *testing.T) {
		assert.True(t, ociRuleValuesOpenIngress(ociIngressValuesOf(securityRuleFromIngress(core.IngressSecurityRule{
			Protocol:   new("17"),
			Source:     new("0.0.0.0/0"),
			SourceType: core.IngressSecurityRuleSourceTypeCidrBlock,
			UdpOptions: &core.UdpOptions{DestinationPortRange: port(53, 53)},
		}))))
	})

	t.Run("every protocol from anywhere is an opening", func(t *testing.T) {
		assert.True(t, ociRuleValuesOpenIngress(ingress("all", "0.0.0.0/0", nil)))
	})

	t.Run("path mtu discovery alone is not an opening", func(t *testing.T) {
		// The second rule of OCI's default VCN security list: ICMP type 3
		// code 4 from 0.0.0.0/0, which Oracle documents keeping even on
		// hardened subnets. It reaches no service port.
		pmtu := securityRuleFromIngress(core.IngressSecurityRule{
			Protocol:    new("1"),
			Source:      new("0.0.0.0/0"),
			SourceType:  core.IngressSecurityRuleSourceTypeCidrBlock,
			IcmpOptions: &core.IcmpOptions{Type: new(3), Code: new(4)},
		})
		assert.False(t, ociRuleValuesOpenIngress(ociIngressValuesOf(pmtu)))
	})

	t.Run("icmpv6 alone is not an opening", func(t *testing.T) {
		assert.False(t, ociRuleValuesOpenIngress(ingress("58", "::/0", nil)))
	})

	t.Run("ssh from a single host is not an opening", func(t *testing.T) {
		assert.False(t, ociRuleValuesOpenIngress(ingress("6", "203.0.113.10/32", port(22, 22))))
	})

	t.Run("an unreadable protocol from anywhere is an opening", func(t *testing.T) {
		// OCI states the protocol as a number, never a name, so "tcp" is a
		// value the predicate has no reading of. Fail toward reachable: a
		// protocol nobody could parse must not be the reason a wide-open rule
		// is reported as harmless.
		assert.True(t, ociRuleValuesOpenIngress(ingress("tcp", "0.0.0.0/0", nil)))
	})
}
