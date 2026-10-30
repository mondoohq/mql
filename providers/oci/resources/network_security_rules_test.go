// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oracle/oci-go-sdk/v65/core"
)

func portRange(min, max int) *core.PortRange {
	return &core.PortRange{Min: &min, Max: &max}
}

func TestRulePorts(t *testing.T) {
	tests := []struct {
		name                           string
		rule                           securityRule
		srcMin, srcMax, dstMin, dstMax *int
	}{
		{
			name: "tcp destination range only",
			rule: securityRule{
				protocol:   "6",
				tcpOptions: &core.TcpOptions{DestinationPortRange: portRange(22, 22)},
			},
			dstMin: new(22), dstMax: new(22),
		},
		{
			name: "tcp source and destination ranges",
			rule: securityRule{
				protocol: "6",
				tcpOptions: &core.TcpOptions{
					SourcePortRange:      portRange(1024, 65535),
					DestinationPortRange: portRange(443, 443),
				},
			},
			srcMin: new(1024), srcMax: new(65535),
			dstMin: new(443), dstMax: new(443),
		},
		{
			name: "udp options are read when tcp options are absent",
			rule: securityRule{
				protocol:   "17",
				udpOptions: &core.UdpOptions{DestinationPortRange: portRange(53, 53)},
			},
			dstMin: new(53), dstMax: new(53),
		},
		{
			// A rule with no options at all covers every port. The bounds must stay
			// nil so the schema reports null rather than port 0, which would read as
			// a narrow rule when the rule is in fact the widest possible.
			name: "no options yields nil bounds, not zero",
			rule: securityRule{protocol: "all"},
		},
		{
			// tcpOptions present but with no ranges means all TCP ports.
			name: "tcp options without ranges yields nil bounds",
			rule: securityRule{protocol: "6", tcpOptions: &core.TcpOptions{}},
		},
		{
			// ICMP carries no ports; only icmpOptions apply.
			name: "icmp rule has no port bounds",
			rule: securityRule{
				protocol:    "1",
				icmpOptions: &core.IcmpOptions{Type: new(8)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcMin, srcMax, dstMin, dstMax := rulePorts(tt.rule)
			assert.Equal(t, tt.srcMin, srcMin, "sourcePortMin")
			assert.Equal(t, tt.srcMax, srcMax, "sourcePortMax")
			assert.Equal(t, tt.dstMin, dstMin, "destinationPortMin")
			assert.Equal(t, tt.dstMax, dstMax, "destinationPortMax")
		})
	}
}

// A rule carrying both option sets is malformed for OCI (protocol selects one),
// but the accessor must still be deterministic rather than depend on map order.
func TestRulePortsPrefersTcpWhenBothPresent(t *testing.T) {
	_, _, dstMin, dstMax := rulePorts(securityRule{
		tcpOptions: &core.TcpOptions{DestinationPortRange: portRange(22, 22)},
		udpOptions: &core.UdpOptions{DestinationPortRange: portRange(53, 53)},
	})
	assert.Equal(t, new(22), dstMin)
	assert.Equal(t, new(22), dstMax)
}

func TestSecurityRuleFromIngress(t *testing.T) {
	stateless := true
	r := securityRuleFromIngress(core.IngressSecurityRule{
		Protocol:    new("6"),
		Source:      new("0.0.0.0/0"),
		SourceType:  core.IngressSecurityRuleSourceTypeCidrBlock,
		IsStateless: &stateless,
		Description: new("ssh from anywhere"),
		TcpOptions:  &core.TcpOptions{DestinationPortRange: portRange(22, 22)},
	})

	assert.Equal(t, securityRuleIngress, r.direction)
	assert.Equal(t, "6", r.protocol)
	assert.Equal(t, "0.0.0.0/0", r.source)
	assert.Equal(t, "CIDR_BLOCK", r.sourceType)
	assert.True(t, r.stateless)
	assert.Equal(t, "ssh from anywhere", r.description)
	// A security list rule has no destination side and no OCID of its own.
	assert.Empty(t, r.destination)
	assert.Empty(t, r.id)
}

func TestSecurityRuleFromEgress(t *testing.T) {
	r := securityRuleFromEgress(core.EgressSecurityRule{
		Protocol:        new("17"),
		Destination:     new("10.0.0.0/16"),
		DestinationType: core.EgressSecurityRuleDestinationTypeCidrBlock,
		UdpOptions:      &core.UdpOptions{DestinationPortRange: portRange(53, 53)},
	})

	assert.Equal(t, securityRuleEgress, r.direction)
	assert.Equal(t, "10.0.0.0/16", r.destination)
	assert.Equal(t, "CIDR_BLOCK", r.destinationType)
	// Egress rules carry no source side.
	assert.Empty(t, r.source)
	// IsStateless is unset on this rule, which OCI reads as stateful.
	assert.False(t, r.stateless)
}

func TestSecurityRuleFromNsgCarriesDirectionAndId(t *testing.T) {
	r := securityRuleFromNsg(core.SecurityRule{
		Id:        new("ocid1.securityrule.oc1..abc"),
		Direction: core.SecurityRuleDirectionEgress,
		Protocol:  new("6"),
	})

	// Unlike a security list rule, an NSG rule states its own direction and has
	// an OCID, which becomes its cache key instead of a positional fallback.
	assert.Equal(t, "EGRESS", r.direction)
	assert.Equal(t, "ocid1.securityrule.oc1..abc", r.id)
}

func TestPortRangeHelperSanity(t *testing.T) {
	pr := portRange(80, 443)
	require.NotNil(t, pr.Min)
	require.NotNil(t, pr.Max)
	assert.Equal(t, 80, *pr.Min)
	assert.Equal(t, 443, *pr.Max)
}
