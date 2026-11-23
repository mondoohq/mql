// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	nftypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// ===== natGateways =====

// A firewall with no NAT gateway mappings reports an empty list rather than
// null, so a policy can count the gateways without a null guard.
func TestFirewallNatGatewaysEmptyWhenNoMappings(t *testing.T) {
	f := &mqlAwsNetworkfirewallFirewall{}
	got, err := f.natGateways()
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.NotNil(t, got)
}

// The mapping list can carry a blank id, which would otherwise resolve to a
// gateway lookup that cannot succeed.
func TestFirewallNatGatewaysSkipsEmptyIds(t *testing.T) {
	f := &mqlAwsNetworkfirewallFirewall{}
	f.cacheNatGatewayIds = []string{"", ""}
	got, err := f.natGateways()
	require.NoError(t, err)
	assert.Empty(t, got)
}

// Synthetic: the shape follows the networkfirewall v1.82.0 FirewallStatus model;
// no proxy mode firewall was available to measure. NAT gateway ids moved from
// Firewall.NatGatewayMappings to the per-zone sync states, so the accessor must
// read them from there, dedupe a gateway reported by two zones, skip blank ids,
// and return a stable order whatever order the map iterates in.
func TestFirewallNatGatewayIds(t *testing.T) {
	assert.Equal(t, []string{}, firewallNatGatewayIds(nil))
	assert.Equal(t, []string{}, firewallNatGatewayIds(&nftypes.FirewallStatus{}))

	status := &nftypes.FirewallStatus{
		SyncStates: map[string]nftypes.SyncState{
			"us-east-1b": {NatGatewayAttachments: []nftypes.NatGatewayAttachment{
				{NatGatewayId: aws.String("nat-bbb")},
				{NatGatewayId: aws.String("nat-shared")},
			}},
			"us-east-1a": {NatGatewayAttachments: []nftypes.NatGatewayAttachment{
				{NatGatewayId: aws.String("nat-aaa")},
				{NatGatewayId: aws.String("")},
				{NatGatewayId: nil},
				{NatGatewayId: aws.String("nat-shared")},
			}},
			"us-east-1c": {},
		},
	}
	for range 20 {
		assert.Equal(t, []string{"nat-aaa", "nat-shared", "nat-bbb"}, firewallNatGatewayIds(status))
	}
}

func TestNfAddressesToRaw(t *testing.T) {
	// Synthetic: SourceIPRanges omitted means "the firewall's VPC CIDRs", which
	// must read as null and not as the empty list "validate nothing".
	t.Run("absent source ranges are null", func(t *testing.T) {
		raw := nfAddressesToRaw(nil, true)
		assert.Same(t, llx.NilData, raw)
	})
	// Synthetic: an explicitly empty list stays an empty list.
	t.Run("empty source ranges are empty", func(t *testing.T) {
		raw := nfAddressesToRaw([]nftypes.Address{}, true)
		require.NotSame(t, llx.NilData, raw)
		assert.Equal(t, []any{}, raw.Value)
	})
	// Synthetic: bypass ranges have no omitted-vs-empty distinction.
	t.Run("absent bypass ranges are empty", func(t *testing.T) {
		raw := nfAddressesToRaw(nil, false)
		assert.Equal(t, []any{}, raw.Value)
	})
	// Synthetic: entries without a definition are dropped.
	t.Run("definitions are kept in order", func(t *testing.T) {
		raw := nfAddressesToRaw([]nftypes.Address{
			{AddressDefinition: aws.String("10.0.0.0/16")},
			{},
			{AddressDefinition: aws.String("2001:db8::/32")},
		}, true)
		assert.Equal(t, []any{"10.0.0.0/16", "2001:db8::/32"}, raw.Value)
	})
}
