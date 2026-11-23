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
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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

// Synthetic: follows the networkfirewall v1.82.0 ListFirewalls model; no
// internet gateway firewall was available to measure. Each ARN keeps the type
// it was listed under, since DescribeFirewall rejects an ARN described with
// the wrong type.
func TestAppendFirewallRefs(t *testing.T) {
	seen := map[string]struct{}{}
	refs := appendFirewallRefs(nil, seen, nftypes.FirewallTypeFirewall, []nftypes.FirewallMetadata{
		{FirewallArn: aws.String("arn:aws:network-firewall:us-east-1:123456789012:firewall/std")},
		{FirewallArn: nil},
		{FirewallArn: aws.String("")},
	})
	refs = appendFirewallRefs(refs, seen, nftypes.FirewallTypeIgwFirewall, []nftypes.FirewallMetadata{
		{FirewallArn: aws.String("arn:aws:network-firewall:us-east-1:123456789012:igw-firewall/igw")},
		// listed again under a second type: the first type is kept
		{FirewallArn: aws.String("arn:aws:network-firewall:us-east-1:123456789012:firewall/std")},
	})
	assert.Equal(t, []nfFirewallRef{
		{arn: "arn:aws:network-firewall:us-east-1:123456789012:firewall/std", fwType: nftypes.FirewallTypeFirewall},
		{arn: "arn:aws:network-firewall:us-east-1:123456789012:igw-firewall/igw", fwType: nftypes.FirewallTypeIgwFirewall},
	}, refs)
}

// Synthetic: both firewall types must be listed, standard first.
func TestNfFirewallTypes(t *testing.T) {
	assert.Equal(t, []nftypes.FirewallType{nftypes.FirewallTypeFirewall, nftypes.FirewallTypeIgwFirewall}, nfFirewallTypes)
}

// Synthetic: an omitted enum such as TransparentFilteringNatScope decodes to
// "" and must read as null, not as an empty string.
func TestNfEnumData(t *testing.T) {
	assert.Same(t, llx.NilData, nfEnumData(""))
	assert.Equal(t, "NAT_ALL", nfEnumData(string(nftypes.TransparentFilteringNatScopeNatAll)).Value)
}

// Synthetic: a firewall without CertificateArn uses a Network Firewall
// managed certificate, so the accessor is null rather than a lookup.
func TestFirewallProxyCertificateNullWhenUnset(t *testing.T) {
	f := &mqlAwsNetworkfirewallFirewall{}
	got, err := f.proxyCertificate()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, f.ProxyCertificate.IsSet())
	assert.True(t, f.ProxyCertificate.IsNull())
}

// Synthetic: VPC and route references resolve a firewall from the cached
// firewall list by ARN; an ARN the list does not hold resolves to nil.
func TestNetworkFirewallByArn(t *testing.T) {
	runtime := cacheRuntime()
	const fwArn = "arn:aws:network-firewall:us-east-1:123456789012:firewall/igw"
	other, err := CreateResource(runtime, ResourceAwsNetworkfirewallFirewall, map[string]*llx.RawData{
		"arn": llx.StringData("arn:aws:network-firewall:us-east-1:123456789012:firewall/other"),
	})
	require.NoError(t, err)
	want, err := CreateResource(runtime, ResourceAwsNetworkfirewallFirewall, map[string]*llx.RawData{
		"arn": llx.StringData(fwArn),
	})
	require.NoError(t, err)
	nf, err := CreateResource(runtime, ResourceAwsNetworkfirewall, map[string]*llx.RawData{})
	require.NoError(t, err)
	nf.(*mqlAwsNetworkfirewall).Firewalls = plugin.TValue[[]any]{Data: []any{other, want}, State: plugin.StateIsSet}

	got, err := networkFirewallByArn(runtime, fwArn)
	require.NoError(t, err)
	assert.Same(t, want, got)

	got, err = networkFirewallByArn(runtime, "arn:aws:network-firewall:us-east-1:999999999999:firewall/foreign")
	require.NoError(t, err)
	assert.Nil(t, got)
}

// Synthetic: follows the networkfirewall v1.81.0 RuleVariables.ContextSets
// model; no context-aware rule group was available to measure. Each context
// set maps to its resource ID list, and a rule group without context sets
// reports an empty map.
func TestRuleGroupContextSets(t *testing.T) {
	runtime := cacheRuntime()
	rg, err := networkfirewallRuleGroupToMql(runtime,
		&nftypes.RuleGroupResponse{RuleGroupArn: aws.String("arn:aws:network-firewall:us-east-1:123456789012:stateful-rulegroup/ctx")},
		&nftypes.RuleGroup{RuleVariables: &nftypes.RuleVariables{
			ContextSets: map[string]nftypes.ContextSet{
				"PROD_VPCS": {Definition: []string{"vpc-1234567890abcdef0", "vpc-0fedcba0987654321"}},
				"WEB_SGS":   {Definition: []string{"sg-1234567890abcdef0"}},
			},
			IPSets: map[string]nftypes.IPSet{"HOME_NET": {Definition: []string{"10.0.0.0/8"}}},
		}},
		"us-east-1")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"PROD_VPCS": []any{"vpc-1234567890abcdef0", "vpc-0fedcba0987654321"},
		"WEB_SGS":   []any{"sg-1234567890abcdef0"},
	}, rg.ContextSets.Data)

	empty, err := networkfirewallRuleGroupToMql(runtime,
		&nftypes.RuleGroupResponse{RuleGroupArn: aws.String("arn:aws:network-firewall:us-east-1:123456789012:stateful-rulegroup/plain")},
		&nftypes.RuleGroup{},
		"us-east-1")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{}, empty.ContextSets.Data)
}
