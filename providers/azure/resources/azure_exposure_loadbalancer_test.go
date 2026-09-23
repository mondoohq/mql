// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	lbID              = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb"
	publicFrontendID  = lbID + "/frontendIPConfigurations/public"
	privateFrontendID = lbID + "/frontendIPConfigurations/internal"
	backendPool       = lbID + "/backendAddressPools/pool"
	otherPool         = lbID + "/backendAddressPools/other"
	vmIPConfig        = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/vm-nic/ipConfigurations/internal"
	otherIPConfig     = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/other-nic/ipConfigurations/internal"
)

func sub(id string) *network.SubResource { return &network.SubResource{ID: &id} }

func frontend(id string, public bool) *network.FrontendIPConfiguration {
	props := &network.FrontendIPConfigurationPropertiesFormat{}
	if public {
		props.PublicIPAddress = &network.PublicIPAddress{ID: strPtr("/…/publicIPAddresses/pip")}
	} else {
		props.PrivateIPAddress = strPtr("10.0.0.9")
	}
	return &network.FrontendIPConfiguration{ID: &id, Properties: props}
}

func pool(id string, memberIPConfigIDs ...string) *network.BackendAddressPool {
	members := make([]*network.InterfaceIPConfiguration, 0, len(memberIPConfigIDs))
	for _, member := range memberIPConfigIDs {
		members = append(members, &network.InterfaceIPConfiguration{ID: strPtr(member)})
	}
	return &network.BackendAddressPool{
		ID:         &id,
		Properties: &network.BackendAddressPoolPropertiesFormat{BackendIPConfigurations: members},
	}
}

func lbRule(frontendID, poolID string) *network.LoadBalancingRule {
	return &network.LoadBalancingRule{
		Properties: &network.LoadBalancingRulePropertiesFormat{
			FrontendIPConfiguration: sub(frontendID),
			BackendAddressPool:      sub(poolID),
		},
	}
}

// The defect: exposure read public IPs off the machine's own network interfaces
// only. Azure's reference architectures put the public IP on a load balancer
// frontend and leave the interface with a private address, so the recommended
// topology reported internetReachable false on a machine reachable from the
// internet -- a verdict that fails open.
func TestInternetForwardedIPConfigIDs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		props *network.LoadBalancerPropertiesFormat
		want  []string
	}{
		{
			name: "a public frontend, a rule, and a pool the machine is in",
			props: &network.LoadBalancerPropertiesFormat{
				FrontendIPConfigurations: []*network.FrontendIPConfiguration{frontend(publicFrontendID, true)},
				LoadBalancingRules:       []*network.LoadBalancingRule{lbRule(publicFrontendID, backendPool)},
				BackendAddressPools:      []*network.BackendAddressPool{pool(backendPool, vmIPConfig, otherIPConfig)},
			},
			want: []string{vmIPConfig, otherIPConfig},
		},
		{
			// An internal load balancer. Traffic through it did not come from the
			// internet, so nothing it forwards to is exposed by it.
			name: "an internal load balancer forwards nothing from the internet",
			props: &network.LoadBalancerPropertiesFormat{
				FrontendIPConfigurations: []*network.FrontendIPConfiguration{frontend(privateFrontendID, false)},
				LoadBalancingRules:       []*network.LoadBalancingRule{lbRule(privateFrontendID, backendPool)},
				BackendAddressPools:      []*network.BackendAddressPool{pool(backendPool, vmIPConfig)},
			},
		},
		{
			// A public IP with nothing bound to it reaches nothing. This is why
			// the rule is checked rather than assumed from the frontend.
			name: "a public frontend with no rule",
			props: &network.LoadBalancerPropertiesFormat{
				FrontendIPConfigurations: []*network.FrontendIPConfiguration{frontend(publicFrontendID, true)},
				BackendAddressPools:      []*network.BackendAddressPool{pool(backendPool, vmIPConfig)},
			},
		},
		{
			// Both frontends exist, but the rule is on the private one.
			name: "a rule on the private frontend of a mixed load balancer",
			props: &network.LoadBalancerPropertiesFormat{
				FrontendIPConfigurations: []*network.FrontendIPConfiguration{
					frontend(publicFrontendID, true), frontend(privateFrontendID, false),
				},
				LoadBalancingRules:  []*network.LoadBalancingRule{lbRule(privateFrontendID, backendPool)},
				BackendAddressPools: []*network.BackendAddressPool{pool(backendPool, vmIPConfig)},
			},
		},
		{
			// Only the pool the public rule points at counts.
			name: "another pool on the same load balancer is not forwarded",
			props: &network.LoadBalancerPropertiesFormat{
				FrontendIPConfigurations: []*network.FrontendIPConfiguration{frontend(publicFrontendID, true)},
				LoadBalancingRules:       []*network.LoadBalancingRule{lbRule(publicFrontendID, backendPool)},
				BackendAddressPools: []*network.BackendAddressPool{
					pool(backendPool, vmIPConfig), pool(otherPool, otherIPConfig),
				},
			},
			want: []string{vmIPConfig},
		},
		{
			// How a single-machine SSH or RDP forward is written: the NAT rule
			// names the IP configuration directly, with no pool at all.
			name: "an inbound NAT rule bound straight to one ip configuration",
			props: &network.LoadBalancerPropertiesFormat{
				FrontendIPConfigurations: []*network.FrontendIPConfiguration{frontend(publicFrontendID, true)},
				InboundNatRules: []*network.InboundNatRule{{
					Properties: &network.InboundNatRulePropertiesFormat{
						FrontendIPConfiguration: sub(publicFrontendID),
						BackendIPConfiguration:  &network.InterfaceIPConfiguration{ID: strPtr(vmIPConfig)},
					},
				}},
			},
			want: []string{vmIPConfig},
		},
		{
			name: "an inbound NAT rule bound to a pool",
			props: &network.LoadBalancerPropertiesFormat{
				FrontendIPConfigurations: []*network.FrontendIPConfiguration{frontend(publicFrontendID, true)},
				InboundNatRules: []*network.InboundNatRule{{
					Properties: &network.InboundNatRulePropertiesFormat{
						FrontendIPConfiguration: sub(publicFrontendID),
						BackendAddressPool:      sub(backendPool),
					},
				}},
				BackendAddressPools: []*network.BackendAddressPool{pool(backendPool, vmIPConfig)},
			},
			want: []string{vmIPConfig},
		},
		{
			name: "a NAT rule on the private frontend",
			props: &network.LoadBalancerPropertiesFormat{
				FrontendIPConfigurations: []*network.FrontendIPConfiguration{frontend(privateFrontendID, false)},
				InboundNatRules: []*network.InboundNatRule{{
					Properties: &network.InboundNatRulePropertiesFormat{
						FrontendIPConfiguration: sub(privateFrontendID),
						BackendIPConfiguration:  &network.InterfaceIPConfiguration{ID: strPtr(vmIPConfig)},
					},
				}},
			},
		},
		{
			// ARM resource ids are case-insensitive, and which casing a caller
			// sees depends on which API returned the id.
			name: "ids match across casings",
			props: &network.LoadBalancerPropertiesFormat{
				FrontendIPConfigurations: []*network.FrontendIPConfiguration{frontend(publicFrontendID, true)},
				LoadBalancingRules: []*network.LoadBalancingRule{
					lbRule(strings.ToUpper(publicFrontendID), strings.ToUpper(backendPool)),
				},
				BackendAddressPools: []*network.BackendAddressPool{pool(backendPool, vmIPConfig)},
			},
			want: []string{vmIPConfig},
		},
		{name: "no properties at all", props: nil},
		{name: "an empty load balancer", props: &network.LoadBalancerPropertiesFormat{}},
		{
			name: "nil elements everywhere",
			props: &network.LoadBalancerPropertiesFormat{
				FrontendIPConfigurations: []*network.FrontendIPConfiguration{nil, frontend(publicFrontendID, true)},
				LoadBalancingRules:       []*network.LoadBalancingRule{nil, lbRule(publicFrontendID, backendPool)},
				InboundNatRules:          []*network.InboundNatRule{nil},
				BackendAddressPools:      []*network.BackendAddressPool{nil, pool(backendPool, vmIPConfig)},
			},
			want: []string{vmIPConfig},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]struct{}
			require.NotPanics(t, func() { got = internetForwardedIPConfigIDs(tc.props) })
			assert.Len(t, got, len(tc.want))
			for _, want := range tc.want {
				_, ok := got[strings.ToLower(want)]
				assert.True(t, ok, "expected %q to be forwarded", want)
			}
		})
	}
}

func TestAnyIPConfigForwarded(t *testing.T) {
	exposed := &network.LoadBalancerPropertiesFormat{
		FrontendIPConfigurations: []*network.FrontendIPConfiguration{frontend(publicFrontendID, true)},
		LoadBalancingRules:       []*network.LoadBalancingRule{lbRule(publicFrontendID, backendPool)},
		BackendAddressPools:      []*network.BackendAddressPool{pool(backendPool, vmIPConfig)},
	}
	internal := &network.LoadBalancerPropertiesFormat{
		FrontendIPConfigurations: []*network.FrontendIPConfiguration{frontend(privateFrontendID, false)},
		LoadBalancingRules:       []*network.LoadBalancingRule{lbRule(privateFrontendID, backendPool)},
		BackendAddressPools:      []*network.BackendAddressPool{pool(backendPool, vmIPConfig)},
	}

	all := []*network.LoadBalancerPropertiesFormat{internal, exposed}
	assert.True(t, anyIPConfigForwarded(all, []string{vmIPConfig}),
		"one public load balancer among several is enough")
	assert.False(t, anyIPConfigForwarded(all, []string{otherIPConfig}),
		"a machine in no forwarded pool is not exposed by these")
	assert.False(t, anyIPConfigForwarded([]*network.LoadBalancerPropertiesFormat{internal}, []string{vmIPConfig}))

	assert.False(t, anyIPConfigForwarded(all, nil), "a machine with no ip configurations")
	assert.False(t, anyIPConfigForwarded(nil, []string{vmIPConfig}), "no load balancers in the subscription")
	assert.False(t, anyIPConfigForwarded([]*network.LoadBalancerPropertiesFormat{nil}, []string{vmIPConfig}))
}

func TestSubResourceID(t *testing.T) {
	assert.Equal(t, "/an/id", subResourceID(sub("/an/id")))
	assert.Equal(t, "", subResourceID(nil))
	assert.Equal(t, "", subResourceID(&network.SubResource{}))
}

func TestLowerSet(t *testing.T) {
	set := lowerSet([]string{"/A/B", "  /c/d  ", "", "   ", "/a/b"})
	assert.Len(t, set, 2, "folded and deduplicated, blanks dropped")
	_, ok := set["/a/b"]
	assert.True(t, ok)
	_, ok = set["/c/d"]
	assert.True(t, ok)
}
