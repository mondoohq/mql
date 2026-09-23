// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	trafficmanager "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager"
	"github.com/stretchr/testify/assert"
)

func TestFrontendIpConfigFields(t *testing.T) {
	t.Run("nil config returns empty strings", func(t *testing.T) {
		id, name, subnetId, publicIpId, privIp, alloc := frontendIpConfigFields(nil)
		assert.Empty(t, id+name+subnetId+publicIpId+privIp+alloc)
	})
	t.Run("internal (private) frontend has subnet, no public IP", func(t *testing.T) {
		id, name := "/fe/id", "privateFrontend"
		subnet := "/subnets/internal"
		priv, alloc := "10.0.0.4", network.IPAllocationMethodStatic
		fc := &network.ApplicationGatewayFrontendIPConfiguration{
			ID:   &id,
			Name: &name,
			Properties: &network.ApplicationGatewayFrontendIPConfigurationPropertiesFormat{
				Subnet:                    &network.SubResource{ID: &subnet},
				PrivateIPAddress:          &priv,
				PrivateIPAllocationMethod: &alloc,
			},
		}
		gotId, gotName, gotSubnet, gotPublic, gotPriv, gotAlloc := frontendIpConfigFields(fc)
		assert.Equal(t, "/fe/id", gotId)
		assert.Equal(t, "privateFrontend", gotName)
		assert.Equal(t, "/subnets/internal", gotSubnet)
		assert.Empty(t, gotPublic)
		assert.Equal(t, "10.0.0.4", gotPriv)
		assert.Equal(t, "Static", gotAlloc)
	})
	t.Run("internet-facing frontend has public IP, no subnet", func(t *testing.T) {
		pip := "/publicIPAddresses/pip"
		fc := &network.ApplicationGatewayFrontendIPConfiguration{
			Properties: &network.ApplicationGatewayFrontendIPConfigurationPropertiesFormat{
				PublicIPAddress: &network.SubResource{ID: &pip},
			},
		}
		_, _, gotSubnet, gotPublic, _, _ := frontendIpConfigFields(fc)
		assert.Empty(t, gotSubnet)
		assert.Equal(t, "/publicIPAddresses/pip", gotPublic)
	})
}

func TestNatGatewayNat64Enabled(t *testing.T) {
	enabled := network.Nat64StateEnabled
	disabled := network.Nat64StateDisabled
	none := network.Nat64StateNone

	tests := []struct {
		name  string
		props *network.NatGatewayPropertiesFormat
		want  bool
	}{
		{"nil properties", nil, false},
		{"unset nat64 field", &network.NatGatewayPropertiesFormat{}, false},
		{"enabled", &network.NatGatewayPropertiesFormat{Nat64: &enabled}, true},
		{"disabled", &network.NatGatewayPropertiesFormat{Nat64: &disabled}, false},
		{"none collapses to false", &network.NatGatewayPropertiesFormat{Nat64: &none}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, natGatewayNat64Enabled(tc.props))
		})
	}
}

func TestWafPolicyEnabled(t *testing.T) {
	enabled := network.WebApplicationFirewallEnabledStateEnabled
	disabled := network.WebApplicationFirewallEnabledStateDisabled

	tests := []struct {
		name     string
		settings *network.PolicySettings
		want     bool
	}{
		{"nil settings defaults to enabled", nil, true},
		{"unset state defaults to enabled", &network.PolicySettings{}, true},
		{"enabled", &network.PolicySettings{State: &enabled}, true},
		{"disabled", &network.PolicySettings{State: &disabled}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, wafPolicyEnabled(tc.settings))
		})
	}
}

func TestTrafficManagerProfileEnabled(t *testing.T) {
	enabled := trafficmanager.ProfileStatusEnabled
	disabled := trafficmanager.ProfileStatusDisabled

	tests := []struct {
		name  string
		props *trafficmanager.ProfileProperties
		want  bool
	}{
		{"nil properties", nil, false},
		{"unset status", &trafficmanager.ProfileProperties{}, false},
		{"enabled", &trafficmanager.ProfileProperties{ProfileStatus: &enabled}, true},
		{"disabled", &trafficmanager.ProfileProperties{ProfileStatus: &disabled}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, trafficManagerProfileEnabled(tc.props))
		})
	}
}

func TestTrafficManagerEndpointEnabled(t *testing.T) {
	enabled := trafficmanager.EndpointStatusEnabled
	disabled := trafficmanager.EndpointStatusDisabled

	tests := []struct {
		name  string
		props *trafficmanager.EndpointProperties
		want  bool
	}{
		{"nil properties", nil, false},
		{"unset status", &trafficmanager.EndpointProperties{}, false},
		{"enabled", &trafficmanager.EndpointProperties{EndpointStatus: &enabled}, true},
		{"disabled", &trafficmanager.EndpointProperties{EndpointStatus: &disabled}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, trafficManagerEndpointEnabled(tc.props))
		})
	}
}

func TestParseAzurePortRange(t *testing.T) {
	entry := "*,80,1024-65535"
	ranges := parseAzureSecurityRulePortRange(entry)
	assert.Equal(t, 3, len(ranges))
	assert.Equal(t, "*", ranges[0].FromPort)
	assert.Equal(t, "*", ranges[0].ToPort)
	assert.Equal(t, "80", ranges[1].FromPort)
	assert.Equal(t, "80", ranges[1].ToPort)
	assert.Equal(t, "1024", ranges[2].FromPort)
	assert.Equal(t, "65535", ranges[2].ToPort)
}

func TestVirtualNetworkIDFromSubnetID(t *testing.T) {
	base := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/my-vnet"
	t.Run("derives the parent virtual network ID", func(t *testing.T) {
		assert.Equal(t, base, virtualNetworkIDFromSubnetID(base+"/subnets/my-subnet"))
	})
	t.Run("case-insensitive on the /subnets/ segment", func(t *testing.T) {
		assert.Equal(t, base, virtualNetworkIDFromSubnetID(base+"/Subnets/my-subnet"))
	})
	t.Run("returns empty when there is no subnets segment", func(t *testing.T) {
		assert.Equal(t, "", virtualNetworkIDFromSubnetID(base))
	})
	t.Run("returns empty for an empty ID", func(t *testing.T) {
		assert.Equal(t, "", virtualNetworkIDFromSubnetID(""))
	})
}
