// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDdosMitigationRuleValuesOf(t *testing.T) {
	t.Run("tcp rule reads both tcp limits and leaves udp null", func(t *testing.T) {
		v := ddosMitigationRuleValuesOf(&network.DdosMitigationRulePropertiesFormat{
			TrafficScope:      to.Ptr(network.DdosMitigationTrafficScopeTCP),
			ProvisioningState: to.Ptr(network.ProvisioningStateSucceeded),
			TCPDefaultMitigations: &network.DdosTCPDefaultMitigations{
				PerSourceConnectionRateLimiting: &network.DdosTCPPerSourceConnectionRateLimitPolicy{ConnectionsPerSecond: to.Ptr[int32](200)},
				PerSourceRateLimiting:           &network.DdosTCPPerSourceRateLimitPolicy{PacketsPerSecond: to.Ptr[int32](5000)},
			},
		})
		require.NotNil(t, v.trafficScope)
		assert.Equal(t, "Tcp", *v.trafficScope)
		require.NotNil(t, v.provisioningState)
		assert.Equal(t, "Succeeded", *v.provisioningState)
		require.NotNil(t, v.tcpPerSourceConnectionsPerSecond)
		assert.Equal(t, int32(200), *v.tcpPerSourceConnectionsPerSecond)
		require.NotNil(t, v.tcpPerSourcePacketsPerSecond)
		assert.Equal(t, int32(5000), *v.tcpPerSourcePacketsPerSecond)
		assert.Nil(t, v.udpPerSourcePacketsPerSecond)
	})

	t.Run("udp rule reads the udp limit and leaves tcp null", func(t *testing.T) {
		v := ddosMitigationRuleValuesOf(&network.DdosMitigationRulePropertiesFormat{
			TrafficScope: to.Ptr(network.DdosMitigationTrafficScopeUDP),
			UDPDefaultMitigations: &network.DdosUDPDefaultMitigations{
				PerSourceRateLimiting: &network.DdosUDPPerSourceRateLimitPolicy{PacketsPerSecond: to.Ptr[int32](10000)},
			},
		})
		require.NotNil(t, v.trafficScope)
		assert.Equal(t, "Udp", *v.trafficScope)
		require.NotNil(t, v.udpPerSourcePacketsPerSecond)
		assert.Equal(t, int32(10000), *v.udpPerSourcePacketsPerSecond)
		assert.Nil(t, v.tcpPerSourceConnectionsPerSecond)
		assert.Nil(t, v.tcpPerSourcePacketsPerSecond)
	})

	t.Run("tcp block without its limits stays null", func(t *testing.T) {
		v := ddosMitigationRuleValuesOf(&network.DdosMitigationRulePropertiesFormat{
			TCPDefaultMitigations: &network.DdosTCPDefaultMitigations{},
			UDPDefaultMitigations: &network.DdosUDPDefaultMitigations{},
		})
		assert.Nil(t, v.tcpPerSourceConnectionsPerSecond)
		assert.Nil(t, v.tcpPerSourcePacketsPerSecond)
		assert.Nil(t, v.udpPerSourcePacketsPerSecond)
		assert.Nil(t, v.trafficScope)
	})

	t.Run("absent properties read null", func(t *testing.T) {
		v := ddosMitigationRuleValuesOf(nil)
		assert.Nil(t, v.trafficScope)
		assert.Nil(t, v.provisioningState)
		assert.Nil(t, v.tcpPerSourceConnectionsPerSecond)
	})
}

func TestDdosSourceOverrideValuesOf(t *testing.T) {
	t.Run("permit override splits geo matches by kind", func(t *testing.T) {
		v := ddosSourceOverrideValuesOf(&network.DdosSourcePolicyOverride{
			PolicyAction: &network.DdosSourcePolicyAction{ActionType: to.Ptr(network.DdosSourcePolicyActionTypePermit)},
			Conditions: &network.DdosSourceMatchConditions{
				IPPrefixes: []*string{new("0.0.0.0/0"), nil, new("2001:db8::/32")},
				GeoMatches: []*network.DdosGeoMatch{
					{Continent: to.Ptr(network.DdosContinentEurope)},
					nil,
					{CountryCode: new("NZ")},
					{Continent: to.Ptr(network.DdosContinentSouthAmerica)},
				},
			},
		})
		require.NotNil(t, v.action)
		assert.Equal(t, "Permit", *v.action)
		assert.Equal(t, []any{"0.0.0.0/0", "2001:db8::/32"}, v.ipPrefixes)
		assert.Equal(t, []any{"Europe", "SouthAmerica"}, v.continents)
		assert.Equal(t, []any{"NZ"}, v.countryCodes)
	})

	t.Run("deny override with prefixes only has empty geo lists", func(t *testing.T) {
		v := ddosSourceOverrideValuesOf(&network.DdosSourcePolicyOverride{
			PolicyAction: &network.DdosSourcePolicyAction{ActionType: to.Ptr(network.DdosSourcePolicyActionTypeDeny)},
			Conditions:   &network.DdosSourceMatchConditions{IPPrefixes: []*string{new("203.0.113.0/24")}},
		})
		require.NotNil(t, v.action)
		assert.Equal(t, "Deny", *v.action)
		assert.Equal(t, []any{"203.0.113.0/24"}, v.ipPrefixes)
		assert.Empty(t, v.continents)
		assert.NotNil(t, v.continents)
		assert.Empty(t, v.countryCodes)
		assert.NotNil(t, v.countryCodes)
	})

	t.Run("absent action and conditions", func(t *testing.T) {
		v := ddosSourceOverrideValuesOf(&network.DdosSourcePolicyOverride{})
		assert.Nil(t, v.action)
		assert.NotNil(t, v.ipPrefixes)
		assert.Empty(t, v.ipPrefixes)
		assert.Empty(t, v.continents)
		assert.Empty(t, v.countryCodes)

		v = ddosSourceOverrideValuesOf(&network.DdosSourcePolicyOverride{PolicyAction: &network.DdosSourcePolicyAction{}})
		assert.Nil(t, v.action)
	})

	t.Run("empty geo values are skipped", func(t *testing.T) {
		v := ddosSourceOverrideValuesOf(&network.DdosSourcePolicyOverride{
			Conditions: &network.DdosSourceMatchConditions{
				GeoMatches: []*network.DdosGeoMatch{{Continent: to.Ptr(network.DdosContinent("")), CountryCode: new("")}},
			},
		})
		assert.Empty(t, v.continents)
		assert.Empty(t, v.countryCodes)
	})
}
