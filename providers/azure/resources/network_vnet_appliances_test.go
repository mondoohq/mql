// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const vnaApplianceJSON = `{
  "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkAppliances/vna1",
  "name": "vna1",
  "type": "Microsoft.Network/virtualNetworkAppliances",
  "location": "eastus2",
  "etag": "W/\"abc\"",
  "tags": {"env": "prod"},
  "properties": {
    "bandwidthInGbps": 50,
    "privateIPAddressVersion": "DualStack",
    "capacityProvider": {"id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/capacityProviders/cp1"},
    "subnet": {"id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/appliances"},
    "provisioningState": "Succeeded",
    "resourceGuid": "00000000-0000-0000-0000-000000000001",
    "ipConfigurations": [
      {
        "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkAppliances/vna1/ipConfigurations/ipconfig1",
        "name": "ipconfig1",
        "etag": "W/\"def\"",
        "type": "Microsoft.Network/virtualNetworkAppliances/ipConfigurations",
        "properties": {
          "primary": true,
          "privateIPAddress": "10.0.1.4",
          "privateIPAddressVersion": "IPv4",
          "privateIPAllocationMethod": "Dynamic",
          "provisioningState": "Succeeded"
        }
      },
      {
        "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkAppliances/vna1/ipConfigurations/ipconfig2",
        "name": "ipconfig2",
        "properties": {
          "primary": false,
          "privateIPAddress": "fd00::4",
          "privateIPAddressVersion": "IPv6",
          "privateIPAllocationMethod": "Static"
        }
      }
    ]
  }
}`

func TestVirtualNetworkApplianceArgs(t *testing.T) {
	t.Run("decodes the appliance and its references", func(t *testing.T) {
		var vna network.VirtualNetworkAppliance
		require.NoError(t, json.Unmarshal([]byte(vnaApplianceJSON), &vna))

		args, subnetId, ipConfigs := virtualNetworkApplianceArgs(&vna)
		assert.Equal(t, "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkAppliances/vna1", args["id"].Value)
		assert.Equal(t, "vna1", args["name"].Value)
		assert.Equal(t, "eastus2", args["location"].Value)
		assert.Equal(t, map[string]any{"env": "prod"}, args["tags"].Value)
		assert.Equal(t, "Succeeded", args["provisioningState"].Value)
		assert.Equal(t, "00000000-0000-0000-0000-000000000001", args["resourceGuid"].Value)
		assert.Equal(t, float64(50), args["bandwidthInGbps"].Value)
		assert.Equal(t, "DualStack", args["privateIpAddressVersion"].Value)
		assert.Equal(t, "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/capacityProviders/cp1", args["capacityProviderId"].Value)
		require.NotNil(t, subnetId)
		assert.Equal(t, "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/appliances", *subnetId)
		assert.Len(t, ipConfigs, 2)
	})

	t.Run("absent properties stay null, not zero", func(t *testing.T) {
		id := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkAppliances/bare"
		args, subnetId, ipConfigs := virtualNetworkApplianceArgs(&network.VirtualNetworkAppliance{ID: &id})
		assert.Equal(t, id, args["id"].Value)
		assert.Nil(t, args["bandwidthInGbps"].Value)
		assert.Nil(t, args["provisioningState"].Value)
		assert.Nil(t, args["privateIpAddressVersion"].Value)
		assert.Nil(t, args["capacityProviderId"].Value)
		assert.Nil(t, subnetId)
		assert.Empty(t, ipConfigs)
	})
}

func TestVirtualNetworkApplianceIPConfigArgs(t *testing.T) {
	var vna network.VirtualNetworkAppliance
	require.NoError(t, json.Unmarshal([]byte(vnaApplianceJSON), &vna))
	require.Len(t, vna.Properties.IPConfigurations, 2)

	t.Run("primary IPv4 configuration", func(t *testing.T) {
		args := virtualNetworkApplianceIPConfigArgs(vna.Properties.IPConfigurations[0])
		assert.Equal(t, "ipconfig1", args["name"].Value)
		assert.Equal(t, true, args["primary"].Value)
		assert.Equal(t, "10.0.1.4", args["privateIpAddress"].Value)
		assert.Equal(t, "IPv4", args["privateIpAddressVersion"].Value)
		assert.Equal(t, "Dynamic", args["privateIpAllocationMethod"].Value)
		assert.Equal(t, "Succeeded", args["provisioningState"].Value)
	})

	t.Run("secondary IPv6 configuration", func(t *testing.T) {
		args := virtualNetworkApplianceIPConfigArgs(vna.Properties.IPConfigurations[1])
		assert.Equal(t, false, args["primary"].Value)
		assert.Equal(t, "fd00::4", args["privateIpAddress"].Value)
		assert.Equal(t, "IPv6", args["privateIpAddressVersion"].Value)
		assert.Equal(t, "Static", args["privateIpAllocationMethod"].Value)
		assert.Nil(t, args["provisioningState"].Value)
	})

	t.Run("absent properties leave primary null rather than false", func(t *testing.T) {
		id := "/x/ipConfigurations/bare"
		args := virtualNetworkApplianceIPConfigArgs(&network.VirtualNetworkApplianceIPConfiguration{ID: &id})
		assert.Nil(t, args["primary"].Value)
		assert.Nil(t, args["privateIpAddress"].Value)
	})
}

const vnaCapabilitiesJSON = `{
  "value": [
    {
      "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkAppliances/vna1/capabilities/nat64",
      "name": "nat64",
      "type": "Microsoft.Network/virtualNetworkAppliances/capabilities",
      "kind": "NAT64",
      "properties": {
        "linkedResourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1",
        "provisioningState": "Succeeded"
      },
      "systemData": {"createdBy": "someone@example.com", "createdByType": "User"}
    },
    {
      "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkAppliances/vna1/capabilities/plgw",
      "name": "plgw",
      "kind": "PLGateway",
      "properties": {
        "ipVersion": "IPv6",
        "linkedResourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1",
        "provisioningState": "Updating"
      }
    },
    {
      "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkAppliances/vna1/capabilities/future",
      "name": "future",
      "kind": "SomeFutureKind",
      "properties": {"ipVersion": "DualStack"}
    },
    {
      "name": "no-id",
      "kind": "PLGatewayFastpath"
    }
  ]
}`

func TestVirtualNetworkApplianceCapabilityArgs(t *testing.T) {
	var page network.VirtualNetworkApplianceCapabilityListResult
	require.NoError(t, json.Unmarshal([]byte(vnaCapabilitiesJSON), &page))
	require.Len(t, page.Value, 4)

	t.Run("NAT64 carries no IP version", func(t *testing.T) {
		args, linkedId, sd, ok := virtualNetworkApplianceCapabilityArgs(page.Value[0])
		require.True(t, ok)
		assert.Equal(t, "NAT64", args["kind"].Value)
		assert.Equal(t, "nat64", args["name"].Value)
		assert.Nil(t, args["ipVersion"].Value)
		assert.Equal(t, "Succeeded", args["provisioningState"].Value)
		require.NotNil(t, linkedId)
		assert.Equal(t, "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1", *linkedId)
		require.NotNil(t, sd)
		require.NotNil(t, sd.CreatedBy)
		assert.Equal(t, "someone@example.com", *sd.CreatedBy)
	})

	t.Run("PLGateway reads its IP version", func(t *testing.T) {
		args, _, sd, ok := virtualNetworkApplianceCapabilityArgs(page.Value[1])
		require.True(t, ok)
		assert.Equal(t, "PLGateway", args["kind"].Value)
		assert.Equal(t, "IPv6", args["ipVersion"].Value)
		assert.Equal(t, "Updating", args["provisioningState"].Value)
		assert.Nil(t, sd)
	})

	t.Run("a kind this SDK does not know keeps its kind", func(t *testing.T) {
		args, linkedId, _, ok := virtualNetworkApplianceCapabilityArgs(page.Value[2])
		require.True(t, ok)
		assert.Equal(t, "SomeFutureKind", args["kind"].Value)
		assert.Equal(t, "DualStack", args["ipVersion"].Value)
		assert.Nil(t, linkedId)
	})

	t.Run("an entry without an id is skipped", func(t *testing.T) {
		_, _, _, ok := virtualNetworkApplianceCapabilityArgs(page.Value[3])
		assert.False(t, ok)
	})

	t.Run("nil is skipped", func(t *testing.T) {
		_, _, _, ok := virtualNetworkApplianceCapabilityArgs(nil)
		assert.False(t, ok)
	})
}

func setStructuredErrors(t *testing.T, on bool) {
	features := mql.Features{byte(mql.ResourceContext)}
	if on {
		features = append(features, byte(mql.StructuredErrors))
	}
	plugin.ReadFeatures([]byte(features))
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
}

func TestVirtualNetworkApplianceUnavailable(t *testing.T) {
	notFound := func() error {
		return armError(http.StatusNotFound, `{"error":{"code":"NoRegisteredProviderFound","message":"No registered resource provider found"}}`)
	}
	forbidden := func() error {
		return armError(http.StatusForbidden, `{"error":{"code":"AuthorizationFailed","message":"does not have authorization"}}`)
	}

	t.Run("without structured errors an unavailable type is an empty list", func(t *testing.T) {
		setStructuredErrors(t, false)
		res, err := virtualNetworkApplianceUnavailable(notFound(), "virtualNetworkAppliances", permVirtualNetworkAppliancesRead)
		require.NoError(t, err)
		assert.Equal(t, []any{}, res)
	})

	t.Run("with structured errors an unavailable type is NotApplicable", func(t *testing.T) {
		setStructuredErrors(t, true)
		res, err := virtualNetworkApplianceUnavailable(notFound(), "virtualNetworkAppliances", permVirtualNetworkAppliancesRead)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.True(t, errors.Is(err, llx.ErrNotApplicable))
	})

	t.Run("a refusal is never an empty list", func(t *testing.T) {
		setStructuredErrors(t, false)
		res, err := virtualNetworkApplianceUnavailable(forbidden(), "virtualNetworkAppliances", permVirtualNetworkAppliancesRead)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.False(t, errors.Is(err, llx.ErrForbidden))
	})

	t.Run("with structured errors a refusal is Forbidden", func(t *testing.T) {
		setStructuredErrors(t, true)
		_, err := virtualNetworkApplianceUnavailable(forbidden(), "virtualNetworkAppliances", permVirtualNetworkAppliancesRead)
		require.Error(t, err)
		assert.True(t, errors.Is(err, llx.ErrForbidden))
	})

	t.Run("a transport failure is returned unclassified", func(t *testing.T) {
		setStructuredErrors(t, true)
		transport := errors.New("dial tcp: i/o timeout")
		_, err := virtualNetworkApplianceUnavailable(transport, "virtualNetworkAppliances", permVirtualNetworkAppliancesRead)
		assert.Same(t, transport, err)
	})
}
