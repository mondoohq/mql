// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// expressRouteLagListItem is one entry of a subscription-wide LAG list
// response, shaped after the 2026-03-01 ExpressRouteLagList REST example.
const expressRouteLagListItem = `{
  "name": "lag1",
  "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/expressRouteLags/lag1",
  "etag": "W/\"etag-1\"",
  "type": "Microsoft.Network/expressRouteLags",
  "location": "eastus2",
  "tags": {"env": "prod"},
  "identity": {
    "type": "UserAssigned",
    "userAssignedIdentities": {
      "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/macsec": {}
    }
  },
  "properties": {
    "provisioningState": "Succeeded",
    "resourceGuid": "4259cba0-885f-4ac6-9c81-7eb15ef10fe0",
    "links": [
      {
        "name": "link1",
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/expressRouteLags/lag1/links/link1",
        "etag": "W/\"etag-1\"",
        "type": "Microsoft.Network/expressRouteLags/links",
        "properties": {
          "provisioningState": "Succeeded",
          "routerName": "router1",
          "interfaceName": "ae",
          "adminState": "Enabled",
          "macSecConfig": {
            "cknSecretIdentifier": "https://vault1.vault.azure.net/secrets/ckn",
            "cakSecretIdentifier": "https://vault1.vault.azure.net/secrets/cak",
            "cipher": "GcmAes256",
            "sciState": "Enabled"
          },
          "members": [
            {
              "name": "member1",
              "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/expressRouteLags/lag1/links/link1/members/member1",
              "properties": {
                "provisioningState": "Succeeded",
                "interfaceName": "Ethernet0/0",
                "patchPanelId": "patchPanelId1",
                "rackId": "rackId1",
                "coloLocation": "colo1",
                "connectorType": "LC",
                "adminState": "Disabled"
              }
            }
          ]
        }
      },
      {
        "name": "link2",
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/expressRouteLags/lag1/links/link2",
        "properties": {
          "adminState": "Disabled"
        }
      }
    ],
    "circuits": [
      {"id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/expressRouteCircuits/circuit1"}
    ],
    "authorizations": [
      {
        "name": "unused",
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/expressRouteLags/lag1/authorizations/unused",
        "type": "Microsoft.Network/expressRouteLags/authorizations",
        "properties": {
          "provisioningState": "Succeeded",
          "authorizationUseStatus": "Available"
        }
      },
      {
        "name": "redeemed",
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/expressRouteLags/lag1/authorizations/redeemed",
        "type": "Microsoft.Network/expressRouteLags/authorizations",
        "properties": {
          "provisioningState": "Succeeded",
          "authorizationUseStatus": "InUse",
          "circuitResourceUri": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg2/providers/Microsoft.Network/expressRouteCircuits/circuit2"
        }
      }
    ],
    "peeringLocation": "Silicon Valley",
    "bandwidthInGbps": 100,
    "encapsulation": "QinQ",
    "provisionedBandwidthInGbps": 12.5,
    "mtu": "1500",
    "allocationDate": "6/16/2026 5:28:06 PM",
    "etherType": "0x8100",
    "billingType": "MeteredData",
    "numberOfPorts": 4,
    "minimumActivePortsRequired": 2,
    "lacpTimer": "Fast"
  }
}`

func decodeExpressRouteLag(t *testing.T, raw string) *network.ExpressRouteLag {
	t.Helper()
	var lag network.ExpressRouteLag
	require.NoError(t, json.Unmarshal([]byte(raw), &lag))
	return &lag
}

func TestExpressRouteLagArgs(t *testing.T) {
	lag := decodeExpressRouteLag(t, expressRouteLagListItem)
	args := expressRouteLagArgs(lag)

	assert.Equal(t, "lag1", args["name"].Value)
	assert.Equal(t, "eastus2", args["location"].Value)
	assert.Equal(t, map[string]any{"env": "prod"}, args["tags"].Value)
	assert.Equal(t, "Succeeded", args["provisioningState"].Value)
	assert.Equal(t, int64(100), args["bandwidthInGbps"].Value)
	assert.Equal(t, 12.5, args["provisionedBandwidthInGbps"].Value)
	assert.Equal(t, int64(4), args["numberOfPorts"].Value)
	assert.Equal(t, int64(2), args["minimumActivePortsRequired"].Value)
	assert.Equal(t, "QinQ", args["encapsulation"].Value)
	assert.Equal(t, "MeteredData", args["billingType"].Value)
	assert.Equal(t, "Fast", args["lacpTimer"].Value)
	assert.Equal(t, "Silicon Valley", args["peeringLocation"].Value)
	assert.Equal(t, "1500", args["mtu"].Value)
	assert.Equal(t, "0x8100", args["etherType"].Value)
	assert.Equal(t, "4259cba0-885f-4ac6-9c81-7eb15ef10fe0", args["resourceGuid"].Value)
	assert.Equal(t, "6/16/2026 5:28:06 PM", args["allocationDate"].Value)
	assert.Equal(t, "UserAssigned", args["identityType"].Value)
	assert.Nil(t, args["principalId"].Value, "no system-assigned identity means no principal ID")

	assert.Equal(t, []string{
		"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/macsec",
	}, sortedUserAssignedIdentityIDs(lag.Identity.UserAssignedIdentities))
	assert.Equal(t, []string{
		"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/expressRouteCircuits/circuit1",
	}, azureNetworkSubResourceIDs(lag.Properties.Circuits))
}

func TestExpressRouteLagArgsAbsentProperties(t *testing.T) {
	lag := decodeExpressRouteLag(t, `{"id": "/x/expressRouteLags/bare", "name": "bare"}`)
	args := expressRouteLagArgs(lag)

	assert.Equal(t, "bare", args["name"].Value)
	// Absent values stay null instead of reading as a measured zero.
	for _, field := range []string{
		"provisioningState", "bandwidthInGbps", "provisionedBandwidthInGbps",
		"numberOfPorts", "minimumActivePortsRequired", "encapsulation",
		"lacpTimer", "allocationDate", "identityType", "principalId",
	} {
		assert.Nil(t, args[field].Value, field)
	}
}

// The authorizations fallback depends on telling an absent authorizations key
// (ask the authorizations endpoint) apart from an empty list (the LAG has none).
func TestExpressRouteLagInlineAuthorizationsPresence(t *testing.T) {
	absent := decodeExpressRouteLag(t, `{"name": "a", "properties": {"provisioningState": "Succeeded"}}`)
	assert.Nil(t, absent.Properties.Authorizations)

	empty := decodeExpressRouteLag(t, `{"name": "a", "properties": {"authorizations": []}}`)
	assert.NotNil(t, empty.Properties.Authorizations)
	assert.Empty(t, empty.Properties.Authorizations)

	populated := decodeExpressRouteLag(t, expressRouteLagListItem)
	assert.Len(t, populated.Properties.Authorizations, 2)
}

func TestExpressRouteLagLinkArgs(t *testing.T) {
	lag := decodeExpressRouteLag(t, expressRouteLagListItem)
	require.Len(t, lag.Properties.Links, 2)

	t.Run("MACsec configured", func(t *testing.T) {
		args, cakId, cknId, err := expressRouteLagLinkArgs(lag.Properties.Links[0])
		require.NoError(t, err)
		assert.Equal(t, "link1", args["name"].Value)
		assert.Equal(t, "Enabled", args["adminState"].Value)
		assert.Equal(t, "router1", args["routerName"].Value)
		assert.Equal(t, "ae", args["interfaceName"].Value)
		assert.Equal(t, "GcmAes256", args["macSecCipher"].Value)
		assert.Equal(t, "Enabled", args["macSecSciState"].Value)
		assert.Equal(t, "https://vault1.vault.azure.net/secrets/cak", cakId)
		assert.Equal(t, "https://vault1.vault.azure.net/secrets/ckn", cknId)

		members, ok := args["members"].Value.([]any)
		require.True(t, ok)
		require.Len(t, members, 1)
		member := members[0].(map[string]any)
		assert.Equal(t, "member1", member["name"])
		props := member["properties"].(map[string]any)
		assert.Equal(t, "Disabled", props["adminState"])
		assert.Equal(t, "LC", props["connectorType"])
		assert.Equal(t, "patchPanelId1", props["patchPanelId"])
		assert.Equal(t, "rackId1", props["rackId"])
		assert.Equal(t, "colo1", props["coloLocation"])
	})

	t.Run("MACsec not configured", func(t *testing.T) {
		args, cakId, cknId, err := expressRouteLagLinkArgs(lag.Properties.Links[1])
		require.NoError(t, err)
		assert.Equal(t, "Disabled", args["adminState"].Value)
		assert.Nil(t, args["macSecCipher"].Value)
		assert.Nil(t, args["macSecSciState"].Value)
		assert.Empty(t, cakId)
		assert.Empty(t, cknId)
		assert.Equal(t, []any{}, args["members"].Value)
	})
}

func TestExpressRouteLagAuthorizationArgs(t *testing.T) {
	lag := decodeExpressRouteLag(t, expressRouteLagListItem)
	require.Len(t, lag.Properties.Authorizations, 2)

	t.Run("unused authorization has no circuit", func(t *testing.T) {
		args, circuitId := expressRouteLagAuthorizationArgs(lag.Properties.Authorizations[0])
		assert.Equal(t, "unused", args["name"].Value)
		assert.Equal(t, "Available", args["authorizationUseStatus"].Value)
		assert.Equal(t, "Succeeded", args["provisioningState"].Value)
		assert.Empty(t, circuitId)
	})

	t.Run("redeemed authorization points at its circuit", func(t *testing.T) {
		args, circuitId := expressRouteLagAuthorizationArgs(lag.Properties.Authorizations[1])
		assert.Equal(t, "InUse", args["authorizationUseStatus"].Value)
		assert.Equal(t, "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg2/providers/Microsoft.Network/expressRouteCircuits/circuit2", circuitId)
	})

	t.Run("no properties", func(t *testing.T) {
		args, circuitId := expressRouteLagAuthorizationArgs(&network.ExpressRouteLagAuthorization{Name: new("bare")})
		assert.Nil(t, args["authorizationUseStatus"].Value)
		assert.Nil(t, args["provisioningState"].Value)
		assert.Empty(t, circuitId)
	})
}
