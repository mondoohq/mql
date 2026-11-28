// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/IBM-Cloud/power-go-client/power/models"
	"github.com/IBM/platform-services-go-sdk/iampolicymanagementv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strp(s string) *string { return &s }

func TestNsgState(t *testing.T) {
	assert.Equal(t, "inactive", nsgState(nil))
	assert.Equal(t, "inactive", nsgState(&models.Workspace{Details: &models.WorkspaceDetails{}}))
	assert.Equal(t, "active", nsgState(&models.Workspace{Details: &models.WorkspaceDetails{
		NetworkSecurityGroups: &models.WorkspaceNetworkSecurityGroupsDetails{State: strp("ACTIVE")},
	}}))
}

func TestNsgRuleArgs(t *testing.T) {
	// No port range: every port.
	args := nsgRuleArgs(&models.NetworkSecurityGroupRule{
		ID:       strp("r1"),
		Action:   strp("allow"),
		Protocol: &models.NetworkSecurityGroupRuleProtocol{Type: "tcp", TCPFlags: []*models.NetworkSecurityGroupRuleProtocolTCPFlag{{Flag: "syn"}, nil}},
		Remote:   &models.NetworkSecurityGroupRuleRemote{Type: "default-network-address-group"},
	})
	assert.Equal(t, int64(1), args["destinationPortMin"].Value)
	assert.Equal(t, int64(65535), args["destinationPortMax"].Value)
	assert.Equal(t, []any{"syn"}, args["tcpFlags"].Value)
	assert.Equal(t, "default-network-address-group", args["remoteType"].Value)

	// A single port.
	args = nsgRuleArgs(&models.NetworkSecurityGroupRule{
		Action:          strp("allow"),
		Protocol:        &models.NetworkSecurityGroupRuleProtocol{Type: "tcp"},
		DestinationPort: &models.NetworkSecurityGroupRulePort{Minimum: 22, Maximum: 22},
		Remote:          &models.NetworkSecurityGroupRuleRemote{Type: "network-address-group", ID: "nag-1"},
	})
	assert.Equal(t, int64(22), args["destinationPortMin"].Value)
	assert.Equal(t, int64(22), args["destinationPortMax"].Value)
	assert.Equal(t, "nag-1", args["remoteId"].Value)

	// ICMP has no ports.
	args = nsgRuleArgs(&models.NetworkSecurityGroupRule{
		Action:   strp("allow"),
		Protocol: &models.NetworkSecurityGroupRuleProtocol{Type: "icmp", IcmpType: strp("echo")},
	})
	assert.Nil(t, args["destinationPortMin"].Value)
	assert.Equal(t, "echo", args["icmpType"].Value)
}

func TestIsAnyAddress(t *testing.T) {
	assert.True(t, isAnyAddress("0.0.0.0/0"))
	assert.True(t, isAnyAddress(" ::/0"))
	assert.False(t, isAnyAddress("10.0.0.0/8"))
	assert.True(t, isAnyAddress(defaultAddressGroupCidr))
}

func TestKeyServiceOf(t *testing.T) {
	assert.Equal(t, "", keyServiceOf(""))
	assert.Equal(t, "kms", keyServiceOf("crn:v1:bluemix:public:kms:us-south:a/acc:inst:key:k1"))
	assert.Equal(t, "hs-crypto", keyServiceOf("crn:v1:bluemix:public:hs-crypto:us-south:a/acc:inst:key:k1"))
}

func TestCbrCovers(t *testing.T) {
	db := cbrTarget{
		accountID:       "acc",
		serviceName:     "databases-for-postgresql",
		serviceInstance: "guid-1",
		region:          "us-south",
		resourceGroupID: "rg-1",
		tags:            []string{"env:prod"},
	}
	cases := []struct {
		name  string
		attrs map[string]string
		ops   map[string]string
		tags  map[string]string
		want  bool
	}{
		{"instance", map[string]string{"accountId": "acc", "serviceName": "databases-for-postgresql", "serviceInstance": "guid-1"}, nil, nil, true},
		{"whole service", map[string]string{"accountId": "acc", "serviceName": "databases-for-postgresql"}, nil, nil, true},
		{"other instance", map[string]string{"accountId": "acc", "serviceName": "databases-for-postgresql", "serviceInstance": "guid-2"}, nil, nil, false},
		{"other service", map[string]string{"accountId": "acc", "serviceName": "databases-for-mysql"}, nil, nil, false},
		{"other account", map[string]string{"accountId": "other", "serviceName": "databases-for-postgresql"}, nil, nil, false},
		{"region and group", map[string]string{"serviceName": "databases-for-postgresql", "region": "us-south", "resourceGroupId": "rg-1"}, nil, nil, true},
		{"other region", map[string]string{"serviceName": "databases-for-postgresql", "region": "eu-de"}, nil, nil, false},
		{"wildcard", map[string]string{"serviceName": "databases-for-*"}, map[string]string{"serviceName": "stringMatch"}, nil, true},
		{"part of the instance", map[string]string{"serviceName": "databases-for-postgresql", "resourceType": "backup"}, nil, nil, false},
		{"no service", map[string]string{"accountId": "acc"}, nil, nil, false},
		{"tag present", map[string]string{"serviceName": "databases-for-postgresql"}, nil, map[string]string{"env": "prod"}, true},
		{"tag absent", map[string]string{"serviceName": "databases-for-postgresql"}, nil, map[string]string{"env": "dev"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, cbrCovers(c.attrs, c.ops, c.tags, db))
		})
	}
}

func TestCbrAddressArgs(t *testing.T) {
	var a cbrAddress
	require.NoError(t, json.Unmarshal([]byte(`{"type":"serviceRef","ref":{"account_id":"acc","service_name":"cloud-object-storage"}}`), &a))
	args := cbrAddressArgs(a)
	assert.Equal(t, "serviceRef", args["type"].Value)
	assert.Equal(t, "cloud-object-storage", args["serviceName"].Value)
	assert.Equal(t, "", args["value"].Value)
}

func TestSecretArgs(t *testing.T) {
	var m secretMetadata
	require.NoError(t, json.Unmarshal([]byte(`{
		"id":"s1","name":"cert","secret_type":"public_cert","state":1,
		"rotation":{"auto_rotate":true,"rotate_keys":false}
	}`), &m))
	args := secretArgs(m)
	assert.Equal(t, "active", args["state"].Value)
	assert.Equal(t, true, args["autoRotate"].Value)
	assert.Equal(t, int64(0), args["rotationInterval"].Value)
	assert.Equal(t, "public", args["issuerType"].Value)

	// No rotation policy: not rotated.
	m = secretMetadata{SecretType: strp("imported_cert")}
	args = secretArgs(m)
	assert.Equal(t, false, args["autoRotate"].Value)
	assert.Equal(t, "imported", args["issuerType"].Value)
	assert.Nil(t, args["expirationDate"].Value)

	m = secretMetadata{SecretType: strp("arbitrary")}
	assert.Equal(t, "", secretArgs(m)["issuerType"].Value)
}

func TestSecretsManagerEndpoint(t *testing.T) {
	u, err := secretsManagerEndpoint(resourcecontrollerv2.ResourceInstance{GUID: strp("g1"), RegionID: strp("us-south")})
	require.NoError(t, err)
	assert.Equal(t, "https://g1.us-south.secrets-manager.appdomain.cloud", u)

	u, err = secretsManagerEndpoint(resourcecontrollerv2.ResourceInstance{Extensions: map[string]any{
		"endpoints": map[string]any{"public": "g1.eu-de.secrets-manager.appdomain.cloud"},
	}})
	require.NoError(t, err)
	assert.Equal(t, "https://g1.eu-de.secrets-manager.appdomain.cloud", u)

	_, err = secretsManagerEndpoint(resourcecontrollerv2.ResourceInstance{})
	assert.Error(t, err)
}

func TestExternalInteractionArgs(t *testing.T) {
	// Nothing set: IBM Cloud's default for every identity type.
	args := externalInteractionArgs(nil)
	assert.Equal(t, "enabled", args["user"].Value)
	assert.Equal(t, "enabled", args["service"].Value)
	assert.Equal(t, []any{}, args["userAllowedAccounts"].Value)

	args = externalInteractionArgs(&iampolicymanagementv1.AccountSettingsAccessManagement{
		ExternalAccountIdentityInteraction: &iampolicymanagementv1.ExternalAccountIdentityInteraction{
			IdentityTypes: &iampolicymanagementv1.IdentityTypes{
				User:      &iampolicymanagementv1.IdentityTypesBase{State: strp("limited"), ExternalAllowedAccounts: []string{"other"}},
				ServiceID: &iampolicymanagementv1.IdentityTypesBase{State: strp("monitor")},
			},
		},
	})
	assert.Equal(t, "limited", args["user"].Value)
	assert.Equal(t, []any{"other"}, args["userAllowedAccounts"].Value)
	assert.Equal(t, "monitor", args["serviceId"].Value)
	assert.Equal(t, "enabled", args["service"].Value)
}
