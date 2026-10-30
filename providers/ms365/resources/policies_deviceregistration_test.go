// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deviceRegistrationPolicyJSON is the body GET /v1.0/policies/deviceRegistrationPolicy
// returned for a live tenant. The membership objects are a polymorphic union
// carried entirely by @odata.type, so the value of azureADJoin.localAdmins
// depends on the discriminator resolving to the right concrete type.
const deviceRegistrationPolicyJSON = `{
  "azureADJoin": {
    "allowedToJoin": {"@odata.type": "#microsoft.graph.allDeviceRegistrationMembership"},
    "isAdminConfigurable": true,
    "localAdmins": {
      "enableGlobalAdmins": true,
      "registeringUsers": {"@odata.type": "#microsoft.graph.allDeviceRegistrationMembership"}
    }
  },
  "azureADRegistration": {
    "allowedToRegister": {"@odata.type": "#microsoft.graph.allDeviceRegistrationMembership"},
    "isAdminConfigurable": false
  },
  "description": "Tenant-wide policy",
  "displayName": "Device Registration Policy",
  "id": "deviceRegistrationPolicy",
  "localAdminPassword": {"isEnabled": false},
  "multiFactorAuthConfiguration": "notRequired",
  "userDeviceQuota": 50
}`

func parseDeviceRegistrationPolicy(t *testing.T, raw string) models.DeviceRegistrationPolicyable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(raw))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateDeviceRegistrationPolicyFromDiscriminatorValue)
	require.NoError(t, err)
	policy, ok := parsed.(models.DeviceRegistrationPolicyable)
	require.True(t, ok)
	return policy
}

// The join and registration blocks were previously dropped on the grounds that
// they came back empty. They do not: both deserialize, and localAdmins carries
// whether global administrators are local admins on every joined device and
// whether the user performing a join becomes one.
func TestDeviceRegistrationPolicy_JoinAndRegistrationArePresent(t *testing.T) {
	policy := parseDeviceRegistrationPolicy(t, deviceRegistrationPolicyJSON)

	join := policy.GetAzureADJoin()
	require.NotNil(t, join)
	assert.True(t, *join.GetIsAdminConfigurable())

	localAdmins := join.GetLocalAdmins()
	require.NotNil(t, localAdmins)
	assert.True(t, *localAdmins.GetEnableGlobalAdmins())
	require.NotNil(t, localAdmins.GetRegisteringUsers())

	registration := policy.GetAzureADRegistration()
	require.NotNil(t, registration)
	assert.False(t, *registration.GetIsAdminConfigurable())
	require.NotNil(t, registration.GetAllowedToRegister())
}

func TestDeviceRegistrationMembershipScope(t *testing.T) {
	membership := func(t *testing.T, raw string) models.DeviceRegistrationMembershipable {
		t.Helper()
		node, err := kjson.NewJsonParseNode([]byte(raw))
		require.NoError(t, err)
		parsed, err := node.GetObjectValue(models.CreateDeviceRegistrationMembershipFromDiscriminatorValue)
		require.NoError(t, err)
		return parsed.(models.DeviceRegistrationMembershipable)
	}

	tests := []struct {
		name       string
		raw        string
		appliesTo  string
		wantUsers  []any
		wantGroups []any
	}{
		{
			name:       "all",
			raw:        `{"@odata.type":"#microsoft.graph.allDeviceRegistrationMembership"}`,
			appliesTo:  "all",
			wantUsers:  []any{},
			wantGroups: []any{},
		},
		{
			// the hardened setting: nobody becomes a local administrator
			// merely by registering a device
			name:       "none",
			raw:        `{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"}`,
			appliesTo:  "none",
			wantUsers:  []any{},
			wantGroups: []any{},
		},
		{
			name: "enumerated",
			raw: `{"@odata.type":"#microsoft.graph.enumeratedDeviceRegistrationMembership",
			       "users":["u1","u2"],"groups":["g1"]}`,
			appliesTo:  "selected",
			wantUsers:  []any{"u1", "u2"},
			wantGroups: []any{"g1"},
		},
		{
			// a variant Graph adds later must not be reported as one of the
			// three we know, because "all" and "none" are opposite answers
			name:       "unknown variant",
			raw:        `{"@odata.type":"#microsoft.graph.futureDeviceRegistrationMembership"}`,
			appliesTo:  "",
			wantUsers:  []any{},
			wantGroups: []any{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			appliesTo, users, groups := deviceRegistrationMembershipScope(membership(t, tc.raw))
			assert.Equal(t, tc.appliesTo, appliesTo)
			assert.Equal(t, tc.wantUsers, users)
			assert.Equal(t, tc.wantGroups, groups)
		})
	}
}
