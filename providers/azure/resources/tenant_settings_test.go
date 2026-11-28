// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"
	"github.com/stretchr/testify/assert"
)

func TestIsAzureNotFound(t *testing.T) {
	assert.True(t, isAzureNotFound(&azcore.ResponseError{StatusCode: http.StatusNotFound}))
	assert.False(t, isAzureNotFound(&azcore.ResponseError{StatusCode: http.StatusForbidden}))
	assert.False(t, isAzureNotFound(errors.New("boom")))
}

func TestEffectiveHierarchySettings(t *testing.T) {
	root := managementGroupIDPrefix + "tenant-1"

	t.Run("never configured reports the root group and no authorization requirement", func(t *testing.T) {
		v := effectiveHierarchySettings("tenant-1", nil)
		assert.Equal(t, root+"/settings/default", v.id)
		assert.Equal(t, "tenant-1", v.tenantID)
		assert.Equal(t, root, v.defaultManagementGroup)
		assert.False(t, v.requireAuthorizationForGroupCreation)
	})

	t.Run("configured values are reported as set", func(t *testing.T) {
		v := effectiveHierarchySettings("tenant-1", &armmanagementgroups.HierarchySettingsProperties{
			DefaultManagementGroup:               new(managementGroupIDPrefix + "landing"),
			RequireAuthorizationForGroupCreation: new(true),
		})
		assert.Equal(t, managementGroupIDPrefix+"landing", v.defaultManagementGroup)
		assert.True(t, v.requireAuthorizationForGroupCreation)
	})

	t.Run("only the authorization requirement set keeps the root as default group", func(t *testing.T) {
		v := effectiveHierarchySettings("tenant-1", &armmanagementgroups.HierarchySettingsProperties{
			RequireAuthorizationForGroupCreation: new(true),
		})
		assert.Equal(t, root, v.defaultManagementGroup)
		assert.True(t, v.requireAuthorizationForGroupCreation)
	})
}

func TestEffectiveSubscriptionPolicy(t *testing.T) {
	t.Run("never configured permits both directions with no exemptions", func(t *testing.T) {
		v := effectiveSubscriptionPolicy("tenant-1", nil)
		assert.Equal(t, "tenant-1", v.tenantID)
		assert.False(t, v.blockLeaving)
		assert.False(t, v.blockInto)
		assert.NotNil(t, v.exemptedPrincipals)
		assert.Empty(t, v.exemptedPrincipals)
	})

	t.Run("configured values and the policy's tenant are reported", func(t *testing.T) {
		v := effectiveSubscriptionPolicy("", &armsubscription.TenantPolicy{
			PolicyID:                        new("tenant-2"),
			BlockSubscriptionsLeavingTenant: new(true),
			BlockSubscriptionsIntoTenant:    new(true),
			ExemptedPrincipals:              []*string{new("p-1"), nil, new("")},
		})
		assert.Equal(t, "tenant-2", v.tenantID)
		assert.True(t, v.blockLeaving)
		assert.True(t, v.blockInto)
		assert.Equal(t, []any{"p-1"}, v.exemptedPrincipals)
	})
}
