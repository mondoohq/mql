// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	web "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"
	"github.com/stretchr/testify/assert"
)

func TestFunctionAppDeploymentStorageAuth(t *testing.T) {
	uami := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/deploy"
	withAuth := func(auth *web.FunctionsDeploymentStorageAuthentication) *web.SiteProperties {
		return &web.SiteProperties{FunctionAppConfig: &web.FunctionAppConfig{
			Deployment: &web.FunctionsDeployment{Storage: &web.FunctionsDeploymentStorage{Authentication: auth}},
		}}
	}

	t.Run("app outside Flex Consumption", func(t *testing.T) {
		// Synthetic: a Consumption or dedicated-plan app has no function app config.
		got := functionAppDeploymentStorageAuth(&web.SiteProperties{})
		assert.Nil(t, got.authType)
		assert.Empty(t, got.userAssignedIdentityID)
		assert.Nil(t, functionAppDeploymentStorageAuth(nil).authType)
	})
	t.Run("user-assigned identity", func(t *testing.T) {
		// Synthetic: covers the identity ID being kept for the user-assigned type.
		got := functionAppDeploymentStorageAuth(withAuth(&web.FunctionsDeploymentStorageAuthentication{
			Type:                           ptr(web.AuthenticationTypeUserAssignedIdentity),
			UserAssignedIdentityResourceID: &uami,
		}))
		assert.Equal(t, "UserAssignedIdentity", *got.authType)
		assert.Equal(t, uami, got.userAssignedIdentityID)
	})
	t.Run("system-assigned identity ignores a stale user identity ID", func(t *testing.T) {
		// Synthetic: an identity ID left behind after switching the type must
		// not be reported as the identity in use.
		got := functionAppDeploymentStorageAuth(withAuth(&web.FunctionsDeploymentStorageAuthentication{
			Type:                           ptr(web.AuthenticationTypeSystemAssignedIdentity),
			UserAssignedIdentityResourceID: &uami,
		}))
		assert.Equal(t, "SystemAssignedIdentity", *got.authType)
		assert.Empty(t, got.userAssignedIdentityID)
	})
	t.Run("connection string", func(t *testing.T) {
		// Synthetic: connection-string authentication has no identity.
		got := functionAppDeploymentStorageAuth(withAuth(&web.FunctionsDeploymentStorageAuthentication{
			Type:                               ptr(web.AuthenticationTypeStorageAccountConnectionString),
			StorageAccountConnectionStringName: ptr("DEPLOYMENT_STORAGE_CONNECTION_STRING"),
		}))
		assert.Equal(t, "StorageAccountConnectionString", *got.authType)
		assert.Empty(t, got.userAssignedIdentityID)
	})
}
