// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func roleAssignmentFor(principalID string) *mqlAzureSubscriptionAuthorizationServiceRoleAssignment {
	return &mqlAzureSubscriptionAuthorizationServiceRoleAssignment{
		PrincipalId: plugin.TValue[string]{Data: principalID, State: plugin.StateIsSet},
	}
}

func TestFilterRoleAssignmentsByPrincipal(t *testing.T) {
	assignments := []any{
		roleAssignmentFor("aaa"),
		roleAssignmentFor("bbb"),
		roleAssignmentFor("aaa"),
		roleAssignmentFor("ccc"),
	}

	t.Run("returns every assignment for the principal", func(t *testing.T) {
		got := filterRoleAssignmentsByPrincipal(assignments, "aaa")
		assert.Len(t, got, 2)
		for _, ra := range got {
			assert.Equal(t, "aaa", ra.(*mqlAzureSubscriptionAuthorizationServiceRoleAssignment).PrincipalId.Data)
		}
	})
	t.Run("single match", func(t *testing.T) {
		assert.Len(t, filterRoleAssignmentsByPrincipal(assignments, "bbb"), 1)
	})
	t.Run("no match yields empty, non-nil slice", func(t *testing.T) {
		got := filterRoleAssignmentsByPrincipal(assignments, "zzz")
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})
	t.Run("empty input yields empty slice", func(t *testing.T) {
		assert.Empty(t, filterRoleAssignmentsByPrincipal(nil, "aaa"))
	})
	t.Run("skips entries of the wrong type", func(t *testing.T) {
		mixed := []any{roleAssignmentFor("aaa"), "not-a-role-assignment", 42}
		assert.Len(t, filterRoleAssignmentsByPrincipal(mixed, "aaa"), 1)
	})
}

func TestTenantIDFromIdentityDict(t *testing.T) {
	t.Run("reads tenantId from the identity dict", func(t *testing.T) {
		id := plugin.TValue[any]{Data: map[string]any{"tenantId": "t-123", "principalId": "p-1"}, State: plugin.StateIsSet}
		assert.Equal(t, "t-123", tenantIDFromIdentityDict(id))
	})
	t.Run("empty when tenantId is absent", func(t *testing.T) {
		id := plugin.TValue[any]{Data: map[string]any{"principalId": "p-1"}, State: plugin.StateIsSet}
		assert.Equal(t, "", tenantIDFromIdentityDict(id))
	})
	t.Run("empty when the value is not a map", func(t *testing.T) {
		assert.Equal(t, "", tenantIDFromIdentityDict(plugin.TValue[any]{Data: "not-a-map"}))
	})
	t.Run("empty when nil", func(t *testing.T) {
		assert.Equal(t, "", tenantIDFromIdentityDict(plugin.TValue[any]{}))
	})
}

func TestFederatedCredentialArgs(t *testing.T) {
	t.Run("GitHub Actions credential", func(t *testing.T) {
		// Synthetic: the documented shape of a federated identity credential
		// (api-version 2023-01-31); no identity we could read had one.
		payload := `{
		  "id": "/subscriptions/0000/resourcegroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1/federatedIdentityCredentials/gh",
		  "name": "gh",
		  "properties": {
		    "issuer": "https://token.actions.githubusercontent.com",
		    "subject": "repo:octo-org/octo-repo:ref:refs/heads/main",
		    "audiences": ["api://AzureADTokenExchange", null]
		  }
		}`
		var fic armmsi.FederatedIdentityCredential
		require.NoError(t, json.Unmarshal([]byte(payload), &fic))

		args := federatedCredentialArgs(&fic)
		assert.Equal(t, "gh", args["name"].Value)
		assert.Equal(t, "https://token.actions.githubusercontent.com", args["issuer"].Value)
		assert.Equal(t, "repo:octo-org/octo-repo:ref:refs/heads/main", args["subject"].Value)
		// The null audience is skipped rather than reported as "".
		assert.Equal(t, []any{"api://AzureADTokenExchange"}, args["audiences"].Value)
	})

	t.Run("absent properties read as null", func(t *testing.T) {
		// Synthetic: a credential without properties; no target showed this.
		args := federatedCredentialArgs(&armmsi.FederatedIdentityCredential{ID: new("/f"), Name: new("f")})
		assert.Nil(t, args["issuer"].Value)
		assert.Nil(t, args["subject"].Value)
		assert.Empty(t, args["audiences"].Value)
	})
}
