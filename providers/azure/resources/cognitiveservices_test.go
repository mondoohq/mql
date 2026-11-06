// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestCognitiveAccountInternetReachable(t *testing.T) {
	tests := []struct {
		name          string
		pna           string
		defaultAction string
		ipRules       []string
		want          bool
	}{
		// Synthetic: public access off wins over an Allow default; no target showed this.
		{"public access disabled", "Disabled", "Allow", nil, false},
		// Synthetic: public access off wins over a catch-all rule; no target showed this.
		{"public access disabled with catch-all rule", "Disabled", "Deny", []string{"0.0.0.0/0"}, false},
		// Synthetic: Allow default admits everything regardless of rules; no target showed this.
		{"allow default", "Enabled", "Allow", []string{"203.0.113.0/24"}, true},
		// Synthetic: no network rule set at all, which Azure treats as Allow; no target showed this.
		{"absent network acls", "Enabled", "", nil, true},
		// Synthetic: accounts created before publicNetworkAccess existed report it empty and are public; no target showed this.
		{"empty public access, absent acls", "", "", nil, true},
		// Synthetic: Deny with only narrow rules; no target showed this.
		{"deny with narrow rules", "Enabled", "Deny", []string{"203.0.113.0/24", "198.51.100.7"}, false},
		// Synthetic: Deny with no rules at all admits nothing public; no target showed this.
		{"deny with no rules", "Enabled", "Deny", nil, false},
		// Synthetic: a catch-all rule behind Deny; no target showed this.
		{"deny with catch-all rule", "Enabled", "Deny", []string{"0.0.0.0/0"}, true},
		// Synthetic: two halves of IPv4 together cover the internet; no target showed this.
		{"deny with split halves", "Enabled", "Deny", []string{"0.0.0.0/1", "128.0.0.0/1"}, true},
		// Synthetic: the API returns enum values in any case; no target showed this.
		{"lower-case deny", "enabled", "deny", []string{"10.0.0.0/8"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cognitiveAccountInternetReachable(tt.pna, tt.defaultAction, tt.ipRules))
		})
	}
}

func TestCognitiveAccountCmkKeyURI(t *testing.T) {
	// Synthetic: Key Vault source with the trailing slash ARM returns on vault URIs; no target showed this.
	assert.Equal(t, "https://kv.vault.azure.net/keys/cmk/abc123",
		cognitiveAccountCmkKeyURI("Microsoft.KeyVault", "https://kv.vault.azure.net/", "cmk", "abc123"))
	// Synthetic: versionless key that tracks the latest version; no target showed this.
	assert.Equal(t, "https://kv.vault.azure.net/keys/cmk",
		cognitiveAccountCmkKeyURI("Microsoft.KeyVault", "https://kv.vault.azure.net", "cmk", ""))
	// Synthetic: platform-managed source with stale Key Vault properties left behind; no target showed this.
	assert.Equal(t, "",
		cognitiveAccountCmkKeyURI("Microsoft.CognitiveServices", "https://kv.vault.azure.net/", "cmk", "abc123"))
	// Synthetic: Key Vault source with no key name; no target showed this.
	assert.Equal(t, "", cognitiveAccountCmkKeyURI("Microsoft.KeyVault", "https://kv.vault.azure.net/", "", ""))
}

func TestFindDeploymentByName(t *testing.T) {
	mk := func(name string) *mqlAzureSubscriptionCognitiveServicesServiceAccountDeployment {
		return &mqlAzureSubscriptionCognitiveServicesServiceAccountDeployment{
			Name: plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
		}
	}
	primary := mk("gpt-4o")
	overflow := mk("gpt-4o-standard")
	deployments := []any{primary, overflow}

	// Synthetic: spillover names a sibling deployment; no target showed this.
	assert.Same(t, overflow, findDeploymentByName(deployments, "gpt-4o-standard"))
	// Synthetic: ARM names compare case-insensitively; no target showed this.
	assert.Same(t, overflow, findDeploymentByName(deployments, "GPT-4o-Standard"))
	// Synthetic: spillover target deleted from the account; no target showed this.
	assert.Nil(t, findDeploymentByName(deployments, "gone"))
	// Synthetic: a non-deployment entry is skipped rather than panicking; no target showed this.
	assert.Nil(t, findDeploymentByName([]any{"gpt-4o"}, "gpt-4o"))
}

// TestCognitiveAccountSubResourcesDoNotAlias covers the network rule, user-owned
// storage and network injection entries, whose ids are another resource's ARM
// id. Two accounts naming the same subnet or storage account must still get
// their own entries, or the second account reports the first one's values.
func TestCognitiveAccountSubResourcesDoNotAlias(t *testing.T) {
	const subnet = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/shared"
	const storage = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/shared"

	mk := func(name, ruleState, identityClientId string, useMSFT bool) *armcognitiveservices.Account {
		return &armcognitiveservices.Account{
			ID:   to.Ptr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/" + name),
			Name: to.Ptr(name),
			Properties: &armcognitiveservices.AccountProperties{
				NetworkACLs: &armcognitiveservices.NetworkRuleSet{
					VirtualNetworkRules: []*armcognitiveservices.VirtualNetworkRule{{ID: to.Ptr(subnet), State: to.Ptr(ruleState)}},
				},
				UserOwnedStorage: []*armcognitiveservices.UserOwnedStorage{{ResourceID: to.Ptr(storage), IdentityClientID: to.Ptr(identityClientId)}},
				NetworkInjections: []*armcognitiveservices.NetworkInjection{{
					SubnetArmID:                to.Ptr(subnet),
					Scenario:                   to.Ptr(armcognitiveservices.ScenarioTypeAgent),
					UseMicrosoftManagedNetwork: to.Ptr(useMSFT),
				}},
			},
		}
	}

	runtime := cacheIDTestRuntime()
	// Synthetic: two accounts sharing one subnet and one storage account; no target showed this.
	a, err := cognitiveServicesAccountToMql(runtime, mk("ai-a", "Succeeded", "client-a", false))
	require.NoError(t, err)
	b, err := cognitiveServicesAccountToMql(runtime, mk("ai-b", "NetworkSourceDeleted", "client-b", true))
	require.NoError(t, err)

	ruleA := a.VirtualNetworkRules.Data[0].(*mqlAzureSubscriptionCognitiveServicesServiceAccountVirtualNetworkRule)
	ruleB := b.VirtualNetworkRules.Data[0].(*mqlAzureSubscriptionCognitiveServicesServiceAccountVirtualNetworkRule)
	assert.Equal(t, "Succeeded", ruleA.State.Data)
	assert.Equal(t, "NetworkSourceDeleted", ruleB.State.Data)
	// The public id stays the subnet id so subnet() resolves.
	assert.Equal(t, subnet, ruleB.Id.Data)

	uosA := a.UserOwnedStorageAccounts.Data[0].(*mqlAzureSubscriptionCognitiveServicesServiceAccountUserOwnedStorage)
	uosB := b.UserOwnedStorageAccounts.Data[0].(*mqlAzureSubscriptionCognitiveServicesServiceAccountUserOwnedStorage)
	assert.Equal(t, "client-a", uosA.IdentityClientId.Data)
	assert.Equal(t, "client-b", uosB.IdentityClientId.Data)
	assert.Equal(t, storage, uosB.Id.Data)

	niA := a.NetworkInjections.Data[0].(*mqlAzureSubscriptionCognitiveServicesServiceAccountNetworkInjection)
	niB := b.NetworkInjections.Data[0].(*mqlAzureSubscriptionCognitiveServicesServiceAccountNetworkInjection)
	assert.False(t, niA.UseMicrosoftManagedNetwork.Data)
	assert.True(t, niB.UseMicrosoftManagedNetwork.Data)
	assert.Equal(t, subnet, niB.Id.Data)
}
