// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
