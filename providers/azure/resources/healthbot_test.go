// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthBotDecode(t *testing.T) {
	// Synthetic: shaped as the 2025-11-01 HealthBot model; no instance was
	// available to measure.
	body := `{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.HealthBot/healthBots/hb","name":"hb","location":"eastus",
		"sku":{"name":"S1"},"identity":{"type":"SystemAssigned","principalId":"p","tenantId":"t"},
		"properties":{"provisioningState":"Succeeded","botManagementPortalLink":"https://portal",
			"accessControlMethod":"Entra",
			"keyVaultProperties":{"keyName":"k","keyVersion":"v1","keyVaultUri":"https://kv.vault.azure.net/","userIdentity":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi"}}}`
	var bot healthBot
	require.NoError(t, json.Unmarshal([]byte(body), &bot))
	require.NotNil(t, bot.Properties)
	assert.Equal(t, "S1", *bot.SKU.Name)
	assert.Equal(t, "Entra", *bot.Properties.AccessControlMethod)
	assert.Equal(t, "https://portal", *bot.Properties.BotManagementPortalLink)
	assert.Equal(t, "https://kv.vault.azure.net/keys/k/v1", healthBotEncryptionKeyURI(bot.Properties.KeyVaultProperties))
	assert.True(t, isUserAssignedIdentityID(*bot.Properties.KeyVaultProperties.UserIdentity))
}

func TestHealthBotEncryptionKeyURI(t *testing.T) {
	// Synthetic cases.
	assert.Equal(t, "", healthBotEncryptionKeyURI(nil), "Microsoft-managed keys")
	assert.Equal(t, "", healthBotEncryptionKeyURI(&healthBotKeyVaultProperties{}))
	assert.Equal(t, "", healthBotEncryptionKeyURI(&healthBotKeyVaultProperties{KeyVaultURI: new("https://kv.vault.azure.net")}),
		"a vault without a key name is no key")
	assert.Equal(t, "", healthBotEncryptionKeyURI(&healthBotKeyVaultProperties{KeyName: new("k")}),
		"a key name without a vault is no key")
	assert.Equal(t, "https://kv.vault.azure.net/keys/k",
		healthBotEncryptionKeyURI(&healthBotKeyVaultProperties{KeyVaultURI: new("https://kv.vault.azure.net"), KeyName: new("k")}),
		"no version follows the latest key version")
}
