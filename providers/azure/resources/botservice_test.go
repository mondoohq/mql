// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/botservice/armbotservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testBotID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.BotService/botServices/support-bot"

// Synthetic: shaped after the Microsoft.BotService 2022-09-15 REST reference; no target showed this.
const testBotBody = `{
  "id": "` + testBotID + `",
  "name": "support-bot",
  "location": "global",
  "kind": "azurebot",
  "sku": {"name": "S1"},
  "tags": {"env": "prod"},
  "properties": {
    "displayName": "Support",
    "endpoint": "https://bot.example.com/api/messages",
    "msaAppId": "00000000-0000-0000-0000-0000000000aa",
    "msaAppType": "UserAssignedMSI",
    "msaAppTenantId": "00000000-0000-0000-0000-0000000000bb",
    "msaAppMSIResourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/bot-id",
    "publicNetworkAccess": "Disabled",
    "disableLocalAuth": true,
    "isCmekEnabled": true,
    "cmekKeyVaultUrl": "https://kv.vault.azure.net/keys/bot-cmk/abc123",
    "enabledChannels": ["webchat", "directline"],
    "configuredChannels": ["webchat", "directline", "msteams"],
    "isStreamingSupported": false,
    "luisKey": "not-a-real-key"
  }
}`

func TestBotToMql(t *testing.T) {
	var bot armbotservice.Bot
	require.NoError(t, json.Unmarshal([]byte(testBotBody), &bot))
	mqlBot, err := botToMql(cacheIDTestRuntime(), &bot)
	require.NoError(t, err)

	assert.Equal(t, "azurebot", mqlBot.Kind.Data)
	assert.Equal(t, "Disabled", mqlBot.PublicNetworkAccess.Data)
	assert.True(t, mqlBot.DisableLocalAuth.Data)
	assert.True(t, mqlBot.IsCmekEnabled.Data)
	assert.Equal(t, "UserAssignedMSI", mqlBot.MsaAppType.Data)
	assert.Equal(t, "00000000-0000-0000-0000-0000000000bb", mqlBot.MsaAppTenantId.Data)
	assert.Equal(t, []any{"webchat", "directline"}, mqlBot.EnabledChannels.Data)
	assert.Equal(t, []any{"webchat", "directline", "msteams"}, mqlBot.ConfiguredChannels.Data)
	assert.False(t, mqlBot.IsStreamingSupported.Data)
	assert.False(t, mqlBot.IsStreamingSupported.IsNull())
	assert.True(t, mqlBot.CmekEncryptionStatus.IsNull())
	assert.Equal(t, "https://kv.vault.azure.net/keys/bot-cmk/abc123", mqlBot.cacheCmkKeyUri)
	assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/bot-id", mqlBot.cacheMsaAppMsiId)
}

func TestBotCmkKeyURI(t *testing.T) {
	url := to.Ptr("https://kv.vault.azure.net/keys/bot-cmk/abc123")
	// Synthetic: CMK on with a key URL; no target showed this.
	assert.Equal(t, *url, botCmkKeyURI(to.Ptr(true), url))
	// Synthetic: CMK switched off with the old key URL left behind; no target showed this.
	assert.Equal(t, "", botCmkKeyURI(to.Ptr(false), url))
	// Synthetic: CMK flag absent; no target showed this.
	assert.Equal(t, "", botCmkKeyURI(nil, url))
	// Synthetic: CMK on with no key URL; no target showed this.
	assert.Equal(t, "", botCmkKeyURI(to.Ptr(true), nil))
}

// directLineChannelBody is a Direct Line channel with one secure site and one
// legacy site. Keys are present to show they are never read.
// Synthetic: shaped after the Microsoft.BotService 2022-09-15 REST reference; no target showed this.
func directLineChannelBody(botID string) string {
	return `{
  "id": "` + botID + `/channels/DirectLineChannel",
  "name": "support-bot/DirectLineChannel",
  "location": "global",
  "properties": {
    "channelName": "DirectLineChannel",
    "provisioningState": "Succeeded",
    "properties": {
      "sites": [{
        "siteId": "site-1",
        "siteName": "Default Site",
        "isEnabled": true,
        "isSecureSiteEnabled": true,
        "trustedOrigins": ["https://app.example.com"],
        "isV1Enabled": false,
        "isV3Enabled": true,
        "isBlockUserUploadEnabled": true,
        "key": "not-a-real-key",
        "key2": "not-a-real-key"
      }, {
        "siteName": "Legacy",
        "isEnabled": true,
        "isV1Enabled": true,
        "isV3Enabled": true
      }, {
        "isEnabled": true
      }]
    }
  }
}`
}

func decodeBotChannel(t *testing.T, body string) *armbotservice.BotChannel {
	t.Helper()
	var ch armbotservice.BotChannel
	require.NoError(t, json.Unmarshal([]byte(body), &ch))
	return &ch
}

func TestBotChannelToMql(t *testing.T) {
	runtime := cacheIDTestRuntime()
	res, err := botChannelToMql(runtime, decodeBotChannel(t, directLineChannelBody(testBotID)))
	require.NoError(t, err)
	ch := res.(*mqlAzureSubscriptionBotServiceBotChannel)
	assert.Equal(t, "DirectLineChannel", ch.ChannelName.Data)
	assert.Equal(t, "Succeeded", ch.ProvisioningState.Data)

	// The entry with neither an id nor a name is skipped.
	require.Len(t, ch.Sites.Data, 2)
	secure := ch.Sites.Data[0].(*mqlAzureSubscriptionBotServiceBotChannelSite)
	assert.Equal(t, "Default Site", secure.SiteName.Data)
	assert.True(t, secure.IsSecureSiteEnabled.Data)
	assert.Equal(t, []any{"https://app.example.com"}, secure.TrustedOrigins.Data)
	assert.False(t, secure.IsV1Enabled.Data)
	assert.True(t, secure.IsBlockUserUploadEnabled.Data)
	assert.True(t, secure.IsTokenEnabled.IsNull())

	// A site without an id is keyed by its name.
	legacy := ch.Sites.Data[1].(*mqlAzureSubscriptionBotServiceBotChannelSite)
	assert.Equal(t, "Legacy", legacy.SiteName.Data)
	assert.True(t, legacy.SiteId.IsNull())
	assert.True(t, legacy.IsV1Enabled.Data)
	assert.True(t, legacy.IsSecureSiteEnabled.IsNull())
}

func TestBotChannelSitesAreKeyedByChannel(t *testing.T) {
	runtime := cacheIDTestRuntime()
	// Synthetic: two bots whose Direct Line sites share a site id; no target showed this.
	a, err := botChannelToMql(runtime, decodeBotChannel(t, directLineChannelBody(testBotID)))
	require.NoError(t, err)
	b, err := botChannelToMql(runtime, decodeBotChannel(t, directLineChannelBody(testBotID+"-2")))
	require.NoError(t, err)
	siteA := a.(*mqlAzureSubscriptionBotServiceBotChannel).Sites.Data[0]
	siteB := b.(*mqlAzureSubscriptionBotServiceBotChannel).Sites.Data[0]
	assert.NotSame(t, siteA, siteB)
}

func TestBotChannelWithoutSites(t *testing.T) {
	// Synthetic: a Teams channel, which has no sites; no target showed this.
	res, err := botChannelToMql(cacheIDTestRuntime(), decodeBotChannel(t, `{
  "id": "`+testBotID+`/channels/MsTeamsChannel",
  "properties": {"channelName": "MsTeamsChannel", "properties": {"isEnabled": true}}
}`))
	require.NoError(t, err)
	ch := res.(*mqlAzureSubscriptionBotServiceBotChannel)
	assert.Equal(t, "MsTeamsChannel", ch.ChannelName.Data)
	assert.Empty(t, ch.Sites.Data)
}

func TestBotConnectionToMql(t *testing.T) {
	// Synthetic: an Entra ID OAuth connection; no target showed this.
	var cs armbotservice.ConnectionSetting
	require.NoError(t, json.Unmarshal([]byte(`{
  "id": "`+testBotID+`/connections/graph",
  "name": "graph",
  "properties": {
    "serviceProviderDisplayName": "Azure Active Directory v2",
    "serviceProviderId": "30dd229c-58e3-4a48-bdfd-91ec48eb906c",
    "scopes": "User.Read",
    "clientId": "00000000-0000-0000-0000-0000000000cc",
    "clientSecret": "not-a-real-secret"
  }
}`), &cs))
	res, err := botConnectionToMql(cacheIDTestRuntime(), &cs)
	require.NoError(t, err)
	c := res.(*mqlAzureSubscriptionBotServiceBotConnection)
	assert.Equal(t, "Azure Active Directory v2", c.ServiceProviderDisplayName.Data)
	assert.Equal(t, "User.Read", c.Scopes.Data)
	assert.True(t, c.ProvisioningState.IsNull())

	// An entry without an id is skipped.
	none, err := botConnectionToMql(cacheIDTestRuntime(), &armbotservice.ConnectionSetting{Name: to.Ptr("x")})
	require.NoError(t, err)
	assert.Nil(t, none)
}
