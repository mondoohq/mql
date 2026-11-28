// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// The armhealthbot module is pinned to API version 2021-06-10, which has
// neither the customer-managed key nor the access control method of a bot, so
// Health Bot instances are listed with requests through the azcore ARM
// pipeline (see arm_raw.go).

// healthBotAPIVersion is the newest stable Microsoft.HealthBot API version.
const healthBotAPIVersion = "2025-11-01"

// healthBotKeyVaultProperties is a bot's customer-managed key.
type healthBotKeyVaultProperties struct {
	KeyName      *string `json:"keyName"`
	KeyVersion   *string `json:"keyVersion"`
	KeyVaultURI  *string `json:"keyVaultUri"`
	UserIdentity *string `json:"userIdentity"`
}

// healthBot is one Microsoft.HealthBot/healthBots row.
type healthBot struct {
	armTrackedResource
	SKU *struct {
		Name *string `json:"name"`
	} `json:"sku"`
	Properties *struct {
		ProvisioningState       *string                      `json:"provisioningState"`
		BotManagementPortalLink *string                      `json:"botManagementPortalLink"`
		KeyVaultProperties      *healthBotKeyVaultProperties `json:"keyVaultProperties"`
		AccessControlMethod     *string                      `json:"accessControlMethod"`
	} `json:"properties"`
}

type mqlAzureSubscriptionHealthBotServiceBotInternal struct {
	cacheEncryptionKeyUri     string
	cacheEncryptionIdentityId string
}

func (a *mqlAzureSubscription) healthBot() (*mqlAzureSubscriptionHealthBotService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionHealthBotService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionHealthBotService), nil
}

func initAzureSubscriptionHealthBotService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, err := azureConn(runtime)
	if err != nil {
		return nil, nil, err
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())
	return args, nil, nil
}

func (a *mqlAzureSubscriptionHealthBotService) id() (string, error) {
	return ResourceAzureSubscriptionHealthBotService + "/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionHealthBotService) bots() ([]any, error) {
	conn, err := azureConn(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client, err := newRawArmClient(conn, "mql-azure-healthbot")
	if err != nil {
		return nil, err
	}
	first := armSubscriptionCollectionURL(client, a.SubscriptionId.Data, "Microsoft.HealthBot/healthBots", healthBotAPIVersion)
	res, err := listPaged(a.MqlRuntime, &a.Bots, "Health Bot instances",
		newArmJSONPager[healthBot](client, "Health Bot instances", first),
		func(page armJSONPage[healthBot]) []*healthBot { return page.Value },
		createHealthBot,
	)
	if err != nil || res == nil {
		return res, err
	}
	return keepTagMatches(a.MqlRuntime, res), nil
}

// healthBotEncryptionKeyURI returns the Key Vault key identifier of a bot's
// customer-managed key, or empty when the bot uses Microsoft-managed keys. A
// key is only in use when both the vault and the key name are set.
func healthBotEncryptionKeyURI(kv *healthBotKeyVaultProperties) string {
	if kv == nil {
		return ""
	}
	return keyVaultKeyURI(convert.ToValue(kv.KeyVaultURI), convert.ToValue(kv.KeyName), convert.ToValue(kv.KeyVersion))
}

// createHealthBot builds the MQL resource for one Health Bot instance.
func createHealthBot(runtime *plugin.Runtime, bot *healthBot) (plugin.Resource, error) {
	p := orZero(bot.Properties)
	keyURI := healthBotEncryptionKeyURI(p.KeyVaultProperties)
	var keyName, keyVersion, keyIdentity string
	if keyURI != "" {
		kv := p.KeyVaultProperties
		keyName = convert.ToValue(kv.KeyName)
		keyVersion = convert.ToValue(kv.KeyVersion)
		keyIdentity = convert.ToValue(kv.UserIdentity)
	}
	args := map[string]*llx.RawData{
		"id":                        llx.StringDataPtr(bot.ID),
		"name":                      llx.StringDataPtr(bot.Name),
		"location":                  llx.StringDataPtr(bot.Location),
		"tags":                      llx.MapData(convert.PtrMapStrToInterface(bot.Tags), types.String),
		"accessControlMethod":       llx.StringData(convert.ToValue(p.AccessControlMethod)),
		"customerManagedKeyEnabled": llx.BoolData(keyURI != ""),
		"encryptionKeyName":         llx.StringData(keyName),
		"encryptionKeyVersion":      llx.StringData(keyVersion),
		"botManagementPortalLink":   llx.StringDataPtr(p.BotManagementPortalLink),
		"provisioningState":         llx.StringDataPtr(p.ProvisioningState),
	}
	var skuNameValue *string
	if bot.SKU != nil {
		skuNameValue = bot.SKU.Name
	}
	if err := setSkuData(runtime, args, skuName(skuNameValue)); err != nil {
		return nil, err
	}
	if err := setArmResourceIdentity(runtime, args, bot.Identity); err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, ResourceAzureSubscriptionHealthBotServiceBot, args)
	if err != nil {
		return nil, err
	}
	mqlBot := res.(*mqlAzureSubscriptionHealthBotServiceBot)
	mqlBot.cacheEncryptionKeyUri = keyURI
	mqlBot.cacheEncryptionIdentityId = keyIdentity
	return mqlBot, nil
}

func (a *mqlAzureSubscriptionHealthBotServiceBot) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionHealthBotServiceBot) encryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cacheEncryptionKeyUri == "" {
		a.EncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cacheEncryptionKeyUri)
}

func (a *mqlAzureSubscriptionHealthBotServiceBot) encryptionIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	return userAssignedIdentityRef(a.MqlRuntime, a.cacheEncryptionIdentityId, &a.EncryptionIdentity)
}
