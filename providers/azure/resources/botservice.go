// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/botservice/armbotservice"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// Bot Service resources never read the secret-bearing parts of the API: the
// bot's allSettings, parameters, LUIS and Application Insights keys and
// publishing credentials, the Direct Line and Web Chat site keys, or a
// connection setting's client secret and parameters. The list calls used here
// leave the keys and the client secret empty anyway; the ListWithKeys and
// ListWithSecrets calls that return them are not used.

func (a *mqlAzureSubscription) botService() (*mqlAzureSubscriptionBotService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionBotService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionBotService), nil
}

func initAzureSubscriptionBotService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())
	return args, nil, nil
}

func (a *mqlAzureSubscriptionBotService) id() (string, error) {
	return ResourceAzureSubscriptionBotService + "/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionBotService) bots() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	client, err := armbotservice.NewBotsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.BotService/botServices/read")
		}
		for _, bot := range page.Value {
			if bot == nil || bot.ID == nil || *bot.ID == "" {
				continue
			}
			mqlBot, err := botToMql(a.MqlRuntime, bot)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlBot)
		}
	}
	return keepTagMatches(a.MqlRuntime, res), nil
}

func botToMql(runtime *plugin.Runtime, bot *armbotservice.Bot) (*mqlAzureSubscriptionBotServiceBot, error) {
	p := orZero(bot.Properties)
	args := map[string]*llx.RawData{
		"id":                   llx.StringDataPtr(bot.ID),
		"name":                 llx.StringDataPtr(bot.Name),
		"location":             llx.StringDataPtr(bot.Location),
		"tags":                 llx.MapData(convert.PtrMapStrToInterface(bot.Tags), types.String),
		"kind":                 llx.StringDataPtr(stringEnumPtr(bot.Kind)),
		"displayName":          llx.StringDataPtr(p.DisplayName),
		"description":          llx.StringDataPtr(p.Description),
		"endpoint":             llx.StringDataPtr(p.Endpoint),
		"endpointVersion":      llx.StringDataPtr(p.EndpointVersion),
		"provisioningState":    llx.StringDataPtr(p.ProvisioningState),
		"publicNetworkAccess":  llx.StringDataPtr(stringEnumPtr(p.PublicNetworkAccess)),
		"disableLocalAuth":     llx.BoolDataPtr(p.DisableLocalAuth),
		"isCmekEnabled":        llx.BoolDataPtr(p.IsCmekEnabled),
		"cmekEncryptionStatus": llx.StringDataPtr(p.CmekEncryptionStatus),
		"msaAppId":             llx.StringDataPtr(p.MsaAppID),
		"msaAppType":           llx.StringDataPtr(stringEnumPtr(p.MsaAppType)),
		"msaAppTenantId":       llx.StringDataPtr(p.MsaAppTenantID),
		"enabledChannels":      llx.ArrayData(strPtrsToAny(p.EnabledChannels), types.String),
		"configuredChannels":   llx.ArrayData(strPtrsToAny(p.ConfiguredChannels), types.String),
		"isStreamingSupported": llx.BoolDataPtr(p.IsStreamingSupported),
	}
	sku := orZero(bot.SKU)
	if err := setSkuData(runtime, args, skuName(sku.Name), skuTier(sku.Tier)); err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, ResourceAzureSubscriptionBotServiceBot, args)
	if err != nil {
		return nil, err
	}
	mqlBot := res.(*mqlAzureSubscriptionBotServiceBot)
	mqlBot.cacheCmkKeyUri = botCmkKeyURI(p.IsCmekEnabled, p.CmekKeyVaultURL)
	mqlBot.cacheMsaAppMsiId = convert.ToValue(p.MsaAppMSIResourceID)
	mqlBot.cachePrivateEndpointConnections = p.PrivateEndpointConnections
	return mqlBot, nil
}

type mqlAzureSubscriptionBotServiceBotInternal struct {
	cacheCmkKeyUri                  string
	cacheMsaAppMsiId                string
	cachePrivateEndpointConnections []*armbotservice.PrivateEndpointConnection
}

// botCmkKeyURI returns the Key Vault key identifier of a bot's customer-managed
// key, or empty unless CMK is enabled: a bot switched back to Microsoft-managed
// keys can still carry the old URL, and resolving it would report a key that
// no longer encrypts anything.
func botCmkKeyURI(isCmekEnabled *bool, keyURL *string) string {
	if isCmekEnabled == nil || !*isCmekEnabled || keyURL == nil {
		return ""
	}
	return *keyURL
}

func (a *mqlAzureSubscriptionBotServiceBot) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionBotServiceBot) cmkKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cacheCmkKeyUri == "" {
		a.CmkKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cacheCmkKeyUri)
}

func (a *mqlAzureSubscriptionBotServiceBot) msaAppManagedIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	if a.cacheMsaAppMsiId == "" {
		a.MsaAppManagedIdentity.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionManagedIdentity,
		map[string]*llx.RawData{"__id": llx.StringData(a.cacheMsaAppMsiId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}

func (a *mqlAzureSubscriptionBotServiceBot) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}

func (a *mqlAzureSubscriptionBotServiceBot) channels() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	botName, err := parsed.Component("botServices")
	if err != nil {
		return nil, err
	}
	client, err := armbotservice.NewChannelsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListByResourceGroupPager(parsed.ResourceGroup, botName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.BotService/botServices/channels/read")
		}
		for _, ch := range page.Value {
			mqlCh, err := botChannelToMql(a.MqlRuntime, ch)
			if err != nil {
				return nil, err
			}
			if mqlCh != nil {
				res = append(res, mqlCh)
			}
		}
	}
	return res, nil
}

// botChannelSite is the part of a Direct Line or Web Chat site this provider
// reads. The two SDK site types carry the same fields; neither the site keys
// nor anything else secret is copied here.
type botChannelSite struct {
	SiteID                   *string
	SiteName                 *string
	IsEnabled                *bool
	IsSecureSiteEnabled      *bool
	TrustedOrigins           []*string
	IsV1Enabled              *bool
	IsV3Enabled              *bool
	IsTokenEnabled           *bool
	IsBlockUserUploadEnabled *bool
	IsNoStorageEnabled       *bool
	IsDetailedLoggingEnabled *bool
}

// botChannelSites returns the sites of a Direct Line or Web Chat channel, and
// nil for channel types that have none.
func botChannelSites(props armbotservice.ChannelClassification) []botChannelSite {
	var out []botChannelSite
	switch ch := props.(type) {
	case *armbotservice.DirectLineChannel:
		if ch.Properties == nil {
			return nil
		}
		for _, s := range ch.Properties.Sites {
			if s == nil {
				continue
			}
			out = append(out, botChannelSite{
				SiteID: s.SiteID, SiteName: s.SiteName, IsEnabled: s.IsEnabled,
				IsSecureSiteEnabled: s.IsSecureSiteEnabled, TrustedOrigins: s.TrustedOrigins,
				IsV1Enabled: s.IsV1Enabled, IsV3Enabled: s.IsV3Enabled, IsTokenEnabled: s.IsTokenEnabled,
				IsBlockUserUploadEnabled: s.IsBlockUserUploadEnabled, IsNoStorageEnabled: s.IsNoStorageEnabled,
				IsDetailedLoggingEnabled: s.IsDetailedLoggingEnabled,
			})
		}
	case *armbotservice.WebChatChannel:
		if ch.Properties == nil {
			return nil
		}
		for _, s := range ch.Properties.Sites {
			if s == nil {
				continue
			}
			out = append(out, botChannelSite{
				SiteID: s.SiteID, SiteName: s.SiteName, IsEnabled: s.IsEnabled,
				IsSecureSiteEnabled: s.IsSecureSiteEnabled, TrustedOrigins: s.TrustedOrigins,
				IsV1Enabled: s.IsV1Enabled, IsV3Enabled: s.IsV3Enabled, IsTokenEnabled: s.IsTokenEnabled,
				IsBlockUserUploadEnabled: s.IsBlockUserUploadEnabled, IsNoStorageEnabled: s.IsNoStorageEnabled,
				IsDetailedLoggingEnabled: s.IsDetailedLoggingEnabled,
			})
		}
	}
	return out
}

func botChannelToMql(runtime *plugin.Runtime, ch *armbotservice.BotChannel) (plugin.Resource, error) {
	if ch == nil || ch.ID == nil || *ch.ID == "" {
		return nil, nil
	}
	var channelName, provisioningState *string
	if ch.Properties != nil {
		if base := ch.Properties.GetChannel(); base != nil {
			channelName = base.ChannelName
			provisioningState = base.ProvisioningState
		}
	}
	sites := []any{}
	for _, s := range botChannelSites(ch.Properties) {
		// A site's own id is the cache key, qualified by the channel; the
		// name stands in when the service leaves the id empty.
		key := convert.ToValue(s.SiteID)
		if key == "" {
			key = convert.ToValue(s.SiteName)
		}
		if key == "" {
			continue
		}
		site, err := CreateResource(runtime, ResourceAzureSubscriptionBotServiceBotChannelSite, map[string]*llx.RawData{
			"__id":                     llx.StringData(subResourceCacheID(nil, *ch.ID, "sites", key)),
			"siteId":                   llx.StringDataPtr(s.SiteID),
			"siteName":                 llx.StringDataPtr(s.SiteName),
			"isEnabled":                llx.BoolDataPtr(s.IsEnabled),
			"isSecureSiteEnabled":      llx.BoolDataPtr(s.IsSecureSiteEnabled),
			"trustedOrigins":           llx.ArrayData(strPtrsToAny(s.TrustedOrigins), types.String),
			"isV1Enabled":              llx.BoolDataPtr(s.IsV1Enabled),
			"isV3Enabled":              llx.BoolDataPtr(s.IsV3Enabled),
			"isTokenEnabled":           llx.BoolDataPtr(s.IsTokenEnabled),
			"isBlockUserUploadEnabled": llx.BoolDataPtr(s.IsBlockUserUploadEnabled),
			"isNoStorageEnabled":       llx.BoolDataPtr(s.IsNoStorageEnabled),
			"isDetailedLoggingEnabled": llx.BoolDataPtr(s.IsDetailedLoggingEnabled),
		})
		if err != nil {
			return nil, err
		}
		sites = append(sites, site)
	}
	return CreateResource(runtime, ResourceAzureSubscriptionBotServiceBotChannel, map[string]*llx.RawData{
		"id":                llx.StringDataPtr(ch.ID),
		"name":              llx.StringDataPtr(ch.Name),
		"channelName":       llx.StringDataPtr(channelName),
		"location":          llx.StringDataPtr(ch.Location),
		"tags":              llx.MapData(convert.PtrMapStrToInterface(ch.Tags), types.String),
		"provisioningState": llx.StringDataPtr(provisioningState),
		"sites":             llx.ArrayData(sites, types.Resource(ResourceAzureSubscriptionBotServiceBotChannelSite)),
	})
}

func (a *mqlAzureSubscriptionBotServiceBotChannel) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionBotServiceBot) connections() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	botName, err := parsed.Component("botServices")
	if err != nil {
		return nil, err
	}
	client, err := armbotservice.NewBotConnectionClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListByBotServicePager(parsed.ResourceGroup, botName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.BotService/botServices/connections/read")
		}
		for _, cs := range page.Value {
			mqlCs, err := botConnectionToMql(a.MqlRuntime, cs)
			if err != nil {
				return nil, err
			}
			if mqlCs != nil {
				res = append(res, mqlCs)
			}
		}
	}
	return res, nil
}

func botConnectionToMql(runtime *plugin.Runtime, cs *armbotservice.ConnectionSetting) (plugin.Resource, error) {
	if cs == nil || cs.ID == nil || *cs.ID == "" {
		return nil, nil
	}
	p := orZero(cs.Properties)
	return CreateResource(runtime, ResourceAzureSubscriptionBotServiceBotConnection, map[string]*llx.RawData{
		"id":                         llx.StringDataPtr(cs.ID),
		"name":                       llx.StringDataPtr(cs.Name),
		"serviceProviderDisplayName": llx.StringDataPtr(p.ServiceProviderDisplayName),
		"serviceProviderId":          llx.StringDataPtr(p.ServiceProviderID),
		"scopes":                     llx.StringDataPtr(p.Scopes),
		"provisioningState":          llx.StringDataPtr(p.ProvisioningState),
	})
}

func (a *mqlAzureSubscriptionBotServiceBotConnection) id() (string, error) {
	return a.Id.Data, nil
}
