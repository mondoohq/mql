// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	web "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionFunctionsService) id() (string, error) {
	return "azure.subscription.functions/" + a.SubscriptionId.Data, nil
}

// functionAppPublicNetworkAccess returns the site's public network access
// setting ("Enabled" or "Disabled"), or "" when the properties or field are
// absent.
func functionAppPublicNetworkAccess(props *web.SiteProperties) string {
	if props == nil || props.PublicNetworkAccess == nil {
		return ""
	}
	return *props.PublicNetworkAccess
}

func initAzureSubscriptionFunctionsService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionFunctionsServiceFunctionApp) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionFunctionsServiceFunctionAppFunction) id() (string, error) {
	return a.Id.Data, nil
}

// initAzureSubscriptionFunctionsServiceFunctionApp resolves a single function
// app by its ARM resource ID so platform-discovered assets can be queried
// directly without re-listing every Microsoft.Web/sites resource in the
// subscription.
func initAzureSubscriptionFunctionsServiceFunctionApp(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionFunctionsService,
		func(s *mqlAzureSubscriptionFunctionsService) *plugin.TValue[[]any] { return s.GetFunctionApps() },
		ResourceAzureSubscriptionFunctionsServiceFunctionApp)
}

func (a *mqlAzureSubscriptionFunctionsService) functionApps() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := web.NewWebAppsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	var res []any

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, site := range page.Value {
			if site == nil {
				continue
			}
			// Filter for function apps only
			if site.Kind == nil || !strings.Contains(strings.ToLower(*site.Kind), "functionapp") {
				continue
			}

			mqlApp, err := functionAppSiteToMql(a.MqlRuntime, site)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlApp)
		}
	}

	return keepTagMatches(a.MqlRuntime, res), nil
}

// functionAppSiteToMql converts a Web App ARM site (already known to be a
// function app) into the matching MQL resource. Shared by the list path and
// the init lookup so both produce identical fields.
func functionAppSiteToMql(runtime *plugin.Runtime, site *web.Site) (plugin.Resource, error) {
	properties, err := convert.JsonToDict(site.Properties)
	if err != nil {
		return nil, err
	}

	var state, defaultHostName, clientCertMode string
	var keyVaultReferenceIdentity, virtualNetworkSubnetId string
	var httpsOnly, clientCertEnabled bool
	publicNetworkAccess := functionAppPublicNetworkAccess(site.Properties)
	if site.Properties != nil {
		if site.Properties.State != nil {
			state = *site.Properties.State
		}
		if site.Properties.DefaultHostName != nil {
			defaultHostName = *site.Properties.DefaultHostName
		}
		if site.Properties.HTTPSOnly != nil {
			httpsOnly = *site.Properties.HTTPSOnly
		}
		if site.Properties.ClientCertEnabled != nil {
			clientCertEnabled = *site.Properties.ClientCertEnabled
		}
		if site.Properties.ClientCertMode != nil {
			clientCertMode = string(*site.Properties.ClientCertMode)
		}
		if site.Properties.KeyVaultReferenceIdentity != nil {
			keyVaultReferenceIdentity = *site.Properties.KeyVaultReferenceIdentity
		}
		if site.Properties.VirtualNetworkSubnetID != nil {
			virtualNetworkSubnetId = *site.Properties.VirtualNetworkSubnetID
		}
	}
	var principalId *string
	var userAssignedIdentityIds []string
	if site.Identity != nil {
		principalId = site.Identity.PrincipalID
		if principalId != nil {
		}
		userAssignedIdentityIds = sortedUserAssignedIdentityIDs(site.Identity.UserAssignedIdentities)
	}

	res, err := CreateResource(runtime, "azure.subscription.functionsService.functionApp", map[string]*llx.RawData{
		"id":                        llx.StringDataPtr(site.ID),
		"name":                      llx.StringDataPtr(site.Name),
		"location":                  llx.StringDataPtr(site.Location),
		"tags":                      llx.MapData(convert.PtrMapStrToInterface(site.Tags), types.String),
		"kind":                      llx.StringDataPtr(site.Kind),
		"state":                     llx.StringData(state),
		"defaultHostName":           llx.StringData(defaultHostName),
		"httpsOnly":                 llx.BoolData(httpsOnly),
		"clientCertEnabled":         llx.BoolData(clientCertEnabled),
		"clientCertMode":            llx.StringData(clientCertMode),
		"principalId":               llx.StringDataPtr(principalId),
		"keyVaultReferenceIdentity": llx.StringData(keyVaultReferenceIdentity),
		"publicNetworkAccess":       llx.StringData(publicNetworkAccess),
		"virtualNetworkSubnetId":    llx.StringData(virtualNetworkSubnetId),
		"properties":                llx.DictData(properties),
	})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(site.SystemData)
	if err != nil {
		return nil, err
	}
	mqlApp := res.(*mqlAzureSubscriptionFunctionsServiceFunctionApp)
	mqlApp.cacheSystemData = sysData
	mqlApp.cacheUserAssignedIdentityIds = userAssignedIdentityIds
	return res, nil
}

type mqlAzureSubscriptionFunctionsServiceFunctionAppInternal struct {
	cacheSystemData              any
	cacheUserAssignedIdentityIds []string
}

func (a *mqlAzureSubscriptionFunctionsServiceFunctionApp) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionFunctionsServiceFunctionApp) systemAssignedIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	// Unlike the other resources, the function app has no identity dict (it models
	// identity as managedServiceIdentityId), so no tenant ID is available here;
	// tenantID is cosmetic on the synthesized identity anyway, as role assignments
	// resolve by principal ID.
	return newSystemAssignedManagedIdentity(a.MqlRuntime, a.Id.Data, a.PrincipalId.Data, "", &a.SystemAssignedIdentity)
}

func (a *mqlAzureSubscriptionFunctionsServiceFunctionApp) virtualNetworkSubnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.VirtualNetworkSubnetId.Data == "" {
		a.VirtualNetworkSubnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet",
		map[string]*llx.RawData{"id": llx.StringData(a.VirtualNetworkSubnetId.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

type mqlAzureSubscriptionFunctionsServiceFunctionAppFunctionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionFunctionsServiceFunctionApp) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionFunctionsServiceFunctionAppFunction) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionFunctionsServiceFunctionApp) functions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	appName := a.Name.Data

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListFunctionsPager(resourceID.ResourceGroup, appName, nil)
	var res []any

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fn := range page.Value {
			if fn == nil {
				continue
			}

			var config any
			var language string
			var isDisabled bool
			if fn.Properties != nil {
				config, err = convert.JsonToDict(fn.Properties.Config)
				if err != nil {
					return nil, err
				}
				if fn.Properties.Language != nil {
					language = *fn.Properties.Language
				}
				if fn.Properties.IsDisabled != nil {
					isDisabled = *fn.Properties.IsDisabled
				}
			}

			mqlFn, err := CreateResource(a.MqlRuntime, "azure.subscription.functionsService.functionApp.function", map[string]*llx.RawData{
				"id":         llx.StringDataPtr(fn.ID),
				"name":       llx.StringDataPtr(fn.Name),
				"config":     llx.DictData(config),
				"language":   llx.StringData(language),
				"isDisabled": llx.BoolData(isDisabled),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(fn.SystemData)
			if err != nil {
				return nil, err
			}
			mqlFn.(*mqlAzureSubscriptionFunctionsServiceFunctionAppFunction).cacheSystemData = sysData
			res = append(res, mqlFn)
		}
	}

	return res, nil
}

// configuration returns the function app's site configuration (minimum TLS
// version, FTPS state, HTTP/2, always-on, IP restrictions). Function apps are
// App Service sites, so this reuses the appsiteconfig resource.
func (a *mqlAzureSubscriptionFunctionsServiceFunctionApp) configuration() (*mqlAzureSubscriptionWebServiceAppsiteconfig, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return webAppSiteConfigToMql(a.MqlRuntime, conn, a.Id.Data)
}
