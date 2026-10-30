// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	web "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionWebServiceStaticSiteInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionWebServiceStaticSite) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceStaticSite) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionWebService) staticSites() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := web.NewStaticSitesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, site := range page.Value {
			if site == nil {
				continue
			}

			var skuName, skuTier string
			if site.SKU != nil {
				if site.SKU.Name != nil {
					skuName = *site.SKU.Name
				}
				if site.SKU.Tier != nil {
					skuTier = *site.SKU.Tier
				}
			}

			var identityType string
			if site.Identity != nil && site.Identity.Type != nil {
				identityType = string(*site.Identity.Type)
			}

			var (
				defaultHostname             string
				contentDistributionEndpoint string
				customDomains               = []any{}
				repositoryUrl               string
				branch                      string
				provider                    string
				publicNetworkAccess         string
				allowConfigFileUpdates      *bool
				stagingEnvironmentPolicy    string
				enterpriseGradeCdnStatus    string
				keyVaultReferenceIdentity   string
				privateEndpointCount        int64
				userProvidedFunctionApps    int64
				linkedBackends              int64
				databaseConnections         int64
			)
			if p := site.Properties; p != nil {
				if p.DefaultHostname != nil {
					defaultHostname = *p.DefaultHostname
				}
				if p.ContentDistributionEndpoint != nil {
					contentDistributionEndpoint = *p.ContentDistributionEndpoint
				}
				for _, d := range p.CustomDomains {
					if d != nil {
						customDomains = append(customDomains, *d)
					}
				}
				if p.RepositoryURL != nil {
					repositoryUrl = *p.RepositoryURL
				}
				if p.Branch != nil {
					branch = *p.Branch
				}
				if p.Provider != nil {
					provider = *p.Provider
				}
				if p.PublicNetworkAccess != nil {
					publicNetworkAccess = *p.PublicNetworkAccess
				}
				allowConfigFileUpdates = p.AllowConfigFileUpdates
				if p.StagingEnvironmentPolicy != nil {
					stagingEnvironmentPolicy = string(*p.StagingEnvironmentPolicy)
				}
				if p.EnterpriseGradeCdnStatus != nil {
					enterpriseGradeCdnStatus = string(*p.EnterpriseGradeCdnStatus)
				}
				if p.KeyVaultReferenceIdentity != nil {
					keyVaultReferenceIdentity = *p.KeyVaultReferenceIdentity
				}
				privateEndpointCount = int64(len(p.PrivateEndpointConnections))
				userProvidedFunctionApps = int64(len(p.UserProvidedFunctionApps))
				linkedBackends = int64(len(p.LinkedBackends))
				databaseConnections = int64(len(p.DatabaseConnections))
			}

			mqlSite, err := CreateResource(a.MqlRuntime, "azure.subscription.webService.staticSite",
				map[string]*llx.RawData{
					"id":                             llx.StringDataPtr(site.ID),
					"name":                           llx.StringDataPtr(site.Name),
					"location":                       llx.StringDataPtr(site.Location),
					"kind":                           llx.StringDataPtr(site.Kind),
					"tags":                           llx.MapData(convert.PtrMapStrToInterface(site.Tags), types.String),
					"skuName":                        llx.StringData(skuName),
					"skuTier":                        llx.StringData(skuTier),
					"identityType":                   llx.StringData(identityType),
					"defaultHostname":                llx.StringData(defaultHostname),
					"contentDistributionEndpoint":    llx.StringData(contentDistributionEndpoint),
					"customDomains":                  llx.ArrayData(customDomains, types.String),
					"repositoryUrl":                  llx.StringData(repositoryUrl),
					"branch":                         llx.StringData(branch),
					"provider":                       llx.StringData(provider),
					"publicNetworkAccess":            llx.StringData(publicNetworkAccess),
					"allowConfigFileUpdates":         llx.BoolDataPtr(allowConfigFileUpdates),
					"stagingEnvironmentPolicy":       llx.StringData(stagingEnvironmentPolicy),
					"enterpriseGradeCdnStatus":       llx.StringData(enterpriseGradeCdnStatus),
					"keyVaultReferenceIdentity":      llx.StringData(keyVaultReferenceIdentity),
					"privateEndpointConnectionCount": llx.IntData(privateEndpointCount),
					"userProvidedFunctionAppCount":   llx.IntData(userProvidedFunctionApps),
					"linkedBackendCount":             llx.IntData(linkedBackends),
					"databaseConnectionCount":        llx.IntData(databaseConnections),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(site.SystemData)
			if err != nil {
				return nil, err
			}
			mqlSite.(*mqlAzureSubscriptionWebServiceStaticSite).cacheSystemData = sysData
			res = append(res, mqlSite)
		}
	}
	return res, nil
}
