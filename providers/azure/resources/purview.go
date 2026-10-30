// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/purview/armpurview"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionPurviewService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionPurviewService) id() (string, error) {
	return "azure.subscription.purviewService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionPurviewServiceAccount) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionPurviewService) accounts() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided. it is not an Azure connection")
	}

	ctx := context.Background()
	client, err := armpurview.NewAccountsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListBySubscriptionPager(&armpurview.AccountsClientListBySubscriptionOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list purview accounts due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			resource, err := purviewAccountToMql(a.MqlRuntime, entry)
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
	}
	return res, nil
}

func purviewAccountToMql(runtime *plugin.Runtime, account *armpurview.Account) (*mqlAzureSubscriptionPurviewServiceAccount, error) {
	idVal := ""
	if account.ID != nil {
		idVal = *account.ID
	}
	name := ""
	if account.Name != nil {
		name = *account.Name
	}
	location := ""
	if account.Location != nil {
		location = *account.Location
	}
	resourceType := ""
	if account.Type != nil {
		resourceType = *account.Type
	}

	tags := map[string]any{}
	for k, v := range account.Tags {
		if v == nil {
			tags[k] = ""
		} else {
			tags[k] = *v
		}
	}

	skuDict, _ := convert.JsonToDict(account.SKU)
	accountSku := orZero(account.SKU)
	identityDict, _ := convert.JsonToDict(account.Identity)
	propertiesDict, _ := convert.JsonToDict(account.Properties)

	var (
		friendlyName             string
		provisioningState        string
		publicNetworkAccess      string
		managedResourceGroupName string
		createdBy                string
		createdByObjectId        string
	)
	createdAt := llx.NilData

	var (
		endpointsDict              map[string]any
		managedResourcesDict       map[string]any
		cloudConnectorsDict        map[string]any
		privateEndpointConnections []any
	)

	if p := account.Properties; p != nil {
		if p.FriendlyName != nil {
			friendlyName = *p.FriendlyName
		}
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		if p.PublicNetworkAccess != nil {
			publicNetworkAccess = string(*p.PublicNetworkAccess)
		}
		if p.ManagedResourceGroupName != nil {
			managedResourceGroupName = *p.ManagedResourceGroupName
		}
		if p.CreatedBy != nil {
			createdBy = *p.CreatedBy
		}
		if p.CreatedByObjectID != nil {
			createdByObjectId = *p.CreatedByObjectID
		}
		if p.CreatedAt != nil {
			createdAt = llx.TimeData(*p.CreatedAt)
		}
		if d, _ := convert.JsonToDict(p.Endpoints); d != nil {
			endpointsDict = d
		}
		if d, _ := convert.JsonToDict(p.ManagedResources); d != nil {
			managedResourcesDict = d
		}
		if d, _ := convert.JsonToDict(p.CloudConnectors); d != nil {
			cloudConnectorsDict = d
		}
		for _, pec := range p.PrivateEndpointConnections {
			if pec == nil {
				continue
			}
			if d, _ := convert.JsonToDict(pec); d != nil {
				privateEndpointConnections = append(privateEndpointConnections, d)
			}
		}
	}

	args := map[string]*llx.RawData{
		"id":                         llx.StringData(idVal),
		"name":                       llx.StringData(name),
		"location":                   llx.StringData(location),
		"type":                       llx.StringData(resourceType),
		"tags":                       llx.MapData(tags, types.String),
		"sku":                        llx.DictData(skuDict),
		"identity":                   llx.DictData(identityDict),
		"friendlyName":               llx.StringData(friendlyName),
		"provisioningState":          llx.StringData(provisioningState),
		"publicNetworkAccess":        llx.StringData(publicNetworkAccess),
		"managedResourceGroupName":   llx.StringData(managedResourceGroupName),
		"managedResources":           llx.DictData(managedResourcesDict),
		"endpoints":                  llx.DictData(endpointsDict),
		"privateEndpointConnections": llx.ArrayData(privateEndpointConnections, types.Dict),
		"cloudConnectors":            llx.DictData(cloudConnectorsDict),
		"createdAt":                  createdAt,
		"createdByObjectId":          llx.StringData(createdByObjectId),
		"createdBy":                  llx.StringData(createdBy),
		"properties":                 llx.DictData(propertiesDict),
	}
	if err := setSkuData(runtime, args, skuName(accountSku.Name), skuCapacity(accountSku.Capacity)); err != nil {
		return nil, err
	}
	accountIdentity := orZero(account.Identity)
	if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(accountIdentity.UserAssignedIdentities),
		identityType(accountIdentity.Type), identityPrincipalId(accountIdentity.PrincipalID), identityTenantId(accountIdentity.TenantID)); err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "azure.subscription.purviewService.account", args)
	if err != nil {
		return nil, err
	}
	mqlAccount := res.(*mqlAzureSubscriptionPurviewServiceAccount)
	sysData, err := convert.JsonToDict(account.SystemData)
	if err != nil {
		return nil, err
	}
	mqlAccount.cacheSystemData = sysData
	return mqlAccount, nil
}

type mqlAzureSubscriptionPurviewServiceAccountInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionPurviewServiceAccount) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
