// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"

	azureres "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v4"
)

type mqlAzureSubscriptionResourceInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscription) resources() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)

	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := azureres.NewClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	expand := "createdTime,changedTime,provisioningState"
	pager := client.NewListPager(&azureres.ClientListOptions{Expand: &expand})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, resource := range page.Value {
			if resource == nil {
				continue
			}
			// NOTE: properties not not properly filled, therefore you would need to ask each individual resource:
			// https://learn.microsoft.com/en-us/rest/api/resources/resources/get-by-id
			// In order to make it happen you need to support each individual type and their api version. Therefore
			// we should not support that via the resource api but instead make sure those properties are properly
			// exposed by the typed resources
			sku, err := convert.JsonToDict(resource.SKU)
			if err != nil {
				return nil, err
			}

			plan, err := convert.JsonToDict(resource.Plan)
			if err != nil {
				return nil, err
			}

			identity, err := convert.JsonToDict(resource.Identity)
			if err != nil {
				return nil, err
			}

			sysData, err := convert.JsonToDict(resource.SystemData)
			if err != nil {
				return nil, err
			}

			args := map[string]*llx.RawData{
				"id":                llx.StringDataPtr(resource.ID),
				"name":              llx.StringDataPtr(resource.Name),
				"kind":              llx.StringDataPtr(resource.Kind),
				"location":          llx.StringDataPtr(resource.Location),
				"tags":              llx.MapData(convert.PtrMapStrToInterface(resource.Tags), types.String),
				"type":              llx.StringDataPtr(resource.Type),
				"managedBy":         llx.StringDataPtr(resource.ManagedBy),
				"sku":               llx.DictData(sku),
				"plan":              llx.DictData(plan),
				"identity":          llx.DictData(identity),
				"provisioningState": llx.StringDataPtr(resource.ProvisioningState),
				"createdTime":       llx.TimeDataPtr(resource.CreatedTime),
				"changedTime":       llx.TimeDataPtr(resource.ChangedTime),
			}
			resourceSku := orZero(resource.SKU)
			if err := setSkuData(a.MqlRuntime, args, skuName(resourceSku.Name), skuTier(resourceSku.Tier), skuSize(resourceSku.Size),
				skuFamily(resourceSku.Family), skuModel(resourceSku.Model), skuCapacity(resourceSku.Capacity)); err != nil {
				return nil, err
			}

			resourceIdentity := orZero(resource.Identity)
			if err := setResourceIdentity(a.MqlRuntime, args, sortedUserAssignedIdentityIDs(resourceIdentity.UserAssignedIdentities),
				identityType(resourceIdentity.Type), identityPrincipalId(resourceIdentity.PrincipalID), identityTenantId(resourceIdentity.TenantID)); err != nil {
				return nil, err
			}

			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.resource", args)
			if err != nil {
				return nil, err
			}
			mqlResource := mqlAzure.(*mqlAzureSubscriptionResource)
			mqlResource.cacheSystemData = sysData
			res = append(res, mqlAzure)
		}
	}
	return res, nil
}

// diagnosticSettings lists the Azure Monitor diagnostic settings on this
// resource.
//
// getDiagnosticSettings takes any ARM resource URI; it was simply only ever
// called with a subscription id, which is why the settings were unreachable
// per resource. The resource's own id is that URI.
func (a *mqlAzureSubscriptionResource) diagnosticSettings() ([]any, error) {
	if a.Id.Error != nil {
		return nil, a.Id.Error
	}
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	settings, err := getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
	if err != nil {
		// Many resource types cannot carry diagnostic settings at all, and ARM
		// says so with a 400 rather than an empty list. Reported as null, not
		// as an empty list: empty would claim the resource has none
		// configured, which reads as a finding, and a type that cannot have
		// them is not one. Left to propagate it would be worse still, since a
		// field error renders as the value of the enclosing collection and one
		// unsupported resource would cost the whole list.
		if isAzureNotConfigured(err) {
			a.DiagnosticSettings.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return settings, nil
}

func (a *mqlAzureSubscriptionResource) id() (string, error) {
	return a.Id.Data, nil
}
