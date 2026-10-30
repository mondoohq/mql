// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"

	azureres "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v4"
)

func (a *mqlAzureSubscription) resourceGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)

	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := azureres.NewResourceGroupsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(&azureres.ResourceGroupsClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, rg := range page.Value {
			if rg == nil {
				continue
			}
			var provisioningState *string
			if rg.Properties != nil {
				provisioningState = rg.Properties.ProvisioningState
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.resourcegroup",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(rg.ID),
					"name":              llx.StringDataPtr(rg.Name),
					"location":          llx.StringDataPtr(rg.Location),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(rg.Tags), types.String),
					"type":              llx.StringDataPtr(rg.Type),
					"provisioningState": llx.StringDataPtr(provisioningState),
					"managedBy":         llx.StringDataPtr(rg.ManagedBy),
				},
			)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionResourcegroup) id() (string, error) {
	return a.Id.Data, nil
}
