// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// Azure AI Video Indexer has no Go SDK module, so its accounts are listed with
// requests through the azcore ARM pipeline (see arm_raw.go).

// videoIndexerAPIVersion is the newest stable Microsoft.VideoIndexer API version.
const videoIndexerAPIVersion = "2025-04-01"

// videoIndexerLinkedService is the storageServices or openAiServices block of
// an account: the linked resource and the identity the account reaches it with.
type videoIndexerLinkedService struct {
	ResourceID           *string `json:"resourceId"`
	UserAssignedIdentity *string `json:"userAssignedIdentity"`
}

// videoIndexerAccount is one Microsoft.VideoIndexer/accounts row.
type videoIndexerAccount struct {
	armTrackedResource
	Properties *struct {
		TenantID                   *string                    `json:"tenantId"`
		AccountID                  *string                    `json:"accountId"`
		StorageServices            *videoIndexerLinkedService `json:"storageServices"`
		OpenAiServices             *videoIndexerLinkedService `json:"openAiServices"`
		TotalMinutesIndexed        *int64                     `json:"totalMinutesIndexed"`
		PublicNetworkAccess        *string                    `json:"publicNetworkAccess"`
		PrivateEndpointConnections []map[string]any           `json:"privateEndpointConnections"`
		ProvisioningState          *string                    `json:"provisioningState"`
	} `json:"properties"`
}

type mqlAzureSubscriptionVideoIndexerServiceAccountInternal struct {
	cacheStorageAccountId           string
	cacheStorageIdentityId          string
	cacheOpenAiAccountId            string
	cacheOpenAiIdentityId           string
	cachePrivateEndpointConnections []map[string]any
}

func (a *mqlAzureSubscription) videoIndexer() (*mqlAzureSubscriptionVideoIndexerService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionVideoIndexerService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionVideoIndexerService), nil
}

func initAzureSubscriptionVideoIndexerService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionVideoIndexerService) id() (string, error) {
	return ResourceAzureSubscriptionVideoIndexerService + "/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionVideoIndexerService) accounts() ([]any, error) {
	conn, err := azureConn(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client, err := newRawArmClient(conn, "mql-azure-videoindexer")
	if err != nil {
		return nil, err
	}
	first := armSubscriptionCollectionURL(client, a.SubscriptionId.Data, "Microsoft.VideoIndexer/accounts", videoIndexerAPIVersion)
	res, err := listPaged(a.MqlRuntime, &a.Accounts, "Video Indexer accounts",
		newArmJSONPager[videoIndexerAccount](client, "Video Indexer accounts", first),
		func(page armJSONPage[videoIndexerAccount]) []*videoIndexerAccount { return page.Value },
		createVideoIndexerAccount,
	)
	if err != nil || res == nil {
		return res, err
	}
	return keepTagMatches(a.MqlRuntime, res), nil
}

// createVideoIndexerAccount builds the MQL resource for one Video Indexer account.
func createVideoIndexerAccount(runtime *plugin.Runtime, acc *videoIndexerAccount) (plugin.Resource, error) {
	p := orZero(acc.Properties)
	storage := orZero(p.StorageServices)
	openAi := orZero(p.OpenAiServices)
	args := map[string]*llx.RawData{
		"id":                  llx.StringDataPtr(acc.ID),
		"name":                llx.StringDataPtr(acc.Name),
		"location":            llx.StringDataPtr(acc.Location),
		"tags":                llx.MapData(convert.PtrMapStrToInterface(acc.Tags), types.String),
		"accountId":           llx.StringDataPtr(p.AccountID),
		"tenantId":            llx.StringDataPtr(p.TenantID),
		"publicNetworkAccess": llx.StringData(orDefault(p.PublicNetworkAccess, "Enabled")),
		"totalMinutesIndexed": llx.IntDataPtr(p.TotalMinutesIndexed),
		"provisioningState":   llx.StringDataPtr(p.ProvisioningState),
	}
	if err := setArmResourceIdentity(runtime, args, acc.Identity); err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, ResourceAzureSubscriptionVideoIndexerServiceAccount, args)
	if err != nil {
		return nil, err
	}
	mqlAcc := res.(*mqlAzureSubscriptionVideoIndexerServiceAccount)
	mqlAcc.cacheStorageAccountId = convert.ToValue(storage.ResourceID)
	mqlAcc.cacheStorageIdentityId = convert.ToValue(storage.UserAssignedIdentity)
	mqlAcc.cacheOpenAiAccountId = convert.ToValue(openAi.ResourceID)
	mqlAcc.cacheOpenAiIdentityId = convert.ToValue(openAi.UserAssignedIdentity)
	mqlAcc.cachePrivateEndpointConnections = p.PrivateEndpointConnections
	return mqlAcc, nil
}

func (a *mqlAzureSubscriptionVideoIndexerServiceAccount) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionVideoIndexerServiceAccount) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}

func (a *mqlAzureSubscriptionVideoIndexerServiceAccount) storageAccount() (*mqlAzureSubscriptionStorageServiceAccount, error) {
	if a.cacheStorageAccountId == "" {
		a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn, err := azureConn(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return getStorageAccount(a.cacheStorageAccountId, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionVideoIndexerServiceAccount) storageAccessIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	return userAssignedIdentityRef(a.MqlRuntime, a.cacheStorageIdentityId, &a.StorageAccessIdentity)
}

func (a *mqlAzureSubscriptionVideoIndexerServiceAccount) openAiAccount() (*mqlAzureSubscriptionCognitiveServicesServiceAccount, error) {
	if a.cacheOpenAiAccountId == "" {
		a.OpenAiAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionCognitiveServicesServiceAccount,
		map[string]*llx.RawData{"id": llx.StringData(a.cacheOpenAiAccountId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionCognitiveServicesServiceAccount), nil
}

func (a *mqlAzureSubscriptionVideoIndexerServiceAccount) openAiAccessIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	return userAssignedIdentityRef(a.MqlRuntime, a.cacheOpenAiIdentityId, &a.OpenAiAccessIdentity)
}
