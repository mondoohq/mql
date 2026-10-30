// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionAutomationService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionAutomationService) id() (string, error) {
	return "azure.subscription.automationService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccount) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccountVariable) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccountCredential) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccountCertificate) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAutomationService) accounts() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	ctx := context.Background()
	client, err := armautomation.NewAccountClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
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
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list Automation accounts due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, acct := range page.Value {
			if acct == nil {
				continue
			}
			mqlAcct, err := automationAccountToMql(a.MqlRuntime, acct)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAcct)
		}
	}
	return res, nil
}

func automationAccountToMql(runtime *plugin.Runtime, acct *armautomation.Account) (*mqlAzureSubscriptionAutomationServiceAccount, error) {
	// Properties is a nullable pointer; guard before reading SKU (the nil guard
	// for the remaining property reads is already below).
	var acctSKU *armautomation.SKU
	if acct.Properties != nil {
		acctSKU = acct.Properties.SKU
	}
	sku, err := convert.JsonToDict(acctSKU)
	if err != nil {
		return nil, err
	}
	identity, err := convert.JsonToDict(acct.Identity)
	if err != nil {
		return nil, err
	}

	var state, cmkKeySource, cmkKeyName, cmkKeyVaultURI string
	var publicNetworkAccess, disableLocalAuth bool
	var creationTime, lastModifiedTime *llx.RawData
	if p := acct.Properties; p != nil {
		state = string(convert.ToValue(p.State))
		publicNetworkAccess = convert.ToValue(p.PublicNetworkAccess)
		disableLocalAuth = convert.ToValue(p.DisableLocalAuth)
		creationTime = llx.TimeDataPtr(p.CreationTime)
		lastModifiedTime = llx.TimeDataPtr(p.LastModifiedTime)
		if enc := p.Encryption; enc != nil {
			cmkKeySource = string(convert.ToValue(enc.KeySource))
			if kv := enc.KeyVaultProperties; kv != nil {
				cmkKeyName = convert.ToValue(kv.KeyName)
				cmkKeyVaultURI = convert.ToValue(kv.KeyvaultURI)
			}
		}
	}
	if creationTime == nil {
		creationTime = llx.NilData
	}
	if lastModifiedTime == nil {
		lastModifiedTime = llx.NilData
	}

	accountArgs := map[string]*llx.RawData{
		"id":                  llx.StringDataPtr(acct.ID),
		"name":                llx.StringDataPtr(acct.Name),
		"location":            llx.StringDataPtr(acct.Location),
		"tags":                llx.MapData(convert.PtrMapStrToInterface(acct.Tags), types.String),
		"sku":                 llx.DictData(sku),
		"identity":            llx.DictData(identity),
		"state":               llx.StringData(state),
		"publicNetworkAccess": llx.BoolData(publicNetworkAccess),
		"disableLocalAuth":    llx.BoolData(disableLocalAuth),
		"cmkKeySource":        llx.StringData(cmkKeySource),
		"cmkKeyName":          llx.StringData(cmkKeyName),
		"cmkKeyVaultUri":      llx.StringData(cmkKeyVaultURI),
		"creationTime":        creationTime,
		"lastModifiedTime":    lastModifiedTime,
	}
	skuVal := orZero(acctSKU)
	if err := setSkuData(runtime, accountArgs, skuName(skuVal.Name), skuFamily(skuVal.Family), skuCapacity(skuVal.Capacity)); err != nil {
		return nil, err
	}

	acctIdentity := orZero(acct.Identity)
	if err := setResourceIdentity(runtime, accountArgs, sortedUserAssignedIdentityIDs(acctIdentity.UserAssignedIdentities),
		identityType(acctIdentity.Type), identityPrincipalId(acctIdentity.PrincipalID), identityTenantId(acctIdentity.TenantID)); err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "azure.subscription.automationService.account", accountArgs)
	if err != nil {
		return nil, err
	}
	mqlAccount := res.(*mqlAzureSubscriptionAutomationServiceAccount)
	sysData, err := convert.JsonToDict(acct.SystemData)
	if err != nil {
		return nil, err
	}
	mqlAccount.cacheSystemData = sysData
	return mqlAccount, nil
}

type mqlAzureSubscriptionAutomationServiceAccountInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionAutomationServiceAccountVariableInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionAutomationServiceAccountCredentialInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionAutomationServiceAccountCertificateInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionAutomationServiceAccount) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionAutomationServiceAccountVariable) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionAutomationServiceAccountCredential) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionAutomationServiceAccountCertificate) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// accountScope parses the resource group and account name out of the
// account's ARM resource ID, which sub-resource list calls require.
func (a *mqlAzureSubscriptionAutomationServiceAccount) accountScope() (resourceGroup string, accountName string, err error) {
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return "", "", err
	}
	accountName, err = resourceID.Component("automationAccounts")
	if err != nil {
		return "", "", err
	}
	return resourceID.ResourceGroup, accountName, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccount) variables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	rg, name, err := a.accountScope()
	if err != nil {
		return nil, err
	}
	client, err := armautomation.NewVariableClient(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListByAutomationAccountPager(rg, name, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list azure variables, returning partial results")
				return res, nil
			}
			return nil, err
		}
		for _, v := range page.Value {
			if v == nil {
				continue
			}
			var description string
			var isEncrypted bool
			creationTime := llx.NilData
			lastModifiedTime := llx.NilData
			if p := v.Properties; p != nil {
				description = convert.ToValue(p.Description)
				isEncrypted = convert.ToValue(p.IsEncrypted)
				creationTime = llx.TimeDataPtr(p.CreationTime)
				lastModifiedTime = llx.TimeDataPtr(p.LastModifiedTime)
			}
			mqlVar, err := CreateResource(a.MqlRuntime, "azure.subscription.automationService.account.variable",
				map[string]*llx.RawData{
					"id":               llx.StringDataPtr(v.ID),
					"name":             llx.StringDataPtr(v.Name),
					"isEncrypted":      llx.BoolData(isEncrypted),
					"description":      llx.StringData(description),
					"creationTime":     creationTime,
					"lastModifiedTime": lastModifiedTime,
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(v.SystemData)
			if err != nil {
				return nil, err
			}
			mqlVar.(*mqlAzureSubscriptionAutomationServiceAccountVariable).cacheSystemData = sysData
			res = append(res, mqlVar)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccount) credentials() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	rg, name, err := a.accountScope()
	if err != nil {
		return nil, err
	}
	client, err := armautomation.NewCredentialClient(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListByAutomationAccountPager(rg, name, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list azure credentials, returning partial results")
				return res, nil
			}
			return nil, err
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			var userName, description string
			creationTime := llx.NilData
			lastModifiedTime := llx.NilData
			if p := c.Properties; p != nil {
				userName = convert.ToValue(p.UserName)
				description = convert.ToValue(p.Description)
				creationTime = llx.TimeDataPtr(p.CreationTime)
				lastModifiedTime = llx.TimeDataPtr(p.LastModifiedTime)
			}
			mqlCred, err := CreateResource(a.MqlRuntime, "azure.subscription.automationService.account.credential",
				map[string]*llx.RawData{
					"id":               llx.StringDataPtr(c.ID),
					"name":             llx.StringDataPtr(c.Name),
					"userName":         llx.StringData(userName),
					"description":      llx.StringData(description),
					"creationTime":     creationTime,
					"lastModifiedTime": lastModifiedTime,
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(c.SystemData)
			if err != nil {
				return nil, err
			}
			mqlCred.(*mqlAzureSubscriptionAutomationServiceAccountCredential).cacheSystemData = sysData
			res = append(res, mqlCred)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccount) certificates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	rg, name, err := a.accountScope()
	if err != nil {
		return nil, err
	}
	client, err := armautomation.NewCertificateClient(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListByAutomationAccountPager(rg, name, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list azure certificates, returning partial results")
				return res, nil
			}
			return nil, err
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			var thumbprint, description string
			var isExportable bool
			expiryTime := llx.NilData
			creationTime := llx.NilData
			if p := c.Properties; p != nil {
				thumbprint = convert.ToValue(p.Thumbprint)
				description = convert.ToValue(p.Description)
				isExportable = convert.ToValue(p.IsExportable)
				expiryTime = llx.TimeDataPtr(p.ExpiryTime)
				creationTime = llx.TimeDataPtr(p.CreationTime)
			}
			mqlCert, err := CreateResource(a.MqlRuntime, "azure.subscription.automationService.account.certificate",
				map[string]*llx.RawData{
					"id":           llx.StringDataPtr(c.ID),
					"name":         llx.StringDataPtr(c.Name),
					"thumbprint":   llx.StringData(thumbprint),
					"expiryTime":   expiryTime,
					"isExportable": llx.BoolData(isExportable),
					"description":  llx.StringData(description),
					"creationTime": creationTime,
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(c.SystemData)
			if err != nil {
				return nil, err
			}
			mqlCert.(*mqlAzureSubscriptionAutomationServiceAccountCertificate).cacheSystemData = sysData
			res = append(res, mqlCert)
		}
	}
	return res, nil
}
