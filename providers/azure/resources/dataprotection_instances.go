// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v4"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupInstanceInternal struct {
	cacheSystemData any
	cachePolicyID   string
	cacheVault      *mqlAzureSubscriptionDataProtectionServiceBackupVault
}

type mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupPolicyInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionDataProtectionServiceResourceGuardInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupInstance) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupPolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionDataProtectionServiceResourceGuard) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupInstance) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupPolicy) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionDataProtectionServiceResourceGuard) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// backupVaultScope returns the subscription, resource group, and vault name
// that the vault's child calls need.
func (a *mqlAzureSubscriptionDataProtectionServiceBackupVault) backupVaultScope() (subscriptionID, resourceGroup, vaultName string, err error) {
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return "", "", "", err
	}
	vaultName, err = resourceID.Component("backupVaults")
	if err != nil {
		return "", "", "", err
	}
	return resourceID.SubscriptionID, resourceID.ResourceGroup, vaultName, nil
}

// backupInstanceArgs builds the backup instance args. Datasource credentials
// are never copied.
func backupInstanceArgs(bi *armdataprotection.BackupInstanceResource) (map[string]*llx.RawData, string) {
	args := map[string]*llx.RawData{
		"id":                     llx.StringDataPtr(bi.ID),
		"name":                   llx.StringDataPtr(bi.Name),
		"tags":                   llx.MapData(convert.PtrMapStrToInterface(bi.Tags), types.String),
		"friendlyName":           llx.NilData,
		"datasourceType":         llx.NilData,
		"datasourceId":           llx.NilData,
		"datasourceLocation":     llx.NilData,
		"protectionStatus":       llx.NilData,
		"currentProtectionState": llx.NilData,
		"provisioningState":      llx.NilData,
	}
	var policyID string
	p := bi.Properties
	if p == nil {
		return args, policyID
	}
	args["friendlyName"] = llx.StringDataPtr(p.FriendlyName)
	args["currentProtectionState"] = llx.StringDataPtr(stringEnumPtr(p.CurrentProtectionState))
	args["provisioningState"] = llx.StringDataPtr(p.ProvisioningState)
	if ds := p.DataSourceInfo; ds != nil {
		args["datasourceType"] = llx.StringDataPtr(ds.DatasourceType)
		args["datasourceId"] = llx.StringDataPtr(ds.ResourceID)
		args["datasourceLocation"] = llx.StringDataPtr(ds.ResourceLocation)
	}
	if ps := p.ProtectionStatus; ps != nil {
		args["protectionStatus"] = llx.StringDataPtr(stringEnumPtr(ps.Status))
	}
	if p.PolicyInfo != nil {
		policyID = convert.ToValue(p.PolicyInfo.PolicyID)
	}
	return args, policyID
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVault) backupInstances() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subID, rg, vaultName, err := a.backupVaultScope()
	if err != nil {
		return nil, err
	}
	client, err := armdataprotection.NewBackupInstancesClient(subID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListPager(rg, vaultName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.DataProtection/backupVaults/backupInstances/read")
		}
		for _, bi := range page.Value {
			if bi == nil || bi.ID == nil {
				continue
			}
			args, policyID := backupInstanceArgs(bi)
			mqlBi, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionDataProtectionServiceBackupVaultBackupInstance, args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(bi.SystemData)
			if err != nil {
				return nil, err
			}
			instance := mqlBi.(*mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupInstance)
			instance.cacheSystemData = sysData
			instance.cachePolicyID = policyID
			instance.cacheVault = a
			res = append(res, instance)
		}
	}
	return res, nil
}

// backupPolicyRetentionRules summarizes a policy's retention rules, one entry
// per rule and datastore. It also returns the duration of the default rule's
// first lifecycle, or "" when the policy has no default rule.
func backupPolicyRetentionRules(rules []armdataprotection.BasePolicyRuleClassification) ([]any, string) {
	res := []any{}
	defaultDuration := ""
	for _, r := range rules {
		rr, ok := r.(*armdataprotection.AzureRetentionRule)
		if !ok || rr == nil {
			continue
		}
		isDefault := convert.ToValue(rr.IsDefault)
		for _, lc := range rr.Lifecycles {
			if lc == nil {
				continue
			}
			var dataStoreType, deleteAfter string
			if lc.SourceDataStore != nil {
				dataStoreType = enumString(lc.SourceDataStore.DataStoreType)
			}
			if lc.DeleteAfter != nil {
				if d := lc.DeleteAfter.GetDeleteOption(); d != nil {
					deleteAfter = convert.ToValue(d.Duration)
				}
			}
			if isDefault && defaultDuration == "" {
				defaultDuration = deleteAfter
			}
			res = append(res, map[string]any{
				"name":          convert.ToValue(rr.Name),
				"isDefault":     isDefault,
				"dataStoreType": dataStoreType,
				"deleteAfter":   deleteAfter,
			})
		}
	}
	return res, defaultDuration
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVault) backupPolicies() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subID, rg, vaultName, err := a.backupVaultScope()
	if err != nil {
		return nil, err
	}
	client, err := armdataprotection.NewBackupPoliciesClient(subID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListPager(rg, vaultName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.DataProtection/backupVaults/backupPolicies/read")
		}
		for _, bp := range page.Value {
			if bp == nil || bp.ID == nil {
				continue
			}
			datasourceTypes := []any{}
			retentionRules := []any{}
			defaultDuration := ""
			if bp.Properties != nil {
				if base := bp.Properties.GetBaseBackupPolicy(); base != nil {
					datasourceTypes = strPtrsToAny(base.DatasourceTypes)
				}
				if policy, ok := bp.Properties.(*armdataprotection.BackupPolicy); ok && policy != nil {
					retentionRules, defaultDuration = backupPolicyRetentionRules(policy.PolicyRules)
				}
			}
			mqlBp, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionDataProtectionServiceBackupVaultBackupPolicy,
				map[string]*llx.RawData{
					"id":                       llx.StringDataPtr(bp.ID),
					"name":                     llx.StringDataPtr(bp.Name),
					"datasourceTypes":          llx.ArrayData(datasourceTypes, types.String),
					"retentionRules":           llx.ArrayData(retentionRules, types.Dict),
					"defaultRetentionDuration": llx.StringData(defaultDuration),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(bp.SystemData)
			if err != nil {
				return nil, err
			}
			policy := mqlBp.(*mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupPolicy)
			policy.cacheSystemData = sysData
			res = append(res, policy)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupInstance) policy() (*mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupPolicy, error) {
	if a.cachePolicyID == "" || a.cacheVault == nil {
		a.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	policies := a.cacheVault.GetBackupPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}
	for _, entry := range policies.Data {
		p, ok := entry.(*mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupPolicy)
		if ok && strings.EqualFold(p.Id.Data, a.cachePolicyID) {
			return p, nil
		}
	}
	a.Policy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// backupDatasourceIs reports whether a backup datasource type is the given
// resource type or one of its child types, the way blob backups name
// "Microsoft.Storage/storageAccounts/blobServices" for a storage account.
func backupDatasourceIs(datasourceType, resourceType string) bool {
	dt := strings.ToLower(datasourceType)
	rt := strings.ToLower(resourceType)
	return dt == rt || strings.HasPrefix(dt, rt+"/")
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupInstance) disk() (*mqlAzureSubscriptionComputeServiceDisk, error) {
	if a.DatasourceId.Data == "" || !backupDatasourceIs(a.DatasourceType.Data, "Microsoft.Compute/disks") {
		a.Disk.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionComputeServiceDisk, map[string]*llx.RawData{
		"id": llx.StringData(a.DatasourceId.Data),
	})
	if err != nil {
		if isAzureFeatureUnavailable(err) {
			a.Disk.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlAzureSubscriptionComputeServiceDisk), nil
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVaultBackupInstance) storageAccount() (*mqlAzureSubscriptionStorageServiceAccount, error) {
	datasourceID := a.DatasourceId.Data
	if datasourceID == "" || !backupDatasourceIs(a.DatasourceType.Data, "Microsoft.Storage/storageAccounts") {
		a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	// Only this subscription's storage accounts can be resolved from its list;
	// an account elsewhere, or one that no longer exists, is reported as null.
	resourceID, err := ParseResourceID(datasourceID)
	if err != nil || !strings.EqualFold(resourceID.SubscriptionID, conn.SubId()) {
		a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionStorageService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, err
	}
	accounts := res.(*mqlAzureSubscriptionStorageService).GetAccounts()
	if accounts.Error != nil {
		return nil, accounts.Error
	}
	account, found := findByID[*mqlAzureSubscriptionStorageServiceAccount](accounts.Data, datasourceID)
	if !found {
		a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return account, nil
}

// resourceGuardArgs builds the Resource Guard args.
func resourceGuardArgs(rg *armdataprotection.ResourceGuardResource) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"id":                                  llx.StringDataPtr(rg.ID),
		"name":                                llx.StringDataPtr(rg.Name),
		"location":                            llx.StringDataPtr(rg.Location),
		"tags":                                llx.MapData(convert.PtrMapStrToInterface(rg.Tags), types.String),
		"description":                         llx.NilData,
		"provisioningState":                   llx.NilData,
		"allowAutoApprovals":                  llx.NilData,
		"protectedOperations":                 llx.ArrayData([]any{}, types.String),
		"vaultCriticalOperationExclusionList": llx.ArrayData([]any{}, types.String),
	}
	p := rg.Properties
	if p == nil {
		return args
	}
	protected := []any{}
	for _, op := range p.ResourceGuardOperations {
		if op != nil && op.VaultCriticalOperation != nil {
			protected = append(protected, *op.VaultCriticalOperation)
		}
	}
	args["description"] = llx.StringDataPtr(p.Description)
	args["provisioningState"] = llx.StringDataPtr(stringEnumPtr(p.ProvisioningState))
	args["allowAutoApprovals"] = llx.BoolDataPtr(p.AllowAutoApprovals)
	args["protectedOperations"] = llx.ArrayData(protected, types.String)
	args["vaultCriticalOperationExclusionList"] = llx.ArrayData(strPtrsToAny(p.VaultCriticalOperationExclusionList), types.String)
	return args
}

func createResourceGuardResource(runtime *plugin.Runtime, guard *armdataprotection.ResourceGuardResource) (*mqlAzureSubscriptionDataProtectionServiceResourceGuard, error) {
	res, err := CreateResource(runtime, ResourceAzureSubscriptionDataProtectionServiceResourceGuard, resourceGuardArgs(guard))
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(guard.SystemData)
	if err != nil {
		return nil, err
	}
	mqlGuard := res.(*mqlAzureSubscriptionDataProtectionServiceResourceGuard)
	mqlGuard.cacheSystemData = sysData
	return mqlGuard, nil
}

func (a *mqlAzureSubscriptionDataProtectionService) resourceGuards() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	client, err := armdataprotection.NewResourceGuardsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewGetResourcesInSubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.DataProtection/resourceGuards/read")
		}
		for _, guard := range page.Value {
			if guard == nil || guard.ID == nil {
				continue
			}
			mqlGuard, err := createResourceGuardResource(a.MqlRuntime, guard)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGuard)
		}
	}
	return res, nil
}

// vaultResourceGuardID returns the Resource Guard id from the vault's
// Resource Guard proxies, or "" when none links the vault to a guard.
func vaultResourceGuardID(proxies []*armdataprotection.ResourceGuardProxyBaseResource) string {
	for _, p := range proxies {
		if p == nil || p.Properties == nil {
			continue
		}
		if id := convert.ToValue(p.Properties.ResourceGuardResourceID); id != "" {
			return id
		}
	}
	return ""
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVault) resourceGuard() (*mqlAzureSubscriptionDataProtectionServiceResourceGuard, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subID, rg, vaultName, err := a.backupVaultScope()
	if err != nil {
		return nil, err
	}
	proxyClient, err := armdataprotection.NewDppResourceGuardProxyClient(subID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	proxies := []*armdataprotection.ResourceGuardProxyBaseResource{}
	pager := proxyClient.NewListPager(rg, vaultName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.DataProtection/backupVaults/backupResourceGuardProxies/read")
		}
		proxies = append(proxies, page.Value...)
	}
	guardID := vaultResourceGuardID(proxies)
	if guardID == "" {
		a.ResourceGuard.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	if cached := cachedResource(a.MqlRuntime, ResourceAzureSubscriptionDataProtectionServiceResourceGuard, guardID); cached != nil {
		return cached.(*mqlAzureSubscriptionDataProtectionServiceResourceGuard), nil
	}

	// The guard usually lives in another subscription, so it is read directly
	// rather than out of this subscription's list.
	guardResourceID, err := ParseResourceID(guardID)
	if err != nil {
		return nil, err
	}
	guardName, err := guardResourceID.Component("resourceGuards")
	if err != nil {
		return nil, err
	}
	guardClient, err := armdataprotection.NewResourceGuardsClient(guardResourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	resp, err := guardClient.Get(ctx, guardResourceID.ResourceGroup, guardName, nil)
	if err != nil {
		if isAzureFeatureUnavailable(err) {
			a.ResourceGuard.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, classifyAzureRefusal(err, "Microsoft.DataProtection/resourceGuards/read")
	}
	return createResourceGuardResource(a.MqlRuntime, &resp.ResourceGuardResource)
}
