// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	storage "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v4"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionStorageServiceAccountFileShare) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionStorageServiceAccountFileShareInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionStorageServiceAccountFileShare) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionStorageServiceAccountPrivateEndpointConnection) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionStorageServiceAccountPrivateEndpointConnectionInternal struct {
	cacheSystemData        any
	cachePrivateEndpointId string
}

func (a *mqlAzureSubscriptionStorageServiceAccountPrivateEndpointConnection) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// privateEndpoint resolves the consumer-side private endpoint of this
// connection so the subnet and virtual network it is reachable from can be
// traversed, giving the private-access path into the storage account.
func (a *mqlAzureSubscriptionStorageServiceAccountPrivateEndpointConnection) privateEndpoint() (*mqlAzureSubscriptionNetworkServicePrivateEndpoint, error) {
	if a.cachePrivateEndpointId == "" {
		a.PrivateEndpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.privateEndpoint",
		map[string]*llx.RawData{"id": llx.StringData(a.cachePrivateEndpointId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateEndpoint), nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountObjectReplicationPolicy) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionStorageServiceAccountObjectReplicationPolicyInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionStorageServiceAccountObjectReplicationPolicy) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionStorageServiceAccountBlobInventoryPolicy) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionStorageServiceAccountBlobInventoryPolicyInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionStorageServiceAccountBlobInventoryPolicy) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// storageAccountResourceGroup returns the {resourceGroup, accountName} pair
// parsed from the parent storage account ARM id, or an error if the id is
// missing or malformed.
func storageAccountResourceGroup(accountId string) (string, string, error) {
	parsed, err := ParseResourceID(accountId)
	if err != nil {
		return "", "", err
	}
	name, err := parsed.Component("storageAccounts")
	if err != nil {
		return "", "", err
	}
	return parsed.ResourceGroup, name, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) fileShares() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, accountName, err := storageAccountResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := storage.NewFileSharesClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(rg, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isFeatureNotSupportedForAccountError(err) {
				a.FileShares.State = plugin.StateIsNull | plugin.StateIsSet
				return nil, nil
			}
			return nil, err
		}
		for _, share := range page.Value {
			if share == nil {
				continue
			}
			mqlShare, err := fileShareToMQL(a.MqlRuntime, share)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlShare)
		}
	}
	return res, nil
}

func fileShareToMQL(runtime *plugin.Runtime, share *storage.FileShareItem) (plugin.Resource, error) {
	var enabledProtocols, accessTier, accessTierStatus, rootSquash string
	var leaseState, leaseStatus, leaseDuration string
	var shareQuotaGiB, provisionedIops, provisionedBandwidthMibps int64
	var signedIdentifierCount int64
	var deleted bool
	var deletedTime, accessTierChangeTime, snapshotTime, lastModifiedTime *time.Time
	metadata := map[string]any{}

	if p := share.Properties; p != nil {
		if p.EnabledProtocols != nil {
			enabledProtocols = string(*p.EnabledProtocols)
		}
		if p.AccessTier != nil {
			accessTier = string(*p.AccessTier)
		}
		if p.AccessTierStatus != nil {
			accessTierStatus = *p.AccessTierStatus
		}
		if p.RootSquash != nil {
			rootSquash = string(*p.RootSquash)
		}
		if p.ShareQuota != nil {
			shareQuotaGiB = int64(*p.ShareQuota)
		}
		if p.ProvisionedIops != nil {
			provisionedIops = int64(*p.ProvisionedIops)
		}
		if p.ProvisionedBandwidthMibps != nil {
			provisionedBandwidthMibps = int64(*p.ProvisionedBandwidthMibps)
		}
		signedIdentifierCount = int64(len(p.SignedIdentifiers))
		if p.Deleted != nil {
			deleted = *p.Deleted
		}
		deletedTime = p.DeletedTime
		accessTierChangeTime = p.AccessTierChangeTime
		snapshotTime = p.SnapshotTime
		lastModifiedTime = p.LastModifiedTime
		if p.LeaseState != nil {
			leaseState = string(*p.LeaseState)
		}
		if p.LeaseStatus != nil {
			leaseStatus = string(*p.LeaseStatus)
		}
		if p.LeaseDuration != nil {
			leaseDuration = string(*p.LeaseDuration)
		}
		for k, v := range p.Metadata {
			if v != nil {
				metadata[k] = *v
			}
		}
	}

	mqlShare, err := CreateResource(runtime, "azure.subscription.storageService.account.fileShare",
		map[string]*llx.RawData{
			"id":                        llx.StringDataPtr(share.ID),
			"name":                      llx.StringDataPtr(share.Name),
			"type":                      llx.StringDataPtr(share.Type),
			"enabledProtocols":          llx.StringData(enabledProtocols),
			"accessTier":                llx.StringData(accessTier),
			"accessTierStatus":          llx.StringData(accessTierStatus),
			"accessTierChangeTime":      llx.TimeDataPtr(accessTierChangeTime),
			"shareQuotaGiB":             llx.IntData(shareQuotaGiB),
			"provisionedIops":           llx.IntData(provisionedIops),
			"provisionedBandwidthMibps": llx.IntData(provisionedBandwidthMibps),
			"rootSquash":                llx.StringData(rootSquash),
			"signedIdentifierCount":     llx.IntData(signedIdentifierCount),
			"deleted":                   llx.BoolData(deleted),
			"deletedTime":               llx.TimeDataPtr(deletedTime),
			"snapshotTime":              llx.TimeDataPtr(snapshotTime),
			"lastModifiedTime":          llx.TimeDataPtr(lastModifiedTime),
			"leaseState":                llx.StringData(leaseState),
			"leaseStatus":               llx.StringData(leaseStatus),
			"leaseDuration":             llx.StringData(leaseDuration),
			"metadata":                  llx.MapData(metadata, types.String),
		})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(share.SystemData)
	if err != nil {
		return nil, err
	}
	mqlShare.(*mqlAzureSubscriptionStorageServiceAccountFileShare).cacheSystemData = sysData
	return mqlShare, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) privateEndpointConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, accountName, err := storageAccountResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := storage.NewPrivateEndpointConnectionsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(rg, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// Private endpoint connections are supported on virtually all storage
			// account kinds, so a FeatureNotSupportedForAccount here would be
			// surprising — surface it rather than swallowing.
			return nil, err
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			var privateEndpointId, status, description, actionsRequired, provisioningState string
			if p := c.Properties; p != nil {
				if p.PrivateEndpoint != nil && p.PrivateEndpoint.ID != nil {
					privateEndpointId = *p.PrivateEndpoint.ID
				}
				if pls := p.PrivateLinkServiceConnectionState; pls != nil {
					if pls.Status != nil {
						status = string(*pls.Status)
					}
					if pls.Description != nil {
						description = *pls.Description
					}
					if pls.ActionRequired != nil {
						actionsRequired = *pls.ActionRequired
					}
				}
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
			}
			mqlPe, err := CreateResource(a.MqlRuntime, "azure.subscription.storageService.account.privateEndpointConnection",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(c.ID),
					"name":              llx.StringDataPtr(c.Name),
					"type":              llx.StringDataPtr(c.Type),
					"status":            llx.StringData(status),
					"description":       llx.StringData(description),
					"actionsRequired":   llx.StringData(actionsRequired),
					"provisioningState": llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(c.SystemData)
			if err != nil {
				return nil, err
			}
			mqlPec := mqlPe.(*mqlAzureSubscriptionStorageServiceAccountPrivateEndpointConnection)
			mqlPec.cacheSystemData = sysData
			mqlPec.cachePrivateEndpointId = privateEndpointId
			res = append(res, mqlPe)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) objectReplicationPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, accountName, err := storageAccountResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := storage.NewObjectReplicationPoliciesClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(rg, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isFeatureNotSupportedForAccountError(err) {
				a.ObjectReplicationPolicies.State = plugin.StateIsNull | plugin.StateIsSet
				return nil, nil
			}
			return nil, err
		}
		for _, pol := range page.Value {
			if pol == nil {
				continue
			}
			var policyId, sourceAccount, destinationAccount string
			var enabledTime *time.Time
			var tagsReplicationEnabled bool
			rules := []any{}
			if p := pol.Properties; p != nil {
				if p.PolicyID != nil {
					policyId = *p.PolicyID
				}
				if p.SourceAccount != nil {
					sourceAccount = *p.SourceAccount
				}
				if p.DestinationAccount != nil {
					destinationAccount = *p.DestinationAccount
				}
				enabledTime = p.EnabledTime
				rules = objectReplicationRulesToDicts(p.Rules)
				if p.TagsReplication != nil && p.TagsReplication.Enabled != nil {
					tagsReplicationEnabled = *p.TagsReplication.Enabled
				}
			}
			mqlPol, err := CreateResource(a.MqlRuntime, "azure.subscription.storageService.account.objectReplicationPolicy",
				map[string]*llx.RawData{
					"id":                     llx.StringDataPtr(pol.ID),
					"name":                   llx.StringDataPtr(pol.Name),
					"type":                   llx.StringDataPtr(pol.Type),
					"policyId":               llx.StringData(policyId),
					"sourceAccount":          llx.StringData(sourceAccount),
					"destinationAccount":     llx.StringData(destinationAccount),
					"enabledTime":            llx.TimeDataPtr(enabledTime),
					"rules":                  llx.ArrayData(rules, types.Dict),
					"tagsReplicationEnabled": llx.BoolData(tagsReplicationEnabled),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(pol.SystemData)
			if err != nil {
				return nil, err
			}
			mqlPol.(*mqlAzureSubscriptionStorageServiceAccountObjectReplicationPolicy).cacheSystemData = sysData
			res = append(res, mqlPol)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountNetworkSecurityPerimeterConfiguration) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionStorageServiceAccountNetworkSecurityPerimeterConfigurationInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionStorageServiceAccountNetworkSecurityPerimeterConfiguration) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionStorageServiceAccount) networkSecurityPerimeterConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, accountName, err := storageAccountResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := storage.NewNetworkSecurityPerimeterConfigurationsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(rg, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// NSP is not available on every account kind/region; treat an
			// unsupported account as "no configurations" rather than failing.
			if isFeatureNotSupportedForAccountError(err) {
				a.NetworkSecurityPerimeterConfigurations.State = plugin.StateIsNull | plugin.StateIsSet
				return nil, nil
			}
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list network security perimeter configurations due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, nsp := range page.Value {
			if nsp == nil {
				continue
			}
			args := map[string]*llx.RawData{
				"id":                        llx.StringDataPtr(nsp.ID),
				"name":                      llx.StringDataPtr(nsp.Name),
				"type":                      llx.StringDataPtr(nsp.Type),
				"provisioningState":         llx.StringData(""),
				"perimeterId":               llx.StringData(""),
				"perimeterLocation":         llx.StringData(""),
				"perimeterGuid":             llx.StringData(""),
				"profileName":               llx.StringData(""),
				"accessRulesVersion":        llx.IntData(0),
				"diagnosticSettingsVersion": llx.IntData(0),
				"enabledLogCategories":      llx.ArrayData(nil, types.String),
				"accessRules":               llx.ArrayData(nil, types.Dict),
				"associationName":           llx.StringData(""),
				"associationAccessMode":     llx.StringData(""),
				"provisioningIssues":        llx.ArrayData(nil, types.Dict),
			}

			if props := nsp.Properties; props != nil {
				if props.ProvisioningState != nil {
					args["provisioningState"] = llx.StringData(string(*props.ProvisioningState))
				}
				if perimeter := props.NetworkSecurityPerimeter; perimeter != nil {
					if perimeter.ID != nil {
						args["perimeterId"] = llx.StringDataPtr(perimeter.ID)
					}
					if perimeter.Location != nil {
						args["perimeterLocation"] = llx.StringDataPtr(perimeter.Location)
					}
					if perimeter.PerimeterGUID != nil {
						args["perimeterGuid"] = llx.StringDataPtr(perimeter.PerimeterGUID)
					}
				}
				if profile := props.Profile; profile != nil {
					if profile.Name != nil {
						args["profileName"] = llx.StringDataPtr(profile.Name)
					}
					if profile.AccessRulesVersion != nil {
						args["accessRulesVersion"] = llx.IntData(int64(*profile.AccessRulesVersion))
					}
					if profile.DiagnosticSettingsVersion != nil {
						args["diagnosticSettingsVersion"] = llx.IntData(int64(*profile.DiagnosticSettingsVersion))
					}
					args["enabledLogCategories"] = llx.ArrayData(strPtrsToAny(profile.EnabledLogCategories), types.String)
					var rules []any
					for _, rule := range profile.AccessRules {
						if rule == nil {
							continue
						}
						if d, err := convert.JsonToDict(rule); err == nil {
							rules = append(rules, flattenNspProperties(d))
						}
					}
					args["accessRules"] = llx.ArrayData(rules, types.Dict)
				}
				if assoc := props.ResourceAssociation; assoc != nil {
					if assoc.Name != nil {
						args["associationName"] = llx.StringDataPtr(assoc.Name)
					}
					if assoc.AccessMode != nil {
						args["associationAccessMode"] = llx.StringData(string(*assoc.AccessMode))
					}
				}
				var issues []any
				for _, iss := range props.ProvisioningIssues {
					if iss == nil {
						continue
					}
					if d, err := convert.JsonToDict(iss); err == nil {
						issues = append(issues, flattenNspProperties(d))
					}
				}
				args["provisioningIssues"] = llx.ArrayData(issues, types.Dict)
			}

			mqlNsp, err := CreateResource(a.MqlRuntime, "azure.subscription.storageService.account.networkSecurityPerimeterConfiguration", args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(nsp.SystemData)
			if err != nil {
				return nil, err
			}
			mqlNsp.(*mqlAzureSubscriptionStorageServiceAccountNetworkSecurityPerimeterConfiguration).cacheSystemData = sysData
			res = append(res, mqlNsp)
		}
	}
	return res, nil
}

// objectReplicationRulesToDicts flattens object-replication rules into the
// stable dict shape advertised in the .lr comment so query output is
// deterministic across runs.
func objectReplicationRulesToDicts(rules []*storage.ObjectReplicationPolicyRule) []any {
	out := []any{}
	for _, r := range rules {
		if r == nil {
			continue
		}
		entry := map[string]any{
			"ruleId":               "",
			"sourceContainer":      "",
			"destinationContainer": "",
			"prefixMatch":          []any{},
			"minCreationTime":      "",
		}
		if r.RuleID != nil {
			entry["ruleId"] = *r.RuleID
		}
		if r.SourceContainer != nil {
			entry["sourceContainer"] = *r.SourceContainer
		}
		if r.DestinationContainer != nil {
			entry["destinationContainer"] = *r.DestinationContainer
		}
		if f := r.Filters; f != nil {
			prefixes := []any{}
			for _, p := range f.PrefixMatch {
				if p != nil {
					prefixes = append(prefixes, *p)
				}
			}
			entry["prefixMatch"] = prefixes
			if f.MinCreationTime != nil {
				entry["minCreationTime"] = *f.MinCreationTime
			}
		}
		out = append(out, entry)
	}
	return out
}

func (a *mqlAzureSubscriptionStorageServiceAccount) blobInventoryPolicy() (*mqlAzureSubscriptionStorageServiceAccountBlobInventoryPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, accountName, err := storageAccountResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := storage.NewBlobInventoryPoliciesClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	resp, err := client.Get(ctx, rg, accountName, storage.BlobInventoryPolicyNameDefault, nil)
	if err != nil {
		// Storage accounts without a blob-inventory policy return 404; surface that as null
		// rather than as an error so .blobInventoryPolicy reads as "no policy" cleanly.
		if isInventoryPolicyNotFoundError(err) {
			a.BlobInventoryPolicy.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	pol := resp.BlobInventoryPolicy

	var enabled bool
	var lastModified *time.Time
	rules := []any{}
	if p := pol.Properties; p != nil {
		lastModified = p.LastModifiedTime
		if p.Policy != nil {
			if p.Policy.Enabled != nil {
				enabled = *p.Policy.Enabled
			}
			rules = inventoryRulesToDicts(p.Policy.Rules)
		}
	}

	mqlPol, err := CreateResource(a.MqlRuntime, "azure.subscription.storageService.account.blobInventoryPolicy",
		map[string]*llx.RawData{
			"id":               llx.StringDataPtr(pol.ID),
			"name":             llx.StringDataPtr(pol.Name),
			"type":             llx.StringDataPtr(pol.Type),
			"enabled":          llx.BoolData(enabled),
			"lastModifiedTime": llx.TimeDataPtr(lastModified),
			"rules":            llx.ArrayData(rules, types.Dict),
		})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(pol.SystemData)
	if err != nil {
		return nil, err
	}
	mqlPol.(*mqlAzureSubscriptionStorageServiceAccountBlobInventoryPolicy).cacheSystemData = sysData
	return mqlPol.(*mqlAzureSubscriptionStorageServiceAccountBlobInventoryPolicy), nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) defenderForStorage() (*mqlAzureSubscriptionStorageServiceAccountDefenderForStorageSetting, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	resourceId := a.Id.Data
	client, err := armsecurity.NewDefenderForStorageClient(conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	resp, err := client.Get(ctx, resourceId, armsecurity.SettingNameCurrent, nil)
	if err != nil {
		var rerr *azcore.ResponseError
		if errors.As(err, &rerr) && (rerr.StatusCode == http.StatusForbidden || rerr.StatusCode == http.StatusNotFound) {
			a.DefenderForStorage.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	var (
		isEnabled                              bool
		overrideSubscriptionLevelSettings      bool
		sensitiveDataDiscoveryEnabled          bool
		malwareScanningOnUploadEnabled         bool
		malwareScanningCapGBPerMonth           int64
		malwareScanningResultsEventGridTopicId string
	)
	var sensitiveDataDiscoveryStatus, malwareScanningStatus map[string]any
	var sensitiveDataDiscoveryOperationStatus, malwareScanningOperationStatus *armsecurity.OperationStatus

	malwareScanningCapGBPerMonth = -1

	if p := resp.Properties; p != nil {
		if p.IsEnabled != nil {
			isEnabled = *p.IsEnabled
		}
		if p.OverrideSubscriptionLevelSettings != nil {
			overrideSubscriptionLevelSettings = *p.OverrideSubscriptionLevelSettings
		}
		if p.SensitiveDataDiscovery != nil {
			if p.SensitiveDataDiscovery.IsEnabled != nil {
				sensitiveDataDiscoveryEnabled = *p.SensitiveDataDiscovery.IsEnabled
			}
			if d, _ := convert.JsonToDict(p.SensitiveDataDiscovery.OperationStatus); d != nil {
				sensitiveDataDiscoveryStatus = d
			}
			sensitiveDataDiscoveryOperationStatus = p.SensitiveDataDiscovery.OperationStatus
		}
		if p.MalwareScanning != nil {
			if p.MalwareScanning.OnUpload != nil {
				if p.MalwareScanning.OnUpload.IsEnabled != nil {
					malwareScanningOnUploadEnabled = *p.MalwareScanning.OnUpload.IsEnabled
				}
				if p.MalwareScanning.OnUpload.CapGBPerMonth != nil {
					malwareScanningCapGBPerMonth = int64(*p.MalwareScanning.OnUpload.CapGBPerMonth)
				}
			}
			if p.MalwareScanning.ScanResultsEventGridTopicResourceID != nil {
				malwareScanningResultsEventGridTopicId = *p.MalwareScanning.ScanResultsEventGridTopicResourceID
			}
			if d, _ := convert.JsonToDict(p.MalwareScanning.OperationStatus); d != nil {
				malwareScanningStatus = d
			}
			malwareScanningOperationStatus = p.MalwareScanning.OperationStatus
		}
	}

	settingId := ""
	if resp.ID != nil {
		settingId = *resp.ID
	}
	if settingId == "" {
		settingId = resourceId + "/providers/Microsoft.Security/defenderForStorageSettings/current"
	}

	sensitiveDataDiscoveryStatusRef, err := defenderOperationStatusToMql(a.MqlRuntime, settingId, "sensitiveDataDiscovery", sensitiveDataDiscoveryOperationStatus)
	if err != nil {
		return nil, err
	}
	malwareScanningStatusRef, err := defenderOperationStatusToMql(a.MqlRuntime, settingId, "malwareScanning", malwareScanningOperationStatus)
	if err != nil {
		return nil, err
	}

	mqlSetting, err := CreateResource(a.MqlRuntime, "azure.subscription.storageService.account.defenderForStorageSetting",
		map[string]*llx.RawData{
			"id":                                     llx.StringData(settingId),
			"isEnabled":                              llx.BoolData(isEnabled),
			"overrideSubscriptionLevelSettings":      llx.BoolData(overrideSubscriptionLevelSettings),
			"sensitiveDataDiscoveryEnabled":          llx.BoolData(sensitiveDataDiscoveryEnabled),
			"sensitiveDataDiscoveryStatus":           llx.DictData(sensitiveDataDiscoveryStatus),
			"sensitiveDataDiscoveryOperationStatus":  sensitiveDataDiscoveryStatusRef,
			"malwareScanningOnUploadEnabled":         llx.BoolData(malwareScanningOnUploadEnabled),
			"malwareScanningCapGBPerMonth":           llx.IntData(malwareScanningCapGBPerMonth),
			"malwareScanningResultsEventGridTopicId": llx.StringData(malwareScanningResultsEventGridTopicId),
			"malwareScanningStatus":                  llx.DictData(malwareScanningStatus),
			"malwareScanningOperationStatus":         malwareScanningStatusRef,
		})
	if err != nil {
		return nil, err
	}
	return mqlSetting.(*mqlAzureSubscriptionStorageServiceAccountDefenderForStorageSetting), nil
}

// defenderOperationStatusToMql maps the status Defender reports for one of its
// features onto the shared status resource.
//
// A feature can be switched on in the configuration and still not be running,
// so a check that reads only the enabled flag can report protection that is
// not in effect. A feature Defender reports no status for reads null.
func defenderOperationStatusToMql(runtime *plugin.Runtime, settingID, feature string, status *armsecurity.OperationStatus) (*llx.RawData, error) {
	if status == nil {
		return llx.NilData, nil
	}
	const resourceName = "azure.subscription.storageService.account.defenderForStorageSetting.operationStatus"
	res, err := CreateResource(runtime, resourceName, map[string]*llx.RawData{
		"__id":    llx.StringData(settingID + "/" + feature + "/operationStatus"),
		"code":    llx.StringDataPtr(status.Code),
		"message": llx.StringDataPtr(status.Message),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, resourceName), nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountDefenderForStorageSetting) id() (string, error) {
	return a.Id.Data, nil
}

func inventoryRulesToDicts(rules []*storage.BlobInventoryPolicyRule) []any {
	out := []any{}
	for _, r := range rules {
		if r == nil {
			continue
		}
		entry := map[string]any{
			"name":        "",
			"enabled":     false,
			"destination": "",
			"definition":  map[string]any{},
		}
		if r.Name != nil {
			entry["name"] = *r.Name
		}
		if r.Enabled != nil {
			entry["enabled"] = *r.Enabled
		}
		if r.Destination != nil {
			entry["destination"] = *r.Destination
		}
		if r.Definition != nil {
			d, err := convert.JsonToDict(r.Definition)
			if err == nil {
				entry["definition"] = d
			}
		}
		out = append(out, entry)
	}
	return out
}

// isInventoryPolicyNotFoundError reports whether the error returned from
// the BlobInventoryPolicies Get call is the "no policy configured" 404 case
// versus a permission or transient error.
func isInventoryPolicyNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if rerr, ok := errors.AsType[*azcore.ResponseError](err); ok {
		return rerr.StatusCode == 404
	}
	return false
}

func (a *mqlAzureSubscriptionStorageServiceAccountQueue) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountTable) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionStorageServiceAccountTableInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionStorageServiceAccountTable) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionStorageServiceAccountQueueInternal struct {
	cacheSystemData any
	cacheAccountId  string
	countFetched    atomic.Bool
	count           int64
	countLock       sync.Mutex
}

func (a *mqlAzureSubscriptionStorageServiceAccountQueue) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionStorageServiceAccount) queues() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, accountName, err := storageAccountResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := storage.NewQueueClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(rg, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isFeatureNotSupportedForAccountError(err) {
				a.Queues.State = plugin.StateIsNull | plugin.StateIsSet
				return nil, nil
			}
			return nil, err
		}
		for _, q := range page.Value {
			if q == nil {
				continue
			}
			metadata := map[string]any{}
			if q.QueueProperties != nil {
				for k, v := range q.QueueProperties.Metadata {
					if v != nil {
						metadata[k] = *v
					}
				}
			}
			mqlQueue, err := CreateResource(a.MqlRuntime, "azure.subscription.storageService.account.queue",
				map[string]*llx.RawData{
					"id":       llx.StringDataPtr(q.ID),
					"name":     llx.StringDataPtr(q.Name),
					"metadata": llx.MapData(metadata, types.String),
				})
			if err != nil {
				return nil, err
			}
			mqlQ := mqlQueue.(*mqlAzureSubscriptionStorageServiceAccountQueue)
			mqlQ.cacheAccountId = a.Id.Data
			sysData, err := convert.JsonToDict(q.SystemData)
			if err != nil {
				return nil, err
			}
			mqlQ.cacheSystemData = sysData
			res = append(res, mqlQ)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountQueue) approximateMessageCount() (int64, error) {
	if a.countFetched.Load() {
		return a.count, nil
	}
	a.countLock.Lock()
	defer a.countLock.Unlock()
	if a.countFetched.Load() {
		return a.count, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.cacheAccountId)
	if err != nil {
		return 0, err
	}
	rg, accountName, err := storageAccountResourceGroup(a.cacheAccountId)
	if err != nil {
		return 0, err
	}
	client, err := storage.NewQueueClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return 0, err
	}
	resp, err := client.Get(ctx, rg, accountName, a.Name.Data, nil)
	if err != nil {
		return 0, err
	}
	if resp.QueueProperties != nil && resp.QueueProperties.ApproximateMessageCount != nil {
		a.count = int64(*resp.QueueProperties.ApproximateMessageCount)
	}
	a.countFetched.Store(true)
	return a.count, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) tables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, accountName, err := storageAccountResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := storage.NewTableClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(rg, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isFeatureNotSupportedForAccountError(err) {
				a.Tables.State = plugin.StateIsNull | plugin.StateIsSet
				return nil, nil
			}
			return nil, err
		}
		for _, t := range page.Value {
			if t == nil {
				continue
			}
			signedIdentifiers := []any{}
			if t.TableProperties != nil {
				for _, si := range t.TableProperties.SignedIdentifiers {
					if si == nil {
						continue
					}
					entry := map[string]any{}
					if si.ID != nil {
						entry["id"] = *si.ID
					}
					if si.AccessPolicy != nil {
						if si.AccessPolicy.Permission != nil {
							entry["permission"] = *si.AccessPolicy.Permission
						}
						if si.AccessPolicy.StartTime != nil {
							entry["startTime"] = si.AccessPolicy.StartTime.Format(time.RFC3339)
						}
						if si.AccessPolicy.ExpiryTime != nil {
							entry["expiryTime"] = si.AccessPolicy.ExpiryTime.Format(time.RFC3339)
						}
					}
					signedIdentifiers = append(signedIdentifiers, entry)
				}
			}
			var tablePolicies []*storage.TableSignedIdentifier
			if t.TableProperties != nil {
				tablePolicies = t.TableProperties.SignedIdentifiers
			}
			storedAccessPolicies, err := storedAccessPoliciesToMql(a.MqlRuntime, convert.ToValue(t.ID), tableStoredAccessPolicies(tablePolicies))
			if err != nil {
				return nil, err
			}
			mqlTable, err := CreateResource(a.MqlRuntime, "azure.subscription.storageService.account.table",
				map[string]*llx.RawData{
					"id":                   llx.StringDataPtr(t.ID),
					"name":                 llx.StringDataPtr(t.Name),
					"signedIdentifiers":    llx.ArrayData(signedIdentifiers, types.Dict),
					"storedAccessPolicies": llx.ArrayData(storedAccessPolicies, types.Resource("azure.subscription.storageService.account.storedAccessPolicy")),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(t.SystemData)
			if err != nil {
				return nil, err
			}
			mqlTable.(*mqlAzureSubscriptionStorageServiceAccountTable).cacheSystemData = sysData
			res = append(res, mqlTable)
		}
	}
	return res, nil
}
