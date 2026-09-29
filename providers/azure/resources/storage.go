// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
	"golang.org/x/sync/errgroup"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	table "github.com/Azure/azure-sdk-for-go/sdk/data/aztables"
	storage "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v4"
)

// see https://github.com/Azure/azure-sdk-for-go/issues/8224
type (
	AzureStorageAccountProperties storage.AccountProperties
	Kind                          storage.Kind
)

func (a *mqlAzureSubscriptionStorageService) id() (string, error) {
	return "azure.subscription.storage/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionStorageService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

type mqlAzureSubscriptionStorageServiceAccountInternal struct {
	cacheSystemData              any
	cacheEncryptionKeySource     string
	cacheEncryptionKeyVaultURI   string
	cacheEncryptionKeyName       string
	cacheEncryptionKeyVersion    string
	cacheUserAssignedIdentityIds []string
	cacheEncryptionIdentityId    string

	fetchBlobSvcOnce sync.Once
	fetchBlobSvcResp *storage.BlobServicesClientGetServicePropertiesResponse
	fetchBlobSvcErr  error
}

// fetchBlobServiceProps retrieves BlobServicesClient.GetServiceProperties for
// this storage account. Cached with sync.Once so blobProperties() and
// dataProtection() share a single API call.
func (a *mqlAzureSubscriptionStorageServiceAccount) fetchBlobServiceProps() (*storage.BlobServicesClientGetServicePropertiesResponse, error) {
	a.fetchBlobSvcOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
		resourceID, err := ParseResourceID(a.Id.Data)
		if err != nil {
			a.fetchBlobSvcErr = err
			return
		}
		account, err := resourceID.Component("storageAccounts")
		if err != nil {
			a.fetchBlobSvcErr = err
			return
		}
		client, err := storage.NewBlobServicesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.fetchBlobSvcErr = err
			return
		}
		resp, err := client.GetServiceProperties(context.Background(), resourceID.ResourceGroup, account, &storage.BlobServicesClientGetServicePropertiesOptions{})
		if err != nil {
			a.fetchBlobSvcErr = err
			return
		}
		a.fetchBlobSvcResp = &resp
	})
	return a.fetchBlobSvcResp, a.fetchBlobSvcErr
}

func (a *mqlAzureSubscriptionStorageServiceAccount) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountContainer) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionStorageServiceAccountContainerInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionStorageServiceAccountContainer) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionStorageServiceAccountDataProtection) id() (string, error) {
	return a.StorageAccountId.Data + "/dataProtection", nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountServiceProperties) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountServicePropertiesRetentionPolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountServicePropertiesLogging) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountServicePropertiesMetrics) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountServiceBlobProperties) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionStorageService) accounts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := storage.NewAccountsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(&storage.AccountsClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, account := range page.Value {
			if account == nil {
				continue
			}
			acc, err := storageAccountToMql(a.MqlRuntime, account)
			if err != nil {
				return nil, err
			}
			res = append(res, acc)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) containers() ([]any, error) {
	// No hierarchical-namespace guard here. This is the ARM control-plane
	// BlobContainers client, which Microsoft supports on HNS-enabled accounts;
	// only four data-plane blob operations are unsupported on Data Lake Storage
	// Gen2, and none of them is this one. Skipping HNS accounts made every ADLS
	// Gen2 account report `containers: null`, so publicAccess,
	// hasImmutabilityPolicy, hasLegalHold and the encryption-scope fields were
	// invisible for exactly the accounts an anonymous-access audit cares about
	// -- and under three-valued logic a where() over null matches nothing, so
	// the check passed rather than failed.
	//
	// The pager below already degrades on the one error that genuinely means
	// "this account does not support the operation".
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	account, err := resourceID.Component("storageAccounts")
	if err != nil {
		return nil, err
	}
	client, err := storage.NewBlobContainersClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, account, &storage.BlobContainersClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isFeatureNotSupportedForAccountError(err) {
				// Keep whatever earlier pages returned. Discarding them would
				// report a partial listing as an empty one.
				return res, nil
			}
			return nil, err
		}

		// The list-by-account API returns hasImmutabilityPolicy/hasLegalHold
		// flags but not the nested ImmutabilityPolicy/LegalHold detail.
		// When either flag is set, fan out the per-container Get calls in
		// parallel — accounts with many locked containers (common in
		// regulated environments) would otherwise serialize one Get per
		// container in the listing hot path.
		detailedProps := make([]*storage.ContainerProperties, len(page.Value))
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(10)
		for i, container := range page.Value {
			if container == nil {
				continue
			}
			containerProps := container.Properties
			needsDetail := containerProps != nil &&
				((containerProps.HasImmutabilityPolicy != nil && *containerProps.HasImmutabilityPolicy) ||
					(containerProps.HasLegalHold != nil && *containerProps.HasLegalHold))
			if !needsDetail || container.Name == nil {
				continue
			}
			name := *container.Name
			g.Go(func() error {
				detail, err := client.Get(gctx, resourceID.ResourceGroup, account, name, nil)
				if err == nil && detail.BlobContainer.ContainerProperties != nil {
					detailedProps[i] = detail.BlobContainer.ContainerProperties
				}
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return nil, err
		}

		for i, container := range page.Value {
			if container == nil {
				continue
			}
			containerProps := container.Properties
			if detailedProps[i] != nil {
				containerProps = detailedProps[i]
			}

			properties, err := convert.JsonToDict(containerProps)
			if err != nil {
				return nil, err
			}

			var publicAccess string
			var hasImmutabilityPolicy, hasLegalHold bool
			var defaultEncryptionScope string
			var denyEncryptionScopeOverride bool
			var leaseState, leaseStatus string
			var leaseDuration *string
			var deleted *bool
			var deletedTime, lastModifiedTime *time.Time
			var remainingRetentionDays *int32
			var immutabilityPolicyState string
			var immutabilityPeriodInDays int64
			var immutabilityAllowProtectedAppendWrites, immutabilityAllowProtectedAppendWritesAll bool
			var objectLevelImmutabilityEnabled bool
			var legalHoldTags []any
			metadata := map[string]any{}
			if containerProps != nil {
				if containerProps.PublicAccess != nil {
					publicAccess = string(*containerProps.PublicAccess)
				}
				if containerProps.HasImmutabilityPolicy != nil {
					hasImmutabilityPolicy = *containerProps.HasImmutabilityPolicy
				}
				if containerProps.HasLegalHold != nil {
					hasLegalHold = *containerProps.HasLegalHold
				}
				if containerProps.DefaultEncryptionScope != nil {
					defaultEncryptionScope = *containerProps.DefaultEncryptionScope
				}
				if containerProps.DenyEncryptionScopeOverride != nil {
					denyEncryptionScopeOverride = *containerProps.DenyEncryptionScopeOverride
				}
				if containerProps.LeaseState != nil {
					leaseState = string(*containerProps.LeaseState)
				}
				if containerProps.LeaseStatus != nil {
					leaseStatus = string(*containerProps.LeaseStatus)
				}
				leaseDuration = stringEnumPtr(containerProps.LeaseDuration)
				deleted = containerProps.Deleted
				deletedTime = containerProps.DeletedTime
				lastModifiedTime = containerProps.LastModifiedTime
				remainingRetentionDays = containerProps.RemainingRetentionDays
				for k, v := range containerProps.Metadata {
					if v != nil {
						metadata[k] = *v
					}
				}
				if ip := containerProps.ImmutabilityPolicy; ip != nil && ip.Properties != nil {
					if ip.Properties.State != nil {
						immutabilityPolicyState = string(*ip.Properties.State)
					}
					if ip.Properties.ImmutabilityPeriodSinceCreationInDays != nil {
						immutabilityPeriodInDays = int64(*ip.Properties.ImmutabilityPeriodSinceCreationInDays)
					}
					if ip.Properties.AllowProtectedAppendWrites != nil {
						immutabilityAllowProtectedAppendWrites = *ip.Properties.AllowProtectedAppendWrites
					}
					if ip.Properties.AllowProtectedAppendWritesAll != nil {
						immutabilityAllowProtectedAppendWritesAll = *ip.Properties.AllowProtectedAppendWritesAll
					}
				}
				if isv := containerProps.ImmutableStorageWithVersioning; isv != nil && isv.Enabled != nil {
					objectLevelImmutabilityEnabled = *isv.Enabled
				}
				if lh := containerProps.LegalHold; lh != nil {
					for _, tag := range lh.Tags {
						if tag == nil {
							continue
						}
						entry := map[string]any{}
						if tag.Tag != nil {
							entry["tag"] = *tag.Tag
						}
						if tag.ObjectIdentifier != nil {
							entry["objectIdentifier"] = *tag.ObjectIdentifier
						}
						if tag.TenantID != nil {
							entry["tenantId"] = *tag.TenantID
						}
						if tag.Upn != nil {
							entry["upn"] = *tag.Upn
						}
						if tag.Timestamp != nil {
							entry["timestamp"] = tag.Timestamp.Format(time.RFC3339)
						}
						legalHoldTags = append(legalHoldTags, entry)
					}
				}
			}

			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.storageService.account.container",
				map[string]*llx.RawData{
					"id":                       llx.StringDataPtr(container.ID),
					"name":                     llx.StringDataPtr(container.Name),
					"etag":                     llx.StringDataPtr(container.Etag),
					"type":                     llx.StringDataPtr(container.Type),
					"properties":               llx.DictData(properties),
					"publicAccess":             llx.StringData(publicAccess),
					"hasImmutabilityPolicy":    llx.BoolData(hasImmutabilityPolicy),
					"hasLegalHold":             llx.BoolData(hasLegalHold),
					"immutabilityPolicyState":  llx.StringData(immutabilityPolicyState),
					"immutabilityPeriodInDays": llx.IntData(immutabilityPeriodInDays),
					"immutabilityPolicyAllowProtectedAppendWrites":    llx.BoolData(immutabilityAllowProtectedAppendWrites),
					"immutabilityPolicyAllowProtectedAppendWritesAll": llx.BoolData(immutabilityAllowProtectedAppendWritesAll),
					"objectLevelImmutabilityEnabled":                  llx.BoolData(objectLevelImmutabilityEnabled),
					"legalHoldTags":                                   llx.ArrayData(legalHoldTags, types.Dict),
					"defaultEncryptionScope":                          llx.StringData(defaultEncryptionScope),
					"denyEncryptionScopeOverride":                     llx.BoolData(denyEncryptionScopeOverride),
					"metadata":                                        llx.MapData(metadata, types.String),
					"lastModifiedTime":                                llx.TimeDataPtr(lastModifiedTime),
					"leaseState":                                      llx.StringData(leaseState),
					"leaseStatus":                                     llx.StringData(leaseStatus),
					"leaseDuration":                                   llx.StringDataPtr(leaseDuration),
					"deleted":                                         llx.BoolDataPtr(deleted),
					"deletedTime":                                     llx.TimeDataPtr(deletedTime),
					"remainingRetentionDays":                          llx.IntDataPtr(remainingRetentionDays),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(container.SystemData)
			if err != nil {
				return nil, err
			}
			mqlAzure.(*mqlAzureSubscriptionStorageServiceAccountContainer).cacheSystemData = sysData
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) queueProperties() (*mqlAzureSubscriptionStorageServiceAccountServiceProperties, error) {
	props, err := a.getServiceStorageProperties("queue")
	if err != nil {
		return nil, err
	}
	id := a.Id.Data
	return toMqlServiceStorageProperties(a.MqlRuntime, props.ServiceProperties, "queue", id)
}

func (a *mqlAzureSubscriptionStorageServiceAccount) diagnosticSettings() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	return getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionStorageServiceAccount) diagnosticSettingsCategories() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	return getDiagnosticSettingsCategories(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionStorageServiceAccount) tableProperties() (*mqlAzureSubscriptionStorageServiceAccountServiceProperties, error) {
	props, err := a.getServiceStorageProperties("table")
	if err != nil {
		return nil, err
	}
	id := a.Id.Data
	return toMqlServiceStorageProperties(a.MqlRuntime, props.ServiceProperties, "table", id)
}

func (a *mqlAzureSubscriptionStorageServiceAccount) blobProperties() (*mqlAzureSubscriptionStorageServiceAccountServiceBlobProperties, error) {
	// Data Lake Storage Gen2 (HNS-enabled) accounts don't support the Blob services API.
	if a.GetIsHnsEnabled().Data {
		a.BlobProperties.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	blobProps, err := a.fetchBlobServiceProps()
	if err != nil {
		if isFeatureNotSupportedForAccountError(err) {
			a.BlobProperties.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	props, err := a.getServiceStorageProperties("blob")
	if err != nil {
		if isFeatureNotSupportedForAccountError(err) {
			a.BlobProperties.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	return toMqlBlobServiceStorageProperties(a.MqlRuntime, props.ServiceProperties, blobProps.BlobServiceProperties, "blob", a.Id.Data)
}

func (a *mqlAzureSubscriptionStorageServiceAccount) dataProtection() (*mqlAzureSubscriptionStorageServiceAccountDataProtection, error) {
	// Data Lake Storage Gen2 (HNS-enabled) accounts don't support the Blob services API.
	if a.GetIsHnsEnabled().Data {
		a.DataProtection.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	properties, err := a.fetchBlobServiceProps()
	if err != nil {
		if isFeatureNotSupportedForAccountError(err) {
			a.DataProtection.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	var blobSoftDeletionEnabled bool
	var blobRetentionDays *int32
	var containerSoftDeletionEnabled bool
	var containerRetentionDays *int32
	// The inner BlobServiceProperties pointer is nullable (empty body for an
	// account with no blob service settings); guard before dereferencing.
	if inner := properties.BlobServiceProperties.BlobServiceProperties; inner != nil {
		if inner.DeleteRetentionPolicy != nil {
			blobSoftDeletionEnabled = convert.ToValue(inner.DeleteRetentionPolicy.Enabled)
			blobRetentionDays = inner.DeleteRetentionPolicy.Days
		}
		if inner.ContainerDeleteRetentionPolicy != nil {
			containerSoftDeletionEnabled = convert.ToValue(inner.ContainerDeleteRetentionPolicy.Enabled)
			containerRetentionDays = inner.ContainerDeleteRetentionPolicy.Days
		}
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccountDataProtection,
		map[string]*llx.RawData{
			"storageAccountId":             llx.StringData(a.Id.Data),
			"blobSoftDeletionEnabled":      llx.BoolData(blobSoftDeletionEnabled),
			"blobRetentionDays":            llx.IntDataDefault(blobRetentionDays, 0),
			"containerSoftDeletionEnabled": llx.BoolData(containerSoftDeletionEnabled),
			"containerRetentionDays":       llx.IntDataDefault(containerRetentionDays, 0),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionStorageServiceAccountDataProtection), nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) fileProperties() (*mqlAzureSubscriptionStorageServiceAccountFilePropertiesConfig, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	account, err := resourceID.Component("storageAccounts")
	if err != nil {
		return nil, err
	}
	client, err := storage.NewFileServicesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	properties, err := client.GetServiceProperties(ctx, resourceID.ResourceGroup, account, &storage.FileServicesClientGetServicePropertiesOptions{})
	if err != nil {
		return nil, err
	}

	// The inner FileServiceProperties pointer is nullable, exactly like the
	// blob-side one guarded above: an account that never had file-service
	// settings written returns an empty body. Dereferencing it bare would
	// panic, and a provider panic is unrecoverable - it kills the whole scan.
	var fileProps *storage.FileServicePropertiesProperties
	if properties.FileServiceProperties.FileServiceProperties != nil {
		fileProps = properties.FileServiceProperties.FileServiceProperties
	}

	// Build share delete retention policy
	var shareDeleteRetentionPolicyEnabled bool
	var shareDeleteRetentionPolicyDays *int32
	var policyFromClient *storage.DeleteRetentionPolicy
	if fileProps != nil {
		policyFromClient = fileProps.ShareDeleteRetentionPolicy
	}
	if policyFromClient != nil {
		shareDeleteRetentionPolicyEnabled = convert.ToValue(policyFromClient.Enabled)
		shareDeleteRetentionPolicyDays = policyFromClient.Days
	}

	shareDeleteRetentionPolicy, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccountFilePropertiesShareDeleteRetentionPolicyConfig,
		map[string]*llx.RawData{
			"__id":    llx.StringData(fmt.Sprintf("%s/fileProperties/shareDeleteRetentionPolicy", id)),
			"enabled": llx.BoolData(shareDeleteRetentionPolicyEnabled),
			"days":    llx.IntDataDefault(shareDeleteRetentionPolicyDays, 0),
		})
	if err != nil {
		return nil, err
	}

	// Build protocol settings SMB
	var smbVersions, smbChannelEncryption, smbAuthenticationMethods, smbKerberosTicketEncryption *string
	var protocolSettingsFromClient *storage.ProtocolSettings
	if fileProps != nil {
		protocolSettingsFromClient = fileProps.ProtocolSettings
	}
	if protocolSettingsFromClient != nil && protocolSettingsFromClient.Smb != nil {
		smb := protocolSettingsFromClient.Smb
		smbVersions = smb.Versions
		smbChannelEncryption = smb.ChannelEncryption
		smbAuthenticationMethods = smb.AuthenticationMethods
		smbKerberosTicketEncryption = smb.KerberosTicketEncryption
	}

	smb, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccountFilePropertiesProtocolSettingsSmbConfig,
		map[string]*llx.RawData{
			"__id":                     llx.StringData(fmt.Sprintf("%s/fileProperties/protocolSettings/smb", id)),
			"versions":                 llx.StringDataPtr(smbVersions),
			"channelEncryption":        llx.StringDataPtr(smbChannelEncryption),
			"authenticationMethods":    llx.StringDataPtr(smbAuthenticationMethods),
			"kerberosTicketEncryption": llx.StringDataPtr(smbKerberosTicketEncryption),
		})
	if err != nil {
		return nil, err
	}

	protocolSettings, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccountFilePropertiesProtocolSettingsConfig,
		map[string]*llx.RawData{
			"__id": llx.StringData(fmt.Sprintf("%s/fileProperties/protocolSettings", id)),
			"smb":  llx.ResourceData(smb, "smb"),
		})
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccountFilePropertiesConfig,
		map[string]*llx.RawData{
			"__id":                       llx.StringData(id + "/fileProperties"),
			"shareDeleteRetentionPolicy": llx.ResourceData(shareDeleteRetentionPolicy, "shareDeleteRetentionPolicy"),
			"protocolSettings":           llx.ResourceData(protocolSettings, "protocolSettings"),
		})
	if err != nil {
		return nil, err
	}

	return res.(*mqlAzureSubscriptionStorageServiceAccountFilePropertiesConfig), nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) getServiceStorageProperties(serviceType string) (table.GetPropertiesResponse, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return table.GetPropertiesResponse{}, err
	}

	account, err := resourceID.Component("storageAccounts")
	if err != nil {
		return table.GetPropertiesResponse{}, err
	}

	ctx := context.Background()
	token := conn.Token()
	urlPath := "https://{accountName}.{serviceType}.core.windows.net/"
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(account))
	urlPath = strings.ReplaceAll(urlPath, "{serviceType}", url.PathEscape(serviceType))

	client, err := table.NewServiceClient(urlPath, token, &table.ClientOptions{})
	if err != nil {
		return table.GetPropertiesResponse{}, err
	}
	props, err := client.GetProperties(ctx, &table.GetPropertiesOptions{})
	if err != nil {
		return table.GetPropertiesResponse{}, err
	}
	return props, nil
}

// normalizeServiceProperties fills in empty structs for the nullable
// logging/metrics pointers (and their retention policies) so the callers that
// dereference them unconditionally cannot panic on an account whose analytics
// settings were never configured.
func normalizeServiceProperties(props *table.ServiceProperties) {
	if props.Logging == nil {
		props.Logging = &table.Logging{}
	}
	if props.Logging.RetentionPolicy == nil {
		props.Logging.RetentionPolicy = &table.RetentionPolicy{}
	}
	if props.MinuteMetrics == nil {
		props.MinuteMetrics = &table.Metrics{}
	}
	if props.MinuteMetrics.RetentionPolicy == nil {
		props.MinuteMetrics.RetentionPolicy = &table.RetentionPolicy{}
	}
	if props.HourMetrics == nil {
		props.HourMetrics = &table.Metrics{}
	}
	if props.HourMetrics.RetentionPolicy == nil {
		props.HourMetrics.RetentionPolicy = &table.RetentionPolicy{}
	}
}

func toMqlServiceStorageProperties(runtime *plugin.Runtime, props table.ServiceProperties, serviceType, parentId string) (*mqlAzureSubscriptionStorageServiceAccountServiceProperties, error) {
	normalizeServiceProperties(&props)
	loggingRetentionPolicy, err := CreateResource(runtime, "azure.subscription.storageService.account.service.properties.retentionPolicy",
		map[string]*llx.RawData{
			"id":            llx.StringData(fmt.Sprintf("%s/%s/properties/logging/retentionPolicy", parentId, serviceType)),
			"retentionDays": llx.IntDataDefault(props.Logging.RetentionPolicy.Days, 0),
			"enabled":       llx.BoolDataPtr(props.Logging.RetentionPolicy.Enabled),
		})
	if err != nil {
		return nil, err
	}
	logging, err := CreateResource(runtime, "azure.subscription.storageService.account.service.properties.logging",
		map[string]*llx.RawData{
			"id":              llx.StringData(fmt.Sprintf("%s/%s/properties/logging", parentId, serviceType)),
			"retentionPolicy": llx.ResourceData(loggingRetentionPolicy, "retentionPolicy"),
			"delete":          llx.BoolDataPtr(props.Logging.Delete),
			"write":           llx.BoolDataPtr(props.Logging.Write),
			"read":            llx.BoolDataPtr(props.Logging.Read),
			"version":         llx.StringDataPtr(props.Logging.Version),
		})
	if err != nil {
		return nil, err
	}
	minuteMetricsRetentionPolicy, err := CreateResource(runtime, "azure.subscription.storageService.account.service.properties.retentionPolicy",
		map[string]*llx.RawData{
			"id":            llx.StringData(fmt.Sprintf("%s/%s/properties/minuteMetrics/retentionPolicy", parentId, serviceType)),
			"retentionDays": llx.IntDataDefault(props.MinuteMetrics.RetentionPolicy.Days, 0),
			"enabled":       llx.BoolDataPtr(props.MinuteMetrics.RetentionPolicy.Enabled),
		})
	if err != nil {
		return nil, err
	}
	minuteMetrics, err := CreateResource(runtime, "azure.subscription.storageService.account.service.properties.metrics",
		map[string]*llx.RawData{
			"id":              llx.StringData(fmt.Sprintf("%s/%s/properties/minuteMetrics/", parentId, serviceType)),
			"retentionPolicy": llx.ResourceData(minuteMetricsRetentionPolicy, "retentionPolicy"),
			"enabled":         llx.BoolDataPtr(props.MinuteMetrics.Enabled),
			"includeAPIs":     llx.BoolDataPtr(props.MinuteMetrics.IncludeAPIs),
			"version":         llx.StringDataPtr(props.MinuteMetrics.Version),
		})
	if err != nil {
		return nil, err
	}
	hourMetricsRetentionPolicy, err := CreateResource(runtime, "azure.subscription.storageService.account.service.properties.retentionPolicy",
		map[string]*llx.RawData{
			"id":            llx.StringData(fmt.Sprintf("%s/%s/properties/hourMetrics/retentionPolicy", parentId, serviceType)),
			"retentionDays": llx.IntDataDefault(props.HourMetrics.RetentionPolicy.Days, 0),
			"enabled":       llx.BoolDataPtr(props.HourMetrics.RetentionPolicy.Enabled),
		})
	if err != nil {
		return nil, err
	}
	hourMetrics, err := CreateResource(runtime, "azure.subscription.storageService.account.service.properties.metrics",
		map[string]*llx.RawData{
			"id":              llx.StringData(fmt.Sprintf("%s/%s/properties/hourMetrics", parentId, serviceType)),
			"retentionPolicy": llx.ResourceData(hourMetricsRetentionPolicy, "retentionPolicy"),
			"enabled":         llx.BoolDataPtr(props.HourMetrics.Enabled),
			"includeAPIs":     llx.BoolDataPtr(props.HourMetrics.IncludeAPIs),
			"version":         llx.StringDataPtr(props.HourMetrics.Version),
		})
	if err != nil {
		return nil, err
	}
	settings, err := CreateResource(runtime, "azure.subscription.storageService.account.service.properties",
		map[string]*llx.RawData{
			"id":            llx.StringData(fmt.Sprintf("%s/%s/properties", parentId, serviceType)),
			"minuteMetrics": llx.ResourceData(minuteMetrics, "minuteMetrics"),
			"hourMetrics":   llx.ResourceData(hourMetrics, "hourMetrics"),
			"logging":       llx.ResourceData(logging, "logging"),
		})
	if err != nil {
		return nil, err
	}
	return settings.(*mqlAzureSubscriptionStorageServiceAccountServiceProperties), nil
}

func toMqlBlobServiceStorageProperties(runtime *plugin.Runtime, props table.ServiceProperties, blobProps storage.BlobServiceProperties, serviceType, parentId string) (*mqlAzureSubscriptionStorageServiceAccountServiceBlobProperties, error) {
	normalizeServiceProperties(&props)
	loggingRetentionPolicy, err := CreateResource(runtime, ResourceAzureSubscriptionStorageServiceAccountServicePropertiesRetentionPolicy,
		map[string]*llx.RawData{
			"id":            llx.StringData(fmt.Sprintf("%s/%s/properties/logging/retentionPolicy", parentId, serviceType)),
			"retentionDays": llx.IntDataDefault(props.Logging.RetentionPolicy.Days, 0),
			"enabled":       llx.BoolDataPtr(props.Logging.RetentionPolicy.Enabled),
		})
	if err != nil {
		return nil, err
	}
	logging, err := CreateResource(runtime, ResourceAzureSubscriptionStorageServiceAccountServicePropertiesLogging,
		map[string]*llx.RawData{
			"id":              llx.StringData(fmt.Sprintf("%s/%s/properties/logging", parentId, serviceType)),
			"retentionPolicy": llx.ResourceData(loggingRetentionPolicy, "retentionPolicy"),
			"delete":          llx.BoolDataPtr(props.Logging.Delete),
			"write":           llx.BoolDataPtr(props.Logging.Write),
			"read":            llx.BoolDataPtr(props.Logging.Read),
			"version":         llx.StringDataPtr(props.Logging.Version),
		})
	if err != nil {
		return nil, err
	}
	minuteMetricsRetentionPolicy, err := CreateResource(runtime, ResourceAzureSubscriptionStorageServiceAccountServicePropertiesRetentionPolicy,
		map[string]*llx.RawData{
			"id":            llx.StringData(fmt.Sprintf("%s/%s/properties/minuteMetrics/retentionPolicy", parentId, serviceType)),
			"retentionDays": llx.IntDataDefault(props.MinuteMetrics.RetentionPolicy.Days, 0),
			"enabled":       llx.BoolDataPtr(props.MinuteMetrics.RetentionPolicy.Enabled),
		})
	if err != nil {
		return nil, err
	}
	minuteMetrics, err := CreateResource(runtime, ResourceAzureSubscriptionStorageServiceAccountServicePropertiesMetrics,
		map[string]*llx.RawData{
			"id":              llx.StringData(fmt.Sprintf("%s/%s/properties/minuteMetrics/", parentId, serviceType)),
			"retentionPolicy": llx.ResourceData(minuteMetricsRetentionPolicy, "retentionPolicy"),
			"enabled":         llx.BoolDataPtr(props.MinuteMetrics.Enabled),
			"includeAPIs":     llx.BoolDataPtr(props.MinuteMetrics.IncludeAPIs),
			"version":         llx.StringDataPtr(props.MinuteMetrics.Version),
		})
	if err != nil {
		return nil, err
	}
	hourMetricsRetentionPolicy, err := CreateResource(runtime, ResourceAzureSubscriptionStorageServiceAccountServicePropertiesRetentionPolicy,
		map[string]*llx.RawData{
			"id":            llx.StringData(fmt.Sprintf("%s/%s/properties/hourMetrics/retentionPolicy", parentId, serviceType)),
			"retentionDays": llx.IntDataDefault(props.HourMetrics.RetentionPolicy.Days, 0),
			"enabled":       llx.BoolDataPtr(props.HourMetrics.RetentionPolicy.Enabled),
		})
	if err != nil {
		return nil, err
	}
	hourMetrics, err := CreateResource(runtime, ResourceAzureSubscriptionStorageServiceAccountServicePropertiesMetrics,
		map[string]*llx.RawData{
			"id":              llx.StringData(fmt.Sprintf("%s/%s/properties/hourMetrics", parentId, serviceType)),
			"retentionPolicy": llx.ResourceData(hourMetricsRetentionPolicy, "retentionPolicy"),
			"enabled":         llx.BoolDataPtr(props.HourMetrics.Enabled),
			"includeAPIs":     llx.BoolDataPtr(props.HourMetrics.IncludeAPIs),
			"version":         llx.StringDataPtr(props.HourMetrics.Version),
		})
	if err != nil {
		return nil, err
	}

	// Extract versioning enabled and static-website config from blob properties
	var isVersioningEnabled bool
	var sw *storage.StaticWebsite
	if blobProps.BlobServiceProperties != nil {
		if blobProps.BlobServiceProperties.IsVersioningEnabled != nil {
			isVersioningEnabled = convert.ToValue(blobProps.BlobServiceProperties.IsVersioningEnabled)
		}
		sw = blobProps.BlobServiceProperties.StaticWebsite
	}
	if sw == nil {
		sw = &storage.StaticWebsite{}
	}
	staticWebsite, err := CreateResource(runtime, ResourceAzureSubscriptionStorageServiceAccountStaticWebsiteConfig,
		map[string]*llx.RawData{
			"__id":                     llx.StringData(fmt.Sprintf("%s/%s/properties/staticWebsite", parentId, serviceType)),
			"enabled":                  llx.BoolDataPtr(sw.Enabled),
			"indexDocument":            llx.StringDataPtr(sw.IndexDocument),
			"errorDocument404Path":     llx.StringDataPtr(sw.ErrorDocument404Path),
			"defaultIndexDocumentPath": llx.StringDataPtr(sw.DefaultIndexDocumentPath),
		})
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":                  llx.StringData(fmt.Sprintf("%s/%s/properties", parentId, serviceType)),
		"minuteMetrics":       llx.ResourceData(minuteMetrics, "minuteMetrics"),
		"hourMetrics":         llx.ResourceData(hourMetrics, "hourMetrics"),
		"logging":             llx.ResourceData(logging, "logging"),
		"isVersioningEnabled": llx.BoolData(isVersioningEnabled),
		"staticWebsite":       llx.ResourceData(staticWebsite, "staticWebsite"),
	}
	for k, v := range blobServiceDataPlaneSettings(blobProps.BlobServiceProperties).rawData() {
		args[k] = v
	}

	settings, err := CreateResource(runtime, ResourceAzureSubscriptionStorageServiceAccountServiceBlobProperties, args)
	if err != nil {
		return nil, err
	}
	return settings.(*mqlAzureSubscriptionStorageServiceAccountServiceBlobProperties), nil
}

// isFeatureNotSupportedForAccountError checks if the error is an Azure ResponseError
// with the error code "FeatureNotSupportedForAccount".
func isFeatureNotSupportedForAccountError(err error) bool {
	var respErr *azcore.ResponseError
	return errors.As(err, &respErr) && respErr.ErrorCode == "FeatureNotSupportedForAccount"
}

func storageAccountToMql(runtime *plugin.Runtime, account *storage.Account) (*mqlAzureSubscriptionStorageServiceAccount, error) {
	var properties map[string]any
	var err error
	var minimumTlsVersion *string
	var publicNetworkAccess *string
	var allowBlobPublicAccess *bool
	var enableHttpsTrafficOnly *bool
	var allowSharedKeyAccess *bool
	var allowCrossTenantReplication *bool
	var allowCrossTenantDelegationSas *bool
	var sasRequireUserBound *bool
	var sasRequireUserBoundAction *string
	var isLocalUserEnabled *bool
	var isSftpEnabled *bool
	var isHnsEnabled *bool
	var provisioningState *string
	var creationTime *time.Time
	var accessTier *string
	var primaryLocation *string
	var statusOfPrimary *string
	var secondaryLocation *string
	var statusOfSecondary *string
	var defaultToOAuthAuthentication *bool
	var enableNfsV3 *bool
	var largeFileSharesState *string
	var lastGeoFailoverTime *time.Time
	var allowedCopyScope, sasExpirationPeriod, sasExpirationAction string
	var requireInfraEnc bool
	var keyExpirationPeriodInDays int64
	serviceKeyTypes := map[string]any{}
	if account.Properties != nil {
		properties, err = convert.JsonToDict(AzureStorageAccountProperties(*account.Properties))
		if err != nil {
			return nil, err
		}
		minimumTlsVersion = (*string)(account.Properties.MinimumTLSVersion)
		publicNetworkAccess = (*string)(account.Properties.PublicNetworkAccess)
		allowBlobPublicAccess = account.Properties.AllowBlobPublicAccess
		enableHttpsTrafficOnly = account.Properties.EnableHTTPSTrafficOnly
		allowSharedKeyAccess = account.Properties.AllowSharedKeyAccess
		allowCrossTenantReplication = account.Properties.AllowCrossTenantReplication
		allowCrossTenantDelegationSas = account.Properties.AllowCrossTenantDelegationSas
		sasRequireUserBound, sasRequireUserBoundAction = sasPolicyUserBoundDelegation(account.Properties.SasPolicy)
		isLocalUserEnabled = account.Properties.IsLocalUserEnabled
		isSftpEnabled = account.Properties.IsSftpEnabled
		isHnsEnabled = account.Properties.IsHnsEnabled
		provisioningState = (*string)(account.Properties.ProvisioningState)
		creationTime = account.Properties.CreationTime
		accessTier = (*string)(account.Properties.AccessTier)
		primaryLocation = account.Properties.PrimaryLocation
		statusOfPrimary = (*string)(account.Properties.StatusOfPrimary)
		secondaryLocation = account.Properties.SecondaryLocation
		statusOfSecondary = (*string)(account.Properties.StatusOfSecondary)
		defaultToOAuthAuthentication = account.Properties.DefaultToOAuthAuthentication
		enableNfsV3 = account.Properties.EnableNfsV3
		largeFileSharesState = (*string)(account.Properties.LargeFileSharesState)
		lastGeoFailoverTime = account.Properties.LastGeoFailoverTime
		if account.Properties.AllowedCopyScope != nil {
			allowedCopyScope = string(*account.Properties.AllowedCopyScope)
		}
		if sas := account.Properties.SasPolicy; sas != nil {
			if sas.SasExpirationPeriod != nil {
				sasExpirationPeriod = *sas.SasExpirationPeriod
			}
			if sas.ExpirationAction != nil {
				sasExpirationAction = string(*sas.ExpirationAction)
			}
		}
		if kp := account.Properties.KeyPolicy; kp != nil && kp.KeyExpirationPeriodInDays != nil {
			keyExpirationPeriodInDays = int64(*kp.KeyExpirationPeriodInDays)
		}
		if enc := account.Properties.Encryption; enc != nil {
			if enc.RequireInfrastructureEncryption != nil {
				requireInfraEnc = *enc.RequireInfrastructureEncryption
			}
			if svcs := enc.Services; svcs != nil {
				if svcs.Blob != nil && svcs.Blob.KeyType != nil {
					serviceKeyTypes["blob"] = string(*svcs.Blob.KeyType)
				}
				if svcs.File != nil && svcs.File.KeyType != nil {
					serviceKeyTypes["file"] = string(*svcs.File.KeyType)
				}
				if svcs.Queue != nil && svcs.Queue.KeyType != nil {
					serviceKeyTypes["queue"] = string(*svcs.Queue.KeyType)
				}
				if svcs.Table != nil && svcs.Table.KeyType != nil {
					serviceKeyTypes["table"] = string(*svcs.Table.KeyType)
				}
			}
		}
	}

	var immutableEnabled, immutableAllowAppend bool
	var immutablePeriodDays int64
	var immutableState string
	if account.Properties != nil && account.Properties.ImmutableStorageWithVersioning != nil {
		isav := account.Properties.ImmutableStorageWithVersioning
		if isav.Enabled != nil {
			immutableEnabled = *isav.Enabled
		}
		if pol := isav.ImmutabilityPolicy; pol != nil {
			if pol.ImmutabilityPeriodSinceCreationInDays != nil {
				immutablePeriodDays = int64(*pol.ImmutabilityPeriodSinceCreationInDays)
			}
			if pol.AllowProtectedAppendWrites != nil {
				immutableAllowAppend = *pol.AllowProtectedAppendWrites
			}
			if pol.State != nil {
				immutableState = string(*pol.State)
			}
		}
	}

	var routingChoice string
	var publishInternetEndpoints, publishMicrosoftEndpoints bool
	if account.Properties != nil && account.Properties.RoutingPreference != nil {
		rp := account.Properties.RoutingPreference
		if rp.RoutingChoice != nil {
			routingChoice = string(*rp.RoutingChoice)
		}
		if rp.PublishInternetEndpoints != nil {
			publishInternetEndpoints = *rp.PublishInternetEndpoints
		}
		if rp.PublishMicrosoftEndpoints != nil {
			publishMicrosoftEndpoints = *rp.PublishMicrosoftEndpoints
		}
	}

	var networkRuleDefaultAction string
	var networkRuleBypass string
	networkRuleIpRanges := []any{}
	networkRuleVirtualNetworkSubnetIds := []any{}
	if account.Properties != nil && account.Properties.NetworkRuleSet != nil {
		nrs := account.Properties.NetworkRuleSet
		if nrs.DefaultAction != nil {
			networkRuleDefaultAction = string(*nrs.DefaultAction)
		}
		if nrs.Bypass != nil {
			networkRuleBypass = string(*nrs.Bypass)
		}
		for _, rule := range nrs.IPRules {
			if rule != nil && rule.IPAddressOrRange != nil {
				networkRuleIpRanges = append(networkRuleIpRanges, *rule.IPAddressOrRange)
			}
		}
		for _, rule := range nrs.VirtualNetworkRules {
			if rule != nil && rule.VirtualNetworkResourceID != nil {
				networkRuleVirtualNetworkSubnetIds = append(networkRuleVirtualNetworkSubnetIds, *rule.VirtualNetworkResourceID)
			}
		}
	}

	// Azure Files identity-based authentication. Absent on an account that has
	// never configured it, in which case SMB shares authenticate with the
	// account key alone.
	var filesDirectoryServiceOptions, filesDefaultSharePermission *string
	var filesADDomainName, filesADForestName, filesADAccountType *string
	if account.Properties != nil && account.Properties.AzureFilesIdentityBasedAuthentication != nil {
		fa := account.Properties.AzureFilesIdentityBasedAuthentication
		filesDirectoryServiceOptions = stringEnumPtr(fa.DirectoryServiceOptions)
		filesDefaultSharePermission = stringEnumPtr(fa.DefaultSharePermission)
		if ad := fa.ActiveDirectoryProperties; ad != nil {
			filesADDomainName = ad.DomainName
			filesADForestName = ad.ForestName
			filesADAccountType = stringEnumPtr(ad.AccountType)
		}
	}

	// Per-service shared-key overrides narrow the account-wide setting. A
	// service missing from the response falls back to allowSharedKeyAccess, so
	// only services Azure actually reported are published here.
	sharedKeyAccessByService := map[string]any{}
	if account.Properties != nil && account.Properties.AllowSharedKeyAccessForServices != nil {
		svc := account.Properties.AllowSharedKeyAccessForServices
		for name, prop := range map[string]*storage.ServiceSharedKeyAccessProperties{
			"blob":  svc.Blob,
			"file":  svc.File,
			"queue": svc.Queue,
			"table": svc.Table,
		} {
			if prop != nil && prop.Enabled != nil {
				if *prop.Enabled {
					sharedKeyAccessByService[name] = "Enabled"
				} else {
					sharedKeyAccessByService[name] = "Disabled"
				}
			}
		}
	}

	// Null when the key has never been rotated since the account was created,
	// which is itself the answer a rotation check is looking for.
	var key1CreationTime, key2CreationTime *time.Time
	if account.Properties != nil && account.Properties.KeyCreationTime != nil {
		key1CreationTime = account.Properties.KeyCreationTime.Key1
		key2CreationTime = account.Properties.KeyCreationTime.Key2
	}

	var dnsEndpointType *string
	var enableExtendedGroups *bool
	if account.Properties != nil {
		dnsEndpointType = stringEnumPtr(account.Properties.DNSEndpointType)
		enableExtendedGroups = account.Properties.EnableExtendedGroups
	}

	accountIdentity := orZero(account.Identity)
	userAssignedIdentityIds := sortedUserAssignedIdentityIDs(accountIdentity.UserAssignedIdentities)

	sku, err := convert.JsonToDict(account.SKU)
	if err != nil {
		return nil, err
	}
	accountSku := orZero(account.SKU)

	kind := ""
	if account.Kind != nil {
		kind = string(*account.Kind)
	}
	args := map[string]*llx.RawData{
		"id":                                   llx.StringDataPtr(account.ID),
		"name":                                 llx.StringDataPtr(account.Name),
		"location":                             llx.StringDataPtr(account.Location),
		"tags":                                 llx.MapData(convert.PtrMapStrToInterface(account.Tags), types.String),
		"type":                                 llx.StringDataPtr(account.Type),
		"properties":                           llx.DictData(properties),
		"principalId":                          llx.StringDataPtr(accountIdentity.PrincipalID),
		"tenantId":                             llx.StringDataPtr(accountIdentity.TenantID),
		"sku":                                  llx.DictData(sku),
		"kind":                                 llx.StringData(kind),
		"minimumTlsVersion":                    llx.StringDataPtr(minimumTlsVersion),
		"allowBlobPublicAccess":                llx.BoolDataPtr(allowBlobPublicAccess),
		"enableHttpsTrafficOnly":               llx.BoolDataPtr(enableHttpsTrafficOnly),
		"publicNetworkAccess":                  llx.StringDataPtr(publicNetworkAccess),
		"allowSharedKeyAccess":                 llx.BoolDataPtr(allowSharedKeyAccess),
		"allowCrossTenantReplication":          llx.BoolDataPtr(allowCrossTenantReplication),
		"allowCrossTenantDelegationSas":        llx.BoolDataPtr(allowCrossTenantDelegationSas),
		"isLocalUserEnabled":                   llx.BoolDataPtr(isLocalUserEnabled),
		"isSftpEnabled":                        llx.BoolDataPtr(isSftpEnabled),
		"isHnsEnabled":                         llx.BoolDataPtr(isHnsEnabled),
		"networkRuleDefaultAction":             llx.StringData(networkRuleDefaultAction),
		"networkRuleBypass":                    llx.StringData(networkRuleBypass),
		"networkRuleIpRanges":                  llx.ArrayData(networkRuleIpRanges, types.String),
		"networkRuleVirtualNetworkSubnetIds":   llx.ArrayData(networkRuleVirtualNetworkSubnetIds, types.String),
		"provisioningState":                    llx.StringDataPtr(provisioningState),
		"creationTime":                         llx.TimeDataPtr(creationTime),
		"accessTier":                           llx.StringDataPtr(accessTier),
		"primaryLocation":                      llx.StringDataPtr(primaryLocation),
		"statusOfPrimary":                      llx.StringDataPtr(statusOfPrimary),
		"secondaryLocation":                    llx.StringDataPtr(secondaryLocation),
		"statusOfSecondary":                    llx.StringDataPtr(statusOfSecondary),
		"defaultToOAuthAuthentication":         llx.BoolDataPtr(defaultToOAuthAuthentication),
		"enableNfsV3":                          llx.BoolDataPtr(enableNfsV3),
		"largeFileSharesState":                 llx.StringDataPtr(largeFileSharesState),
		"lastGeoFailoverTime":                  llx.TimeDataPtr(lastGeoFailoverTime),
		"allowedCopyScope":                     llx.StringData(allowedCopyScope),
		"requireInfrastructureEncryption":      llx.BoolData(requireInfraEnc),
		"serviceKeyTypes":                      llx.MapData(serviceKeyTypes, types.String),
		"sasExpirationPeriod":                  llx.StringData(sasExpirationPeriod),
		"sasExpirationAction":                  llx.StringData(sasExpirationAction),
		"sasRequireUserBoundUserDelegationSas": llx.BoolDataPtr(sasRequireUserBound),
		"sasRequireUserBoundUserDelegationSasAction":       llx.StringDataPtr(sasRequireUserBoundAction),
		"keyExpirationPeriodInDays":                        llx.IntData(keyExpirationPeriodInDays),
		"sharedKeyAccessByService":                         llx.MapData(sharedKeyAccessByService, types.String),
		"key1CreationTime":                                 llx.TimeDataPtr(key1CreationTime),
		"key2CreationTime":                                 llx.TimeDataPtr(key2CreationTime),
		"filesDirectoryServiceOptions":                     llx.StringDataPtr(filesDirectoryServiceOptions),
		"filesDefaultSharePermission":                      llx.StringDataPtr(filesDefaultSharePermission),
		"filesActiveDirectoryDomainName":                   llx.StringDataPtr(filesADDomainName),
		"filesActiveDirectoryForestName":                   llx.StringDataPtr(filesADForestName),
		"filesActiveDirectoryAccountType":                  llx.StringDataPtr(filesADAccountType),
		"enableExtendedGroups":                             llx.BoolDataPtr(enableExtendedGroups),
		"dnsEndpointType":                                  llx.StringDataPtr(dnsEndpointType),
		"immutableStorageEnabled":                          llx.BoolData(immutableEnabled),
		"immutableStoragePolicyPeriodDays":                 llx.IntData(immutablePeriodDays),
		"immutableStoragePolicyAllowProtectedAppendWrites": llx.BoolData(immutableAllowAppend),
		"immutableStoragePolicyState":                      llx.StringData(immutableState),
		"routingChoice":                                    llx.StringData(routingChoice),
		"publishInternetEndpoints":                         llx.BoolData(publishInternetEndpoints),
		"publishMicrosoftEndpoints":                        llx.BoolData(publishMicrosoftEndpoints),
	}
	if err := setSkuData(runtime, args, skuName(accountSku.Name), skuTier(accountSku.Tier)); err != nil {
		return nil, err
	}
	if err := setResourceIdentity(runtime, args, userAssignedIdentityIds,
		identityType(accountIdentity.Type), identityPrincipalId(accountIdentity.PrincipalID), identityTenantId(accountIdentity.TenantID)); err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, "azure.subscription.storageService.account", args)
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAzureSubscriptionStorageServiceAccount)
	mqlRes.cacheUserAssignedIdentityIds = userAssignedIdentityIds
	sysData, err := convert.JsonToDict(account.SystemData)
	if err != nil {
		return nil, err
	}
	mqlRes.cacheSystemData = sysData
	if account.Properties != nil && account.Properties.Encryption != nil {
		enc := account.Properties.Encryption
		if enc.EncryptionIdentity != nil && enc.EncryptionIdentity.EncryptionUserAssignedIdentity != nil {
			mqlRes.cacheEncryptionIdentityId = *enc.EncryptionIdentity.EncryptionUserAssignedIdentity
		}
		if enc.KeySource != nil {
			mqlRes.cacheEncryptionKeySource = string(*enc.KeySource)
		}
		if enc.KeyVaultProperties != nil {
			if enc.KeyVaultProperties.KeyVaultURI != nil {
				mqlRes.cacheEncryptionKeyVaultURI = *enc.KeyVaultProperties.KeyVaultURI
			}
			if enc.KeyVaultProperties.KeyName != nil {
				mqlRes.cacheEncryptionKeyName = *enc.KeyVaultProperties.KeyName
			}
			if enc.KeyVaultProperties.KeyVersion != nil {
				mqlRes.cacheEncryptionKeyVersion = *enc.KeyVaultProperties.KeyVersion
			}
		}
	}
	return mqlRes, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionStorageServiceAccount) encryptionIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	if a.cacheEncryptionIdentityId == "" {
		a.EncryptionIdentity.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{"__id": llx.StringData(a.cacheEncryptionIdentityId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) encryptionKeySource() (string, error) {
	return a.cacheEncryptionKeySource, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) encryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	keyURI := keyVaultKeyURI(a.cacheEncryptionKeyVaultURI, a.cacheEncryptionKeyName, a.cacheEncryptionKeyVersion)
	if keyURI == "" {
		a.EncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, keyURI)
}

func getStorageAccount(id string, runtime *plugin.Runtime, azureConnection *connection.AzureConnection) (*mqlAzureSubscriptionStorageServiceAccount, error) {
	client, err := storage.NewAccountsClient(azureConnection.SubId(), azureConnection.Token(), &arm.ClientOptions{
		ClientOptions: azureConnection.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	// parse the id
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	accountName, err := resourceID.Component("storageAccounts")
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	account, err := client.GetProperties(ctx, resourceID.ResourceGroup, accountName, &storage.AccountsClientGetPropertiesOptions{})
	if err != nil {
		return nil, err
	}

	return storageAccountToMql(runtime, &account.Account)
}

func initAzureSubscriptionStorageServiceAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure storage account")
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.storageService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	storage := res.(*mqlAzureSubscriptionStorageService)
	accs := storage.GetAccounts()
	if accs.Error != nil {
		return nil, nil, accs.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range accs.Data {
		storageAcc := entry.(*mqlAzureSubscriptionStorageServiceAccount)
		if storageAcc.Id.Data == id {
			return args, storageAcc, nil
		}
	}

	return nil, nil, errors.New("azure storage account does not exist")
}

func initAzureSubscriptionStorageServiceAccountContainer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure storage account")
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.storageService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	storage := res.(*mqlAzureSubscriptionStorageService)
	accs := storage.GetAccounts()
	if accs.Error != nil {
		return nil, nil, accs.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range accs.Data {
		storageAcc := entry.(*mqlAzureSubscriptionStorageServiceAccount)
		containers := storageAcc.GetContainers()
		if containers.Error != nil {
			return nil, nil, containers.Error
		}
		for _, c := range containers.Data {
			container := c.(*mqlAzureSubscriptionStorageServiceAccountContainer)
			if container.Id.Data == id {
				return args, container, nil
			}
		}
	}

	return nil, nil, errors.New("azure storage container does not exist")
}

func (a *mqlAzureSubscriptionStorageServiceAccountEncryptionScope) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionStorageServiceAccountEncryptionScopeInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionStorageServiceAccountEncryptionScope) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionStorageServiceAccountManagementPolicy) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionStorageServiceAccountManagementPolicyInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionStorageServiceAccountManagementPolicy) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionStorageServiceAccountManagementPolicyRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) encryptionScopes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	account, err := resourceID.Component("storageAccounts")
	if err != nil {
		return nil, err
	}

	subId := resourceID.SubscriptionID
	client, err := storage.NewEncryptionScopesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, account, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && (respErr.StatusCode == http.StatusForbidden || isFeatureNotSupportedForAccountError(err)) {
				log.Warn().Err(err).Msg("could not list encryption scopes due to access denied or feature not supported")
				return res, nil
			}
			return nil, err
		}
		for _, scope := range page.Value {
			if scope == nil {
				continue
			}

			var source, state string
			var requireInfrastructureEncryption *bool
			var keyVaultKeyUri, currentVersionedKeyIdentifier *string
			var creationTime, lastModifiedTime, lastKeyRotationTimestamp *time.Time

			if scope.EncryptionScopeProperties != nil {
				props := scope.EncryptionScopeProperties
				if props.Source != nil {
					source = string(*props.Source)
				}
				if props.State != nil {
					state = string(*props.State)
				}
				requireInfrastructureEncryption = props.RequireInfrastructureEncryption
				creationTime = props.CreationTime
				lastModifiedTime = props.LastModifiedTime
				if props.KeyVaultProperties != nil {
					keyVaultKeyUri = props.KeyVaultProperties.KeyURI
					currentVersionedKeyIdentifier = props.KeyVaultProperties.CurrentVersionedKeyIdentifier
					lastKeyRotationTimestamp = props.KeyVaultProperties.LastKeyRotationTimestamp
				}
			}

			mqlScope, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccountEncryptionScope,
				map[string]*llx.RawData{
					"id":                              llx.StringDataPtr(scope.ID),
					"name":                            llx.StringDataPtr(scope.Name),
					"type":                            llx.StringDataPtr(scope.Type),
					"source":                          llx.StringData(source),
					"state":                           llx.StringData(state),
					"requireInfrastructureEncryption": llx.BoolDataPtr(requireInfrastructureEncryption),
					"keyVaultKeyUri":                  llx.StringDataPtr(keyVaultKeyUri),
					"currentVersionedKeyIdentifier":   llx.StringDataPtr(currentVersionedKeyIdentifier),
					"lastKeyRotationTimestamp":        llx.TimeDataPtr(lastKeyRotationTimestamp),
					"creationTime":                    llx.TimeDataPtr(creationTime),
					"lastModifiedTime":                llx.TimeDataPtr(lastModifiedTime),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(scope.SystemData)
			if err != nil {
				return nil, err
			}
			mqlScope.(*mqlAzureSubscriptionStorageServiceAccountEncryptionScope).cacheSystemData = sysData
			res = append(res, mqlScope)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionStorageServiceAccount) managementPolicy() (*mqlAzureSubscriptionStorageServiceAccountManagementPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	account, err := resourceID.Component("storageAccounts")
	if err != nil {
		return nil, err
	}

	subId := resourceID.SubscriptionID
	client, err := storage.NewManagementPoliciesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	resp, err := client.Get(ctx, resourceID.ResourceGroup, account, storage.ManagementPolicyNameDefault, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && (respErr.StatusCode == http.StatusNotFound || respErr.StatusCode == http.StatusForbidden) {
			if respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not get management policy due to access denied")
			}
			a.ManagementPolicy.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	policy := resp.ManagementPolicy

	var lastModifiedTime *time.Time
	var rules []any
	if policy.Properties != nil {
		lastModifiedTime = policy.Properties.LastModifiedTime
		if policy.Properties.Policy != nil && policy.Properties.Policy.Rules != nil {
			for _, rule := range policy.Properties.Policy.Rules {
				if rule == nil {
					continue
				}

				var ruleType string
				if rule.Type != nil {
					ruleType = string(*rule.Type)
				}

				var blobTypes, prefixMatch []any
				var baseBlobActions, snapshotActions, versionActions map[string]any
				if rule.Definition != nil {
					if rule.Definition.Filters != nil {
						for _, bt := range rule.Definition.Filters.BlobTypes {
							if bt != nil {
								blobTypes = append(blobTypes, *bt)
							}
						}
						for _, pm := range rule.Definition.Filters.PrefixMatch {
							if pm != nil {
								prefixMatch = append(prefixMatch, *pm)
							}
						}
					}
					if rule.Definition.Actions != nil {
						if rule.Definition.Actions.BaseBlob != nil {
							baseBlobActions, err = convert.JsonToDict(rule.Definition.Actions.BaseBlob)
							if err != nil {
								return nil, err
							}
						}
						if rule.Definition.Actions.Snapshot != nil {
							snapshotActions, err = convert.JsonToDict(rule.Definition.Actions.Snapshot)
							if err != nil {
								return nil, err
							}
						}
						if rule.Definition.Actions.Version != nil {
							versionActions, err = convert.JsonToDict(rule.Definition.Actions.Version)
							if err != nil {
								return nil, err
							}
						}
					}
				}

				ruleId := fmt.Sprintf("%s/managementPolicy/rules/%s", id, convert.ToValue(rule.Name))
				mqlRule, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccountManagementPolicyRule,
					map[string]*llx.RawData{
						"id":                llx.StringData(ruleId),
						"name":              llx.StringDataPtr(rule.Name),
						"enabled":           llx.BoolDataPtr(rule.Enabled),
						"type":              llx.StringData(ruleType),
						"filterBlobTypes":   llx.ArrayData(blobTypes, types.String),
						"filterPrefixMatch": llx.ArrayData(prefixMatch, types.String),
						"baseBlobActions":   llx.DictData(baseBlobActions),
						"snapshotActions":   llx.DictData(snapshotActions),
						"versionActions":    llx.DictData(versionActions),
					})
				if err != nil {
					return nil, err
				}
				rules = append(rules, mqlRule)
			}
		}
	}

	policyId := fmt.Sprintf("%s/managementPolicy", id)
	if policy.ID != nil {
		policyId = *policy.ID
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccountManagementPolicy,
		map[string]*llx.RawData{
			"id":               llx.StringData(policyId),
			"name":             llx.StringDataPtr(policy.Name),
			"type":             llx.StringDataPtr(policy.Type),
			"lastModifiedTime": llx.TimeDataPtr(lastModifiedTime),
			"rules":            llx.ArrayData(rules, types.Resource(ResourceAzureSubscriptionStorageServiceAccountManagementPolicyRule)),
		})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(policy.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionStorageServiceAccountManagementPolicy).cacheSystemData = sysData
	return res.(*mqlAzureSubscriptionStorageServiceAccountManagementPolicy), nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountLocalUser) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionStorageServiceAccountLocalUserInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionStorageServiceAccountLocalUser) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// localUsers fetches local SFTP/SSH user accounts on the storage account.
// Local users bypass shared-key and AAD auth so they're a high-impact audit surface.
func (a *mqlAzureSubscriptionStorageServiceAccount) localUsers() ([]any, error) {
	enabled := a.GetIsLocalUserEnabled()
	if enabled.Error != nil {
		return nil, enabled.Error
	}
	if !enabled.Data {
		return []any{}, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	account, err := resourceID.Component("storageAccounts")
	if err != nil {
		return nil, err
	}

	client, err := storage.NewLocalUsersClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, account, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && (respErr.StatusCode == http.StatusForbidden || isFeatureNotSupportedForAccountError(err)) {
				log.Warn().Err(err).Msg("could not list storage local users due to access denied or feature not supported")
				return res, nil
			}
			return nil, err
		}
		for _, lu := range page.Value {
			if lu == nil {
				continue
			}
			var allowAcl, hasSshKey, hasSshPassword, hasSharedKey, isNFSv3 bool
			var homeDirectory string
			var userId, groupId int64
			var permissionScopes []any
			permissions := []any{}
			if p := lu.Properties; p != nil {
				if p.AllowACLAuthorization != nil {
					allowAcl = *p.AllowACLAuthorization
				}
				if p.HasSSHKey != nil {
					hasSshKey = *p.HasSSHKey
				}
				if p.HasSSHPassword != nil {
					hasSshPassword = *p.HasSSHPassword
				}
				if p.HasSharedKey != nil {
					hasSharedKey = *p.HasSharedKey
				}
				if p.IsNFSv3Enabled != nil {
					isNFSv3 = *p.IsNFSv3Enabled
				}
				if p.HomeDirectory != nil {
					homeDirectory = *p.HomeDirectory
				}
				if p.UserID != nil {
					userId = int64(*p.UserID)
				}
				if p.GroupID != nil {
					groupId = int64(*p.GroupID)
				}
				for i, ps := range p.PermissionScopes {
					if ps == nil {
						continue
					}
					if d, err := convert.JsonToDict(ps); err == nil {
						permissionScopes = append(permissionScopes, d)
					}
					// A permission scope carries no ARM identifier, so the
					// position within the user's list is what distinguishes
					// one row from the next.
					mqlScope, err := CreateResource(a.MqlRuntime, "azure.subscription.storageService.account.localUser.permissionScope",
						map[string]*llx.RawData{
							"__id":         llx.StringData(subResourceCacheID(nil, convert.ToValue(lu.ID), "permissionScopes", strconv.Itoa(i))),
							"permissions":  llx.StringDataPtr(ps.Permissions),
							"service":      llx.StringDataPtr(ps.Service),
							"resourceName": llx.StringDataPtr(ps.ResourceName),
						})
					if err != nil {
						return nil, err
					}
					permissions = append(permissions, mqlScope)
				}
			}

			mqlLu, err := CreateResource(a.MqlRuntime, "azure.subscription.storageService.account.localUser",
				map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(lu.ID),
					"name":                  llx.StringDataPtr(lu.Name),
					"type":                  llx.StringDataPtr(lu.Type),
					"allowAclAuthorization": llx.BoolData(allowAcl),
					"hasSshKey":             llx.BoolData(hasSshKey),
					"hasSshPassword":        llx.BoolData(hasSshPassword),
					"hasSharedKey":          llx.BoolData(hasSharedKey),
					"isNFSv3Enabled":        llx.BoolData(isNFSv3),
					"homeDirectory":         llx.StringData(homeDirectory),
					"permissionScopes":      llx.ArrayData(permissionScopes, types.Dict),
					"permissions":           llx.ArrayData(permissions, types.Resource("azure.subscription.storageService.account.localUser.permissionScope")),
					"userId":                llx.IntData(userId),
					"groupId":               llx.IntData(groupId),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(lu.SystemData)
			if err != nil {
				return nil, err
			}
			mqlLu.(*mqlAzureSubscriptionStorageServiceAccountLocalUser).cacheSystemData = sysData
			res = append(res, mqlLu)
		}
	}
	return res, nil
}

// sasPolicyUserBoundDelegation returns the user-bound user delegation SAS
// requirement and its violation action from a SAS policy. Both are nil when
// the policy is absent or does not set them.
func sasPolicyUserBoundDelegation(sas *storage.SasPolicy) (*bool, *string) {
	if sas == nil {
		return nil, nil
	}
	return sas.RequireUserBoundUserDelegationSas, (*string)(sas.RequireUserBoundUserDelegationSasAction)
}
