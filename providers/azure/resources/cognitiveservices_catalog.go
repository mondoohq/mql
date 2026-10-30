// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// cognitiveServicesAccountScope pulls the subscription, resource group, and
// account name out of an account-scoped resource ID. Every collection below is
// listed per account, so they all need the same three values.
func cognitiveServicesAccountScope(resourceId string) (subscriptionId, resourceGroup, accountName string, err error) {
	parsed, err := ParseResourceID(resourceId)
	if err != nil {
		return "", "", "", err
	}
	return parsed.SubscriptionID, parsed.ResourceGroup, parsed.Path["accounts"], nil
}

// isAzureForbidden reports whether err is an Azure 403, which the listers below
// degrade to an empty collection rather than failing the whole query.
func isAzureForbidden(err error) bool {
	var respErr *azcore.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden
}

// isAzureNotFoundOrBadRequest reports whether err is a 404 or 400. The
// capability-host and encryption-scope surfaces are newer than the accounts
// they hang off, so an account that predates them (or a SKU that does not
// support them) answers that way rather than with an empty list.
func isAzureNotFoundOrBadRequest(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	return respErr.StatusCode == http.StatusNotFound || respErr.StatusCode == http.StatusBadRequest
}

// parseModelDate parses the date-only strings the model catalog reports for
// retirement. Returning a time rather than the raw string is what lets a query
// compare a retirement date against now.
func parseModelDate(value *string) *time.Time {
	if value == nil || *value == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if parsed, err := time.Parse(layout, *value); err == nil {
			return &parsed
		}
	}
	log.Debug().Str("value", *value).Msg("could not parse cognitive services model deprecation date")
	return nil
}

// --- Model catalog ---

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) models() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subscriptionId, resourceGroup, accountName, err := cognitiveServicesAccountScope(a.Id.Data)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := armcognitiveservices.NewAccountsClient(subscriptionId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListModelsPager(resourceGroup, accountName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureForbidden(err) {
				log.Warn().Err(err).Msg("could not list cognitive services account models due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, m := range page.Value {
			if m == nil {
				continue
			}
			mqlModel, err := cognitiveServicesAccountModelToMql(a.MqlRuntime, a.Id.Data, m)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlModel)
		}
	}
	return res, nil
}

func cognitiveServicesAccountModelToMql(runtime *plugin.Runtime, accountId string, m *armcognitiveservices.AccountModel) (*mqlAzureSubscriptionCognitiveServicesServiceAccountModel, error) {
	var name, version, format, publisher, lifecycleStatus string
	var deprecationStatus, replacementModelName, replacementModelVersion, catalogAssetId string
	var isDefaultVersion bool
	var maxCapacity, replacementLeadTimeDays int64
	var inferenceDeprecation, fineTuneDeprecation, replacementAutoUpgradeStart *time.Time

	if m.BaseModel != nil {
		name = convert.ToValue(m.BaseModel.Name)
		version = convert.ToValue(m.BaseModel.Version)
		format = convert.ToValue(m.BaseModel.Format)
		publisher = convert.ToValue(m.BaseModel.Publisher)
	}
	// The model's own Name/Version/Format win when set: BaseModel describes the
	// model a fine-tune derives from, while these describe the entry itself.
	if m.Name != nil && *m.Name != "" {
		name = *m.Name
	}
	if m.Version != nil && *m.Version != "" {
		version = *m.Version
	}
	if m.Format != nil && *m.Format != "" {
		format = *m.Format
	}
	if m.Publisher != nil && *m.Publisher != "" {
		publisher = *m.Publisher
	}
	if m.IsDefaultVersion != nil {
		isDefaultVersion = *m.IsDefaultVersion
	}
	if m.LifecycleStatus != nil {
		lifecycleStatus = string(*m.LifecycleStatus)
	}
	if m.MaxCapacity != nil {
		maxCapacity = int64(*m.MaxCapacity)
	}
	if m.ModelCatalogAssetID != nil {
		catalogAssetId = *m.ModelCatalogAssetID
	}
	if d := m.Deprecation; d != nil {
		inferenceDeprecation = parseModelDate(d.Inference)
		fineTuneDeprecation = parseModelDate(d.FineTune)
		if d.DeprecationStatus != nil {
			deprecationStatus = string(*d.DeprecationStatus)
		}
	}
	if r := m.ReplacementConfig; r != nil {
		replacementModelName = convert.ToValue(r.TargetModelName)
		replacementModelVersion = convert.ToValue(r.TargetModelVersion)
		replacementAutoUpgradeStart = r.AutoUpgradeStartDate
		if r.UpgradeOnExpiryLeadTimeDays != nil {
			replacementLeadTimeDays = int64(*r.UpgradeOnExpiryLeadTimeDays)
		}
	}

	skus, err := convert.JsonToDictSlice(m.SKUs)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account.model", map[string]*llx.RawData{
		// The catalog entry is not an ARM resource, so it has no id of its own.
		// Key it on the account plus the format/name/version that select it.
		"__id":                                   llx.StringData(fmt.Sprintf("%s/models/%s/%s/%s", accountId, format, name, version)),
		"name":                                   llx.StringData(name),
		"version":                                llx.StringData(version),
		"format":                                 llx.StringData(format),
		"publisher":                              llx.StringData(publisher),
		"isDefaultVersion":                       llx.BoolData(isDefaultVersion),
		"lifecycleStatus":                        llx.StringData(lifecycleStatus),
		"inferenceDeprecationDate":               llx.TimeDataPtr(inferenceDeprecation),
		"fineTuneDeprecationDate":                llx.TimeDataPtr(fineTuneDeprecation),
		"deprecationStatus":                      llx.StringData(deprecationStatus),
		"replacementModelName":                   llx.StringData(replacementModelName),
		"replacementModelVersion":                llx.StringData(replacementModelVersion),
		"replacementAutoUpgradeStartDate":        llx.TimeDataPtr(replacementAutoUpgradeStart),
		"replacementUpgradeOnExpiryLeadTimeDays": llx.IntData(replacementLeadTimeDays),
		"maxCapacity":                            llx.IntData(maxCapacity),
		"catalogAssetId":                         llx.StringData(catalogAssetId),
		"capabilities":                           llx.MapData(convert.PtrMapStrToInterface(m.Capabilities), types.String),
		"finetuneCapabilities":                   llx.MapData(convert.PtrMapStrToInterface(m.FinetuneCapabilities), types.String),
		"skus":                                   llx.ArrayData(skus, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionCognitiveServicesServiceAccountModel), nil
}

// model resolves the catalog entry for the version a deployment serves by
// matching against the account's model list. A deployment that names no version
// tracks the model's default version, so that is what matches in that case.
func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountDeployment) model() (*mqlAzureSubscriptionCognitiveServicesServiceAccountModel, error) {
	modelName := a.ModelName.Data
	if modelName == "" || a.cacheAccountId == "" {
		a.Model.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	mqlAccount, err := NewResource(a.MqlRuntime, "azure.subscription.cognitiveServicesService.account",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheAccountId)})
	if err != nil {
		return nil, err
	}
	account := mqlAccount.(*mqlAzureSubscriptionCognitiveServicesServiceAccount)
	models := account.GetModels()
	if models.Error != nil {
		return nil, models.Error
	}

	wantVersion := a.ModelVersion.Data
	for _, entry := range models.Data {
		model, ok := entry.(*mqlAzureSubscriptionCognitiveServicesServiceAccountModel)
		if !ok || model.Name.Data != modelName {
			continue
		}
		if wantVersion == "" {
			if model.IsDefaultVersion.Data {
				return model, nil
			}
			continue
		}
		if model.Version.Data == wantVersion {
			return model, nil
		}
	}

	a.Model.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// --- Blocklists ---

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) raiBlocklists() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subscriptionId, resourceGroup, accountName, err := cognitiveServicesAccountScope(a.Id.Data)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := armcognitiveservices.NewRaiBlocklistsClient(subscriptionId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceGroup, accountName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureForbidden(err) {
				log.Warn().Err(err).Msg("could not list cognitive services RAI blocklists due to access denied")
				return res, nil
			}
			if isAzureNotFoundOrBadRequest(err) {
				log.Debug().Err(err).Msg("cognitive services RAI blocklists are not available on this account")
				return res, nil
			}
			return nil, err
		}
		for _, bl := range page.Value {
			if bl == nil {
				continue
			}
			description := ""
			if bl.Properties != nil {
				description = convert.ToValue(bl.Properties.Description)
			}
			mqlBl, err := CreateResource(a.MqlRuntime, "azure.subscription.cognitiveServicesService.account.raiBlocklist", map[string]*llx.RawData{
				"id":          llx.StringDataPtr(bl.ID),
				"name":        llx.StringDataPtr(bl.Name),
				"description": llx.StringData(description),
				"tags":        llx.MapData(convert.PtrMapStrToInterface(bl.Tags), types.String),
				"etag":        llx.StringDataPtr(bl.Etag),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(bl.SystemData)
			if err != nil {
				return nil, err
			}
			mqlBl.(*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiBlocklist).cacheSystemData = sysData
			res = append(res, mqlBl)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountRaiBlocklistInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountRaiBlocklist) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountRaiBlocklist) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountRaiBlocklist) items() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName := parsed.Path["accounts"]
	blocklistName := parsed.Path["raiBlocklists"]
	if blocklistName == "" {
		blocklistName = a.Name.Data
	}

	ctx := context.Background()
	client, err := armcognitiveservices.NewRaiBlocklistItemsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, accountName, blocklistName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureForbidden(err) {
				log.Warn().Err(err).Msg("could not list cognitive services RAI blocklist items due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, item := range page.Value {
			if item == nil {
				continue
			}
			var pattern string
			var isRegex bool
			if p := item.Properties; p != nil {
				pattern = convert.ToValue(p.Pattern)
				if p.IsRegex != nil {
					isRegex = *p.IsRegex
				}
			}
			mqlItem, err := CreateResource(a.MqlRuntime, "azure.subscription.cognitiveServicesService.account.raiBlocklist.item", map[string]*llx.RawData{
				"id":      llx.StringDataPtr(item.ID),
				"name":    llx.StringDataPtr(item.Name),
				"pattern": llx.StringData(pattern),
				"isRegex": llx.BoolData(isRegex),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(item.SystemData)
			if err != nil {
				return nil, err
			}
			mqlItem.(*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiBlocklistItem).cacheSystemData = sysData
			res = append(res, mqlItem)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountRaiBlocklistItemInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountRaiBlocklistItem) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountRaiBlocklistItem) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// --- Encryption scopes ---

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) encryptionScopes() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subscriptionId, resourceGroup, accountName, err := cognitiveServicesAccountScope(a.Id.Data)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := armcognitiveservices.NewEncryptionScopesClient(subscriptionId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceGroup, accountName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureForbidden(err) {
				log.Warn().Err(err).Msg("could not list cognitive services encryption scopes due to access denied")
				return res, nil
			}
			if isAzureNotFoundOrBadRequest(err) {
				log.Debug().Err(err).Msg("cognitive services encryption scopes are not available on this account")
				return res, nil
			}
			return nil, err
		}
		for _, scope := range page.Value {
			if scope == nil {
				continue
			}
			var state, keySource, keyName, keyVaultUri, keyVersion, identityClientId, provisioningState string
			if p := scope.Properties; p != nil {
				if p.State != nil {
					state = string(*p.State)
				}
				if p.KeySource != nil {
					keySource = string(*p.KeySource)
				}
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				if kv := p.KeyVaultProperties; kv != nil {
					keyName = convert.ToValue(kv.KeyName)
					keyVaultUri = convert.ToValue(kv.KeyVaultURI)
					keyVersion = convert.ToValue(kv.KeyVersion)
					identityClientId = convert.ToValue(kv.IdentityClientID)
				}
			}
			mqlScope, err := CreateResource(a.MqlRuntime, "azure.subscription.cognitiveServicesService.account.encryptionScope", map[string]*llx.RawData{
				"id":                  llx.StringDataPtr(scope.ID),
				"name":                llx.StringDataPtr(scope.Name),
				"state":               llx.StringData(state),
				"keySource":           llx.StringData(keySource),
				"keyVaultKeyName":     llx.StringData(keyName),
				"keyVaultUri":         llx.StringData(keyVaultUri),
				"keyVaultKeyVersion":  llx.StringData(keyVersion),
				"keyIdentityClientId": llx.StringData(identityClientId),
				"provisioningState":   llx.StringData(provisioningState),
				"tags":                llx.MapData(convert.PtrMapStrToInterface(scope.Tags), types.String),
				"etag":                llx.StringDataPtr(scope.Etag),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(scope.SystemData)
			if err != nil {
				return nil, err
			}
			mqlScope.(*mqlAzureSubscriptionCognitiveServicesServiceAccountEncryptionScope).cacheSystemData = sysData
			res = append(res, mqlScope)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountEncryptionScopeInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountEncryptionScope) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountEncryptionScope) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// --- Capability hosts ---

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) capabilityHosts() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subscriptionId, resourceGroup, accountName, err := cognitiveServicesAccountScope(a.Id.Data)
	if err != nil {
		return nil, err
	}

	client, err := armcognitiveservices.NewAccountCapabilityHostsClient(subscriptionId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListPager(resourceGroup, accountName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if handled, hErr := handleCapabilityHostListError(err); handled {
				return res, hErr
			}
			return nil, err
		}
		for _, host := range page.Value {
			if host == nil {
				continue
			}
			var kind, description, provisioningState, customerSubnetId string
			var threadStorage, storage, vectorStore, aiServices []any
			tags := map[string]*string{}
			if p := host.Properties; p != nil {
				if p.CapabilityHostKind != nil {
					kind = string(*p.CapabilityHostKind)
				}
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				description = convert.ToValue(p.Description)
				customerSubnetId = convert.ToValue(p.CustomerSubnet)
				threadStorage = ptrSliceToAny(p.ThreadStorageConnections)
				storage = ptrSliceToAny(p.StorageConnections)
				vectorStore = ptrSliceToAny(p.VectorStoreConnections)
				aiServices = ptrSliceToAny(p.AiServicesConnections)
				if p.Tags != nil {
					tags = p.Tags
				}
			}
			mqlHost, err := newMqlCapabilityHost(a.MqlRuntime, capabilityHostFields{
				id:                       host.ID,
				name:                     host.Name,
				kind:                     kind,
				description:              description,
				provisioningState:        provisioningState,
				customerSubnetId:         customerSubnetId,
				threadStorageConnections: threadStorage,
				storageConnections:       storage,
				vectorStoreConnections:   vectorStore,
				aiServicesConnections:    aiServices,
				tags:                     tags,
				systemData:               host.SystemData,
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlHost)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountProject) capabilityHosts() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName := parsed.Path["accounts"]
	projectName := parsed.Path["projects"]
	if projectName == "" {
		projectName = a.Name.Data
	}

	client, err := armcognitiveservices.NewProjectCapabilityHostsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListPager(parsed.ResourceGroup, accountName, projectName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if handled, hErr := handleCapabilityHostListError(err); handled {
				return res, hErr
			}
			return nil, err
		}
		for _, host := range page.Value {
			if host == nil {
				continue
			}
			// The project-scoped shape carries only the connections and the
			// provisioning state; kind, description, subnet, and tags are
			// account-level and stay empty here.
			var provisioningState string
			var threadStorage, storage, vectorStore, aiServices []any
			if p := host.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				threadStorage = ptrSliceToAny(p.ThreadStorageConnections)
				storage = ptrSliceToAny(p.StorageConnections)
				vectorStore = ptrSliceToAny(p.VectorStoreConnections)
				aiServices = ptrSliceToAny(p.AiServicesConnections)
			}
			mqlHost, err := newMqlCapabilityHost(a.MqlRuntime, capabilityHostFields{
				id:                       host.ID,
				name:                     host.Name,
				provisioningState:        provisioningState,
				threadStorageConnections: threadStorage,
				storageConnections:       storage,
				vectorStoreConnections:   vectorStore,
				aiServicesConnections:    aiServices,
				systemData:               host.SystemData,
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlHost)
		}
	}
	return res, nil
}

// handleCapabilityHostListError reports whether the error is one the listers
// degrade to an empty collection: access denied, or a surface the account or
// project does not offer. Returns (true, nil) when the caller should return what
// it has so far.
func handleCapabilityHostListError(err error) (bool, error) {
	if isAzureForbidden(err) {
		log.Warn().Err(err).Msg("could not list cognitive services capability hosts due to access denied")
		return true, nil
	}
	if isAzureNotFoundOrBadRequest(err) {
		log.Debug().Err(err).Msg("cognitive services capability hosts are not available here")
		return true, nil
	}
	return false, nil
}

// capabilityHostFields carries the values shared by the account- and
// project-scoped capability-host shapes, which the SDK models as two distinct
// types over an overlapping field set.
type capabilityHostFields struct {
	id                       *string
	name                     *string
	kind                     string
	description              string
	provisioningState        string
	customerSubnetId         string
	threadStorageConnections []any
	storageConnections       []any
	vectorStoreConnections   []any
	aiServicesConnections    []any
	tags                     map[string]*string
	systemData               *armcognitiveservices.SystemData
}

func newMqlCapabilityHost(runtime *plugin.Runtime, f capabilityHostFields) (*mqlAzureSubscriptionCognitiveServicesServiceAccountCapabilityHost, error) {
	res, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account.capabilityHost", map[string]*llx.RawData{
		"id":                       llx.StringDataPtr(f.id),
		"name":                     llx.StringDataPtr(f.name),
		"kind":                     llx.StringData(f.kind),
		"description":              llx.StringData(f.description),
		"provisioningState":        llx.StringData(f.provisioningState),
		"customerSubnetId":         llx.StringData(f.customerSubnetId),
		"threadStorageConnections": llx.ArrayData(f.threadStorageConnections, types.String),
		"storageConnections":       llx.ArrayData(f.storageConnections, types.String),
		"vectorStoreConnections":   llx.ArrayData(f.vectorStoreConnections, types.String),
		"aiServicesConnections":    llx.ArrayData(f.aiServicesConnections, types.String),
		"tags":                     llx.MapData(convert.PtrMapStrToInterface(f.tags), types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlHost := res.(*mqlAzureSubscriptionCognitiveServicesServiceAccountCapabilityHost)
	sysData, err := convert.JsonToDict(f.systemData)
	if err != nil {
		return nil, err
	}
	mqlHost.cacheSystemData = sysData
	return mqlHost, nil
}

// ptrSliceToAny flattens a slice of string pointers, dropping nil entries.
func ptrSliceToAny(values []*string) []any {
	res := make([]any, 0, len(values))
	for _, v := range values {
		if v != nil {
			res = append(res, *v)
		}
	}
	return res
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountCapabilityHostInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountCapabilityHost) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountCapabilityHost) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountCapabilityHost) customerSubnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	return cognitiveServicesResolveSubnet(a.MqlRuntime, &a.CustomerSubnet, a.CustomerSubnetId.Data)
}
