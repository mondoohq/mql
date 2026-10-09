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

func initAzureSubscriptionCognitiveServicesService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionCognitiveServicesService) id() (string, error) {
	return "azure.subscription.cognitiveServicesService/" + a.SubscriptionId.Data, nil
}

// initAzureSubscriptionCognitiveServicesServiceAccount resolves a single AI
// Services (Cognitive Services) account. When called without arguments it falls
// back to the discovered asset's platform id (see getAssetIdentifier), so an
// azure-cognitiveservices-account asset resolves to its backing account instead
// of an empty husk.
func initAzureSubscriptionCognitiveServicesServiceAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionCognitiveServicesService,
		func(s *mqlAzureSubscriptionCognitiveServicesService) *plugin.TValue[[]any] { return s.GetAccounts() },
		ResourceAzureSubscriptionCognitiveServicesServiceAccount)
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesService) accounts() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	ctx := context.Background()
	client, err := armcognitiveservices.NewAccountsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
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
				log.Warn().Err(err).Msg("could not list cognitive services accounts due to access denied")
				return keepTagMatches(a.MqlRuntime, res), nil
			}
			return nil, err
		}
		for _, account := range page.Value {
			if account == nil {
				continue
			}
			mqlAccount, err := cognitiveServicesAccountToMql(a.MqlRuntime, account)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAccount)
		}
	}
	return keepTagMatches(a.MqlRuntime, res), nil
}

func cognitiveServicesAccountToMql(runtime *plugin.Runtime, account *armcognitiveservices.Account) (*mqlAzureSubscriptionCognitiveServicesServiceAccount, error) {
	sku, err := convert.JsonToDict(account.SKU)
	if err != nil {
		return nil, err
	}
	accountSku := orZero(account.SKU)
	identity, err := convert.JsonToDict(account.Identity)
	if err != nil {
		return nil, err
	}

	var publicNetworkAccess, customSubDomainName string
	var cmkKeySource, cmkKeyName, cmkKeyVaultUri, cmkKeyVersion, cmkIdentityClientId string
	var endpoint, provisioningState string
	var disableLocalAuth, restrictOutboundNetworkAccess, storedCompletionsDisabled bool
	var networkAclsDefaultAction, networkAclsBypass string
	var creationTime *time.Time
	networkAcls := llx.NilData

	var abusePenaltyAction, raiMonitorAdxStorage, raiMonitorIdentityClientId, multiRegionRoutingMethod string
	var abusePenaltyExpiration *time.Time
	var abusePenaltyRateLimit float64
	allowedFqdnList := []any{}
	ipRules := []any{}
	associatedProjects := []any{}
	var allowProjectManagement *bool
	vnetRules := []any{}
	userOwnedStorage := []any{}
	networkInjections := []any{}
	commitmentPlanAssociations := []any{}
	multiRegionSettings := []any{}

	if p := account.Properties; p != nil {
		// DateCreated arrives as an ISO 8601 string; parse it to a timestamp.
		creationTime = parseAzureTimestamp(p.DateCreated)
		if p.PublicNetworkAccess != nil {
			publicNetworkAccess = string(*p.PublicNetworkAccess)
		}
		if p.DisableLocalAuth != nil {
			disableLocalAuth = *p.DisableLocalAuth
		}
		if p.RestrictOutboundNetworkAccess != nil {
			restrictOutboundNetworkAccess = *p.RestrictOutboundNetworkAccess
		}
		if p.CustomSubDomainName != nil {
			customSubDomainName = *p.CustomSubDomainName
		}
		if p.NetworkACLs != nil {
			d, err := convert.JsonToDict(p.NetworkACLs)
			if err != nil {
				return nil, err
			}
			networkAcls = llx.DictData(d)
			if p.NetworkACLs.DefaultAction != nil {
				networkAclsDefaultAction = string(*p.NetworkACLs.DefaultAction)
			}
			if p.NetworkACLs.Bypass != nil {
				networkAclsBypass = string(*p.NetworkACLs.Bypass)
			}
			for _, ipr := range p.NetworkACLs.IPRules {
				if ipr != nil && ipr.Value != nil {
					ipRules = append(ipRules, *ipr.Value)
				}
			}
			for _, vr := range p.NetworkACLs.VirtualNetworkRules {
				if vr == nil || vr.ID == nil {
					continue
				}
				var state string
				if vr.State != nil {
					state = *vr.State
				}
				var ignore bool
				if vr.IgnoreMissingVnetServiceEndpoint != nil {
					ignore = *vr.IgnoreMissingVnetServiceEndpoint
				}
				mqlVr, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account.virtualNetworkRule", map[string]*llx.RawData{
					"id":                               llx.StringDataPtr(vr.ID),
					"state":                            llx.StringData(state),
					"ignoreMissingVnetServiceEndpoint": llx.BoolData(ignore),
				})
				if err != nil {
					return nil, err
				}
				vnetRules = append(vnetRules, mqlVr)
			}
		}
		if enc := p.Encryption; enc != nil {
			if enc.KeySource != nil {
				cmkKeySource = string(*enc.KeySource)
			}
			if enc.KeyVaultProperties != nil {
				if enc.KeyVaultProperties.KeyName != nil {
					cmkKeyName = *enc.KeyVaultProperties.KeyName
				}
				if enc.KeyVaultProperties.KeyVaultURI != nil {
					cmkKeyVaultUri = *enc.KeyVaultProperties.KeyVaultURI
				}
				if enc.KeyVaultProperties.KeyVersion != nil {
					cmkKeyVersion = *enc.KeyVaultProperties.KeyVersion
				}
				if enc.KeyVaultProperties.IdentityClientID != nil {
					cmkIdentityClientId = *enc.KeyVaultProperties.IdentityClientID
				}
			}
		}
		if p.Endpoint != nil {
			endpoint = *p.Endpoint
		}
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		if p.StoredCompletionsDisabled != nil {
			storedCompletionsDisabled = *p.StoredCompletionsDisabled
		}
		allowProjectManagement = p.AllowProjectManagement
		associatedProjects = strPtrsToAny(p.AssociatedProjects)
		for _, fqdn := range p.AllowedFqdnList {
			if fqdn != nil {
				allowedFqdnList = append(allowedFqdnList, *fqdn)
			}
		}
		if ap := p.AbusePenalty; ap != nil {
			if ap.Action != nil {
				abusePenaltyAction = string(*ap.Action)
			}
			abusePenaltyExpiration = ap.Expiration
			if ap.RateLimitPercentage != nil {
				abusePenaltyRateLimit = float64(*ap.RateLimitPercentage)
			}
		}
		if rmc := p.RaiMonitorConfig; rmc != nil {
			if rmc.AdxStorageResourceID != nil {
				raiMonitorAdxStorage = *rmc.AdxStorageResourceID
			}
			if rmc.IdentityClientID != nil {
				raiMonitorIdentityClientId = *rmc.IdentityClientID
			}
		}
		for _, uos := range p.UserOwnedStorage {
			if uos == nil || uos.ResourceID == nil {
				continue
			}
			var identityClientId string
			if uos.IdentityClientID != nil {
				identityClientId = *uos.IdentityClientID
			}
			mqlUos, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account.userOwnedStorage", map[string]*llx.RawData{
				"id":               llx.StringDataPtr(uos.ResourceID),
				"identityClientId": llx.StringData(identityClientId),
			})
			if err != nil {
				return nil, err
			}
			userOwnedStorage = append(userOwnedStorage, mqlUos)
		}
		for _, cpa := range p.CommitmentPlanAssociations {
			if cpa == nil {
				continue
			}
			d, err := convert.JsonToDict(cpa)
			if err != nil {
				return nil, err
			}
			commitmentPlanAssociations = append(commitmentPlanAssociations, d)
		}
		if loc := p.Locations; loc != nil {
			if loc.RoutingMethod != nil {
				multiRegionRoutingMethod = string(*loc.RoutingMethod)
			}
			for _, rs := range loc.Regions {
				if rs == nil {
					continue
				}
				d, err := convert.JsonToDict(rs)
				if err != nil {
					return nil, err
				}
				multiRegionSettings = append(multiRegionSettings, d)
			}
		}
		for _, ni := range p.NetworkInjections {
			if ni == nil || ni.SubnetArmID == nil {
				continue
			}
			var scenario string
			if ni.Scenario != nil {
				scenario = string(*ni.Scenario)
			}
			var useMSFT bool
			if ni.UseMicrosoftManagedNetwork != nil {
				useMSFT = *ni.UseMicrosoftManagedNetwork
			}
			mqlNi, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account.networkInjection", map[string]*llx.RawData{
				// The subnet ARM ID alone is not unique: the same subnet can back
				// more than one injection scenario. Key the cache on subnet+scenario
				// while keeping the user-facing id the bare subnet ID so subnet()
				// still resolves.
				"__id":                       llx.StringData(*ni.SubnetArmID + "/" + scenario),
				"id":                         llx.StringDataPtr(ni.SubnetArmID),
				"scenario":                   llx.StringData(scenario),
				"useMicrosoftManagedNetwork": llx.BoolData(useMSFT),
			})
			if err != nil {
				return nil, err
			}
			networkInjections = append(networkInjections, mqlNi)
		}
	}

	args := map[string]*llx.RawData{
		"id":                              llx.StringDataPtr(account.ID),
		"name":                            llx.StringDataPtr(account.Name),
		"location":                        llx.StringDataPtr(account.Location),
		"kind":                            llx.StringDataPtr(account.Kind),
		"tags":                            llx.MapData(convert.PtrMapStrToInterface(account.Tags), types.String),
		"sku":                             llx.DictData(sku),
		"identity":                        llx.DictData(identity),
		"publicNetworkAccess":             llx.StringData(publicNetworkAccess),
		"disableLocalAuth":                llx.BoolData(disableLocalAuth),
		"restrictOutboundNetworkAccess":   llx.BoolData(restrictOutboundNetworkAccess),
		"customSubDomainName":             llx.StringData(customSubDomainName),
		"networkAcls":                     networkAcls,
		"networkAclsDefaultAction":        llx.StringData(networkAclsDefaultAction),
		"networkAclsBypass":               llx.StringData(networkAclsBypass),
		"cmkKeySource":                    llx.StringData(cmkKeySource),
		"cmkKeyName":                      llx.StringData(cmkKeyName),
		"cmkKeyVaultUri":                  llx.StringData(cmkKeyVaultUri),
		"endpoint":                        llx.StringData(endpoint),
		"provisioningState":               llx.StringData(provisioningState),
		"storedCompletionsDisabled":       llx.BoolData(storedCompletionsDisabled),
		"allowProjectManagement":          llx.BoolDataPtr(allowProjectManagement),
		"associatedProjects":              llx.ArrayData(associatedProjects, types.String),
		"creationTime":                    llx.TimeDataPtr(creationTime),
		"allowedFqdnList":                 llx.ArrayData(allowedFqdnList, types.String),
		"ipRules":                         llx.ArrayData(ipRules, types.String),
		"virtualNetworkRules":             llx.ArrayData(vnetRules, types.Resource("azure.subscription.cognitiveServicesService.account.virtualNetworkRule")),
		"abusePenaltyAction":              llx.StringData(abusePenaltyAction),
		"abusePenaltyExpiration":          llx.TimeDataPtr(abusePenaltyExpiration),
		"abusePenaltyRateLimitPercentage": llx.FloatData(abusePenaltyRateLimit),
		"cmkKeyVersion":                   llx.StringData(cmkKeyVersion),
		"cmkIdentityClientId":             llx.StringData(cmkIdentityClientId),
		"userOwnedStorageAccounts":        llx.ArrayData(userOwnedStorage, types.Resource("azure.subscription.cognitiveServicesService.account.userOwnedStorage")),
		"raiMonitorAdxStorageResourceId":  llx.StringData(raiMonitorAdxStorage),
		"raiMonitorIdentityClientId":      llx.StringData(raiMonitorIdentityClientId),
		"commitmentPlanAssociations":      llx.ArrayData(commitmentPlanAssociations, types.Dict),
		"multiRegionSettings":             llx.ArrayData(multiRegionSettings, types.Dict),
		"multiRegionRoutingMethod":        llx.StringData(multiRegionRoutingMethod),
		"networkInjections":               llx.ArrayData(networkInjections, types.Resource("azure.subscription.cognitiveServicesService.account.networkInjection")),
	}
	if err := setSkuData(runtime, args, skuName(accountSku.Name), skuTier(accountSku.Tier), skuSize(accountSku.Size), skuFamily(accountSku.Family), skuCapacity(accountSku.Capacity)); err != nil {
		return nil, err
	}
	accountIdentity := orZero(account.Identity)
	if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(accountIdentity.UserAssignedIdentities),
		identityType(accountIdentity.Type), identityPrincipalId(accountIdentity.PrincipalID), identityTenantId(accountIdentity.TenantID)); err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account", args)
	if err != nil {
		return nil, err
	}
	mqlAccount := res.(*mqlAzureSubscriptionCognitiveServicesServiceAccount)
	sysData, err := convert.JsonToDict(account.SystemData)
	if err != nil {
		return nil, err
	}
	mqlAccount.cacheSystemData = sysData
	if account.Properties != nil {
		mqlAccount.cachePrivateEndpointConnections = account.Properties.PrivateEndpointConnections
	}
	return mqlAccount, nil
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountInternal struct {
	cacheSystemData                 any
	cachePrivateEndpointConnections []*armcognitiveservices.PrivateEndpointConnection
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}

// roleAssignments returns the effective Microsoft Entra role assignments at the
// account scope. NewListForScopePager with no filter returns assignments at the
// scope and inherited from the resource group, subscription, and management-
// group ancestors, so the result reflects effective RBAC access to the account
// (not just assignments made directly on it).
func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) roleAssignments() ([]any, error) {
	return roleAssignmentsForScope(a.MqlRuntime, a.Id.Data, "cognitive services account")
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountVirtualNetworkRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountVirtualNetworkRule) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	return cognitiveServicesResolveSubnet(a.MqlRuntime, &a.Subnet, a.Id.Data)
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountNetworkInjection) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	return cognitiveServicesResolveSubnet(a.MqlRuntime, &a.Subnet, a.Id.Data)
}

// cognitiveServicesResolveSubnet resolves a subnet ARM ID to the typed subnet
// resource, marking the field null when the ID is empty. Shared by the
// virtual-network-rule and network-injection sub-resources.
func cognitiveServicesResolveSubnet(runtime *plugin.Runtime, field *plugin.TValue[*mqlAzureSubscriptionNetworkServiceSubnet], subnetId string) (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if subnetId == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "azure.subscription.networkService.subnet",
		map[string]*llx.RawData{"id": llx.StringData(subnetId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountUserOwnedStorage) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountUserOwnedStorage) storageAccount() (*mqlAzureSubscriptionStorageServiceAccount, error) {
	if a.Id.Data == "" {
		a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.storageService.account",
		map[string]*llx.RawData{"id": llx.StringData(a.Id.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionStorageServiceAccount), nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountRaiTopic) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) defenderForAIEnabled() (bool, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return false, errors.New("invalid connection provided, it is not an Azure connection")
	}

	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return false, err
	}
	accountName := parsed.Path["accounts"]

	client, err := armcognitiveservices.NewDefenderForAISettingsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return false, err
	}

	ctx := context.Background()
	pager := client.NewListPager(parsed.ResourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not read Defender for AI settings due to access denied")
				return false, nil
			}
			return false, err
		}
		for _, s := range page.Value {
			if s == nil || s.Properties == nil || s.Properties.State == nil {
				continue
			}
			if *s.Properties.State == armcognitiveservices.DefenderForAISettingStateEnabled {
				return true, nil
			}
		}
	}
	return false, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) raiPolicies() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName := parsed.Path["accounts"]

	ctx := context.Background()
	client, err := armcognitiveservices.NewRaiPoliciesClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, accountName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list cognitive services RAI policies due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, pol := range page.Value {
			if pol == nil {
				continue
			}
			mqlPol, err := raiPolicyToMql(a.MqlRuntime, pol)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPol)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) raiTopics() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName := parsed.Path["accounts"]

	ctx := context.Background()
	client, err := armcognitiveservices.NewRaiTopicsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, accountName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list cognitive services RAI topics due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, t := range page.Value {
			if t == nil {
				continue
			}
			mqlTopic, err := raiTopicToMql(a.MqlRuntime, t)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTopic)
		}
	}
	return res, nil
}

func raiPolicyToMql(runtime *plugin.Runtime, pol *armcognitiveservices.RaiPolicy) (*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicy, error) {
	var mode, policyType, basePolicyName string
	contentFilters := []any{}
	customBlocklists := []any{}
	topicRefs := []any{}

	if p := pol.Properties; p != nil {
		if p.Mode != nil {
			mode = string(*p.Mode)
		}
		if p.Type != nil {
			policyType = string(*p.Type)
		}
		if p.BasePolicyName != nil {
			basePolicyName = *p.BasePolicyName
		}
		for i, f := range p.ContentFilters {
			if f == nil {
				continue
			}
			cf, err := raiContentFilterToMql(runtime, pol, i, f)
			if err != nil {
				return nil, err
			}
			contentFilters = append(contentFilters, cf)
		}
		for _, b := range p.CustomBlocklists {
			if b == nil {
				continue
			}
			entry := map[string]any{}
			if b.BlocklistName != nil {
				entry["blocklistName"] = *b.BlocklistName
			}
			if b.Source != nil {
				entry["source"] = string(*b.Source)
			}
			if b.Blocking != nil {
				entry["blocking"] = *b.Blocking
			}
			customBlocklists = append(customBlocklists, entry)
		}
		for _, t := range p.CustomTopics {
			if t == nil {
				continue
			}
			ref, err := raiTopicRefToMql(runtime, pol, t)
			if err != nil {
				return nil, err
			}
			topicRefs = append(topicRefs, ref)
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account.raiPolicy", map[string]*llx.RawData{
		"id":               llx.StringDataPtr(pol.ID),
		"name":             llx.StringDataPtr(pol.Name),
		"mode":             llx.StringData(mode),
		"policyType":       llx.StringData(policyType),
		"basePolicyName":   llx.StringData(basePolicyName),
		"contentFilters":   llx.ArrayData(contentFilters, types.Resource("azure.subscription.cognitiveServicesService.account.raiPolicy.contentFilter")),
		"customBlocklists": llx.ArrayData(customBlocklists, types.Dict),
		"customTopics":     llx.ArrayData(topicRefs, types.Resource("azure.subscription.cognitiveServicesService.account.raiPolicy.topicRef")),
	})
	if err != nil {
		return nil, err
	}
	mqlPolicy := res.(*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicy)
	sysData, err := convert.JsonToDict(pol.SystemData)
	if err != nil {
		return nil, err
	}
	mqlPolicy.cacheSystemData = sysData
	return mqlPolicy, nil
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicyInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicy) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func raiContentFilterToMql(runtime *plugin.Runtime, pol *armcognitiveservices.RaiPolicy, idx int, f *armcognitiveservices.RaiPolicyContentFilter) (*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicyContentFilter, error) {
	policyId := ""
	if pol.ID != nil {
		policyId = *pol.ID
	}
	name := ""
	source := ""
	severityThreshold := ""
	var enabled, blocking bool
	if f.Name != nil {
		name = *f.Name
	}
	if f.Source != nil {
		source = string(*f.Source)
	}
	if f.SeverityThreshold != nil {
		severityThreshold = string(*f.SeverityThreshold)
	}
	if f.Enabled != nil {
		enabled = *f.Enabled
	}
	if f.Blocking != nil {
		blocking = *f.Blocking
	}
	id := fmt.Sprintf("%s/contentFilter/%s/%s", policyId, source, name)
	if name == "" && source == "" {
		id = fmt.Sprintf("%s/contentFilter/%d", policyId, idx)
	}
	res, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account.raiPolicy.contentFilter", map[string]*llx.RawData{
		"__id":              llx.StringData(id),
		"name":              llx.StringData(name),
		"source":            llx.StringData(source),
		"enabled":           llx.BoolData(enabled),
		"blocking":          llx.BoolData(blocking),
		"severityThreshold": llx.StringData(severityThreshold),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicyContentFilter), nil
}

func raiTopicRefToMql(runtime *plugin.Runtime, pol *armcognitiveservices.RaiPolicy, t *armcognitiveservices.CustomTopicConfig) (*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicyTopicRef, error) {
	policyId := ""
	if pol.ID != nil {
		policyId = *pol.ID
	}
	topicName := ""
	source := ""
	var blocking bool
	if t.TopicName != nil {
		topicName = *t.TopicName
	}
	if t.Source != nil {
		source = string(*t.Source)
	}
	if t.Blocking != nil {
		blocking = *t.Blocking
	}
	id := fmt.Sprintf("%s/topicRef/%s/%s", policyId, source, topicName)
	res, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account.raiPolicy.topicRef", map[string]*llx.RawData{
		"__id":      llx.StringData(id),
		"topicName": llx.StringData(topicName),
		"source":    llx.StringData(source),
		"blocking":  llx.BoolData(blocking),
	})
	if err != nil {
		return nil, err
	}
	ref := res.(*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicyTopicRef)
	if parsed, err := ParseResourceID(policyId); err == nil {
		ref.cacheTopicId = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.CognitiveServices/accounts/%s/raiTopics/%s",
			parsed.SubscriptionID, parsed.ResourceGroup, parsed.Path["accounts"], topicName)
	}
	return ref, nil
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicyTopicRefInternal struct {
	cacheTopicId string
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicyTopicRef) topic() (*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiTopic, error) {
	if a.cacheTopicId == "" {
		a.Topic.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlTopic, err := NewResource(a.MqlRuntime, "azure.subscription.cognitiveServicesService.account.raiTopic",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheTopicId)})
	if err != nil {
		return nil, err
	}
	return mqlTopic.(*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiTopic), nil
}

func initAzureSubscriptionCognitiveServicesServiceAccountRaiTopic(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idArg, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	parsed, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	accountName := parsed.Path["accounts"]
	topicName := parsed.Path["raitopics"]
	if accountName == "" || topicName == "" {
		return args, nil, nil
	}

	client, err := armcognitiveservices.NewRaiTopicsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), parsed.ResourceGroup, accountName, topicName, nil)
	if err != nil {
		return nil, nil, err
	}
	mqlTopic, err := raiTopicToMql(runtime, &resp.RaiTopic)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlTopic, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountDeployment) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) deployments() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName := parsed.Path["accounts"]

	ctx := context.Background()
	client, err := armcognitiveservices.NewDeploymentsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, accountName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list cognitive services deployments due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, dep := range page.Value {
			if dep == nil {
				continue
			}
			mqlDep, err := cognitiveServicesDeploymentToMql(a.MqlRuntime, dep)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDep)
		}
	}
	return res, nil
}

func cognitiveServicesDeploymentToMql(runtime *plugin.Runtime, dep *armcognitiveservices.Deployment) (*mqlAzureSubscriptionCognitiveServicesServiceAccountDeployment, error) {
	var skuName string
	var skuCapacity int64
	if dep.SKU != nil {
		if dep.SKU.Name != nil {
			skuName = *dep.SKU.Name
		}
		if dep.SKU.Capacity != nil {
			skuCapacity = int64(*dep.SKU.Capacity)
		}
	}

	var provisioningState, versionUpgradeOption, raiPolicyName string
	var modelFormat, modelName, modelVersion, modelPublisher, modelSource string
	var currentCapacity int64
	var dynamicThrottlingEnabled bool
	capabilities := map[string]any{}

	if p := dep.Properties; p != nil {
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		if p.VersionUpgradeOption != nil {
			versionUpgradeOption = string(*p.VersionUpgradeOption)
		}
		if p.RaiPolicyName != nil {
			raiPolicyName = *p.RaiPolicyName
		}
		if p.CurrentCapacity != nil {
			currentCapacity = int64(*p.CurrentCapacity)
		}
		if p.DynamicThrottlingEnabled != nil {
			dynamicThrottlingEnabled = *p.DynamicThrottlingEnabled
		}
		for k, v := range p.Capabilities {
			if v != nil {
				capabilities[k] = *v
			}
		}
		if m := p.Model; m != nil {
			if m.Format != nil {
				modelFormat = *m.Format
			}
			if m.Name != nil {
				modelName = *m.Name
			}
			if m.Version != nil {
				modelVersion = *m.Version
			}
			if m.Publisher != nil {
				modelPublisher = *m.Publisher
			}
			if m.Source != nil {
				modelSource = *m.Source
			}
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account.deployment", map[string]*llx.RawData{
		"id":                       llx.StringDataPtr(dep.ID),
		"name":                     llx.StringDataPtr(dep.Name),
		"tags":                     llx.MapData(convert.PtrMapStrToInterface(dep.Tags), types.String),
		"provisioningState":        llx.StringData(provisioningState),
		"skuName":                  llx.StringData(skuName),
		"skuCapacity":              llx.IntData(skuCapacity),
		"currentCapacity":          llx.IntData(currentCapacity),
		"modelFormat":              llx.StringData(modelFormat),
		"modelName":                llx.StringData(modelName),
		"modelVersion":             llx.StringData(modelVersion),
		"modelPublisher":           llx.StringData(modelPublisher),
		"modelSource":              llx.StringData(modelSource),
		"versionUpgradeOption":     llx.StringData(versionUpgradeOption),
		"dynamicThrottlingEnabled": llx.BoolData(dynamicThrottlingEnabled),
		"capabilities":             llx.MapData(capabilities, types.String),
		"raiPolicyName":            llx.StringData(raiPolicyName),
	})
	if err != nil {
		return nil, err
	}
	mqlDep := res.(*mqlAzureSubscriptionCognitiveServicesServiceAccountDeployment)
	// The owning account is what both raiPolicy and model resolve against, so
	// record it for every deployment rather than only the ones with a policy.
	if parsed, err := ParseResourceID(convert.ToValue(dep.ID)); err == nil {
		mqlDep.cacheAccountId = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.CognitiveServices/accounts/%s",
			parsed.SubscriptionID, parsed.ResourceGroup, parsed.Path["accounts"])
	}
	sysData, err := convert.JsonToDict(dep.SystemData)
	if err != nil {
		return nil, err
	}
	mqlDep.cacheSystemData = sysData
	return mqlDep, nil
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountDeploymentInternal struct {
	cacheAccountId  string
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountDeployment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// raiPolicy resolves the deployment's content-filter policy by matching raiPolicyName
// against the account's own policies. Deployments that use a system-managed default
// (e.g. "Microsoft.DefaultV2") have no account-scoped policy resource, so this returns
// null in that case while raiPolicyName still carries the name.
func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountDeployment) raiPolicy() (*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicy, error) {
	policyName := a.RaiPolicyName.Data
	if policyName == "" || a.cacheAccountId == "" {
		a.RaiPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	mqlAccount, err := NewResource(a.MqlRuntime, "azure.subscription.cognitiveServicesService.account",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheAccountId)})
	if err != nil {
		return nil, err
	}
	account := mqlAccount.(*mqlAzureSubscriptionCognitiveServicesServiceAccount)
	policies := account.GetRaiPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}
	for _, p := range policies.Data {
		policy, ok := p.(*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiPolicy)
		if !ok {
			continue
		}
		if policy.Name.Data == policyName {
			return policy, nil
		}
	}

	a.RaiPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func raiTopicToMql(runtime *plugin.Runtime, t *armcognitiveservices.RaiTopic) (*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiTopic, error) {
	var topicName, topicId, description, status, failedReason, sampleBlobUrl string
	var createdAt, lastModifiedAt *time.Time

	if p := t.Properties; p != nil {
		if p.TopicName != nil {
			topicName = *p.TopicName
		}
		if p.TopicID != nil {
			topicId = *p.TopicID
		}
		if p.Description != nil {
			description = *p.Description
		}
		if p.Status != nil {
			status = *p.Status
		}
		if p.FailedReason != nil {
			failedReason = *p.FailedReason
		}
		if p.SampleBlobURL != nil {
			sampleBlobUrl = *p.SampleBlobURL
		}
		createdAt = p.CreatedAt
		lastModifiedAt = p.LastModifiedAt
	}

	res, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account.raiTopic", map[string]*llx.RawData{
		"id":             llx.StringDataPtr(t.ID),
		"name":           llx.StringDataPtr(t.Name),
		"topicName":      llx.StringData(topicName),
		"topicId":        llx.StringData(topicId),
		"description":    llx.StringData(description),
		"status":         llx.StringData(status),
		"failedReason":   llx.StringData(failedReason),
		"sampleBlobUrl":  llx.StringData(sampleBlobUrl),
		"creationTime":   llx.TimeDataPtr(createdAt),
		"lastModifiedAt": llx.TimeDataPtr(lastModifiedAt),
	})
	if err != nil {
		return nil, err
	}
	mqlTopic := res.(*mqlAzureSubscriptionCognitiveServicesServiceAccountRaiTopic)
	sysData, err := convert.JsonToDict(t.SystemData)
	if err != nil {
		return nil, err
	}
	mqlTopic.cacheSystemData = sysData
	return mqlTopic, nil
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountRaiTopicInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountRaiTopic) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountProject) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountConnection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountProjectConnection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) projects() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName := parsed.Path["accounts"]

	ctx := context.Background()
	client, err := armcognitiveservices.NewProjectsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, accountName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list cognitive services projects due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, proj := range page.Value {
			if proj == nil {
				continue
			}
			mqlProj, err := cognitiveServicesProjectToMql(a.MqlRuntime, proj)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlProj)
		}
	}
	return res, nil
}

func cognitiveServicesProjectToMql(runtime *plugin.Runtime, proj *armcognitiveservices.Project) (*mqlAzureSubscriptionCognitiveServicesServiceAccountProject, error) {
	identity, err := convert.JsonToDict(proj.Identity)
	if err != nil {
		return nil, err
	}

	var displayName, description, provisioningState string
	var isDefault bool
	endpoints := map[string]any{}
	if p := proj.Properties; p != nil {
		if p.DisplayName != nil {
			displayName = *p.DisplayName
		}
		if p.Description != nil {
			description = *p.Description
		}
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		if p.IsDefault != nil {
			isDefault = *p.IsDefault
		}
		for k, v := range p.Endpoints {
			if v != nil {
				endpoints[k] = *v
			}
		}
	}

	projArgs := map[string]*llx.RawData{
		"id":                llx.StringDataPtr(proj.ID),
		"name":              llx.StringDataPtr(proj.Name),
		"location":          llx.StringDataPtr(proj.Location),
		"tags":              llx.MapData(convert.PtrMapStrToInterface(proj.Tags), types.String),
		"identity":          llx.DictData(identity),
		"displayName":       llx.StringData(displayName),
		"description":       llx.StringData(description),
		"isDefault":         llx.BoolData(isDefault),
		"provisioningState": llx.StringData(provisioningState),
		"endpoints":         llx.MapData(endpoints, types.String),
	}
	projIdentity := orZero(proj.Identity)
	if err := setResourceIdentity(runtime, projArgs, sortedUserAssignedIdentityIDs(projIdentity.UserAssignedIdentities),
		identityType(projIdentity.Type), identityPrincipalId(projIdentity.PrincipalID), identityTenantId(projIdentity.TenantID)); err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, "azure.subscription.cognitiveServicesService.account.project", projArgs)
	if err != nil {
		return nil, err
	}
	mqlProject := res.(*mqlAzureSubscriptionCognitiveServicesServiceAccountProject)
	sysData, err := convert.JsonToDict(proj.SystemData)
	if err != nil {
		return nil, err
	}
	mqlProject.cacheSystemData = sysData
	return mqlProject, nil
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountProjectInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountProject) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) connections() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName := parsed.Path["accounts"]

	ctx := context.Background()
	client, err := armcognitiveservices.NewAccountConnectionsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, accountName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list cognitive services account connections due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			mqlConn, err := cognitiveServicesConnectionToMql(a.MqlRuntime, "azure.subscription.cognitiveServicesService.account.connection", c)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlConn)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountProject) connections() ([]any, error) {
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

	ctx := context.Background()
	client, err := armcognitiveservices.NewProjectConnectionsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, accountName, projectName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list cognitive services project connections due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			mqlConn, err := cognitiveServicesConnectionToMql(a.MqlRuntime, "azure.subscription.cognitiveServicesService.account.project.connection", c)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlConn)
		}
	}
	return res, nil
}

// cognitiveServicesConnectionToMql maps an account- or project-scoped connection to the
// given MQL resource type. Both scopes share the same ConnectionPropertiesV2 shape.
func cognitiveServicesConnectionToMql(runtime *plugin.Runtime, resourceType string, c *armcognitiveservices.ConnectionPropertiesV2BasicResource) (plugin.Resource, error) {
	var category, authType, target, group, errMsg string
	var isSharedToAll, useWorkspaceManagedIdentity bool
	var peRequirement, peStatus string
	var expiryTime *time.Time
	metadata := map[string]any{}

	if c.Properties != nil {
		if p := c.Properties.GetConnectionPropertiesV2(); p != nil {
			if p.Category != nil {
				category = string(*p.Category)
			}
			if p.AuthType != nil {
				authType = string(*p.AuthType)
			}
			if p.Target != nil {
				target = *p.Target
			}
			if p.Group != nil {
				group = string(*p.Group)
			}
			if p.Error != nil {
				errMsg = *p.Error
			}
			if p.IsSharedToAll != nil {
				isSharedToAll = *p.IsSharedToAll
			}
			if p.UseWorkspaceManagedIdentity != nil {
				useWorkspaceManagedIdentity = *p.UseWorkspaceManagedIdentity
			}
			if p.PeRequirement != nil {
				peRequirement = string(*p.PeRequirement)
			}
			if p.PeStatus != nil {
				peStatus = string(*p.PeStatus)
			}
			expiryTime = p.ExpiryTime
			for k, v := range p.Metadata {
				if v != nil {
					metadata[k] = *v
				}
			}
		}
	}

	res, err := CreateResource(runtime, resourceType, map[string]*llx.RawData{
		"id":                          llx.StringDataPtr(c.ID),
		"name":                        llx.StringDataPtr(c.Name),
		"category":                    llx.StringData(category),
		"authType":                    llx.StringData(authType),
		"target":                      llx.StringData(target),
		"group":                       llx.StringData(group),
		"isSharedToAll":               llx.BoolData(isSharedToAll),
		"useWorkspaceManagedIdentity": llx.BoolData(useWorkspaceManagedIdentity),
		"peRequirement":               llx.StringData(peRequirement),
		"peStatus":                    llx.StringData(peStatus),
		"metadata":                    llx.MapData(metadata, types.String),
		"error":                       llx.StringData(errMsg),
		"expiryTime":                  llx.TimeDataPtr(expiryTime),
	})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(c.SystemData)
	if err != nil {
		return nil, err
	}
	switch r := res.(type) {
	case *mqlAzureSubscriptionCognitiveServicesServiceAccountConnection:
		r.cacheSystemData = sysData
	case *mqlAzureSubscriptionCognitiveServicesServiceAccountProjectConnection:
		r.cacheSystemData = sysData
	}
	return res, nil
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountConnectionInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionCognitiveServicesServiceAccountProjectConnectionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountConnection) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccountProjectConnection) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
