// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionContainerRegistryServiceRegistryInternal struct {
	cacheNetworkRuleSet             *armcontainerregistry.NetworkRuleSet
	cachePolicies                   *armcontainerregistry.Policies
	cacheEncryption                 *armcontainerregistry.EncryptionProperty
	cachePrivateEndpointConnections []*armcontainerregistry.PrivateEndpointConnection
	cacheSystemData                 any
	cacheUserAssignedIdentityIds    []string
}

type mqlAzureSubscriptionContainerRegistryServiceRegistryWebhookInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionContainerRegistryServiceRegistryReplicationInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionContainerRegistryServiceRegistryScopeMapInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionContainerRegistryServiceRegistryTokenInternal struct {
	cacheScopeMapID string
	cacheSystemData any
}

type mqlAzureSubscriptionContainerRegistryServiceRegistryCacheRuleInternal struct {
	cacheCredentialSetResourceID string
	cacheSystemData              any
}

type mqlAzureSubscriptionContainerRegistryServiceRegistryCredentialSetInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionContainerRegistryServiceRegistryConnectedRegistryInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionContainerRegistryService) id() (string, error) {
	return "azure.subscription.containerRegistryService/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionContainerRegistryService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionContainerRegistryServiceRegistry(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure container registry")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.containerRegistryService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	svc := res.(*mqlAzureSubscriptionContainerRegistryService)
	list := svc.GetRegistries()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range list.Data {
		reg := entry.(*mqlAzureSubscriptionContainerRegistryServiceRegistry)
		if reg.Id.Data == id {
			return args, reg, nil
		}
	}

	if filtered := tagFilteredOut(runtime, ResourceAzureSubscriptionContainerRegistryServiceRegistry, id); filtered != nil {
		return args, filtered, nil
	}

	return nil, nil, errors.New("azure container registry does not exist")
}

func (a *mqlAzureSubscriptionContainerRegistryService) registries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	clientFactory, err := armcontainerregistry.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	client := clientFactory.NewRegistriesClient()
	pager := client.NewListPager(nil)

	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, reg := range page.Value {
			if reg == nil {
				continue
			}
			mqlReg, err := createRegistryResource(a.MqlRuntime, reg)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlReg)
		}
	}
	return keepTagMatches(a.MqlRuntime, res), nil
}

func createRegistryResource(runtime *plugin.Runtime, reg *armcontainerregistry.Registry) (*mqlAzureSubscriptionContainerRegistryServiceRegistry, error) {
	props := reg.Properties
	if props == nil {
		props = &armcontainerregistry.RegistryProperties{}
	}

	var regPrincipalId, regTenantId *string
	var userAssignedIdentityIds []string
	if reg.Identity != nil {
		regPrincipalId = reg.Identity.PrincipalID
		regTenantId = reg.Identity.TenantID
		userAssignedIdentityIds = sortedUserAssignedIdentityIDs(reg.Identity.UserAssignedIdentities)
	}

	var skuName string
	if reg.SKU != nil && reg.SKU.Name != nil {
		skuName = string(*reg.SKU.Name)
	}

	var publicNetworkAccess string
	if props.PublicNetworkAccess != nil {
		publicNetworkAccess = string(*props.PublicNetworkAccess)
	}

	var networkRuleBypassOptions string
	if props.NetworkRuleBypassOptions != nil {
		networkRuleBypassOptions = string(*props.NetworkRuleBypassOptions)
	}

	var zoneRedundancy string
	if props.ZoneRedundancy != nil {
		zoneRedundancy = string(*props.ZoneRedundancy)
	}

	var provisioningState string
	if props.ProvisioningState != nil {
		provisioningState = string(*props.ProvisioningState)
	}

	var roleAssignmentMode string
	if props.RoleAssignmentMode != nil {
		roleAssignmentMode = string(*props.RoleAssignmentMode)
	}

	var creationDate *llx.RawData
	if props.CreationDate != nil {
		creationDate = llx.TimeDataPtr(props.CreationDate)
	} else {
		creationDate = llx.NilData
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionContainerRegistryServiceRegistry,
		map[string]*llx.RawData{
			"id":                               llx.StringDataPtr(reg.ID),
			"name":                             llx.StringDataPtr(reg.Name),
			"location":                         llx.StringDataPtr(reg.Location),
			"type":                             llx.StringDataPtr(reg.Type),
			"tags":                             llx.MapData(convert.PtrMapStrToInterface(reg.Tags), types.String),
			"skuName":                          llx.StringData(skuName),
			"principalId":                      llx.StringDataPtr(regPrincipalId),
			"tenantId":                         llx.StringDataPtr(regTenantId),
			"adminUserEnabled":                 llx.BoolDataPtr(props.AdminUserEnabled),
			"anonymousPullEnabled":             llx.BoolDataPtr(props.AnonymousPullEnabled),
			"networkRuleBypassAllowedForTasks": llx.BoolDataPtr(props.NetworkRuleBypassAllowedForTasks),
			"roleAssignmentMode":               llx.StringData(roleAssignmentMode),
			"publicNetworkAccess":              llx.StringData(publicNetworkAccess),
			"networkRuleBypassOptions":         llx.StringData(networkRuleBypassOptions),
			"zoneRedundancy":                   llx.StringData(zoneRedundancy),
			"dataEndpointEnabled":              llx.BoolDataPtr(props.DataEndpointEnabled),
			"loginServer":                      llx.StringDataPtr(props.LoginServer),
			"creationDate":                     creationDate,
			"provisioningState":                llx.StringData(provisioningState),
		})
	if err != nil {
		return nil, err
	}

	mqlReg := resource.(*mqlAzureSubscriptionContainerRegistryServiceRegistry)
	mqlReg.cacheNetworkRuleSet = props.NetworkRuleSet
	mqlReg.cachePolicies = props.Policies
	mqlReg.cacheEncryption = props.Encryption
	mqlReg.cachePrivateEndpointConnections = props.PrivateEndpointConnections
	mqlReg.cacheUserAssignedIdentityIds = userAssignedIdentityIds
	sysData, err := convert.JsonToDict(reg.SystemData)
	if err != nil {
		return nil, err
	}
	mqlReg.cacheSystemData = sysData

	return mqlReg, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

// networkRuleSet builds the network rule set sub-resource from cached data.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) networkRuleSet() (*mqlAzureSubscriptionContainerRegistryServiceRegistryNetworkRuleSet, error) {
	nrs := a.cacheNetworkRuleSet
	if nrs == nil {
		a.NetworkRuleSet.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var defaultAction string
	if nrs.DefaultAction != nil {
		defaultAction = string(*nrs.DefaultAction)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistryNetworkRuleSet,
		map[string]*llx.RawData{
			"id":            llx.StringData(a.Id.Data + "/networkRuleSet"),
			"defaultAction": llx.StringData(defaultAction),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionContainerRegistryServiceRegistryNetworkRuleSet), nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryNetworkRuleSet) id() (string, error) {
	return a.Id.Data, nil
}

// ipRules returns the IP rules from the parent registry's cached network rule set.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryNetworkRuleSet) ipRules() ([]any, error) {
	parentID := a.Id.Data
	// parentID is like ".../networkRuleSet" — strip suffix to get registry ID
	registryID := strings.TrimSuffix(parentID, "/networkRuleSet")

	// Look up the parent registry resource to get the cached data.
	cached, ok := a.MqlRuntime.Resources.Get(ResourceAzureSubscriptionContainerRegistryServiceRegistry + "\x00" + registryID)
	if !ok {
		return []any{}, nil
	}
	registry := cached.(*mqlAzureSubscriptionContainerRegistryServiceRegistry)
	nrs := registry.cacheNetworkRuleSet
	if nrs == nil {
		return []any{}, nil
	}

	var res []any
	for i, rule := range nrs.IPRules {
		if rule == nil {
			continue
		}
		var action string
		if rule.Action != nil {
			action = string(*rule.Action)
		}
		mqlRule, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistryNetworkRuleSetIpRule,
			map[string]*llx.RawData{
				"id":               llx.StringData(fmt.Sprintf("%s/ipRules/%d", parentID, i)),
				"ipAddressOrRange": llx.StringDataPtr(rule.IPAddressOrRange),
				"action":           llx.StringData(action),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryNetworkRuleSetIpRule) id() (string, error) {
	return a.Id.Data, nil
}

// policies builds the flattened policies sub-resource from cached data.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) policies() (*mqlAzureSubscriptionContainerRegistryServiceRegistryPolicies, error) {
	p := a.cachePolicies
	if p == nil {
		a.Policies.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var trustEnabled bool
	var trustType string
	if p.TrustPolicy != nil {
		if p.TrustPolicy.Status != nil {
			trustEnabled = string(*p.TrustPolicy.Status) == "enabled"
		}
		if p.TrustPolicy.Type != nil {
			trustType = string(*p.TrustPolicy.Type)
		}
	}

	var retentionEnabled bool
	var retentionDays int64
	if p.RetentionPolicy != nil {
		if p.RetentionPolicy.Status != nil {
			retentionEnabled = string(*p.RetentionPolicy.Status) == "enabled"
		}
		if p.RetentionPolicy.Days != nil {
			retentionDays = int64(*p.RetentionPolicy.Days)
		}
	}

	var quarantineEnabled bool
	if p.QuarantinePolicy != nil && p.QuarantinePolicy.Status != nil {
		quarantineEnabled = string(*p.QuarantinePolicy.Status) == "enabled"
	}

	var exportEnabled bool
	if p.ExportPolicy != nil && p.ExportPolicy.Status != nil {
		exportEnabled = string(*p.ExportPolicy.Status) == "enabled"
	}

	var aadAsArmEnabled bool
	if p.AzureADAuthenticationAsArmPolicy != nil && p.AzureADAuthenticationAsArmPolicy.Status != nil {
		aadAsArmEnabled = string(*p.AzureADAuthenticationAsArmPolicy.Status) == string(armcontainerregistry.AzureADAuthenticationAsArmPolicyStatusEnabled)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistryPolicies,
		map[string]*llx.RawData{
			"id":                      llx.StringData(a.Id.Data + "/policies"),
			"trustPolicyEnabled":      llx.BoolData(trustEnabled),
			"trustPolicyType":         llx.StringData(trustType),
			"retentionPolicyEnabled":  llx.BoolData(retentionEnabled),
			"retentionPolicyDays":     llx.IntData(retentionDays),
			"quarantinePolicyEnabled": llx.BoolData(quarantineEnabled),
			"exportPolicyEnabled":     llx.BoolData(exportEnabled),

			"azureADAuthenticationAsArmPolicyEnabled": llx.BoolData(aadAsArmEnabled),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionContainerRegistryServiceRegistryPolicies), nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryPolicies) id() (string, error) {
	return a.Id.Data, nil
}

// encryption builds the encryption sub-resource from cached data.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) encryption() (*mqlAzureSubscriptionContainerRegistryServiceRegistryEncryption, error) {
	enc := a.cacheEncryption
	if enc == nil {
		a.Encryption.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var status string
	if enc.Status != nil {
		status = string(*enc.Status)
	}

	var keyVaultKeyIdentifier string
	var keyRotationEnabled bool
	var lastKeyRotationTimestamp *llx.RawData
	if enc.KeyVaultProperties != nil {
		if enc.KeyVaultProperties.KeyIdentifier != nil {
			keyVaultKeyIdentifier = *enc.KeyVaultProperties.KeyIdentifier
		}
		if enc.KeyVaultProperties.KeyRotationEnabled != nil {
			keyRotationEnabled = *enc.KeyVaultProperties.KeyRotationEnabled
		}
		if enc.KeyVaultProperties.LastKeyRotationTimestamp != nil {
			lastKeyRotationTimestamp = llx.TimeDataPtr(enc.KeyVaultProperties.LastKeyRotationTimestamp)
		}
	}
	if lastKeyRotationTimestamp == nil {
		lastKeyRotationTimestamp = llx.NilData
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistryEncryption,
		map[string]*llx.RawData{
			"id":                       llx.StringData(a.Id.Data + "/encryption"),
			"status":                   llx.StringData(status),
			"keyVaultKeyIdentifier":    llx.StringData(keyVaultKeyIdentifier),
			"keyRotationEnabled":       llx.BoolData(keyRotationEnabled),
			"lastKeyRotationTimestamp": lastKeyRotationTimestamp,
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionContainerRegistryServiceRegistryEncryption), nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryEncryption) id() (string, error) {
	return a.Id.Data, nil
}

// key returns a typed reference to the Key Vault key used for CMK encryption.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryEncryption) key() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	keyURI := a.KeyVaultKeyIdentifier.Data
	if keyURI == "" {
		a.Key.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, keyURI)
}

// privateEndpointConnections builds the shared private endpoint connection resources.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) privateEndpointConnections() ([]any, error) {
	var res []any
	for _, pec := range a.cachePrivateEndpointConnections {
		if pec == nil {
			continue
		}

		var name, resType string
		if pec.ID != nil {
			connResourceID, err := ParseResourceID(*pec.ID)
			if err == nil {
				if nameComp, err := connResourceID.Component("privateEndpointConnections"); err == nil {
					name = nameComp
				}
				if connResourceID.Provider != "" {
					resType = connResourceID.Provider + "/registries/privateEndpointConnections"
				}
			}
			if name == "" {
				parts := strings.Split(*pec.ID, "/")
				if len(parts) > 0 {
					name = parts[len(parts)-1]
				}
			}
		}
		if resType == "" {
			resType = "Microsoft.ContainerRegistry/registries/privateEndpointConnections"
		}

		var pecPrivateEndpointID string
		pecArgs := map[string]*llx.RawData{
			"__id": llx.StringDataPtr(pec.ID),
			"id":   llx.StringDataPtr(pec.ID),
			"name": llx.StringData(name),
			"type": llx.StringData(resType),
		}

		if pec.Properties != nil {
			props := pec.Properties
			propsMap, err := convert.JsonToDict(props)
			if err != nil {
				return nil, err
			}
			pecArgs["properties"] = llx.DictData(propsMap)

			if props.PrivateEndpoint != nil {
				pecPrivateEndpointID = convert.ToValue(props.PrivateEndpoint.ID)
			}
			if props.PrivateLinkServiceConnectionState != nil {
				stateRes, err := newPrivateLinkServiceConnectionState(a.MqlRuntime, convert.ToValue(pec.ID),
					stringEnumPtr(props.PrivateLinkServiceConnectionState.ActionsRequired),
					props.PrivateLinkServiceConnectionState.Description,
					stringEnumPtr(props.PrivateLinkServiceConnectionState.Status))
				if err != nil {
					return nil, err
				}
				pecArgs["privateLinkServiceConnectionState"] = llx.ResourceData(stateRes, ResourceAzureSubscriptionPrivateEndpointConnectionConnectionState)
			}
			if props.ProvisioningState != nil {
				pecArgs["provisioningState"] = llx.StringData(string(*props.ProvisioningState))
			}
		}

		mqlRes, err := newAzurePrivateEndpointConnection(a.MqlRuntime, pecArgs, pecPrivateEndpointID)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRes)
	}
	return res, nil
}

// webhooks fetches all webhooks for the registry.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) webhooks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	registryName, err := resourceID.Component("registries")
	if err != nil {
		return nil, err
	}

	client, err := armcontainerregistry.NewWebhooksClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, registryName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, wh := range page.Value {
			if wh == nil {
				continue
			}

			var status, scope, provisioningState string
			var actions []any
			if wh.Properties != nil {
				if wh.Properties.Status != nil {
					status = string(*wh.Properties.Status)
				}
				if wh.Properties.Scope != nil {
					scope = *wh.Properties.Scope
				}
				if wh.Properties.ProvisioningState != nil {
					provisioningState = string(*wh.Properties.ProvisioningState)
				}
				for _, act := range wh.Properties.Actions {
					if act != nil {
						actions = append(actions, string(*act))
					}
				}
			}

			mqlWh, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistryWebhook,
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(wh.ID),
					"name":              llx.StringDataPtr(wh.Name),
					"location":          llx.StringDataPtr(wh.Location),
					"type":              llx.StringDataPtr(wh.Type),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(wh.Tags), types.String),
					"status":            llx.StringData(status),
					"scope":             llx.StringData(scope),
					"actions":           llx.ArrayData(actions, types.String),
					"provisioningState": llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(wh.SystemData)
			if err != nil {
				return nil, err
			}
			mqlWh.(*mqlAzureSubscriptionContainerRegistryServiceRegistryWebhook).cacheSystemData = sysData
			res = append(res, mqlWh)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryWebhook) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryWebhook) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// replications fetches all geo-replications for the registry.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) replications() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	registryName, err := resourceID.Component("registries")
	if err != nil {
		return nil, err
	}

	client, err := armcontainerregistry.NewReplicationsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, registryName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, repl := range page.Value {
			if repl == nil {
				continue
			}

			var regionEndpointEnabled bool
			var zoneRedundancy, provisioningState string
			if repl.Properties != nil {
				if repl.Properties.RegionEndpointEnabled != nil {
					regionEndpointEnabled = *repl.Properties.RegionEndpointEnabled
				}
				if repl.Properties.ZoneRedundancy != nil {
					zoneRedundancy = string(*repl.Properties.ZoneRedundancy)
				}
				if repl.Properties.ProvisioningState != nil {
					provisioningState = string(*repl.Properties.ProvisioningState)
				}
			}

			mqlRepl, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistryReplication,
				map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(repl.ID),
					"name":                  llx.StringDataPtr(repl.Name),
					"location":              llx.StringDataPtr(repl.Location),
					"type":                  llx.StringDataPtr(repl.Type),
					"tags":                  llx.MapData(convert.PtrMapStrToInterface(repl.Tags), types.String),
					"regionEndpointEnabled": llx.BoolData(regionEndpointEnabled),
					"zoneRedundancy":        llx.StringData(zoneRedundancy),
					"provisioningState":     llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(repl.SystemData)
			if err != nil {
				return nil, err
			}
			mqlRepl.(*mqlAzureSubscriptionContainerRegistryServiceRegistryReplication).cacheSystemData = sysData
			res = append(res, mqlRepl)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryReplication) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryReplication) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// scopeMaps fetches all scope maps for the registry.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) scopeMaps() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	registryName, err := resourceID.Component("registries")
	if err != nil {
		return nil, err
	}

	client, err := armcontainerregistry.NewScopeMapsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, registryName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, sm := range page.Value {
			if sm == nil {
				continue
			}
			mqlSm, err := createScopeMapResource(a.MqlRuntime, sm)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSm)
		}
	}
	return res, nil
}

func createScopeMapResource(runtime *plugin.Runtime, sm *armcontainerregistry.ScopeMap) (*mqlAzureSubscriptionContainerRegistryServiceRegistryScopeMap, error) {
	var description, provisioningState, resType string
	var actions []any
	var creationDate *llx.RawData

	if sm.Properties != nil {
		if sm.Properties.Description != nil {
			description = *sm.Properties.Description
		}
		if sm.Properties.ProvisioningState != nil {
			provisioningState = string(*sm.Properties.ProvisioningState)
		}
		for _, act := range sm.Properties.Actions {
			if act != nil {
				actions = append(actions, *act)
			}
		}
		if sm.Properties.CreationDate != nil {
			creationDate = llx.TimeDataPtr(sm.Properties.CreationDate)
		}
	}
	if creationDate == nil {
		creationDate = llx.NilData
	}
	if sm.Type != nil {
		resType = *sm.Type
	}

	res, err := CreateResource(runtime, ResourceAzureSubscriptionContainerRegistryServiceRegistryScopeMap,
		map[string]*llx.RawData{
			"id":                llx.StringDataPtr(sm.ID),
			"name":              llx.StringDataPtr(sm.Name),
			"type":              llx.StringData(resType),
			"description":       llx.StringData(description),
			"actions":           llx.ArrayData(actions, types.String),
			"creationDate":      creationDate,
			"provisioningState": llx.StringData(provisioningState),
		})
	if err != nil {
		return nil, err
	}
	mqlSm := res.(*mqlAzureSubscriptionContainerRegistryServiceRegistryScopeMap)
	sysData, err := convert.JsonToDict(sm.SystemData)
	if err != nil {
		return nil, err
	}
	mqlSm.cacheSystemData = sysData
	return mqlSm, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryScopeMap) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryScopeMap) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// initAzureSubscriptionContainerRegistryServiceRegistryScopeMap fetches a scope map by ID
// when it hasn't been pre-cached via the parent registry's scopeMaps() call.
func initAzureSubscriptionContainerRegistryServiceRegistryScopeMap(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	idRaw, ok := args["id"]
	if !ok || idRaw == nil {
		return nil, nil, errors.New("id required to fetch scope map")
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("id must be a non-empty string")
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	registryName, err := resourceID.Component("registries")
	if err != nil {
		return nil, nil, err
	}
	scopeMapName, err := resourceID.Component("scopeMaps")
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	client, err := armcontainerregistry.NewScopeMapsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.Get(ctx, resourceID.ResourceGroup, registryName, scopeMapName, nil)
	if err != nil {
		return nil, nil, err
	}

	mqlSm, err := createScopeMapResource(runtime, &resp.ScopeMap)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlSm, nil
}

// tokens fetches all tokens for the registry.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) tokens() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	registryName, err := resourceID.Component("registries")
	if err != nil {
		return nil, err
	}

	client, err := armcontainerregistry.NewTokensClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, registryName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, tk := range page.Value {
			if tk == nil {
				continue
			}
			mqlTk, err := createTokenResource(a.MqlRuntime, tk)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTk)
		}
	}
	return res, nil
}

func createTokenResource(runtime *plugin.Runtime, tk *armcontainerregistry.Token) (*mqlAzureSubscriptionContainerRegistryServiceRegistryToken, error) {
	var status, provisioningState, resType, scopeMapID string
	var creationDate *llx.RawData
	var certificates []any
	var passwords []any

	if tk.Properties != nil {
		if tk.Properties.Status != nil {
			status = string(*tk.Properties.Status)
		}
		if tk.Properties.ProvisioningState != nil {
			provisioningState = string(*tk.Properties.ProvisioningState)
		}
		if tk.Properties.ScopeMapID != nil {
			scopeMapID = *tk.Properties.ScopeMapID
		}
		if tk.Properties.CreationDate != nil {
			creationDate = llx.TimeDataPtr(tk.Properties.CreationDate)
		}
		if tk.Properties.Credentials != nil {
			for _, cert := range tk.Properties.Credentials.Certificates {
				if cert == nil {
					continue
				}
				certDict, err := convert.JsonToDict(cert)
				if err != nil {
					return nil, err
				}
				certificates = append(certificates, certDict)
			}
			for _, pw := range tk.Properties.Credentials.Passwords {
				if pw == nil {
					continue
				}
				// Deliberately exclude the secret Value field; only expose metadata.
				pwData := map[string]any{}
				if pw.Name != nil {
					pwData["name"] = string(*pw.Name)
				}
				if pw.CreationTime != nil {
					pwData["creationTime"] = pw.CreationTime.Format(time.RFC3339)
				}
				if pw.Expiry != nil {
					pwData["expiry"] = pw.Expiry.Format(time.RFC3339)
				}
				passwords = append(passwords, pwData)
			}
		}
	}
	if creationDate == nil {
		creationDate = llx.NilData
	}
	if tk.Type != nil {
		resType = *tk.Type
	}

	res, err := CreateResource(runtime, ResourceAzureSubscriptionContainerRegistryServiceRegistryToken,
		map[string]*llx.RawData{
			"id":                llx.StringDataPtr(tk.ID),
			"name":              llx.StringDataPtr(tk.Name),
			"type":              llx.StringData(resType),
			"status":            llx.StringData(status),
			"creationDate":      creationDate,
			"provisioningState": llx.StringData(provisioningState),
			"certificates":      llx.ArrayData(certificates, types.Dict),
			"passwords":         llx.ArrayData(passwords, types.Dict),
		})
	if err != nil {
		return nil, err
	}

	mqlToken := res.(*mqlAzureSubscriptionContainerRegistryServiceRegistryToken)
	mqlToken.cacheScopeMapID = scopeMapID
	sysData, err := convert.JsonToDict(tk.SystemData)
	if err != nil {
		return nil, err
	}
	mqlToken.cacheSystemData = sysData

	return mqlToken, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryToken) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryToken) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// scopeMap returns a typed reference to the token's scope map.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryToken) scopeMap() (*mqlAzureSubscriptionContainerRegistryServiceRegistryScopeMap, error) {
	if a.cacheScopeMapID == "" {
		a.ScopeMap.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistryScopeMap,
		map[string]*llx.RawData{
			"id": llx.StringData(a.cacheScopeMapID),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionContainerRegistryServiceRegistryScopeMap), nil
}

// cacheRules fetches all pull-through cache rules for the registry.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) cacheRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	registryName, err := resourceID.Component("registries")
	if err != nil {
		return nil, err
	}

	client, err := armcontainerregistry.NewCacheRulesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, registryName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cr := range page.Value {
			if cr == nil {
				continue
			}

			var sourceRepo, targetRepo, credSetID, provisioningState string
			var creationDate *llx.RawData
			if cr.Properties != nil {
				if cr.Properties.SourceRepository != nil {
					sourceRepo = *cr.Properties.SourceRepository
				}
				if cr.Properties.TargetRepository != nil {
					targetRepo = *cr.Properties.TargetRepository
				}
				if cr.Properties.CredentialSetResourceID != nil {
					credSetID = *cr.Properties.CredentialSetResourceID
				}
				if cr.Properties.ProvisioningState != nil {
					provisioningState = string(*cr.Properties.ProvisioningState)
				}
				if cr.Properties.CreationDate != nil {
					creationDate = llx.TimeDataPtr(cr.Properties.CreationDate)
				}
			}
			if creationDate == nil {
				creationDate = llx.NilData
			}

			mqlRes, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistryCacheRule,
				map[string]*llx.RawData{
					"id":                      llx.StringDataPtr(cr.ID),
					"name":                    llx.StringDataPtr(cr.Name),
					"type":                    llx.StringDataPtr(cr.Type),
					"sourceRepository":        llx.StringData(sourceRepo),
					"targetRepository":        llx.StringData(targetRepo),
					"credentialSetResourceId": llx.StringData(credSetID),
					"creationDate":            creationDate,
					"provisioningState":       llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			mqlCr := mqlRes.(*mqlAzureSubscriptionContainerRegistryServiceRegistryCacheRule)
			mqlCr.cacheCredentialSetResourceID = credSetID
			sysData, err := convert.JsonToDict(cr.SystemData)
			if err != nil {
				return nil, err
			}
			mqlCr.cacheSystemData = sysData
			res = append(res, mqlCr)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryCacheRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryCacheRule) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// credentialSet returns a typed reference to the credential set used by this cache rule.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryCacheRule) credentialSet() (*mqlAzureSubscriptionContainerRegistryServiceRegistryCredentialSet, error) {
	if a.cacheCredentialSetResourceID == "" {
		a.CredentialSet.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistryCredentialSet,
		map[string]*llx.RawData{
			"id": llx.StringData(a.cacheCredentialSetResourceID),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionContainerRegistryServiceRegistryCredentialSet), nil
}

// credentialSets fetches all credential sets for the registry.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) credentialSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	registryName, err := resourceID.Component("registries")
	if err != nil {
		return nil, err
	}

	client, err := armcontainerregistry.NewCredentialSetsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, registryName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cs := range page.Value {
			if cs == nil {
				continue
			}
			mqlCs, err := createCredentialSetResource(a.MqlRuntime, cs)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCs)
		}
	}
	return res, nil
}

func createCredentialSetResource(runtime *plugin.Runtime, cs *armcontainerregistry.CredentialSet) (*mqlAzureSubscriptionContainerRegistryServiceRegistryCredentialSet, error) {
	identity, err := convert.JsonToDict(cs.Identity)
	if err != nil {
		return nil, err
	}

	var loginServer, provisioningState string
	var creationDate *llx.RawData
	var authCredentials []any
	if cs.Properties != nil {
		if cs.Properties.LoginServer != nil {
			loginServer = *cs.Properties.LoginServer
		}
		if cs.Properties.ProvisioningState != nil {
			provisioningState = string(*cs.Properties.ProvisioningState)
		}
		if cs.Properties.CreationDate != nil {
			creationDate = llx.TimeDataPtr(cs.Properties.CreationDate)
		}
		for _, ac := range cs.Properties.AuthCredentials {
			if ac == nil {
				continue
			}
			d, err := convert.JsonToDict(ac)
			if err != nil {
				return nil, err
			}
			authCredentials = append(authCredentials, d)
		}
	}
	if creationDate == nil {
		creationDate = llx.NilData
	}

	csArgs := map[string]*llx.RawData{
		"id":                llx.StringDataPtr(cs.ID),
		"name":              llx.StringDataPtr(cs.Name),
		"type":              llx.StringDataPtr(cs.Type),
		"loginServer":       llx.StringData(loginServer),
		"identity":          llx.DictData(identity),
		"authCredentials":   llx.ArrayData(authCredentials, types.Dict),
		"creationDate":      creationDate,
		"provisioningState": llx.StringData(provisioningState),
	}
	csIdentity := orZero(cs.Identity)
	if err := setResourceIdentity(runtime, csArgs, sortedUserAssignedIdentityIDs(csIdentity.UserAssignedIdentities),
		identityType(csIdentity.Type), identityPrincipalId(csIdentity.PrincipalID), identityTenantId(csIdentity.TenantID)); err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, ResourceAzureSubscriptionContainerRegistryServiceRegistryCredentialSet, csArgs)
	if err != nil {
		return nil, err
	}
	mqlCs := res.(*mqlAzureSubscriptionContainerRegistryServiceRegistryCredentialSet)
	sysData, err := convert.JsonToDict(cs.SystemData)
	if err != nil {
		return nil, err
	}
	mqlCs.cacheSystemData = sysData
	return mqlCs, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryCredentialSet) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryCredentialSet) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// initAzureSubscriptionContainerRegistryServiceRegistryCredentialSet fetches a credential set
// by ID for cross-ref resolution from cacheRule.credentialSet().
func initAzureSubscriptionContainerRegistryServiceRegistryCredentialSet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	idRaw, ok := args["id"]
	if !ok || idRaw == nil {
		return args, nil, nil
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	registryName, err := resourceID.Component("registries")
	if err != nil {
		return nil, nil, err
	}
	credSetName, err := resourceID.Component("credentialSets")
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	client, err := armcontainerregistry.NewCredentialSetsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.Get(ctx, resourceID.ResourceGroup, registryName, credSetName, nil)
	if err != nil {
		return nil, nil, err
	}

	mqlCs, err := createCredentialSetResource(runtime, &resp.CredentialSet)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlCs, nil
}

// connectedRegistries fetches all connected (edge/on-prem) registries that mirror this registry.
func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) connectedRegistries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	registryName, err := resourceID.Component("registries")
	if err != nil {
		return nil, err
	}

	client, err := armcontainerregistry.NewConnectedRegistriesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, registryName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cr := range page.Value {
			if cr == nil {
				continue
			}

			args := map[string]*llx.RawData{
				"id":   llx.StringDataPtr(cr.ID),
				"name": llx.StringDataPtr(cr.Name),
				"type": llx.StringDataPtr(cr.Type),
			}

			var clientTokenIDs []any
			var notifications []any
			args["mode"] = llx.StringData("")
			args["connectionState"] = llx.StringData("")
			args["activationStatus"] = llx.StringData("")
			args["version"] = llx.StringData("")
			args["lastActivityTime"] = llx.NilData
			args["auditLogStatus"] = llx.StringData("")
			args["logLevel"] = llx.StringData("")
			args["loginServerHost"] = llx.StringData("")
			args["tlsStatus"] = llx.StringData("")
			args["garbageCollectionEnabled"] = llx.BoolData(false)
			args["garbageCollectionSchedule"] = llx.StringData("")
			args["parentId"] = llx.StringData("")
			args["syncTokenId"] = llx.StringData("")
			args["syncSchedule"] = llx.StringData("")
			args["syncWindow"] = llx.StringData("")
			args["syncLastSyncTime"] = llx.NilData
			args["syncMessageTtl"] = llx.StringData("")
			args["provisioningState"] = llx.StringData("")

			if props := cr.Properties; props != nil {
				if props.Mode != nil {
					args["mode"] = llx.StringData(string(*props.Mode))
				}
				if props.ConnectionState != nil {
					args["connectionState"] = llx.StringData(string(*props.ConnectionState))
				}
				if props.Version != nil {
					args["version"] = llx.StringDataPtr(props.Version)
				}
				if props.LastActivityTime != nil {
					args["lastActivityTime"] = llx.TimeDataPtr(props.LastActivityTime)
				}
				if props.ProvisioningState != nil {
					args["provisioningState"] = llx.StringData(string(*props.ProvisioningState))
				}
				if props.Activation != nil && props.Activation.Status != nil {
					args["activationStatus"] = llx.StringData(string(*props.Activation.Status))
				}
				if props.Logging != nil {
					if props.Logging.AuditLogStatus != nil {
						args["auditLogStatus"] = llx.StringData(string(*props.Logging.AuditLogStatus))
					}
					if props.Logging.LogLevel != nil {
						args["logLevel"] = llx.StringData(string(*props.Logging.LogLevel))
					}
				}
				if props.LoginServer != nil {
					if props.LoginServer.Host != nil {
						args["loginServerHost"] = llx.StringDataPtr(props.LoginServer.Host)
					}
					if props.LoginServer.TLS != nil && props.LoginServer.TLS.Status != nil {
						args["tlsStatus"] = llx.StringData(string(*props.LoginServer.TLS.Status))
					}
				}
				if props.GarbageCollection != nil {
					if props.GarbageCollection.Enabled != nil {
						args["garbageCollectionEnabled"] = llx.BoolDataPtr(props.GarbageCollection.Enabled)
					}
					if props.GarbageCollection.Schedule != nil {
						args["garbageCollectionSchedule"] = llx.StringDataPtr(props.GarbageCollection.Schedule)
					}
				}
				if props.Parent != nil {
					if props.Parent.ID != nil {
						args["parentId"] = llx.StringDataPtr(props.Parent.ID)
					}
					if sp := props.Parent.SyncProperties; sp != nil {
						if sp.TokenID != nil {
							args["syncTokenId"] = llx.StringDataPtr(sp.TokenID)
						}
						if sp.Schedule != nil {
							args["syncSchedule"] = llx.StringDataPtr(sp.Schedule)
						}
						if sp.SyncWindow != nil {
							args["syncWindow"] = llx.StringDataPtr(sp.SyncWindow)
						}
						if sp.LastSyncTime != nil {
							args["syncLastSyncTime"] = llx.TimeDataPtr(sp.LastSyncTime)
						}
						if sp.MessageTTL != nil {
							args["syncMessageTtl"] = llx.StringDataPtr(sp.MessageTTL)
						}
					}
				}
				for _, t := range props.ClientTokenIDs {
					if t != nil {
						clientTokenIDs = append(clientTokenIDs, *t)
					}
				}
				for _, n := range props.NotificationsList {
					if n != nil {
						notifications = append(notifications, *n)
					}
				}
			}
			args["clientTokenIds"] = llx.ArrayData(clientTokenIDs, types.String)
			args["notificationsList"] = llx.ArrayData(notifications, types.String)

			mqlRes, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistryConnectedRegistry, args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(cr.SystemData)
			if err != nil {
				return nil, err
			}
			mqlRes.(*mqlAzureSubscriptionContainerRegistryServiceRegistryConnectedRegistry).cacheSystemData = sysData
			res = append(res, mqlRes)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryConnectedRegistry) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistryConnectedRegistry) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
