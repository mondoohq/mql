// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// -----------------------------------------------------------------------------
// Azure Virtual Network Manager
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceNetworkManagerInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionNetworkService) networkManagers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewManagersClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListBySubscriptionPager(&network.ManagersClientListBySubscriptionOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, mgr := range page.Value {
			if mgr == nil {
				continue
			}
			var provisioningState, description, resourceGuid string
			scopeAccesses := []any{}
			scopeSubscriptions := []any{}
			scopeManagementGroups := []any{}
			if p := mgr.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				description = convert.ToValue(p.Description)
				resourceGuid = convert.ToValue(p.ResourceGUID)
				for _, sa := range p.NetworkManagerScopeAccesses {
					if sa != nil {
						scopeAccesses = append(scopeAccesses, string(*sa))
					}
				}
				if p.NetworkManagerScopes != nil {
					scopeSubscriptions = strPtrsToAny(p.NetworkManagerScopes.Subscriptions)
					scopeManagementGroups = strPtrsToAny(p.NetworkManagerScopes.ManagementGroups)
				}
			}
			mqlMgr, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.networkManager",
				map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(mgr.ID),
					"name":                  llx.StringDataPtr(mgr.Name),
					"location":              llx.StringDataPtr(mgr.Location),
					"tags":                  llx.MapData(convert.PtrMapStrToInterface(mgr.Tags), types.String),
					"type":                  llx.StringDataPtr(mgr.Type),
					"etag":                  llx.StringDataPtr(mgr.Etag),
					"provisioningState":     llx.StringData(provisioningState),
					"description":           llx.StringData(description),
					"resourceGuid":          llx.StringData(resourceGuid),
					"scopeAccesses":         llx.ArrayData(scopeAccesses, types.String),
					"scopeSubscriptions":    llx.ArrayData(scopeSubscriptions, types.String),
					"scopeManagementGroups": llx.ArrayData(scopeManagementGroups, types.String),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(mgr.SystemData)
			if err != nil {
				return nil, err
			}
			mqlMgr.(*mqlAzureSubscriptionNetworkServiceNetworkManager).cacheSystemData = sysData
			res = append(res, mqlMgr)
		}
	}
	return res, nil
}

// strPtrsToAny converts a []*string into []any, skipping nil elements (the
// convert helpers panic on nil pointers).
func strPtrsToAny(s []*string) []any {
	res := []any{}
	for _, v := range s {
		if v != nil {
			res = append(res, *v)
		}
	}
	return res
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManager) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManager) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManager) networkGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	managerName, err := resourceID.Component("networkManagers")
	if err != nil {
		return nil, err
	}
	client, err := network.NewGroupsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(resourceID.ResourceGroup, managerName, &network.GroupsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, g := range page.Value {
			if g == nil {
				continue
			}
			mqlGroup, err := azureNetworkGroupToMql(a.MqlRuntime, g)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGroup)
		}
	}
	return res, nil
}

// azureNetworkGroupToMql maps a network manager network group into its MQL
// resource. Shared by the manager's networkGroups listing and the by-ID init
// so both paths produce identical resources.
func azureNetworkGroupToMql(runtime *plugin.Runtime, g *network.Group) (*mqlAzureSubscriptionNetworkServiceNetworkManagerNetworkGroup, error) {
	var provisioningState, description, memberType, resourceGuid string
	if p := g.Properties; p != nil {
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		description = convert.ToValue(p.Description)
		resourceGuid = convert.ToValue(p.ResourceGUID)
		if p.MemberType != nil {
			memberType = string(*p.MemberType)
		}
	}
	mqlGroup, err := CreateResource(runtime, "azure.subscription.networkService.networkManager.networkGroup",
		map[string]*llx.RawData{
			"id":                llx.StringDataPtr(g.ID),
			"name":              llx.StringDataPtr(g.Name),
			"type":              llx.StringDataPtr(g.Type),
			"etag":              llx.StringDataPtr(g.Etag),
			"provisioningState": llx.StringData(provisioningState),
			"description":       llx.StringData(description),
			"memberType":        llx.StringData(memberType),
			"resourceGuid":      llx.StringData(resourceGuid),
		})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(g.SystemData)
	if err != nil {
		return nil, err
	}
	mqlGroup.(*mqlAzureSubscriptionNetworkServiceNetworkManagerNetworkGroup).cacheSystemData = sysData
	return mqlGroup.(*mqlAzureSubscriptionNetworkServiceNetworkManagerNetworkGroup), nil
}

type mqlAzureSubscriptionNetworkServiceNetworkManagerNetworkGroupInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerNetworkGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerNetworkGroup) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionNetworkServiceNetworkManagerNetworkGroupStaticMemberInternal struct {
	cacheMemberType string
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerNetworkGroupStaticMember) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerNetworkGroup) staticMembers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	managerName, err := resourceID.Component("networkManagers")
	if err != nil {
		return nil, err
	}
	groupName, err := resourceID.Component("networkGroups")
	if err != nil {
		return nil, err
	}
	client, err := network.NewStaticMembersClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(resourceID.ResourceGroup, managerName, groupName, &network.StaticMembersClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, m := range page.Value {
			if m == nil {
				continue
			}
			var resourceId, region string
			if p := m.Properties; p != nil {
				resourceId = convert.ToValue(p.ResourceID)
				region = convert.ToValue(p.Region)
			}
			mqlMember, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.networkManager.networkGroup.staticMember",
				map[string]*llx.RawData{
					"id":         llx.StringDataPtr(m.ID),
					"name":       llx.StringDataPtr(m.Name),
					"resourceId": llx.StringData(resourceId),
					"region":     llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			mqlMember.(*mqlAzureSubscriptionNetworkServiceNetworkManagerNetworkGroupStaticMember).cacheMemberType = a.MemberType.Data
			res = append(res, mqlMember)
		}
	}
	return res, nil
}

// virtualNetwork resolves a static member's resource to its typed virtual
// network. Returns null for members whose group is subnet-typed, since the
// member ID then points at a subnet rather than a virtual network.
func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerNetworkGroupStaticMember) virtualNetwork() (*mqlAzureSubscriptionNetworkServiceVirtualNetwork, error) {
	if a.cacheMemberType != "VirtualNetwork" || a.ResourceId.Data == "" {
		a.VirtualNetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.virtualNetwork", map[string]*llx.RawData{
		"id": llx.StringData(a.ResourceId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceVirtualNetwork), nil
}

// initAzureSubscriptionNetworkServiceNetworkManagerNetworkGroup resolves a
// network group by its ARM ID so typed references to it (from admin rule
// collections and connectivity configurations) populate fully.
func initAzureSubscriptionNetworkServiceNetworkManagerNetworkGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	managerName, err := azureId.Component("networkManagers")
	if err != nil {
		return nil, nil, err
	}
	groupName, err := azureId.Component("networkGroups")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceNetworkManagerNetworkGroup, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewGroupsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, managerName, groupName, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureNetworkGroupToMql(runtime, &resp.Group)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManager) securityAdminConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	managerName, err := resourceID.Component("networkManagers")
	if err != nil {
		return nil, err
	}
	client, err := network.NewSecurityAdminConfigurationsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(resourceID.ResourceGroup, managerName, &network.SecurityAdminConfigurationsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cfg := range page.Value {
			if cfg == nil {
				continue
			}
			var provisioningState, description string
			intentServices := []any{}
			if p := cfg.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				description = convert.ToValue(p.Description)
				for _, svc := range p.ApplyOnNetworkIntentPolicyBasedServices {
					if svc != nil {
						intentServices = append(intentServices, string(*svc))
					}
				}
			}
			mqlCfg, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.networkManager.securityAdminConfiguration",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(cfg.ID),
					"name":              llx.StringDataPtr(cfg.Name),
					"type":              llx.StringDataPtr(cfg.Type),
					"etag":              llx.StringDataPtr(cfg.Etag),
					"provisioningState": llx.StringData(provisioningState),
					"description":       llx.StringData(description),
					"applyOnNetworkIntentPolicyBasedServices": llx.ArrayData(intentServices, types.String),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(cfg.SystemData)
			if err != nil {
				return nil, err
			}
			mqlCfg.(*mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfiguration).cacheSystemData = sysData
			res = append(res, mqlCfg)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfigurationInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfiguration) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfiguration) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfiguration) ruleCollections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	managerName, err := resourceID.Component("networkManagers")
	if err != nil {
		return nil, err
	}
	configName, err := resourceID.Component("securityAdminConfigurations")
	if err != nil {
		return nil, err
	}
	client, err := network.NewAdminRuleCollectionsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(resourceID.ResourceGroup, managerName, configName, &network.AdminRuleCollectionsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, rc := range page.Value {
			if rc == nil {
				continue
			}
			var provisioningState, description string
			var appliesToGroupIds []string
			if p := rc.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				description = convert.ToValue(p.Description)
				appliesToGroupIds = managerSecurityGroupIDs(p.AppliesToGroups)
			}
			mqlRc, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.networkManager.securityAdminConfiguration.ruleCollection",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(rc.ID),
					"name":              llx.StringDataPtr(rc.Name),
					"type":              llx.StringDataPtr(rc.Type),
					"etag":              llx.StringDataPtr(rc.Etag),
					"provisioningState": llx.StringData(provisioningState),
					"description":       llx.StringData(description),
				})
			if err != nil {
				return nil, err
			}
			mqlRc.(*mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfigurationRuleCollection).cacheAppliesToGroupIds = appliesToGroupIds
			res = append(res, mqlRc)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfigurationRuleCollectionInternal struct {
	cacheAppliesToGroupIds []string
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfigurationRuleCollection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfigurationRuleCollection) appliesToGroups() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.networkManager.networkGroup", a.cacheAppliesToGroupIds)
}

// managerSecurityGroupIDs flattens the network group references on an admin
// rule collection into their ARM IDs, skipping nil entries and nil IDs.
func managerSecurityGroupIDs(items []*network.ManagerSecurityGroupItem) []string {
	var ids []string
	for _, item := range items {
		if item != nil && item.NetworkGroupID != nil {
			ids = append(ids, *item.NetworkGroupID)
		}
	}
	return ids
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfigurationRuleCollection) rules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	managerName, err := resourceID.Component("networkManagers")
	if err != nil {
		return nil, err
	}
	configName, err := resourceID.Component("securityAdminConfigurations")
	if err != nil {
		return nil, err
	}
	collectionName, err := resourceID.Component("ruleCollections")
	if err != nil {
		return nil, err
	}
	client, err := network.NewAdminRulesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(resourceID.ResourceGroup, managerName, configName, collectionName, &network.AdminRulesClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, rule := range page.Value {
			if rule == nil {
				continue
			}
			mqlRule, err := azureAdminRuleToMql(a.MqlRuntime, rule)
			if err != nil {
				return nil, err
			}
			if mqlRule != nil {
				res = append(res, mqlRule)
			}
		}
	}
	return res, nil
}

// azureAdminRuleToMql maps a network manager admin rule into its MQL resource.
// Admin rules are polymorphic: custom rules (*AdminRule) carry a full set of
// match fields, while default rules (*DefaultAdminRule) expose the same fields
// as read-only values derived from a built-in flag. Both are flattened to the
// same typed fields so a query does not have to care which kind it is.
func azureAdminRuleToMql(runtime *plugin.Runtime, rule network.BaseAdminRuleClassification) (*mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfigurationRuleCollectionRule, error) {
	var args map[string]*llx.RawData
	// Custom (AdminRule) and default (DefaultAdminRule) rules carry the same
	// match fields on distinct property structs; adminRuleArgs unifies them.
	switch r := rule.(type) {
	case *network.AdminRule:
		if p := r.Properties; p != nil {
			args = adminRuleArgs(r.ID, r.Name, r.Type, r.Etag, network.AdminRuleKindCustom,
				p.Access, p.Direction, p.Protocol, p.Priority, p.ProvisioningState, p.Description,
				p.SourcePortRanges, p.DestinationPortRanges, p.Sources, p.Destinations)
		} else {
			args = adminRuleArgs(r.ID, r.Name, r.Type, r.Etag, network.AdminRuleKindCustom,
				nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		}
	case *network.DefaultAdminRule:
		if p := r.Properties; p != nil {
			args = adminRuleArgs(r.ID, r.Name, r.Type, r.Etag, network.AdminRuleKindDefault,
				p.Access, p.Direction, p.Protocol, p.Priority, p.ProvisioningState, p.Description,
				p.SourcePortRanges, p.DestinationPortRanges, p.Sources, p.Destinations)
		} else {
			args = adminRuleArgs(r.ID, r.Name, r.Type, r.Etag, network.AdminRuleKindDefault,
				nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		}
	default:
		// Unknown rule kind; skip rather than emit a malformed resource.
		return nil, nil
	}

	mqlRule, err := CreateResource(runtime, "azure.subscription.networkService.networkManager.securityAdminConfiguration.ruleCollection.rule", args)
	if err != nil {
		return nil, err
	}
	return mqlRule.(*mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfigurationRuleCollectionRule), nil
}

// adminRuleArgs builds the MQL args for an admin rule from its identity fields
// and the match fields shared by custom and default rules, so both polymorphic
// kinds map through a single path.
func adminRuleArgs(id, name, typ, etag *string, kind network.AdminRuleKind,
	access *network.SecurityConfigurationRuleAccess, direction *network.SecurityConfigurationRuleDirection,
	protocol *network.SecurityConfigurationRuleProtocol, priority *int32, provState *network.ProvisioningState,
	description *string, srcPorts, dstPorts []*string, sources, destinations []*network.AddressPrefixItem,
) map[string]*llx.RawData {
	var accessStr, directionStr, protocolStr, provStateStr string
	var priorityVal int64
	if access != nil {
		accessStr = string(*access)
	}
	if direction != nil {
		directionStr = string(*direction)
	}
	if protocol != nil {
		protocolStr = string(*protocol)
	}
	if provState != nil {
		provStateStr = string(*provState)
	}
	if priority != nil {
		priorityVal = int64(*priority)
	}
	return map[string]*llx.RawData{
		"id":                    llx.StringDataPtr(id),
		"name":                  llx.StringDataPtr(name),
		"type":                  llx.StringDataPtr(typ),
		"etag":                  llx.StringDataPtr(etag),
		"kind":                  llx.StringData(string(kind)),
		"provisioningState":     llx.StringData(provStateStr),
		"description":           llx.StringData(convert.ToValue(description)),
		"access":                llx.StringData(accessStr),
		"direction":             llx.StringData(directionStr),
		"priority":              llx.IntData(priorityVal),
		"protocol":              llx.StringData(protocolStr),
		"sourcePortRanges":      llx.ArrayData(strPtrsToAny(srcPorts), types.String),
		"destinationPortRanges": llx.ArrayData(strPtrsToAny(dstPorts), types.String),
		"sources":               llx.ArrayData(addressPrefixItemsToDict(sources), types.Dict),
		"destinations":          llx.ArrayData(addressPrefixItemsToDict(destinations), types.Dict),
	}
}

// addressPrefixItemsToDict flattens a slice of *AddressPrefixItem into dicts of
// addressPrefix and addressPrefixType, so an auditor can tell a service tag
// (for example "Internet") from a raw CIDR. Skips nil entries.
func addressPrefixItemsToDict(items []*network.AddressPrefixItem) []any {
	res := []any{}
	for _, item := range items {
		if item == nil {
			continue
		}
		entry := map[string]any{}
		if item.AddressPrefix != nil {
			entry["addressPrefix"] = *item.AddressPrefix
		}
		if item.AddressPrefixType != nil {
			entry["addressPrefixType"] = string(*item.AddressPrefixType)
		}
		res = append(res, entry)
	}
	return res
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerSecurityAdminConfigurationRuleCollectionRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManager) connectivityConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	managerName, err := resourceID.Component("networkManagers")
	if err != nil {
		return nil, err
	}
	client, err := network.NewConnectivityConfigurationsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(resourceID.ResourceGroup, managerName, &network.ConnectivityConfigurationsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cfg := range page.Value {
			if cfg == nil {
				continue
			}
			var provisioningState, description, topology string
			var isGlobal, deleteExistingPeering bool
			var appliesToGroupIds []string
			hubs := []any{}
			if p := cfg.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				description = convert.ToValue(p.Description)
				if p.ConnectivityTopology != nil {
					topology = string(*p.ConnectivityTopology)
				}
				if p.IsGlobal != nil {
					isGlobal = *p.IsGlobal == network.IsGlobalTrue
				}
				if p.DeleteExistingPeering != nil {
					deleteExistingPeering = *p.DeleteExistingPeering == network.DeleteExistingPeeringTrue
				}
				for _, grp := range p.AppliesToGroups {
					if grp != nil && grp.NetworkGroupID != nil {
						appliesToGroupIds = append(appliesToGroupIds, *grp.NetworkGroupID)
					}
				}
				hubDicts, err := convert.JsonToDictSlice(p.Hubs)
				if err != nil {
					return nil, err
				}
				hubs = hubDicts
			}
			mqlCfg, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.networkManager.connectivityConfiguration",
				map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(cfg.ID),
					"name":                  llx.StringDataPtr(cfg.Name),
					"type":                  llx.StringDataPtr(cfg.Type),
					"etag":                  llx.StringDataPtr(cfg.Etag),
					"provisioningState":     llx.StringData(provisioningState),
					"description":           llx.StringData(description),
					"connectivityTopology":  llx.StringData(topology),
					"isGlobal":              llx.BoolData(isGlobal),
					"deleteExistingPeering": llx.BoolData(deleteExistingPeering),
					"hubs":                  llx.ArrayData(hubs, types.Dict),
				})
			if err != nil {
				return nil, err
			}
			mqlCfg.(*mqlAzureSubscriptionNetworkServiceNetworkManagerConnectivityConfiguration).cacheAppliesToGroupIds = appliesToGroupIds
			sysData, err := convert.JsonToDict(cfg.SystemData)
			if err != nil {
				return nil, err
			}
			mqlCfg.(*mqlAzureSubscriptionNetworkServiceNetworkManagerConnectivityConfiguration).cacheSystemData = sysData
			res = append(res, mqlCfg)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceNetworkManagerConnectivityConfigurationInternal struct {
	cacheAppliesToGroupIds []string
	cacheSystemData        any
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerConnectivityConfiguration) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerConnectivityConfiguration) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionNetworkServiceNetworkManagerConnectivityConfiguration) appliesToGroups() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.networkManager.networkGroup", a.cacheAppliesToGroupIds)
}
