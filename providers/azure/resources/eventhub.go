// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionEventHubServiceNamespaceInternal struct {
	networkRuleSetFetched           atomic.Bool
	networkRuleSetProps             *armeventhub.NetworkRuleSetProperties
	networkRuleSetLock              sync.Mutex
	cacheSystemData                 any
	cachePrivateEndpointConnections []*armeventhub.PrivateEndpointConnection
}

func (a *mqlAzureSubscriptionEventHubServiceNamespace) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}

type mqlAzureSubscriptionEventHubServiceNamespaceEventHubInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionEventHubServiceNamespaceEventHubConsumerGroupInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionEventHubServiceNamespaceEventHubConsumerGroup) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionEventHubServiceAuthorizationRuleInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionEventHubServiceAuthorizationRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionEventHubServiceAuthorizationRule) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// eventHubAuthorizationRulesToMql maps a list of Event Hubs SAS authorization rules
// (from a namespace or an individual Event Hub) to the shared authorizationRule resource.
func eventHubAuthorizationRulesToMql(runtime *plugin.Runtime, rules []*armeventhub.AuthorizationRule) ([]any, error) {
	res := []any{}
	for _, r := range rules {
		if r == nil {
			continue
		}
		rights := []any{}
		if r.Properties != nil {
			for _, right := range r.Properties.Rights {
				if right == nil {
					continue
				}
				rights = append(rights, string(*right))
			}
		}
		mqlRule, err := CreateResource(runtime, ResourceAzureSubscriptionEventHubServiceAuthorizationRule, map[string]*llx.RawData{
			"id":     llx.StringDataPtr(r.ID),
			"name":   llx.StringDataPtr(r.Name),
			"rights": llx.ArrayData(rights, types.String),
		})
		if err != nil {
			return nil, err
		}
		sysData, err := convert.JsonToDict(r.SystemData)
		if err != nil {
			return nil, err
		}
		mqlRule.(*mqlAzureSubscriptionEventHubServiceAuthorizationRule).cacheSystemData = sysData
		res = append(res, mqlRule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionEventHubServiceNamespace) authorizationRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := armeventhub.NewNamespacesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListAuthorizationRulesPager(resourceID.ResourceGroup, a.Name.Data, nil)
	var rules []*armeventhub.AuthorizationRule
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		rules = append(rules, page.Value...)
	}
	return eventHubAuthorizationRulesToMql(a.MqlRuntime, rules)
}

func (a *mqlAzureSubscriptionEventHubServiceNamespaceEventHub) authorizationRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	nsName, err := resourceID.Component("namespaces")
	if err != nil {
		return nil, err
	}
	client, err := armeventhub.NewEventHubsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListAuthorizationRulesPager(resourceID.ResourceGroup, nsName, a.Name.Data, nil)
	var rules []*armeventhub.AuthorizationRule
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		rules = append(rules, page.Value...)
	}
	return eventHubAuthorizationRulesToMql(a.MqlRuntime, rules)
}

func (a *mqlAzureSubscriptionEventHubService) id() (string, error) {
	return "azure.subscription.eventHub/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionEventHubService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionEventHubServiceNamespace) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionEventHubServiceNamespaceEventHub) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionEventHubServiceNamespaceEventHubConsumerGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionEventHubService) namespaces() ([]any, error) {
	conn, err := azureConn(a.MqlRuntime)
	if err != nil {
		return nil, err
	}

	client, err := armeventhub.NewNamespacesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	return listPaged(a.MqlRuntime, &a.Namespaces, "event hub namespaces",
		client.NewListPager(nil),
		func(page armeventhub.NamespacesClientListResponse) []*armeventhub.EHNamespace {
			return page.Value
		},
		createEventHubNamespace,
	)
}

// createEventHubNamespace builds the MQL resource for one Event Hub namespace.
func createEventHubNamespace(runtime *plugin.Runtime, ns *armeventhub.EHNamespace) (plugin.Resource, error) {
	rawData, err := createEventHubNamespaceRawData(runtime, ns)
	if err != nil {
		return nil, err
	}

	mqlNs, err := CreateResource(runtime, ResourceAzureSubscriptionEventHubServiceNamespace, rawData)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(ns.SystemData)
	if err != nil {
		return nil, err
	}
	mqlNsRes := mqlNs.(*mqlAzureSubscriptionEventHubServiceNamespace)
	mqlNsRes.cacheSystemData = sysData
	if ns.Properties != nil {
		mqlNsRes.cachePrivateEndpointConnections = ns.Properties.PrivateEndpointConnections
	}
	return mqlNs, nil
}

// createEventHubNamespaceRawData maps one namespace onto its MQL fields.
//
// Pure by construction -- no client, no context, no runtime -- so it can be
// exercised against the shapes ARM actually returns, including a row with no
// Properties block and a KeyVaultProperties list with a nil entry in it. Both of
// those panic if dereferenced, and a panic in an accessor ends the scan rather
// than the query.
func createEventHubNamespaceRawData(runtime *plugin.Runtime, ns *armeventhub.EHNamespace) (map[string]*llx.RawData, error) {
	sku, err := convert.JsonToDict(ns.SKU)
	if err != nil {
		return nil, err
	}

	var status, cmkKeySource string
	var isAutoInflateEnabled, kafkaEnabled, disableLocalAuth, zoneRedundant bool
	var requireInfraEnc *bool
	var maximumThroughputUnits int64
	var minimumTlsVersion, publicNetworkAccess string
	var cmkKeys []any
	var creationTime, updatedAt *time.Time
	var alternateName, metricId, clusterArmId, serviceBusEndpoint *string
	if ns.Properties != nil {
		creationTime = ns.Properties.CreatedAt
		updatedAt = ns.Properties.UpdatedAt
		alternateName = ns.Properties.AlternateName
		metricId = ns.Properties.MetricID
		clusterArmId = ns.Properties.ClusterArmID
		serviceBusEndpoint = ns.Properties.ServiceBusEndpoint
		if ns.Properties.Status != nil {
			status = *ns.Properties.Status
		}
		if ns.Properties.IsAutoInflateEnabled != nil {
			isAutoInflateEnabled = *ns.Properties.IsAutoInflateEnabled
		}
		if ns.Properties.MaximumThroughputUnits != nil {
			maximumThroughputUnits = int64(*ns.Properties.MaximumThroughputUnits)
		}
		if ns.Properties.KafkaEnabled != nil {
			kafkaEnabled = *ns.Properties.KafkaEnabled
		}
		if ns.Properties.DisableLocalAuth != nil {
			disableLocalAuth = *ns.Properties.DisableLocalAuth
		}
		if ns.Properties.MinimumTLSVersion != nil {
			minimumTlsVersion = string(*ns.Properties.MinimumTLSVersion)
		}
		if ns.Properties.PublicNetworkAccess != nil {
			publicNetworkAccess = string(*ns.Properties.PublicNetworkAccess)
		}
		if ns.Properties.ZoneRedundant != nil {
			zoneRedundant = *ns.Properties.ZoneRedundant
		}
		if enc := ns.Properties.Encryption; enc != nil {
			if enc.KeySource != nil {
				cmkKeySource = string(*enc.KeySource)
			}
			requireInfraEnc = enc.RequireInfrastructureEncryption
			for _, kvp := range enc.KeyVaultProperties {
				if kvp == nil {
					continue
				}
				if d, err := convert.JsonToDict(kvp); err == nil {
					cmkKeys = append(cmkKeys, d)
				}
			}
		}
	}

	args := map[string]*llx.RawData{
		"id":                              llx.StringDataPtr(ns.ID),
		"name":                            llx.StringDataPtr(ns.Name),
		"location":                        llx.StringDataPtr(ns.Location),
		"tags":                            llx.MapData(convert.PtrMapStrToInterface(ns.Tags), types.String),
		"sku":                             llx.DictData(sku),
		"status":                          llx.StringData(status),
		"isAutoInflateEnabled":            llx.BoolData(isAutoInflateEnabled),
		"maximumThroughputUnits":          llx.IntData(maximumThroughputUnits),
		"kafkaEnabled":                    llx.BoolData(kafkaEnabled),
		"disableLocalAuth":                llx.BoolData(disableLocalAuth),
		"minimumTlsVersion":               llx.StringData(minimumTlsVersion),
		"publicNetworkAccess":             llx.StringData(publicNetworkAccess),
		"zoneRedundant":                   llx.BoolData(zoneRedundant),
		"cmkKeySource":                    llx.StringData(cmkKeySource),
		"requireInfrastructureEncryption": llx.BoolDataPtr(requireInfraEnc),
		"cmkKeys":                         llx.ArrayData(cmkKeys, types.Dict),
		"creationTime":                    llx.TimeDataPtr(creationTime),
		"alternateName":                   llx.StringDataPtr(alternateName),
		"metricId":                        llx.StringDataPtr(metricId),
		"clusterArmId":                    llx.StringDataPtr(clusterArmId),
		"serviceBusEndpoint":              llx.StringDataPtr(serviceBusEndpoint),
		"updatedAt":                       llx.TimeDataPtr(updatedAt),
	}
	nsSku := orZero(ns.SKU)
	if err := setSkuData(runtime, args, skuName(nsSku.Name), skuTier(nsSku.Tier), skuCapacity(nsSku.Capacity)); err != nil {
		return nil, err
	}

	return args, nil
}

func (a *mqlAzureSubscriptionEventHubServiceNamespace) eventHubs() ([]any, error) {
	conn, err := azureConn(a.MqlRuntime)
	if err != nil {
		return nil, err
	}

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	client, err := armeventhub.NewEventHubsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	return listPaged(a.MqlRuntime, &a.EventHubs, "event hubs",
		client.NewListByNamespacePager(resourceID.ResourceGroup, a.Name.Data, nil),
		func(page armeventhub.EventHubsClientListByNamespaceResponse) []*armeventhub.Eventhub {
			return page.Value
		},
		createEventHub,
	)
}

// createEventHub builds the MQL resource for one event hub within a namespace.
func createEventHub(runtime *plugin.Runtime, eh *armeventhub.Eventhub) (plugin.Resource, error) {
	mqlEh, err := CreateResource(runtime, ResourceAzureSubscriptionEventHubServiceNamespaceEventHub,
		createEventHubRawData(eh))
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(eh.SystemData)
	if err != nil {
		return nil, err
	}
	mqlEh.(*mqlAzureSubscriptionEventHubServiceNamespaceEventHub).cacheSystemData = sysData
	return mqlEh, nil
}

// createEventHubRawData maps one event hub onto its MQL fields. Pure, so the
// nil-Properties and nil-partition-id cases are testable without a namespace.
func createEventHubRawData(eh *armeventhub.Eventhub) map[string]*llx.RawData {
	var partitionCount, messageRetentionInDays int64
	var status string
	var partitionIds []any
	var creationTime *time.Time
	if eh.Properties != nil {
		creationTime = eh.Properties.CreatedAt
		if eh.Properties.PartitionCount != nil {
			partitionCount = *eh.Properties.PartitionCount
		}
		if eh.Properties.MessageRetentionInDays != nil {
			messageRetentionInDays = *eh.Properties.MessageRetentionInDays
		}
		if eh.Properties.Status != nil {
			status = string(*eh.Properties.Status)
		}
		if eh.Properties.PartitionIDs != nil {
			for _, pid := range eh.Properties.PartitionIDs {
				if pid != nil {
					partitionIds = append(partitionIds, *pid)
				}
			}
		}
	}

	return map[string]*llx.RawData{
		"id":                     llx.StringDataPtr(eh.ID),
		"name":                   llx.StringDataPtr(eh.Name),
		"partitionCount":         llx.IntData(partitionCount),
		"messageRetentionInDays": llx.IntData(messageRetentionInDays),
		"status":                 llx.StringData(status),
		"partitionIds":           llx.ArrayData(partitionIds, types.String),
		"creationTime":           llx.TimeDataPtr(creationTime),
	}
}

func (a *mqlAzureSubscriptionEventHubServiceNamespaceEventHub) consumerGroups() ([]any, error) {
	conn, err := azureConn(a.MqlRuntime)
	if err != nil {
		return nil, err
	}

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	nsName, err := resourceID.Component("namespaces")
	if err != nil {
		return nil, err
	}

	client, err := armeventhub.NewConsumerGroupsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	return listPaged(a.MqlRuntime, &a.ConsumerGroups, "event hub consumer groups",
		client.NewListByEventHubPager(resourceID.ResourceGroup, nsName, a.Name.Data, nil),
		func(page armeventhub.ConsumerGroupsClientListByEventHubResponse) []*armeventhub.ConsumerGroup {
			return page.Value
		},
		createEventHubConsumerGroup,
	)
}

// createEventHubConsumerGroup builds the MQL resource for one consumer group of
// an event hub.
func createEventHubConsumerGroup(runtime *plugin.Runtime, cg *armeventhub.ConsumerGroup) (plugin.Resource, error) {
	mqlCg, err := CreateResource(runtime, ResourceAzureSubscriptionEventHubServiceNamespaceEventHubConsumerGroup,
		createEventHubConsumerGroupRawData(cg))
	if err != nil {
		return nil, err
	}

	sysData, err := convert.JsonToDict(cg.SystemData)
	if err != nil {
		return nil, err
	}
	mqlCg.(*mqlAzureSubscriptionEventHubServiceNamespaceEventHubConsumerGroup).cacheSystemData = sysData

	return mqlCg, nil
}

// createEventHubConsumerGroupRawData maps one consumer group onto its MQL
// fields. Pure, so the nil-Properties case is reachable without an event hub
// behind it -- the $Default group comes back that way.
func createEventHubConsumerGroupRawData(cg *armeventhub.ConsumerGroup) map[string]*llx.RawData {
	var userMetadata string
	var creationTime *time.Time
	if cg.Properties != nil {
		creationTime = cg.Properties.CreatedAt
		if cg.Properties.UserMetadata != nil {
			userMetadata = *cg.Properties.UserMetadata
		}
	}

	return map[string]*llx.RawData{
		"id":           llx.StringDataPtr(cg.ID),
		"name":         llx.StringDataPtr(cg.Name),
		"userMetadata": llx.StringData(userMetadata),
		"creationTime": llx.TimeDataPtr(creationTime),
	}
}

func (a *mqlAzureSubscriptionEventHubServiceNamespace) networkRules() (*mqlAzureSubscriptionEventHubServiceNamespaceNetworkRules, error) {
	props, err := a.fetchNetworkRuleSetProperties()
	if err != nil {
		return nil, err
	}
	if props == nil {
		a.NetworkRules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	defaultAction := ""
	if props.DefaultAction != nil {
		defaultAction = string(*props.DefaultAction)
	}
	publicNetworkAccess := ""
	if props.PublicNetworkAccess != nil {
		publicNetworkAccess = string(*props.PublicNetworkAccess)
	}
	trustedServiceAccess := false
	if props.TrustedServiceAccessEnabled != nil {
		trustedServiceAccess = *props.TrustedServiceAccessEnabled
	}

	const ipRuleResource = "azure.subscription.eventHubService.namespace.networkRules.ipRule"
	ipRules := []any{}
	ipAllowRules := []any{}
	for i, r := range props.IPRules {
		if r == nil {
			continue
		}
		entry := map[string]any{}
		if r.IPMask != nil {
			entry["ipMask"] = *r.IPMask
		}
		if r.Action != nil {
			entry["action"] = string(*r.Action)
		}
		ipRules = append(ipRules, entry)

		// The address range keys the rule; a namespace can be returned with a
		// rule that carries none, and the position keeps those apart.
		key := convert.ToValue(r.IPMask)
		if key == "" {
			key = strconv.Itoa(i)
		}
		mqlIPRule, err := CreateResource(a.MqlRuntime, ipRuleResource, map[string]*llx.RawData{
			"__id":   llx.StringData(subResourceCacheID(nil, a.Id.Data+"/networkRules", "ipRules", key)),
			"ipMask": llx.StringDataPtr(r.IPMask),
			"action": llx.StringDataPtr(stringEnumPtr(r.Action)),
		})
		if err != nil {
			return nil, err
		}
		ipAllowRules = append(ipAllowRules, mqlIPRule)
	}

	vnetRules := []any{}
	for i, r := range props.VirtualNetworkRules {
		if r == nil {
			continue
		}
		ignore := false
		if r.IgnoreMissingVnetServiceEndpoint != nil {
			ignore = *r.IgnoreMissingVnetServiceEndpoint
		}
		subnetID := ""
		if r.Subnet != nil && r.Subnet.ID != nil {
			subnetID = *r.Subnet.ID
		}
		id := fmt.Sprintf("%s/networkRules/virtualNetworkRules/%d", a.Id.Data, i)
		mqlRule, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionEventHubServiceNamespaceNetworkRulesVirtualNetworkRule,
			map[string]*llx.RawData{
				"__id":                             llx.StringData(id),
				"ignoreMissingVnetServiceEndpoint": llx.BoolData(ignore),
			})
		if err != nil {
			return nil, err
		}
		mqlRule.(*mqlAzureSubscriptionEventHubServiceNamespaceNetworkRulesVirtualNetworkRule).cacheSubnetID = subnetID
		vnetRules = append(vnetRules, mqlRule)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionEventHubServiceNamespaceNetworkRules, map[string]*llx.RawData{
		"__id":                        llx.StringData(a.Id.Data + "/networkRules"),
		"defaultAction":               llx.StringData(defaultAction),
		"publicNetworkAccess":         llx.StringData(publicNetworkAccess),
		"trustedServiceAccessEnabled": llx.BoolData(trustedServiceAccess),
		"ipRules":                     llx.ArrayData(ipRules, types.Dict),
		"ipAllowRules":                llx.ArrayData(ipAllowRules, types.Resource(ipRuleResource)),
		"virtualNetworkRules":         llx.ArrayData(vnetRules, types.Resource(ResourceAzureSubscriptionEventHubServiceNamespaceNetworkRulesVirtualNetworkRule)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionEventHubServiceNamespaceNetworkRules), nil
}

func (a *mqlAzureSubscriptionEventHubServiceNamespace) fetchNetworkRuleSetProperties() (*armeventhub.NetworkRuleSetProperties, error) {
	if a.networkRuleSetFetched.Load() {
		return a.networkRuleSetProps, nil
	}
	a.networkRuleSetLock.Lock()
	defer a.networkRuleSetLock.Unlock()
	if a.networkRuleSetFetched.Load() {
		return a.networkRuleSetProps, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	namespace, err := resourceID.Component("namespaces")
	if err != nil {
		return nil, err
	}
	client, err := armeventhub.NewNamespacesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	resp, err := client.GetNetworkRuleSet(ctx, resourceID.ResourceGroup, namespace, nil)
	if err != nil {
		return nil, err
	}
	a.networkRuleSetProps = resp.NetworkRuleSet.Properties
	a.networkRuleSetFetched.Store(true)
	return a.networkRuleSetProps, nil
}

type mqlAzureSubscriptionEventHubServiceNamespaceNetworkRulesVirtualNetworkRuleInternal struct {
	cacheSubnetID string
}

func (a *mqlAzureSubscriptionEventHubServiceNamespaceNetworkRulesVirtualNetworkRule) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.cacheSubnetID == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceSubnet,
		map[string]*llx.RawData{"id": llx.StringData(a.cacheSubnetID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}
