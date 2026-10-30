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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionServiceBusServiceNamespaceInternal struct {
	networkRuleSetFetched           atomic.Bool
	networkRuleSetProps             *armservicebus.NetworkRuleSetProperties
	networkRuleSetLock              sync.Mutex
	cacheSystemData                 any
	cachePrivateEndpointConnections []*armservicebus.PrivateEndpointConnection
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespace) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}

type mqlAzureSubscriptionServiceBusServiceNamespaceQueueInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionServiceBusServiceNamespaceTopicInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionServiceBusServiceNamespaceTopicSubscriptionInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionServiceBusServiceAuthorizationRuleInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionServiceBusServiceAuthorizationRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionServiceBusServiceAuthorizationRule) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// serviceBusAuthorizationRulesToMql maps a list of Service Bus SAS authorization rules
// (from a namespace, queue, or topic) to the shared authorizationRule resource.
func serviceBusAuthorizationRulesToMql(runtime *plugin.Runtime, rules []*armservicebus.SBAuthorizationRule) ([]any, error) {
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
		mqlRule, err := CreateResource(runtime, "azure.subscription.serviceBusService.authorizationRule", map[string]*llx.RawData{
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
		mqlRule.(*mqlAzureSubscriptionServiceBusServiceAuthorizationRule).cacheSystemData = sysData
		res = append(res, mqlRule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespace) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespaceQueue) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespaceTopic) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespaceTopicSubscription) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionServiceBusService) id() (string, error) {
	return "azure.subscription.serviceBus/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionServiceBusService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionServiceBusServiceNamespace) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespaceQueue) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespaceTopic) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespaceTopicSubscription) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionServiceBusService) namespaces() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := armservicebus.NewNamespacesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	var res []any

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ns := range page.Value {
			if ns == nil {
				continue
			}

			sku, err := convert.JsonToDict(ns.SKU)
			if err != nil {
				return nil, err
			}

			var status, serviceBusEndpoint, provisioningState, cmkKeySource string
			var disableLocalAuth, zoneRedundant bool
			var requireInfraEnc *bool
			var cmkKeys []any
			var creationTime, updatedAt *time.Time
			var alternateName, metricId *string
			if ns.Properties != nil {
				creationTime = ns.Properties.CreatedAt
				updatedAt = ns.Properties.UpdatedAt
				alternateName = ns.Properties.AlternateName
				metricId = ns.Properties.MetricID
				if ns.Properties.Status != nil {
					status = *ns.Properties.Status
				}
				if ns.Properties.ServiceBusEndpoint != nil {
					serviceBusEndpoint = *ns.Properties.ServiceBusEndpoint
				}
				if ns.Properties.DisableLocalAuth != nil {
					disableLocalAuth = *ns.Properties.DisableLocalAuth
				}
				if ns.Properties.ZoneRedundant != nil {
					zoneRedundant = *ns.Properties.ZoneRedundant
				}
				if ns.Properties.ProvisioningState != nil {
					provisioningState = *ns.Properties.ProvisioningState
				}
				if enc := ns.Properties.Encryption; enc != nil {
					if enc.KeySource != nil {
						cmkKeySource = *enc.KeySource
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
				"serviceBusEndpoint":              llx.StringData(serviceBusEndpoint),
				"disableLocalAuth":                llx.BoolData(disableLocalAuth),
				"zoneRedundant":                   llx.BoolData(zoneRedundant),
				"provisioningState":               llx.StringData(provisioningState),
				"cmkKeySource":                    llx.StringData(cmkKeySource),
				"requireInfrastructureEncryption": llx.BoolDataPtr(requireInfraEnc),
				"cmkKeys":                         llx.ArrayData(cmkKeys, types.Dict),
				"creationTime":                    llx.TimeDataPtr(creationTime),
				"alternateName":                   llx.StringDataPtr(alternateName),
				"metricId":                        llx.StringDataPtr(metricId),
				"updatedAt":                       llx.TimeDataPtr(updatedAt),
			}
			nsSku := orZero(ns.SKU)
			if err := setSkuData(a.MqlRuntime, args, skuName(nsSku.Name), skuTier(nsSku.Tier), skuCapacity(nsSku.Capacity)); err != nil {
				return nil, err
			}

			mqlNs, err := CreateResource(a.MqlRuntime, "azure.subscription.serviceBusService.namespace", args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(ns.SystemData)
			if err != nil {
				return nil, err
			}
			mqlNsRes := mqlNs.(*mqlAzureSubscriptionServiceBusServiceNamespace)
			mqlNsRes.cacheSystemData = sysData
			if ns.Properties != nil {
				mqlNsRes.cachePrivateEndpointConnections = ns.Properties.PrivateEndpointConnections
			}
			res = append(res, mqlNs)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespace) queues() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	nsName := a.Name.Data

	client, err := armservicebus.NewQueuesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListByNamespacePager(resourceID.ResourceGroup, nsName, nil)
	var res []any

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, q := range page.Value {
			if q == nil {
				continue
			}

			var status string
			var maxSizeInMegabytes, maxDeliveryCount int64
			var messageCount, deadLetterMessageCount int64
			var lockDuration, defaultMessageTimeToLive string
			var requiresDuplicateDetection, requiresSession, enablePartitioning bool
			var creationTime *time.Time
			if q.Properties != nil {
				creationTime = q.Properties.CreatedAt
				if q.Properties.Status != nil {
					status = string(*q.Properties.Status)
				}
				if q.Properties.MaxSizeInMegabytes != nil {
					maxSizeInMegabytes = int64(*q.Properties.MaxSizeInMegabytes)
				}
				if q.Properties.MessageCount != nil {
					messageCount = *q.Properties.MessageCount
				}
				if q.Properties.CountDetails != nil && q.Properties.CountDetails.DeadLetterMessageCount != nil {
					deadLetterMessageCount = *q.Properties.CountDetails.DeadLetterMessageCount
				}
				if q.Properties.MaxDeliveryCount != nil {
					maxDeliveryCount = int64(*q.Properties.MaxDeliveryCount)
				}
				if q.Properties.LockDuration != nil {
					lockDuration = *q.Properties.LockDuration
				}
				if q.Properties.DefaultMessageTimeToLive != nil {
					defaultMessageTimeToLive = *q.Properties.DefaultMessageTimeToLive
				}
				if q.Properties.RequiresDuplicateDetection != nil {
					requiresDuplicateDetection = *q.Properties.RequiresDuplicateDetection
				}
				if q.Properties.RequiresSession != nil {
					requiresSession = *q.Properties.RequiresSession
				}
				if q.Properties.EnablePartitioning != nil {
					enablePartitioning = *q.Properties.EnablePartitioning
				}
			}

			mqlQueue, err := CreateResource(a.MqlRuntime, "azure.subscription.serviceBusService.namespace.queue", map[string]*llx.RawData{
				"id":                         llx.StringDataPtr(q.ID),
				"name":                       llx.StringDataPtr(q.Name),
				"status":                     llx.StringData(status),
				"maxSizeInMegabytes":         llx.IntData(maxSizeInMegabytes),
				"messageCount":               llx.IntData(messageCount),
				"deadLetterMessageCount":     llx.IntData(deadLetterMessageCount),
				"maxDeliveryCount":           llx.IntData(maxDeliveryCount),
				"lockDuration":               llx.StringData(lockDuration),
				"defaultMessageTimeToLive":   llx.StringData(defaultMessageTimeToLive),
				"requiresDuplicateDetection": llx.BoolData(requiresDuplicateDetection),
				"requiresSession":            llx.BoolData(requiresSession),
				"enablePartitioning":         llx.BoolData(enablePartitioning),
				"creationTime":               llx.TimeDataPtr(creationTime),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(q.SystemData)
			if err != nil {
				return nil, err
			}
			mqlQueue.(*mqlAzureSubscriptionServiceBusServiceNamespaceQueue).cacheSystemData = sysData
			res = append(res, mqlQueue)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespace) topics() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	nsName := a.Name.Data

	client, err := armservicebus.NewTopicsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListByNamespacePager(resourceID.ResourceGroup, nsName, nil)
	var res []any

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range page.Value {
			if t == nil {
				continue
			}

			var status string
			var maxSizeInMegabytes int64
			var subscriptionCount int64
			var enablePartitioning, supportOrdering, requiresDuplicateDetection bool
			var defaultMessageTimeToLive string
			var creationTime *time.Time
			if t.Properties != nil {
				creationTime = t.Properties.CreatedAt
				if t.Properties.Status != nil {
					status = string(*t.Properties.Status)
				}
				if t.Properties.MaxSizeInMegabytes != nil {
					maxSizeInMegabytes = int64(*t.Properties.MaxSizeInMegabytes)
				}
				if t.Properties.SubscriptionCount != nil {
					subscriptionCount = int64(*t.Properties.SubscriptionCount)
				}
				if t.Properties.EnablePartitioning != nil {
					enablePartitioning = *t.Properties.EnablePartitioning
				}
				if t.Properties.SupportOrdering != nil {
					supportOrdering = *t.Properties.SupportOrdering
				}
				if t.Properties.RequiresDuplicateDetection != nil {
					requiresDuplicateDetection = *t.Properties.RequiresDuplicateDetection
				}
				if t.Properties.DefaultMessageTimeToLive != nil {
					defaultMessageTimeToLive = *t.Properties.DefaultMessageTimeToLive
				}
			}

			mqlTopic, err := CreateResource(a.MqlRuntime, "azure.subscription.serviceBusService.namespace.topic", map[string]*llx.RawData{
				"id":                         llx.StringDataPtr(t.ID),
				"name":                       llx.StringDataPtr(t.Name),
				"status":                     llx.StringData(status),
				"maxSizeInMegabytes":         llx.IntData(maxSizeInMegabytes),
				"subscriptionCount":          llx.IntData(subscriptionCount),
				"enablePartitioning":         llx.BoolData(enablePartitioning),
				"supportOrdering":            llx.BoolData(supportOrdering),
				"requiresDuplicateDetection": llx.BoolData(requiresDuplicateDetection),
				"defaultMessageTimeToLive":   llx.StringData(defaultMessageTimeToLive),
				"creationTime":               llx.TimeDataPtr(creationTime),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(t.SystemData)
			if err != nil {
				return nil, err
			}
			mqlTopic.(*mqlAzureSubscriptionServiceBusServiceNamespaceTopic).cacheSystemData = sysData
			res = append(res, mqlTopic)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespaceTopic) subscriptions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	nsName, err := resourceID.Component("namespaces")
	if err != nil {
		return nil, err
	}

	topicName := a.Name.Data

	client, err := armservicebus.NewSubscriptionsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListByTopicPager(resourceID.ResourceGroup, nsName, topicName, nil)
	var res []any

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, sub := range page.Value {
			if sub == nil {
				continue
			}

			var status string
			var messageCount, deadLetterMessageCount int64
			var maxDeliveryCount int64
			var lockDuration, defaultMessageTimeToLive string
			var requiresSession bool
			var creationTime *time.Time
			if sub.Properties != nil {
				creationTime = sub.Properties.CreatedAt
				if sub.Properties.Status != nil {
					status = string(*sub.Properties.Status)
				}
				if sub.Properties.MessageCount != nil {
					messageCount = *sub.Properties.MessageCount
				}
				if sub.Properties.CountDetails != nil && sub.Properties.CountDetails.DeadLetterMessageCount != nil {
					deadLetterMessageCount = *sub.Properties.CountDetails.DeadLetterMessageCount
				}
				if sub.Properties.MaxDeliveryCount != nil {
					maxDeliveryCount = int64(*sub.Properties.MaxDeliveryCount)
				}
				if sub.Properties.LockDuration != nil {
					lockDuration = *sub.Properties.LockDuration
				}
				if sub.Properties.DefaultMessageTimeToLive != nil {
					defaultMessageTimeToLive = *sub.Properties.DefaultMessageTimeToLive
				}
				if sub.Properties.RequiresSession != nil {
					requiresSession = *sub.Properties.RequiresSession
				}
			}

			mqlSub, err := CreateResource(a.MqlRuntime, "azure.subscription.serviceBusService.namespace.topic.subscription", map[string]*llx.RawData{
				"id":                       llx.StringDataPtr(sub.ID),
				"name":                     llx.StringDataPtr(sub.Name),
				"status":                   llx.StringData(status),
				"messageCount":             llx.IntData(messageCount),
				"deadLetterMessageCount":   llx.IntData(deadLetterMessageCount),
				"maxDeliveryCount":         llx.IntData(maxDeliveryCount),
				"lockDuration":             llx.StringData(lockDuration),
				"defaultMessageTimeToLive": llx.StringData(defaultMessageTimeToLive),
				"requiresSession":          llx.BoolData(requiresSession),
				"creationTime":             llx.TimeDataPtr(creationTime),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(sub.SystemData)
			if err != nil {
				return nil, err
			}
			mqlSub.(*mqlAzureSubscriptionServiceBusServiceNamespaceTopicSubscription).cacheSystemData = sysData
			res = append(res, mqlSub)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespace) authorizationRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := armservicebus.NewNamespacesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListAuthorizationRulesPager(resourceID.ResourceGroup, a.Name.Data, nil)
	var rules []*armservicebus.SBAuthorizationRule
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		rules = append(rules, page.Value...)
	}
	return serviceBusAuthorizationRulesToMql(a.MqlRuntime, rules)
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespaceQueue) authorizationRules() ([]any, error) {
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
	client, err := armservicebus.NewQueuesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListAuthorizationRulesPager(resourceID.ResourceGroup, nsName, a.Name.Data, nil)
	var rules []*armservicebus.SBAuthorizationRule
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		rules = append(rules, page.Value...)
	}
	return serviceBusAuthorizationRulesToMql(a.MqlRuntime, rules)
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespaceTopic) authorizationRules() ([]any, error) {
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
	client, err := armservicebus.NewTopicsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListAuthorizationRulesPager(resourceID.ResourceGroup, nsName, a.Name.Data, nil)
	var rules []*armservicebus.SBAuthorizationRule
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		rules = append(rules, page.Value...)
	}
	return serviceBusAuthorizationRulesToMql(a.MqlRuntime, rules)
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespace) networkRules() (*mqlAzureSubscriptionServiceBusServiceNamespaceNetworkRules, error) {
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

	const ipRuleResource = "azure.subscription.serviceBusService.namespace.networkRules.ipRule"
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
		mqlRule, err := CreateResource(a.MqlRuntime, "azure.subscription.serviceBusService.namespace.networkRules.virtualNetworkRule",
			map[string]*llx.RawData{
				"__id":                             llx.StringData(id),
				"ignoreMissingVnetServiceEndpoint": llx.BoolData(ignore),
			})
		if err != nil {
			return nil, err
		}
		mqlRule.(*mqlAzureSubscriptionServiceBusServiceNamespaceNetworkRulesVirtualNetworkRule).cacheSubnetID = subnetID
		vnetRules = append(vnetRules, mqlRule)
	}

	res, err := CreateResource(a.MqlRuntime, "azure.subscription.serviceBusService.namespace.networkRules", map[string]*llx.RawData{
		"__id":                        llx.StringData(a.Id.Data + "/networkRules"),
		"defaultAction":               llx.StringData(defaultAction),
		"publicNetworkAccess":         llx.StringData(publicNetworkAccess),
		"trustedServiceAccessEnabled": llx.BoolData(trustedServiceAccess),
		"ipRules":                     llx.ArrayData(ipRules, types.Dict),
		"ipAllowRules":                llx.ArrayData(ipAllowRules, types.Resource(ipRuleResource)),
		"virtualNetworkRules":         llx.ArrayData(vnetRules, types.Resource("azure.subscription.serviceBusService.namespace.networkRules.virtualNetworkRule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionServiceBusServiceNamespaceNetworkRules), nil
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespace) fetchNetworkRuleSetProperties() (*armservicebus.NetworkRuleSetProperties, error) {
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
	client, err := armservicebus.NewNamespacesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
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

type mqlAzureSubscriptionServiceBusServiceNamespaceNetworkRulesVirtualNetworkRuleInternal struct {
	cacheSubnetID string
}

func (a *mqlAzureSubscriptionServiceBusServiceNamespaceNetworkRulesVirtualNetworkRule) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.cacheSubnetID == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheSubnetID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}
