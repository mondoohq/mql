// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	eventgrid "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid/v2"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// Constructed inline at each call site so the permissions extractor, which
// tracks client variables per function body, records the Microsoft.EventGrid
// reads in azure.permissions.json.

// eventSubscriptionDestination reduces a polymorphic destination to the two
// things an audit asks: what kind of sink it is, and where it points. For a
// webhook the endpoint is the base URL, which Azure returns without the query
// string that carries the webhook's secret; for the Azure-native sinks it is the
// sink's ARM resource ID.
func eventSubscriptionDestination(dest eventgrid.EventSubscriptionDestinationClassification) (kind string, endpoint string) {
	if dest == nil {
		return "", ""
	}
	base := dest.GetEventSubscriptionDestination()
	if base != nil && base.EndpointType != nil {
		kind = string(*base.EndpointType)
	}

	switch d := dest.(type) {
	case *eventgrid.WebHookEventSubscriptionDestination:
		if d.Properties != nil {
			// EndpointBaseURL is the URL with the secret query string removed.
			// EndpointURL itself is write-only and comes back nil on a read.
			endpoint = convert.ToValue(d.Properties.EndpointBaseURL)
		}
	case *eventgrid.EventHubEventSubscriptionDestination:
		if d.Properties != nil {
			endpoint = convert.ToValue(d.Properties.ResourceID)
		}
	case *eventgrid.StorageQueueEventSubscriptionDestination:
		if d.Properties != nil {
			endpoint = convert.ToValue(d.Properties.ResourceID)
		}
	case *eventgrid.ServiceBusQueueEventSubscriptionDestination:
		if d.Properties != nil {
			endpoint = convert.ToValue(d.Properties.ResourceID)
		}
	case *eventgrid.ServiceBusTopicEventSubscriptionDestination:
		if d.Properties != nil {
			endpoint = convert.ToValue(d.Properties.ResourceID)
		}
	case *eventgrid.AzureFunctionEventSubscriptionDestination:
		if d.Properties != nil {
			endpoint = convert.ToValue(d.Properties.ResourceID)
		}
	case *eventgrid.HybridConnectionEventSubscriptionDestination:
		if d.Properties != nil {
			endpoint = convert.ToValue(d.Properties.ResourceID)
		}
	case *eventgrid.NamespaceTopicEventSubscriptionDestination:
		if d.Properties != nil {
			endpoint = convert.ToValue(d.Properties.ResourceID)
		}
	case *eventgrid.MonitorAlertEventSubscriptionDestination:
		// A monitor alert has no single resource target; the action groups it
		// notifies are carried in its own properties.
		endpoint = ""
	}
	return kind, endpoint
}

// newMqlEventSubscription maps one event subscription. Shared by the topic,
// system topic and domain accessors, which differ only in which client lists
// them.
func newMqlEventSubscription(runtime *plugin.Runtime, sub *eventgrid.EventSubscription) (plugin.Resource, error) {
	var provisioningState, topicID, eventDeliverySchema string
	destinationType, destinationEndpoint := "", ""
	deliveryWithResourceIdentity := false
	filter := map[string]any{}
	retryPolicy := map[string]any{}
	deadLetter := map[string]any{}
	labels := []any{}
	var expiration *time.Time

	if props := sub.Properties; props != nil {
		provisioningState = string(convert.ToValue(props.ProvisioningState))
		topicID = convert.ToValue(props.Topic)
		eventDeliverySchema = string(convert.ToValue(props.EventDeliverySchema))
		expiration = props.ExpirationTimeUTC

		// A subscription delivers either with a managed identity or with the
		// destination's own credential; only one of the two blocks is set.
		if dwi := props.DeliveryWithResourceIdentity; dwi != nil {
			deliveryWithResourceIdentity = true
			destinationType, destinationEndpoint = eventSubscriptionDestination(dwi.Destination)
		} else {
			destinationType, destinationEndpoint = eventSubscriptionDestination(props.Destination)
		}

		if props.Filter != nil {
			d, err := convert.JsonToDict(props.Filter)
			if err != nil {
				return nil, err
			}
			filter = d
		}
		if props.RetryPolicy != nil {
			d, err := convert.JsonToDict(props.RetryPolicy)
			if err != nil {
				return nil, err
			}
			retryPolicy = d
		}
		if props.DeadLetterDestination != nil {
			d, err := convert.JsonToDict(props.DeadLetterDestination)
			if err != nil {
				return nil, err
			}
			deadLetter = d
		}
		for _, l := range props.Labels {
			if l != nil {
				labels = append(labels, *l)
			}
		}
	}

	return CreateResource(runtime, "azure.subscription.eventGridService.eventSubscription",
		map[string]*llx.RawData{
			"__id":                         llx.StringDataPtr(sub.ID),
			"id":                           llx.StringDataPtr(sub.ID),
			"name":                         llx.StringDataPtr(sub.Name),
			"provisioningState":            llx.StringData(provisioningState),
			"topicId":                      llx.StringData(topicID),
			"destinationType":              llx.StringData(destinationType),
			"destinationEndpoint":          llx.StringData(destinationEndpoint),
			"deliveryWithResourceIdentity": llx.BoolData(deliveryWithResourceIdentity),
			"eventDeliverySchema":          llx.StringData(eventDeliverySchema),
			"filter":                       llx.DictData(filter),
			"retryPolicy":                  llx.DictData(retryPolicy),
			"deadLetterDestination":        llx.DictData(deadLetter),
			"labels":                       llx.ArrayData(labels, types.String),
			"expirationTimeUtc":            llx.TimeDataPtr(expiration),
		})
}

func (a *mqlAzureSubscriptionEventGridServiceTopic) eventSubscriptions() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	topicName, err := resourceID.Component("topics")
	if err != nil {
		return nil, err
	}
	factory, err := eventgrid.NewClientFactory(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := factory.NewTopicEventSubscriptionsClient().NewListPager(resourceID.ResourceGroup, topicName,
		&eventgrid.TopicEventSubscriptionsClientListOptions{})
	return collectEventSubscriptions(ctx, a.MqlRuntime, func() ([]*eventgrid.EventSubscription, bool, error) {
		if !pager.More() {
			return nil, false, nil
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, false, err
		}
		return page.Value, true, nil
	})
}

func (a *mqlAzureSubscriptionEventGridServiceSystemTopic) eventSubscriptions() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	topicName, err := resourceID.Component("systemTopics")
	if err != nil {
		return nil, err
	}
	factory, err := eventgrid.NewClientFactory(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := factory.NewSystemTopicEventSubscriptionsClient().NewListBySystemTopicPager(resourceID.ResourceGroup, topicName,
		&eventgrid.SystemTopicEventSubscriptionsClientListBySystemTopicOptions{})
	return collectEventSubscriptions(ctx, a.MqlRuntime, func() ([]*eventgrid.EventSubscription, bool, error) {
		if !pager.More() {
			return nil, false, nil
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, false, err
		}
		return page.Value, true, nil
	})
}

func (a *mqlAzureSubscriptionEventGridServiceDomain) eventSubscriptions() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	domainName, err := resourceID.Component("domains")
	if err != nil {
		return nil, err
	}
	factory, err := eventgrid.NewClientFactory(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := factory.NewDomainEventSubscriptionsClient().NewListPager(resourceID.ResourceGroup, domainName,
		&eventgrid.DomainEventSubscriptionsClientListOptions{})
	return collectEventSubscriptions(ctx, a.MqlRuntime, func() ([]*eventgrid.EventSubscription, bool, error) {
		if !pager.More() {
			return nil, false, nil
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, false, err
		}
		return page.Value, true, nil
	})
}

// collectEventSubscriptions drains a page-producing function into mapped
// resources. The three listings above use three distinct SDK client types with
// no shared interface, so the pager is passed in as a closure rather than
// duplicating the mapping loop three times.
func collectEventSubscriptions(ctx context.Context, runtime *plugin.Runtime, nextPage func() ([]*eventgrid.EventSubscription, bool, error)) ([]any, error) {
	res := []any{}
	for {
		values, more, err := nextPage()
		if err != nil {
			return nil, err
		}
		if !more {
			return res, nil
		}
		for _, sub := range values {
			if sub == nil {
				continue
			}
			mqlSub, err := newMqlEventSubscription(runtime, sub)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSub)
		}
	}
}

func (a *mqlAzureSubscriptionEventGridService) namespaces() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	factory, err := eventgrid.NewClientFactory(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := factory.NewNamespacesClient().NewListBySubscriptionPager(&eventgrid.NamespacesClientListBySubscriptionOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ns := range page.Value {
			if ns == nil {
				continue
			}

			var skuName string
			var skuCapacity *int64
			if ns.SKU != nil {
				skuName = string(convert.ToValue(ns.SKU.Name))
				if ns.SKU.Capacity != nil {
					v := int64(*ns.SKU.Capacity)
					skuCapacity = &v
				}
			}

			var provisioningState, publicNetworkAccess, minTLS, topicSpacesState string
			var topicSpacesHostname, routeTopicResourceID string
			isZoneRedundant := false
			inboundIPRules := []any{}
			inboundIPAllowRules := []any{}
			var maxSessions, maxSessionExpiry *int64

			if props := ns.Properties; props != nil {
				provisioningState = string(convert.ToValue(props.ProvisioningState))
				publicNetworkAccess = string(convert.ToValue(props.PublicNetworkAccess))
				minTLS = string(convert.ToValue(props.MinimumTLSVersionAllowed))
				isZoneRedundant = convert.ToValue(props.IsZoneRedundant)

				inboundIPAllowRules, err = eventGridInboundIpRulesToMql(a.MqlRuntime, convert.ToValue(ns.ID), props.InboundIPRules)
				if err != nil {
					return nil, err
				}
				for _, rule := range props.InboundIPRules {
					if rule == nil {
						continue
					}
					d, err := convert.JsonToDict(rule)
					if err != nil {
						return nil, err
					}
					inboundIPRules = append(inboundIPRules, d)
				}

				if ts := props.TopicSpacesConfiguration; ts != nil {
					topicSpacesState = string(convert.ToValue(ts.State))
					topicSpacesHostname = convert.ToValue(ts.Hostname)
					routeTopicResourceID = convert.ToValue(ts.RouteTopicResourceID)
					if ts.MaximumClientSessionsPerAuthenticationName != nil {
						v := int64(*ts.MaximumClientSessionsPerAuthenticationName)
						maxSessions = &v
					}
					if ts.MaximumSessionExpiryInHours != nil {
						v := int64(*ts.MaximumSessionExpiryInHours)
						maxSessionExpiry = &v
					}
				}
			}

			var identityType string
			if ns.Identity != nil {
				identityType = string(convert.ToValue(ns.Identity.Type))
			}

			mqlNs, err := CreateResource(a.MqlRuntime, "azure.subscription.eventGridService.namespace",
				map[string]*llx.RawData{
					"__id":                     llx.StringDataPtr(ns.ID),
					"id":                       llx.StringDataPtr(ns.ID),
					"name":                     llx.StringDataPtr(ns.Name),
					"location":                 llx.StringDataPtr(ns.Location),
					"tags":                     llx.MapData(convert.PtrMapStrToInterface(ns.Tags), types.String),
					"skuName":                  llx.StringData(skuName),
					"skuCapacity":              llx.IntDataPtr(skuCapacity),
					"provisioningState":        llx.StringData(provisioningState),
					"publicNetworkAccess":      llx.StringData(publicNetworkAccess),
					"minimumTlsVersionAllowed": llx.StringData(minTLS),
					"inboundIpRules":           llx.ArrayData(inboundIPRules, types.Dict),
					"inboundIpAllowRules":      llx.ArrayData(inboundIPAllowRules, types.Resource("azure.subscription.eventGridService.inboundIpRule")),
					"topicSpacesState":         llx.StringData(topicSpacesState),
					"topicSpacesHostname":      llx.StringData(topicSpacesHostname),
					"routeTopicResourceId":     llx.StringData(routeTopicResourceID),
					"maximumClientSessionsPerAuthenticationName": llx.IntDataPtr(maxSessions),
					"maximumSessionExpiryInHours":                llx.IntDataPtr(maxSessionExpiry),
					"isZoneRedundant":                            llx.BoolData(isZoneRedundant),
					"identityType":                               llx.StringData(identityType),
				})
			if err != nil {
				return nil, err
			}

			sysData, err := convert.JsonToDict(ns.SystemData)
			if err != nil {
				return nil, err
			}
			mqlNs.(*mqlAzureSubscriptionEventGridServiceNamespace).cacheSystemData = sysData
			res = append(res, mqlNs)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionEventGridServiceNamespaceInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionEventGridServiceNamespace) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.__id, a.cacheSystemData, &a.SystemMetadata)
}
