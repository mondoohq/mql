// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	eventgrid "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid/v2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionEventGridService) id() (string, error) {
	return "azure.subscription.eventGrid/" + a.SubscriptionId.Data, nil
}

type mqlAzureSubscriptionEventGridServiceTopicInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionEventGridServiceSystemTopicInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionEventGridServiceDomainInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionEventGridServiceTopic) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionEventGridServiceTopic) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionEventGridServiceSystemTopic) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionEventGridServiceDomain) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionEventGridServiceSystemTopic) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionEventGridServiceDomain) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionEventGridService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func eventGridIpRulesToDict(rules []*eventgrid.InboundIPRule) []any {
	out := []any{}
	for _, r := range rules {
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
		out = append(out, entry)
	}
	return out
}

// eventGridInboundIpRulesToMql maps the firewall entries of an Event Grid
// resource onto their own rows.
//
// The rules only take effect while public network access is enabled, so an
// empty list on a topic that is publicly reachable is the finding, not a
// missing reading.
func eventGridInboundIpRulesToMql(runtime *plugin.Runtime, parentID string, rules []*eventgrid.InboundIPRule) ([]any, error) {
	const resourceName = "azure.subscription.eventGridService.inboundIpRule"
	out := []any{}
	for i, r := range rules {
		if r == nil {
			continue
		}
		// The address range keys the rule; the position covers a rule the
		// service returned without one.
		key := convert.ToValue(r.IPMask)
		if key == "" {
			key = strconv.Itoa(i)
		}
		res, err := CreateResource(runtime, resourceName, map[string]*llx.RawData{
			"__id":   llx.StringData(subResourceCacheID(nil, parentID, "inboundIpRules", key)),
			"ipMask": llx.StringDataPtr(r.IPMask),
			"action": llx.StringDataPtr(stringEnumPtr(r.Action)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func eventGridIdentityType(identity *eventgrid.IdentityInfo) string {
	if identity == nil || identity.Type == nil {
		return ""
	}
	return string(*identity.Type)
}

func (a *mqlAzureSubscriptionEventGridService) topics() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := eventgrid.NewTopicsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list azure topics, returning partial results")
				return res, nil
			}
			return nil, err
		}
		for _, t := range page.Value {
			if t == nil {
				continue
			}
			var (
				provisioningState        string
				endpoint                 string
				metricResourceId         string
				disableLocalAuth         bool
				publicNetworkAccess      string
				inputSchema              string
				minimumTlsVersionAllowed string
				dataResidencyBoundary    string
				inboundIpRules           []any
				inboundIpAllowRules      = []any{}
				privateEndpointCount     int64
			)
			if p := t.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				if p.Endpoint != nil {
					endpoint = *p.Endpoint
				}
				if p.MetricResourceID != nil {
					metricResourceId = *p.MetricResourceID
				}
				if p.DisableLocalAuth != nil {
					disableLocalAuth = *p.DisableLocalAuth
				}
				if p.PublicNetworkAccess != nil {
					publicNetworkAccess = string(*p.PublicNetworkAccess)
				}
				if p.InputSchema != nil {
					inputSchema = string(*p.InputSchema)
				}
				if p.MinimumTLSVersionAllowed != nil {
					minimumTlsVersionAllowed = string(*p.MinimumTLSVersionAllowed)
				}
				if p.DataResidencyBoundary != nil {
					dataResidencyBoundary = string(*p.DataResidencyBoundary)
				}
				inboundIpRules = eventGridIpRulesToDict(p.InboundIPRules)
				inboundIpAllowRules, err = eventGridInboundIpRulesToMql(a.MqlRuntime, convert.ToValue(t.ID), p.InboundIPRules)
				if err != nil {
					return nil, err
				}
				privateEndpointCount = int64(len(p.PrivateEndpointConnections))
			}

			mqlTopic, err := CreateResource(a.MqlRuntime, "azure.subscription.eventGridService.topic",
				map[string]*llx.RawData{
					"id":                             llx.StringDataPtr(t.ID),
					"name":                           llx.StringDataPtr(t.Name),
					"location":                       llx.StringDataPtr(t.Location),
					"tags":                           llx.MapData(convert.PtrMapStrToInterface(t.Tags), types.String),
					"provisioningState":              llx.StringData(provisioningState),
					"endpoint":                       llx.StringData(endpoint),
					"metricResourceId":               llx.StringData(metricResourceId),
					"disableLocalAuth":               llx.BoolData(disableLocalAuth),
					"publicNetworkAccess":            llx.StringData(publicNetworkAccess),
					"inputSchema":                    llx.StringData(inputSchema),
					"minimumTlsVersionAllowed":       llx.StringData(minimumTlsVersionAllowed),
					"dataResidencyBoundary":          llx.StringData(dataResidencyBoundary),
					"inboundIpRules":                 llx.ArrayData(inboundIpRules, types.Dict),
					"inboundIpAllowRules":            llx.ArrayData(inboundIpAllowRules, types.Resource("azure.subscription.eventGridService.inboundIpRule")),
					"identityType":                   llx.StringData(eventGridIdentityType(t.Identity)),
					"privateEndpointConnectionCount": llx.IntData(privateEndpointCount),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(t.SystemData)
			if err != nil {
				return nil, err
			}
			mqlTopic.(*mqlAzureSubscriptionEventGridServiceTopic).cacheSystemData = sysData
			res = append(res, mqlTopic)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionEventGridService) systemTopics() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := eventgrid.NewSystemTopicsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list azure systemTopics, returning partial results")
				return res, nil
			}
			return nil, err
		}
		for _, st := range page.Value {
			if st == nil {
				continue
			}
			var provisioningState, source, topicType, metricResourceId string
			if p := st.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				if p.Source != nil {
					source = *p.Source
				}
				if p.TopicType != nil {
					topicType = *p.TopicType
				}
				if p.MetricResourceID != nil {
					metricResourceId = *p.MetricResourceID
				}
			}
			mqlSt, err := CreateResource(a.MqlRuntime, "azure.subscription.eventGridService.systemTopic",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(st.ID),
					"name":              llx.StringDataPtr(st.Name),
					"location":          llx.StringDataPtr(st.Location),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(st.Tags), types.String),
					"provisioningState": llx.StringData(provisioningState),
					"source":            llx.StringData(source),
					"topicType":         llx.StringData(topicType),
					"metricResourceId":  llx.StringData(metricResourceId),
					"identityType":      llx.StringData(eventGridIdentityType(st.Identity)),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(st.SystemData)
			if err != nil {
				return nil, err
			}
			mqlSt.(*mqlAzureSubscriptionEventGridServiceSystemTopic).cacheSystemData = sysData
			res = append(res, mqlSt)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionEventGridService) domains() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := eventgrid.NewDomainsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list azure domains, returning partial results")
				return res, nil
			}
			return nil, err
		}
		for _, d := range page.Value {
			if d == nil {
				continue
			}
			var (
				provisioningState                    string
				endpoint                             string
				metricResourceId                     string
				disableLocalAuth                     bool
				publicNetworkAccess                  string
				inputSchema                          string
				minimumTlsVersionAllowed             string
				dataResidencyBoundary                string
				autoCreateTopicWithFirstSubscription bool
				autoDeleteTopicWithLastSubscription  bool
				inboundIpRules                       []any
				inboundIpAllowRules                  = []any{}
				privateEndpointCount                 int64
			)
			if p := d.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				if p.Endpoint != nil {
					endpoint = *p.Endpoint
				}
				if p.MetricResourceID != nil {
					metricResourceId = *p.MetricResourceID
				}
				if p.DisableLocalAuth != nil {
					disableLocalAuth = *p.DisableLocalAuth
				}
				if p.PublicNetworkAccess != nil {
					publicNetworkAccess = string(*p.PublicNetworkAccess)
				}
				if p.InputSchema != nil {
					inputSchema = string(*p.InputSchema)
				}
				if p.MinimumTLSVersionAllowed != nil {
					minimumTlsVersionAllowed = string(*p.MinimumTLSVersionAllowed)
				}
				if p.DataResidencyBoundary != nil {
					dataResidencyBoundary = string(*p.DataResidencyBoundary)
				}
				if p.AutoCreateTopicWithFirstSubscription != nil {
					autoCreateTopicWithFirstSubscription = *p.AutoCreateTopicWithFirstSubscription
				}
				if p.AutoDeleteTopicWithLastSubscription != nil {
					autoDeleteTopicWithLastSubscription = *p.AutoDeleteTopicWithLastSubscription
				}
				inboundIpRules = eventGridIpRulesToDict(p.InboundIPRules)
				inboundIpAllowRules, err = eventGridInboundIpRulesToMql(a.MqlRuntime, convert.ToValue(d.ID), p.InboundIPRules)
				if err != nil {
					return nil, err
				}
				privateEndpointCount = int64(len(p.PrivateEndpointConnections))
			}

			mqlDomain, err := CreateResource(a.MqlRuntime, "azure.subscription.eventGridService.domain",
				map[string]*llx.RawData{
					"id":                                   llx.StringDataPtr(d.ID),
					"name":                                 llx.StringDataPtr(d.Name),
					"location":                             llx.StringDataPtr(d.Location),
					"tags":                                 llx.MapData(convert.PtrMapStrToInterface(d.Tags), types.String),
					"provisioningState":                    llx.StringData(provisioningState),
					"endpoint":                             llx.StringData(endpoint),
					"metricResourceId":                     llx.StringData(metricResourceId),
					"disableLocalAuth":                     llx.BoolData(disableLocalAuth),
					"publicNetworkAccess":                  llx.StringData(publicNetworkAccess),
					"inputSchema":                          llx.StringData(inputSchema),
					"minimumTlsVersionAllowed":             llx.StringData(minimumTlsVersionAllowed),
					"dataResidencyBoundary":                llx.StringData(dataResidencyBoundary),
					"autoCreateTopicWithFirstSubscription": llx.BoolData(autoCreateTopicWithFirstSubscription),
					"autoDeleteTopicWithLastSubscription":  llx.BoolData(autoDeleteTopicWithLastSubscription),
					"inboundIpRules":                       llx.ArrayData(inboundIpRules, types.Dict),
					"inboundIpAllowRules":                  llx.ArrayData(inboundIpAllowRules, types.Resource("azure.subscription.eventGridService.inboundIpRule")),
					"identityType":                         llx.StringData(eventGridIdentityType(d.Identity)),
					"privateEndpointConnectionCount":       llx.IntData(privateEndpointCount),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(d.SystemData)
			if err != nil {
				return nil, err
			}
			mqlDomain.(*mqlAzureSubscriptionEventGridServiceDomain).cacheSystemData = sysData
			res = append(res, mqlDomain)
		}
	}
	return res, nil
}
