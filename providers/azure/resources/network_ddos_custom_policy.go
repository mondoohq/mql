// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

const ddosCustomPolicyReadPermission = "Microsoft.Network/ddosCustomPolicies/read"

type mqlAzureSubscriptionNetworkServiceDdosCustomPolicyInternal struct {
	cacheMitigationRules []*network.DdosMitigationRule
	cachePublicIpIds     []string
}

type mqlAzureSubscriptionNetworkServiceDdosCustomPolicyMitigationRuleInternal struct {
	cacheSourcePolicyOverrides []*network.DdosSourcePolicyOverride
}

func (a *mqlAzureSubscriptionNetworkService) ddosCustomPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	client, err := network.NewDdosCustomPoliciesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, ddosCustomPolicyReadPermission)
		}
		for _, policy := range page.Value {
			if policy == nil {
				continue
			}
			mqlPolicy, err := ddosCustomPolicyToMql(a.MqlRuntime, policy)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
	}
	return res, nil
}

func ddosCustomPolicyToMql(runtime *plugin.Runtime, policy *network.DdosCustomPolicy) (*mqlAzureSubscriptionNetworkServiceDdosCustomPolicy, error) {
	props := orZero(policy.Properties)
	res, err := CreateResource(runtime, ResourceAzureSubscriptionNetworkServiceDdosCustomPolicy,
		map[string]*llx.RawData{
			"id":                llx.StringDataPtr(policy.ID),
			"name":              llx.StringDataPtr(policy.Name),
			"location":          llx.StringDataPtr(policy.Location),
			"tags":              llx.MapData(convert.PtrMapStrToInterface(policy.Tags), types.String),
			"type":              llx.StringDataPtr(policy.Type),
			"etag":              llx.StringDataPtr(policy.Etag),
			"provisioningState": llx.StringDataPtr(stringEnumPtr(props.ProvisioningState)),
			"resourceGuid":      llx.StringDataPtr(props.ResourceGUID),
		})
	if err != nil {
		return nil, err
	}
	mqlPolicy := res.(*mqlAzureSubscriptionNetworkServiceDdosCustomPolicy)
	mqlPolicy.cacheMitigationRules = props.MitigationRules
	mqlPolicy.cachePublicIpIds = subResourceIDs(props.PublicIPAddresses)
	return mqlPolicy, nil
}

func (a *mqlAzureSubscriptionNetworkServiceDdosCustomPolicy) id() (string, error) {
	return a.Id.Data, nil
}

// initAzureSubscriptionNetworkServiceDdosCustomPolicy resolves a DDoS custom
// policy by its ARM id, so the references from frontend IP configurations and
// public IP addresses populate fully. A policy in this connection's
// subscription comes out of the subscription-wide list, which one call fills
// for every reference; only a policy in another subscription costs a Get.
func initAzureSubscriptionNetworkServiceDdosCustomPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return nil, nil, missingResourceID(ResourceAzureSubscriptionNetworkServiceDdosCustomPolicy)
	}
	id, ok := args["id"].Value.(string)
	if !ok || id == "" {
		return nil, nil, missingResourceID(ResourceAzureSubscriptionNetworkServiceDdosCustomPolicy)
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("ddosCustomPolicies")
	if err != nil {
		return nil, nil, err
	}

	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceDdosCustomPolicy, id); cached != nil {
		return args, cached, nil
	}
	if policy := lookupInServiceList(runtime, ResourceAzureSubscriptionNetworkService,
		func(s *mqlAzureSubscriptionNetworkService) *plugin.TValue[[]any] { return s.GetDdosCustomPolicies() },
		id); policy != nil {
		return args, policy, nil
	}

	client, err := network.NewDdosCustomPoliciesClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, classifyAzureRefusal(err, ddosCustomPolicyReadPermission)
	}
	res, err := ddosCustomPolicyToMql(runtime, &resp.DdosCustomPolicy)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceDdosCustomPolicy) publicIpAddresses() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceIpAddress, a.cachePublicIpIds)
}

// ddosMitigationRuleValues holds the scalar fields of a mitigation rule, read
// out of the SDK struct with every absent value kept nil.
type ddosMitigationRuleValues struct {
	trafficScope                     *string
	provisioningState                *string
	tcpPerSourceConnectionsPerSecond *int32
	tcpPerSourcePacketsPerSecond     *int32
	udpPerSourcePacketsPerSecond     *int32
}

func ddosMitigationRuleValuesOf(props *network.DdosMitigationRulePropertiesFormat) ddosMitigationRuleValues {
	var v ddosMitigationRuleValues
	if props == nil {
		return v
	}
	v.trafficScope = stringEnumPtr(props.TrafficScope)
	v.provisioningState = stringEnumPtr(props.ProvisioningState)
	if tcp := props.TCPDefaultMitigations; tcp != nil {
		if tcp.PerSourceConnectionRateLimiting != nil {
			v.tcpPerSourceConnectionsPerSecond = tcp.PerSourceConnectionRateLimiting.ConnectionsPerSecond
		}
		if tcp.PerSourceRateLimiting != nil {
			v.tcpPerSourcePacketsPerSecond = tcp.PerSourceRateLimiting.PacketsPerSecond
		}
	}
	if udp := props.UDPDefaultMitigations; udp != nil && udp.PerSourceRateLimiting != nil {
		v.udpPerSourcePacketsPerSecond = udp.PerSourceRateLimiting.PacketsPerSecond
	}
	return v
}

func (a *mqlAzureSubscriptionNetworkServiceDdosCustomPolicy) mitigationRules() ([]any, error) {
	res := []any{}
	for _, rule := range a.cacheMitigationRules {
		if rule == nil {
			continue
		}
		v := ddosMitigationRuleValuesOf(rule.Properties)
		var overrides []*network.DdosSourcePolicyOverride
		if rule.Properties != nil {
			overrides = rule.Properties.SourcePolicyOverrides
		}
		r, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceDdosCustomPolicyMitigationRule,
			map[string]*llx.RawData{
				"__id":                             llx.StringData(subResourceCacheID(rule.ID, a.Id.Data, "mitigationRules", convert.ToValue(rule.Name))),
				"id":                               llx.StringDataPtr(rule.ID),
				"name":                             llx.StringDataPtr(rule.Name),
				"etag":                             llx.StringDataPtr(rule.Etag),
				"trafficScope":                     llx.StringDataPtr(v.trafficScope),
				"provisioningState":                llx.StringDataPtr(v.provisioningState),
				"tcpPerSourceConnectionsPerSecond": llx.IntDataPtr(v.tcpPerSourceConnectionsPerSecond),
				"tcpPerSourcePacketsPerSecond":     llx.IntDataPtr(v.tcpPerSourcePacketsPerSecond),
				"udpPerSourcePacketsPerSecond":     llx.IntDataPtr(v.udpPerSourcePacketsPerSecond),
			})
		if err != nil {
			return nil, err
		}
		mqlRule := r.(*mqlAzureSubscriptionNetworkServiceDdosCustomPolicyMitigationRule)
		mqlRule.cacheSourcePolicyOverrides = overrides
		res = append(res, mqlRule)
	}
	return res, nil
}

// ddosSourceOverrideValues holds an override's action and match conditions.
// The geographic matches are split by kind: each entry names a continent or a
// country, and every entry is an alternative, so two lists say the same thing
// as the SDK's list of pairs.
type ddosSourceOverrideValues struct {
	action       *string
	ipPrefixes   []any
	continents   []any
	countryCodes []any
}

func ddosSourceOverrideValuesOf(o *network.DdosSourcePolicyOverride) ddosSourceOverrideValues {
	v := ddosSourceOverrideValues{
		ipPrefixes:   []any{},
		continents:   []any{},
		countryCodes: []any{},
	}
	if o == nil {
		return v
	}
	if o.PolicyAction != nil {
		v.action = stringEnumPtr(o.PolicyAction.ActionType)
	}
	if c := o.Conditions; c != nil {
		v.ipPrefixes = strPtrsToAny(c.IPPrefixes)
		for _, g := range c.GeoMatches {
			if g == nil {
				continue
			}
			if g.Continent != nil && *g.Continent != "" {
				v.continents = append(v.continents, string(*g.Continent))
			}
			if g.CountryCode != nil && *g.CountryCode != "" {
				v.countryCodes = append(v.countryCodes, *g.CountryCode)
			}
		}
	}
	return v
}

func (a *mqlAzureSubscriptionNetworkServiceDdosCustomPolicyMitigationRule) sourcePolicyOverrides() ([]any, error) {
	res := []any{}
	for i, o := range a.cacheSourcePolicyOverrides {
		if o == nil {
			continue
		}
		v := ddosSourceOverrideValuesOf(o)
		r, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceDdosCustomPolicySourcePolicyOverride,
			map[string]*llx.RawData{
				"__id":         llx.StringData(a.__id + "/sourcePolicyOverrides/" + strconv.Itoa(i)),
				"action":       llx.StringDataPtr(v.action),
				"ipPrefixes":   llx.ArrayData(v.ipPrefixes, types.String),
				"continents":   llx.ArrayData(v.continents, types.String),
				"countryCodes": llx.ArrayData(v.countryCodes, types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// ddosCustomPolicyRef resolves the DDoS custom policy an ARM id names, or
// marks the field null when there is none.
func ddosCustomPolicyRef(runtime *plugin.Runtime, id *string, field *plugin.TValue[*mqlAzureSubscriptionNetworkServiceDdosCustomPolicy]) (*mqlAzureSubscriptionNetworkServiceDdosCustomPolicy, error) {
	if id == nil || *id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(runtime, ResourceAzureSubscriptionNetworkServiceDdosCustomPolicy, map[string]*llx.RawData{
		"id": llx.StringData(*id),
	})
	if err != nil {
		return nil, fmt.Errorf("could not resolve DDoS custom policy %q: %w", *id, err)
	}
	return r.(*mqlAzureSubscriptionNetworkServiceDdosCustomPolicy), nil
}

func (a *mqlAzureSubscriptionNetworkServiceFrontendIpConfig) ddosCustomPolicy() (*mqlAzureSubscriptionNetworkServiceDdosCustomPolicy, error) {
	return ddosCustomPolicyRef(a.MqlRuntime, a.cacheDdosCustomPolicyID, &a.DdosCustomPolicy)
}

func (a *mqlAzureSubscriptionNetworkServiceIpAddress) ddosCustomPolicy() (*mqlAzureSubscriptionNetworkServiceDdosCustomPolicy, error) {
	return ddosCustomPolicyRef(a.MqlRuntime, a.cacheDdosCustomPolicyID, &a.DdosCustomPolicy)
}
