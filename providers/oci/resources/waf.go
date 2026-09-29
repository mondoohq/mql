// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/waf"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciWaf) id() (string, error) {
	return "oci.waf", nil
}

func (o *mqlOciWaf) firewalls() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci WAF firewalls with region %s", region)

			svc, err := conn.WafClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]waf.WebAppFirewallSummary, *string, error) {
				response, err := svc.ListWebAppFirewalls(ctx, waf.ListWebAppFirewallsRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for _, item := range items {
				// The summary is an interface; we handle the LoadBalancer concrete type
				lbWaf, ok := item.(waf.WebAppFirewallLoadBalancerSummary)
				if !ok {
					continue
				}

				var created *time.Time
				if lbWaf.TimeCreated != nil {
					created = &lbWaf.TimeCreated.Time
				}
				var timeUpdated *time.Time
				if lbWaf.TimeUpdated != nil {
					timeUpdated = &lbWaf.TimeUpdated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.waf.firewall", stringValue(lbWaf.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(lbWaf.Id),
					"name":         llx.StringDataPtr(lbWaf.DisplayName),
					"state":        llx.StringData(string(lbWaf.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"timeUpdated":  llx.TimeDataPtr(timeUpdated),
					"freeformTags": llx.MapData(strMapToAny(lbWaf.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(lbWaf.DefinedTags), types.Any),
					"systemTags":   llx.MapData(definedTagsToAny(lbWaf.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlFw := mqlInstance.(*mqlOciWafFirewall)
				mqlFw.cachePolicyID = stringValue(lbWaf.WebAppFirewallPolicyId)
				mqlFw.cacheLoadBalancerID = stringValue(lbWaf.LoadBalancerId)
				res = append(res, mqlFw)
			}

			return res, nil
		})
}

type mqlOciWafFirewallInternal struct {
	ociCompartmentRef
	cachePolicyID       string
	cacheLoadBalancerID string
}

func (o *mqlOciWafFirewall) id() (string, error) {
	return "oci.waf.firewall/" + o.Id.Data, nil
}

func (o *mqlOciWafFirewall) policy() (*mqlOciWafPolicy, error) {
	if o.cachePolicyID == "" {
		o.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlPolicy, err := NewResource(o.MqlRuntime, "oci.waf.policy", map[string]*llx.RawData{
		"id": llx.StringData(o.cachePolicyID),
	})
	if err != nil {
		return nil, err
	}
	return mqlPolicy.(*mqlOciWafPolicy), nil
}

func (o *mqlOciWafFirewall) loadBalancer() (*mqlOciLoadBalancerLoadBalancer, error) {
	if o.cacheLoadBalancerID == "" {
		o.LoadBalancer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlLb, err := NewResource(o.MqlRuntime, "oci.loadBalancer.loadBalancer", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheLoadBalancerID),
	})
	if err != nil {
		return nil, err
	}
	return mqlLb.(*mqlOciLoadBalancerLoadBalancer), nil
}

func (o *mqlOciWaf) policies() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci WAF policies with region %s", region)

			svc, err := conn.WafClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]waf.WebAppFirewallPolicySummary, *string, error) {
				response, err := svc.ListWebAppFirewallPolicies(ctx, waf.ListWebAppFirewallPoliciesRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range items {
				p := items[i]

				var created *time.Time
				if p.TimeCreated != nil {
					created = &p.TimeCreated.Time
				}
				var timeUpdated *time.Time
				if p.TimeUpdated != nil {
					timeUpdated = &p.TimeUpdated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.waf.policy", stringValue(p.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(p.Id),
					"name":         llx.StringDataPtr(p.DisplayName),
					"state":        llx.StringData(string(p.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"timeUpdated":  llx.TimeDataPtr(timeUpdated),
					"freeformTags": llx.MapData(strMapToAny(p.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(p.DefinedTags), types.Any),
					"systemTags":   llx.MapData(definedTagsToAny(p.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlPolicy := mqlInstance.(*mqlOciWafPolicy)
				mqlPolicy.cacheRegion = region
				res = append(res, mqlPolicy)
			}

			return res, nil
		})
}

func initOciWafPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.waf.policy")
	}

	obj, err := CreateResource(runtime, "oci.waf", nil)
	if err != nil {
		return nil, nil, err
	}
	w := obj.(*mqlOciWaf)

	rawPolicies := w.GetPolicies()
	if rawPolicies.Error != nil {
		return nil, nil, rawPolicies.Error
	}

	for _, raw := range rawPolicies.Data {
		p := raw.(*mqlOciWafPolicy)
		if p.Id.Data == idVal {
			return args, p, nil
		}
	}

	return nil, nil, errors.New("oci.waf.policy not found: " + idVal)
}

func (o *mqlOciWafPolicy) id() (string, error) {
	return "oci.waf.policy/" + o.Id.Data, nil
}

type mqlOciWafPolicyInternal struct {
	ociCompartmentRef
	// WAF policies are regional, so the detail fetch has to go back to the
	// region the policy was listed in.
	cacheRegion string
	detail      ociLazy[*waf.WebAppFirewallPolicy]
}
