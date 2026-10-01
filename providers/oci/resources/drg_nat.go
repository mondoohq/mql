// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// DRG NAT policies

type mqlOciNetworkDrgNatPolicyInternal struct {
	ociCompartmentRef
	cacheRegion string
}

func (o *mqlOciNetwork) drgNatPolicies() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci DRG NAT policies with region %s", region)

			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}

			policies, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.DrgNatPolicy, *string, error) {
				response, err := svc.ListDrgNatPolicies(ctx, core.ListDrgNatPoliciesRequest{
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

			res := make([]any, 0, len(policies))
			for i := range policies {
				p := policies[i]
				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.drgNatPolicy", stringValue(p.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(p.Id),
					"name":         llx.StringDataPtr(p.DisplayName),
					"state":        llx.StringData(string(p.LifecycleState)),
					"created":      sdkTimeData(p.TimeCreated),
					"freeformTags": llx.MapData(strMapToAny(p.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(p.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlPolicy := mqlInstance.(*mqlOciNetworkDrgNatPolicy)
				mqlPolicy.cacheRegion = region
				res = append(res, mqlPolicy)
			}
			return res, nil
		})
}

func initOciNetworkDrgNatPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.network", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciNetwork).GetDrgNatPolicies()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.network.drgNatPolicy", id, items)
}

func (o *mqlOciNetworkDrgNatPolicy) id() (string, error) {
	return "oci.network.drgNatPolicy/" + o.Id.Data, nil
}

func (o *mqlOciNetworkDrgNatPolicy) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkDrgNatPolicy) policyRegion() string {
	if o.cacheRegion != "" {
		return o.cacheRegion
	}
	return ociRegionFromOCID(o.Id.Data)
}

func (o *mqlOciNetworkDrgNatPolicy) rules() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.NetworkClient(o.policyRegion())
	if err != nil {
		return nil, err
	}

	rules, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]core.DrgNatRule, *string, error) {
		response, err := svc.ListDrgNatRules(ctx, core.ListDrgNatRulesRequest{
			DrgNatPolicyId: common.String(o.Id.Data),
			Page:           page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(rules))
	for i := range rules {
		mqlRule, err := CreateResource(o.MqlRuntime, "oci.network.drgNatPolicy.rule", drgNatRuleArgs(o.Id.Data, rules[i]))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

// drgNatRuleArgs maps one DRG NAT rule onto its MQL arguments. The rule id is
// only assigned by Oracle within its policy, so the cache key carries the
// policy OCID as well.
func drgNatRuleArgs(policyID string, rule core.DrgNatRule) map[string]*llx.RawData {
	priority := llx.NilData
	if rule.DrgNatRulePriority != nil {
		priority = llx.IntData(*rule.DrgNatRulePriority)
	}
	return map[string]*llx.RawData{
		"__id":                  llx.StringData(policyID + "/rule/" + stringValue(rule.Id)),
		"id":                    llx.StringDataPtr(rule.Id),
		"priority":              priority,
		"originalSource":        llx.StringDataPtr(rule.OriginalSource),
		"translatedSource":      llx.StringDataPtr(rule.TranslatedSource),
		"originalDestination":   llx.StringDataPtr(rule.OriginalDestination),
		"translatedDestination": llx.StringDataPtr(rule.TranslatedDestination),
	}
}

func (o *mqlOciNetworkDrgAttachment) natPolicy() (*mqlOciNetworkDrgNatPolicy, error) {
	if !isOcid(o.cacheDrgNatPolicyID) {
		o.NatPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.network.drgNatPolicy", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheDrgNatPolicyID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciNetworkDrgNatPolicy), nil
}
