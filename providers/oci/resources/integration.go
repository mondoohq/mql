// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/integration"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciIntegration) id() (string, error) {
	return "oci.integration", nil
}

func (o *mqlOciIntegration) instances() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci integration instances with region %s", region)

			svc, err := conn.IntegrationInstanceClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]integration.IntegrationInstanceSummary, *string, error) {
				response, err := svc.ListIntegrationInstances(ctx, integration.ListIntegrationInstancesRequest{
					CompartmentId: new(compartmentID),
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

			res := make([]any, 0, len(items))
			for i := range items {
				inst := items[i]

				if conn.Filters.IsFilteredOutByTags(inst.FreeformTags, inst.DefinedTags) {
					continue
				}

				access, err := integrationNetworkAccessOf(inst.NetworkEndpointDetails)
				if err != nil {
					return nil, err
				}

				var created, updated *time.Time
				if inst.TimeCreated != nil {
					created = &inst.TimeCreated.Time
				}
				if inst.TimeUpdated != nil {
					updated = &inst.TimeUpdated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.integration.instance", stringValue(inst.CompartmentId), map[string]*llx.RawData{
					"id":                          llx.StringDataPtr(inst.Id),
					"name":                        llx.StringDataPtr(inst.DisplayName),
					"integrationInstanceType":     llx.StringData(string(inst.IntegrationInstanceType)),
					"shape":                       llx.StringData(string(inst.Shape)),
					"consumptionModel":            llx.StringData(string(inst.ConsumptionModel)),
					"isByol":                      llx.BoolDataPtr(inst.IsByol),
					"messagePacks":                llx.IntDataPtr(inst.MessagePacks),
					"instanceUrl":                 llx.StringDataPtr(inst.InstanceUrl),
					"instanceDesignTimeUrl":       llx.StringDataPtr(inst.InstanceDesignTimeUrl),
					"isFileServerEnabled":         llx.BoolDataPtr(inst.IsFileServerEnabled),
					"isVisualBuilderEnabled":      llx.BoolDataPtr(inst.IsVisualBuilderEnabled),
					"isDisasterRecoveryEnabled":   llx.BoolDataPtr(inst.IsDisasterRecoveryEnabled),
					"state":                       llx.StringData(string(inst.LifecycleState)),
					"created":                     llx.TimeDataPtr(created),
					"timeUpdated":                 llx.TimeDataPtr(updated),
					"networkEndpointType":         llx.StringData(access.endpointType),
					"allowlistedHttpIps":          llx.ArrayData(access.allowlistedIps, types.String),
					"allowlistedHttpVcns":         llx.ArrayData(access.allowlistedVcns, types.Dict),
					"isIntegrationVcnAllowlisted": llx.BoolData(access.integrationVcnAllowlisted),
					"networkEndpointDetails":      dictOrNil(access.details),
					"freeformTags":                llx.MapData(strMapToAny(inst.FreeformTags), types.String),
					"definedTags":                 llx.MapData(definedTagsToAny(inst.DefinedTags), types.Any),
					"systemTags":                  llx.MapData(definedTagsToAny(inst.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlInstance.(*mqlOciIntegrationInstance).cacheInternetReachable = access.internetReachable
				res = append(res, mqlInstance)
			}

			return res, nil
		})
}

// integrationNetworkAccess is what an Oracle Integration instance's network
// access restriction allows.
type integrationNetworkAccess struct {
	// PUBLIC when access is restricted, empty when it is not.
	endpointType              string
	allowlistedIps            []any
	allowlistedVcns           []any
	integrationVcnAllowlisted bool
	// The restriction as the API returns it; nil when there is none.
	details           map[string]any
	internetReachable bool
}

// integrationNetworkAccessOf reads an instance's network endpoint details.
//
// An instance without them has "Restrict Network Access" turned off: its
// public endpoint takes traffic from any address. With them, only the
// allowlisted addresses and VCNs get through, unless one of the allowlists
// (the instance's own, or the separate runtime and design-time ones) admits
// every address itself.
func integrationNetworkAccessOf(d integration.NetworkEndpointDetails) (integrationNetworkAccess, error) {
	res := integrationNetworkAccess{
		allowlistedIps:  []any{},
		allowlistedVcns: []any{},
	}

	var public *integration.PublicEndpointDetails
	switch v := d.(type) {
	case nil:
		res.internetReachable = true
		return res, nil
	case integration.PublicEndpointDetails:
		public = &v
	case *integration.PublicEndpointDetails:
		if v == nil {
			res.internetReachable = true
			return res, nil
		}
		public = v
	default:
		// A restriction type this SDK does not know yet. Report what the API
		// sent, and don't claim the instance is reachable on a guess.
		details, err := convert.JsonToDict(d)
		if err != nil {
			return res, err
		}
		res.details = details
		if t, ok := details["networkEndpointType"].(string); ok {
			res.endpointType = t
		}
		return res, nil
	}

	details, err := convert.JsonToDict(public)
	if err != nil {
		return res, err
	}
	res.details = details
	res.endpointType = string(integration.NetworkEndpointTypePublic)
	res.allowlistedIps = convert.SliceAnyToInterface(public.AllowlistedHttpIps)
	res.allowlistedVcns = integrationVcnsToDicts(public.AllowlistedHttpVcns)
	if public.IsIntegrationVcnAllowlisted != nil {
		res.integrationVcnAllowlisted = *public.IsIntegrationVcnAllowlisted
	}

	res.internetReachable = ociWhitelistOpensInternet(res.allowlistedIps)
	for _, component := range []*integration.ComponentAllowListDetails{public.Runtime, public.DesignTime} {
		if component != nil && ociWhitelistOpensInternet(convert.SliceAnyToInterface(component.AllowlistedHttpIps)) {
			res.internetReachable = true
		}
	}
	return res, nil
}

// dictOrNil reports an absent dict as null rather than as an empty one.
func dictOrNil(d map[string]any) *llx.RawData {
	if d == nil {
		return llx.NilData
	}
	return llx.DictData(d)
}

func integrationVcnsToDicts(vcns []integration.VirtualCloudNetwork) []any {
	res := make([]any, 0, len(vcns))
	for _, vcn := range vcns {
		ips := vcn.AllowlistedIps
		if ips == nil {
			ips = []string{}
		}
		res = append(res, map[string]any{
			"id":             stringValue(vcn.Id),
			"allowlistedIps": convert.SliceAnyToInterface(ips),
		})
	}
	return res
}

type mqlOciIntegrationInstanceInternal struct {
	ociCompartmentRef
	cacheInternetReachable bool
}

func initOciIntegrationInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return args, nil, nil
	}

	obj, err := CreateResource(runtime, "oci.integration", nil)
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlOciIntegration)

	list := svc.GetInstances()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		inst := raw.(*mqlOciIntegrationInstance)
		if inst.Id.Data == idVal {
			return args, inst, nil
		}
	}

	return nil, nil, errors.New("oci.integration.instance not found: " + idVal)
}

func (o *mqlOciIntegrationInstance) id() (string, error) {
	return "oci.integration.instance/" + o.Id.Data, nil
}

func (o *mqlOciIntegrationInstance) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciIntegrationInstance) internetReachable() (bool, error) {
	return o.cacheInternetReachable, nil
}
