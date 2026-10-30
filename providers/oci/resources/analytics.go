// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/analytics"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciAnalytics) id() (string, error) {
	return "oci.analytics", nil
}

func (o *mqlOciAnalytics) instances() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci analytics instances with region %s", region)

			svc, err := conn.AnalyticsClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]analytics.AnalyticsInstanceSummary, *string, error) {
				response, err := svc.ListAnalyticsInstances(ctx, analytics.ListAnalyticsInstancesRequest{
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

				endpoint := analyticsEndpointOf(inst.NetworkEndpointDetails)

				var created, updated *time.Time
				if inst.TimeCreated != nil {
					created = &inst.TimeCreated.Time
				}
				if inst.TimeUpdated != nil {
					updated = &inst.TimeUpdated.Time
				}

				var capacityType string
				var capacityValue *int
				if inst.Capacity != nil {
					capacityType = string(inst.Capacity.CapacityType)
					capacityValue = inst.Capacity.CapacityValue
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.analytics.instance", stringValue(inst.CompartmentId), map[string]*llx.RawData{
					"id":                  llx.StringDataPtr(inst.Id),
					"name":                llx.StringDataPtr(inst.Name),
					"description":         llx.StringDataPtr(inst.Description),
					"featureSet":          llx.StringData(string(inst.FeatureSet)),
					"capacityType":        llx.StringData(capacityType),
					"capacityValue":       llx.IntDataPtr(capacityValue),
					"licenseType":         llx.StringData(string(inst.LicenseType)),
					"serviceUrl":          llx.StringDataPtr(inst.ServiceUrl),
					"state":               llx.StringData(string(inst.LifecycleState)),
					"created":             llx.TimeDataPtr(created),
					"timeUpdated":         llx.TimeDataPtr(updated),
					"networkEndpointType": llx.StringData(endpoint.endpointType),
					"whitelistedIps":      llx.ArrayData(endpoint.whitelistedIps, types.String),
					"whitelistedVcns":     llx.ArrayData(endpoint.whitelistedVcns, types.Dict),
					"whitelistedServices": llx.ArrayData(endpoint.whitelistedServices, types.String),
					"freeformTags":        llx.MapData(strMapToAny(inst.FreeformTags), types.String),
					"definedTags":         llx.MapData(definedTagsToAny(inst.DefinedTags), types.Any),
					"systemTags":          llx.MapData(definedTagsToAny(inst.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlInstance.(*mqlOciAnalyticsInstance)
				typed.cacheEndpoint = endpoint
				res = append(res, typed)
			}

			return res, nil
		})
}

// analyticsEndpoint is an Oracle Analytics Cloud instance's network endpoint.
type analyticsEndpoint struct {
	// PUBLIC or PRIVATE; empty when the API reported no endpoint.
	endpointType        string
	whitelistedIps      []any
	whitelistedVcns     []any
	whitelistedServices []any
	vcnID               string
	subnetID            string
	nsgIDs              []string
	internetReachable   bool
}

// analyticsEndpointOf reads an instance's network endpoint details.
//
// A private endpoint lives in a subnet of a customer VCN and is not
// reachable from the internet. A public endpoint is reachable from any
// address unless access control rules allow only some: allowlisted IP
// addresses and CIDR blocks, VCNs, or Oracle services. With no rule at all,
// or with a rule that admits every address, it is open to the internet.
func analyticsEndpointOf(d analytics.NetworkEndpointDetails) analyticsEndpoint {
	res := analyticsEndpoint{
		whitelistedIps:      []any{},
		whitelistedVcns:     []any{},
		whitelistedServices: []any{},
	}

	switch v := d.(type) {
	case analytics.PrivateEndpointDetails:
		res.setPrivate(&v)
	case *analytics.PrivateEndpointDetails:
		if v != nil {
			res.setPrivate(v)
		}
	case analytics.PublicEndpointDetails:
		res.setPublic(&v)
	case *analytics.PublicEndpointDetails:
		if v != nil {
			res.setPublic(v)
		} else {
			res.setPublic(&analytics.PublicEndpointDetails{})
		}
	case nil:
		// OAC creates an instance with a public endpoint and no access
		// control rules unless told otherwise.
		res.setPublic(&analytics.PublicEndpointDetails{})
		res.endpointType = ""
	}
	return res
}

func (e *analyticsEndpoint) setPrivate(p *analytics.PrivateEndpointDetails) {
	e.endpointType = string(analytics.NetworkEndpointTypePrivate)
	e.vcnID = stringValue(p.VcnId)
	e.subnetID = stringValue(p.SubnetId)
	e.nsgIDs = p.NetworkSecurityGroupIds
	e.internetReachable = false
}

func (e *analyticsEndpoint) setPublic(p *analytics.PublicEndpointDetails) {
	e.endpointType = string(analytics.NetworkEndpointTypePublic)
	e.whitelistedIps = convert.SliceAnyToInterface(p.WhitelistedIps)
	for _, vcn := range p.WhitelistedVcns {
		ips := vcn.WhitelistedIps
		if ips == nil {
			ips = []string{}
		}
		e.whitelistedVcns = append(e.whitelistedVcns, map[string]any{
			"id":             stringValue(vcn.Id),
			"whitelistedIps": convert.SliceAnyToInterface(ips),
		})
	}
	for _, svc := range p.WhitelistedServices {
		e.whitelistedServices = append(e.whitelistedServices, string(svc))
	}

	noRules := len(p.WhitelistedIps) == 0 && len(p.WhitelistedVcns) == 0 && len(p.WhitelistedServices) == 0
	e.internetReachable = noRules || ociWhitelistOpensInternet(e.whitelistedIps)
}

type mqlOciAnalyticsInstanceInternal struct {
	ociCompartmentRef
	cacheEndpoint analyticsEndpoint
}

func initOciAnalyticsInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return args, nil, nil
	}

	obj, err := CreateResource(runtime, "oci.analytics", nil)
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlOciAnalytics)

	list := svc.GetInstances()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		inst := raw.(*mqlOciAnalyticsInstance)
		if inst.Id.Data == idVal {
			return args, inst, nil
		}
	}

	return nil, nil, errors.New("oci.analytics.instance not found: " + idVal)
}

func (o *mqlOciAnalyticsInstance) id() (string, error) {
	return "oci.analytics.instance/" + o.Id.Data, nil
}

func (o *mqlOciAnalyticsInstance) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciAnalyticsInstance) internetReachable() (bool, error) {
	return o.cacheEndpoint.internetReachable, nil
}

func (o *mqlOciAnalyticsInstance) vcn() (*mqlOciNetworkVcn, error) {
	return resolveRef(o.MqlRuntime, "oci.network.vcn", o.cacheEndpoint.vcnID, &o.Vcn)
}

func (o *mqlOciAnalyticsInstance) subnet() (*mqlOciNetworkSubnet, error) {
	return resolveRef(o.MqlRuntime, "oci.network.subnet", o.cacheEndpoint.subnetID, &o.Subnet)
}

func (o *mqlOciAnalyticsInstance) networkSecurityGroups() ([]any, error) {
	res := make([]any, 0, len(o.cacheEndpoint.nsgIDs))
	for _, nsgID := range o.cacheEndpoint.nsgIDs {
		mqlNsg, err := NewResource(o.MqlRuntime, "oci.network.networkSecurityGroup", map[string]*llx.RawData{
			"id": llx.StringData(nsgID),
		})
		if err != nil {
			// Skip an element we cannot resolve rather than failing the whole
			// list and losing the ones that did resolve.
			log.Debug().Err(err).Str("nsg", nsgID).Msg("skipping unresolvable oci reference")
			continue
		}
		res = append(res, mqlNsg)
	}
	return res, nil
}
