// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/oracle/oci-go-sdk/v65/bastion"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciBastion) id() (string, error) {
	return "oci.bastion", nil
}

func (o *mqlOciBastion) bastions() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci bastion with region %s", region)

			svc, err := conn.BastionClient(region)
			if err != nil {
				return nil, err
			}

			bastions, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]bastion.BastionSummary, *string, error) {
				response, err := svc.ListBastions(ctx, bastion.ListBastionsRequest{
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

			var res []any
			for i := range bastions {
				b := bastions[i]

				var created *time.Time
				if b.TimeCreated != nil {
					created = &b.TimeCreated.Time
				}
				var timeUpdated *time.Time
				if b.TimeUpdated != nil {
					timeUpdated = &b.TimeUpdated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.bastion.instance", stringValue(b.CompartmentId), map[string]*llx.RawData{
					"id":             llx.StringDataPtr(b.Id),
					"name":           llx.StringDataPtr(b.Name),
					"bastionType":    llx.StringDataPtr(b.BastionType),
					"state":          llx.StringData(string(b.LifecycleState)),
					"dnsProxyStatus": llx.StringData(string(b.DnsProxyStatus)),
					"created":        llx.TimeDataPtr(created),
					"timeUpdated":    llx.TimeDataPtr(timeUpdated),
					"freeformTags":   llx.MapData(strMapToAny(b.FreeformTags), types.String),
					"definedTags":    llx.MapData(definedTagsToAny(b.DefinedTags), types.Any),
					"systemTags":     llx.MapData(definedTagsToAny(b.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlB := mqlInstance.(*mqlOciBastionInstance)
				mqlB.cacheTargetVcnID = stringValue(b.TargetVcnId)
				mqlB.cacheTargetSubnetID = stringValue(b.TargetSubnetId)
				mqlB.cacheRegion = region
				res = append(res, mqlB)
			}

			return res, nil
		})
}

type mqlOciBastionInstanceInternal struct {
	ociCompartmentRef
	cacheTargetVcnID    string
	cacheTargetSubnetID string
	cacheRegion         string

	bastion ociRetryLazy[*bastion.Bastion]
}

func (o *mqlOciBastionInstance) id() (string, error) {
	return "oci.bastion.instance/" + o.Id.Data, nil
}

// getBastionDetails lazily fetches the full bastion. ListBastions returns a
// summary that omits the session-control settings - most importantly the client
// CIDR allow list, which decides who on the internet may open a session - so
// they are only reachable through this call. Five accessors share it, and the
// runtime resolves them concurrently, so the fetch is guarded.
func (o *mqlOciBastionInstance) getBastionDetails() (*bastion.Bastion, error) {
	return o.bastion.get(func() (*bastion.Bastion, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		region := o.cacheRegion
		if region == "" {
			region = ociRegionFromOCID(o.Id.Data)
		}
		svc, err := conn.BastionClient(region)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetBastion(context.Background(), bastion.GetBastionRequest{
			BastionId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.Bastion, nil
	})
}

func (o *mqlOciBastionInstance) clientCidrBlockAllowList() ([]any, error) {
	b, err := o.getBastionDetails()
	if err != nil {
		return nil, err
	}
	return stringsToAny(b.ClientCidrBlockAllowList), nil
}

func (o *mqlOciBastionInstance) staticJumpHostIpAddresses() ([]any, error) {
	b, err := o.getBastionDetails()
	if err != nil {
		return nil, err
	}
	return stringsToAny(b.StaticJumpHostIpAddresses), nil
}

func (o *mqlOciBastionInstance) maxSessionTtlInSeconds() (int64, error) {
	b, err := o.getBastionDetails()
	if err != nil {
		return 0, err
	}
	if b.MaxSessionTtlInSeconds == nil {
		o.MaxSessionTtlInSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*b.MaxSessionTtlInSeconds), nil
}

func (o *mqlOciBastionInstance) maxSessionsAllowed() (int64, error) {
	b, err := o.getBastionDetails()
	if err != nil {
		return 0, err
	}
	if b.MaxSessionsAllowed == nil {
		o.MaxSessionsAllowed.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*b.MaxSessionsAllowed), nil
}

func (o *mqlOciBastionInstance) privateEndpointIpAddress() (string, error) {
	b, err := o.getBastionDetails()
	if err != nil {
		return "", err
	}
	if b.PrivateEndpointIpAddress == nil {
		o.PrivateEndpointIpAddress.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *b.PrivateEndpointIpAddress, nil
}

func (o *mqlOciBastionInstance) targetSubnet() (*mqlOciNetworkSubnet, error) {
	if o.cacheTargetSubnetID == "" {
		o.TargetSubnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlSubnet, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheTargetSubnetID),
	})
	if err != nil {
		return nil, err
	}
	return mqlSubnet.(*mqlOciNetworkSubnet), nil
}

func (o *mqlOciBastionInstance) targetVcn() (*mqlOciNetworkVcn, error) {
	if o.cacheTargetVcnID == "" {
		o.TargetVcn.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVcn, err := NewResource(o.MqlRuntime, "oci.network.vcn", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheTargetVcnID),
	})
	if err != nil {
		return nil, err
	}
	return mqlVcn.(*mqlOciNetworkVcn), nil
}
