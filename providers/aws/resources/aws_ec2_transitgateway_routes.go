// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// newMqlAwsEc2TransitgatewayAttachment builds an aws.ec2.transitgateway.attachment
// from an SDK TransitGatewayAttachment. Shared by the per-gateway list and by the
// by-id init that typed route references resolve through.
func newMqlAwsEc2TransitgatewayAttachment(runtime *plugin.Runtime, region string, att ec2types.TransitGatewayAttachment) (plugin.Resource, error) {
	return CreateResource(runtime, ResourceAwsEc2TransitgatewayAttachment,
		map[string]*llx.RawData{
			"id":               llx.StringData(convert.ToValue(att.TransitGatewayAttachmentId)),
			"transitGatewayId": llx.StringData(convert.ToValue(att.TransitGatewayId)),
			"resourceId":       llx.StringData(convert.ToValue(att.ResourceId)),
			"resourceType":     llx.StringData(string(att.ResourceType)),
			"state":            llx.StringData(string(att.State)),
			"createdAt":        llx.TimeDataPtr(att.CreationTime),
			"tags":             llx.MapData(toInterfaceMap(ec2TagsToMap(att.Tags)), types.String),
			"region":           llx.StringData(region),
		})
}

// initAwsEc2TransitgatewayAttachment resolves an attachment by ID so route and
// route-table references can hand back a fully populated resource instead of a
// bare ID. The attachment ID is the cache key, so an attachment already listed
// through aws.ec2.transitgateways.attachments costs no API call here.
func initAwsEc2TransitgatewayAttachment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	attachmentId, _ := args["id"].Value.(string)
	if attachmentId == "" {
		return args, nil, nil
	}

	if cached, ok := runtime.Resources.Get(ResourceAwsEc2TransitgatewayAttachment + "\x00" + attachmentId); ok {
		return args, cached, nil
	}

	var region string
	if args["region"] != nil {
		region, _ = args["region"].Value.(string)
	}
	if region == "" {
		return nil, nil, fmt.Errorf("aws.ec2.transitgateway.attachment with id %q needs a region to resolve", attachmentId)
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	resp, err := svc.DescribeTransitGatewayAttachments(context.Background(), &ec2.DescribeTransitGatewayAttachmentsInput{
		TransitGatewayAttachmentIds: []string{attachmentId},
	})
	if err != nil {
		return nil, nil, classifyAwsError(fmt.Errorf("fetching aws.ec2.transitgateway.attachment with id %q in region %s: %w", attachmentId, region, err), "ec2:DescribeTransitGatewayAttachments")
	}
	if len(resp.TransitGatewayAttachments) == 0 {
		return nil, nil, fmt.Errorf("aws.ec2.transitgateway.attachment with id %q not found in region %s", attachmentId, region)
	}
	res, err := newMqlAwsEc2TransitgatewayAttachment(runtime, region, resp.TransitGatewayAttachments[0])
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// resolveTransitGatewayAttachments turns attachment IDs into typed resources,
// skipping any that cannot be resolved rather than failing the whole list: a
// route can reference an attachment that was deleted out from under it, and one
// dangling reference should not hide the rest of the route table.
func resolveTransitGatewayAttachments(runtime *plugin.Runtime, region string, attachmentIds []string) ([]any, error) {
	res := []any{}
	for _, id := range attachmentIds {
		if id == "" {
			continue
		}
		att, err := NewResource(runtime, ResourceAwsEc2TransitgatewayAttachment,
			map[string]*llx.RawData{
				"id":     llx.StringData(id),
				"region": llx.StringData(region),
			})
		if err != nil {
			log.Debug().Err(err).Str("attachment", id).Msg("cannot resolve transit gateway attachment")
			continue
		}
		res = append(res, att)
	}
	return res, nil
}

type mqlAwsEc2TransitgatewayRouteTableRouteInternal struct {
	region             string
	cachePrefixListId  string
	cacheAttachmentIds []string
}

func (a *mqlAwsEc2TransitgatewayRouteTableRoute) managedPrefixList() (*mqlAwsEc2ManagedPrefixList, error) {
	if a.cachePrefixListId == "" {
		a.ManagedPrefixList.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnStr := fmt.Sprintf(prefixListArnPattern, a.region, conn.AccountId(), a.cachePrefixListId)
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2ManagedPrefixList,
		map[string]*llx.RawData{"arn": llx.StringData(arnStr)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2ManagedPrefixList), nil
}

func (a *mqlAwsEc2TransitgatewayRouteTableRoute) attachments() ([]any, error) {
	return resolveTransitGatewayAttachments(a.MqlRuntime, a.region, a.cacheAttachmentIds)
}

// routes returns every route in the transit gateway route table.
//
// SearchTransitGatewayRoutes requires at least one filter, so the search filters
// on route type with both of its values -- every route is either static or
// propagated -- which matches all routes regardless of state. The API caps a
// result set at 1000 routes and reports the overflow through
// AdditionalRoutesAvailable; that case is logged rather than silently truncated.
func (a *mqlAwsEc2TransitgatewayRouteTable) routes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	routeTableId := a.Id.Data
	svc := conn.Ec2(region)
	ctx := context.Background()

	res := []any{}
	var nextToken *string
	for {
		resp, err := svc.SearchTransitGatewayRoutes(ctx, &ec2.SearchTransitGatewayRoutesInput{
			TransitGatewayRouteTableId: aws.String(routeTableId),
			Filters: []ec2types.Filter{{
				Name:   aws.String("type"),
				Values: []string{string(ec2types.TransitGatewayRouteTypeStatic), string(ec2types.TransitGatewayRouteTypePropagated)},
			}},
			NextToken: nextToken,
		})
		if err != nil {
			return nil, classifyAwsError(err, "ec2:SearchTransitGatewayRoutes")
		}

		for _, route := range resp.Routes {
			mqlRoute, err := newMqlAwsEc2TransitgatewayRouteTableRoute(a.MqlRuntime, region, routeTableId, len(res), route)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRoute)
		}

		if convert.ToValue(resp.AdditionalRoutesAvailable) && resp.NextToken == nil {
			log.Warn().
				Str("routeTable", routeTableId).
				Int("returned", len(res)).
				Msg("transit gateway route table has more routes than SearchTransitGatewayRoutes will return")
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return res, nil
}

// newMqlAwsEc2TransitgatewayRouteTableRoute builds one route resource. index is
// the route's position in the API result set, used only to key a route that
// carries no destination of its own.
func newMqlAwsEc2TransitgatewayRouteTableRoute(runtime *plugin.Runtime, region string, routeTableId string, index int, route ec2types.TransitGatewayRoute) (plugin.Resource, error) {
	prefixListId := convert.ToValue(route.PrefixListId)
	destination := convert.ToValue(route.DestinationCidrBlock)
	if destination == "" {
		destination = prefixListId
	}
	if destination == "" {
		// Neither a CIDR nor a prefix list leaves nothing stable to key on, so
		// fall back to the position in the result set. Without this, two such
		// routes in one table share a cache key and the second silently
		// replaces the first.
		destination = fmt.Sprintf("route-%d", index)
	}

	attachmentIds := make([]string, 0, len(route.TransitGatewayAttachments))
	for _, att := range route.TransitGatewayAttachments {
		if id := convert.ToValue(att.TransitGatewayAttachmentId); id != "" {
			attachmentIds = append(attachmentIds, id)
		}
	}

	mqlRoute, err := CreateResource(runtime, ResourceAwsEc2TransitgatewayRouteTableRoute,
		map[string]*llx.RawData{
			"__id":                     llx.StringData(routeTableId + "/" + destination),
			"destinationCidrBlock":     llx.StringData(convert.ToValue(route.DestinationCidrBlock)),
			"state":                    llx.StringData(string(route.State)),
			"type":                     llx.StringData(string(route.Type)),
			"routeTableAnnouncementId": llx.StringData(convert.ToValue(route.TransitGatewayRouteTableAnnouncementId)),
		})
	if err != nil {
		return nil, err
	}
	internal := mqlRoute.(*mqlAwsEc2TransitgatewayRouteTableRoute)
	internal.region = region
	internal.cachePrefixListId = prefixListId
	internal.cacheAttachmentIds = attachmentIds
	return mqlRoute, nil
}

// associatedAttachments returns the attachments whose outbound traffic this
// route table controls.
func (a *mqlAwsEc2TransitgatewayRouteTable) associatedAttachments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Ec2(region)
	ctx := context.Background()

	attachmentIds := []string{}
	params := &ec2.GetTransitGatewayRouteTableAssociationsInput{
		TransitGatewayRouteTableId: aws.String(a.Id.Data),
	}
	paginator := ec2.NewGetTransitGatewayRouteTableAssociationsPaginator(svc, params)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "ec2:GetTransitGatewayRouteTableAssociations")
		}
		for _, assoc := range page.Associations {
			attachmentIds = append(attachmentIds, convert.ToValue(assoc.TransitGatewayAttachmentId))
		}
	}
	return resolveTransitGatewayAttachments(a.MqlRuntime, region, attachmentIds)
}

// propagatingAttachments returns the attachments whose routes are installed into
// this route table. Only propagations in the enabled state are included: a
// disabled propagation contributes nothing to the table, so reporting it would
// overstate what the route table can reach.
func (a *mqlAwsEc2TransitgatewayRouteTable) propagatingAttachments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Ec2(region)
	ctx := context.Background()

	attachmentIds := []string{}
	params := &ec2.GetTransitGatewayRouteTablePropagationsInput{
		TransitGatewayRouteTableId: aws.String(a.Id.Data),
	}
	paginator := ec2.NewGetTransitGatewayRouteTablePropagationsPaginator(svc, params)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "ec2:GetTransitGatewayRouteTablePropagations")
		}
		for _, prop := range page.TransitGatewayRouteTablePropagations {
			if prop.State != ec2types.TransitGatewayPropagationStateEnabled {
				continue
			}
			attachmentIds = append(attachmentIds, convert.ToValue(prop.TransitGatewayAttachmentId))
		}
	}
	return resolveTransitGatewayAttachments(a.MqlRuntime, region, attachmentIds)
}
