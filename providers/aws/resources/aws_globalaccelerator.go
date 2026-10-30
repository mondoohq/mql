// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	gatypes "github.com/aws/aws-sdk-go-v2/service/globalaccelerator/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsGlobalaccelerator) id() (string, error) {
	return "aws.globalaccelerator", nil
}

func (a *mqlAwsGlobalacceleratorAccelerator) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsGlobalacceleratorListener) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsGlobalacceleratorEndpointGroup) id() (string, error) {
	return a.Arn.Data, nil
}

// accelerators lists the account's accelerators. Global Accelerator is a global
// service, so there is no region loop: one call covers the account.
func (a *mqlAwsGlobalaccelerator) accelerators() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.GlobalAccelerator()
	ctx := context.Background()

	res := []any{}
	paginator := globalaccelerator.NewListAcceleratorsPaginator(svc, &globalaccelerator.ListAcceleratorsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				// Unlike a regional service, being denied here empties the whole
				// resource rather than dimming one region, and an SCP denying
				// us-west-2 looks the same as having no accelerators. Say which
				// it was so an empty result is traceable.
				log.Debug().Err(err).
					Msg("access denied listing global accelerators in the us-west-2 control plane, reporting none")
				return res, nil
			}
			return nil, err
		}
		for _, acc := range page.Accelerators {
			ipSets, err := convert.JsonToDictSlice(acc.IpSets)
			if err != nil {
				return nil, err
			}
			mqlAcc, err := CreateResource(a.MqlRuntime, ResourceAwsGlobalacceleratorAccelerator,
				map[string]*llx.RawData{
					"arn":              llx.StringDataPtr(acc.AcceleratorArn),
					"name":             llx.StringDataPtr(acc.Name),
					"enabled":          llx.BoolDataPtr(acc.Enabled),
					"ipAddressType":    llx.StringData(string(acc.IpAddressType)),
					"dnsName":          llx.StringDataPtr(acc.DnsName),
					"dualStackDnsName": llx.StringDataPtr(acc.DualStackDnsName),
					"ipSets":           llx.ArrayData(ipSets, types.Any),
					"status":           llx.StringData(string(acc.Status)),
					"createdAt":        llx.TimeDataPtr(acc.CreatedTime),
					"lastModifiedAt":   llx.TimeDataPtr(acc.LastModifiedTime),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAcc)
		}
	}
	return res, nil
}

// tags is a separate call, so it is only made when the field is read.
func (a *mqlAwsGlobalacceleratorAccelerator) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.GlobalAccelerator()

	resp, err := svc.ListTagsForResource(context.Background(), &globalaccelerator.ListTagsForResourceInput{
		ResourceArn: &a.Arn.Data,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}
	tags := map[string]any{}
	for _, tag := range resp.Tags {
		tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
	}
	return tags, nil
}

func (a *mqlAwsGlobalacceleratorAccelerator) listeners() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.GlobalAccelerator()
	ctx := context.Background()

	res := []any{}
	paginator := globalaccelerator.NewListListenersPaginator(svc, &globalaccelerator.ListListenersInput{
		AcceleratorArn: &a.Arn.Data,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, listener := range page.Listeners {
			portRanges, err := convert.JsonToDictSlice(listener.PortRanges)
			if err != nil {
				return nil, err
			}
			mqlListener, err := CreateResource(a.MqlRuntime, ResourceAwsGlobalacceleratorListener,
				map[string]*llx.RawData{
					"arn":            llx.StringDataPtr(listener.ListenerArn),
					"protocol":       llx.StringData(string(listener.Protocol)),
					"clientAffinity": llx.StringData(string(listener.ClientAffinity)),
					"portRanges":     llx.ArrayData(portRanges, types.Any),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlListener)
		}
	}
	return res, nil
}

func (a *mqlAwsGlobalacceleratorListener) endpointGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.GlobalAccelerator()
	ctx := context.Background()

	res := []any{}
	paginator := globalaccelerator.NewListEndpointGroupsPaginator(svc, &globalaccelerator.ListEndpointGroupsInput{
		ListenerArn: &a.Arn.Data,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, group := range page.EndpointGroups {
			mqlGroup, err := newMqlAwsGlobalacceleratorEndpointGroup(a.MqlRuntime, group)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGroup)
		}
	}
	return res, nil
}

func newMqlAwsGlobalacceleratorEndpointGroup(runtime *plugin.Runtime, group gatypes.EndpointGroup) (plugin.Resource, error) {
	endpoints, err := convert.JsonToDictSlice(group.EndpointDescriptions)
	if err != nil {
		return nil, err
	}
	portOverrides, err := convert.JsonToDictSlice(group.PortOverrides)
	if err != nil {
		return nil, err
	}

	mqlGroup, err := CreateResource(runtime, ResourceAwsGlobalacceleratorEndpointGroup,
		map[string]*llx.RawData{
			"arn":                        llx.StringDataPtr(group.EndpointGroupArn),
			"region":                     llx.StringDataPtr(group.EndpointGroupRegion),
			"trafficDialPercentage":      llx.FloatData(float64(convert.ToValue(group.TrafficDialPercentage))),
			"healthCheckIntervalSeconds": llx.IntDataDefault(group.HealthCheckIntervalSeconds, 0),
			"healthCheckPath":            llx.StringDataPtr(group.HealthCheckPath),
			"healthCheckPort":            llx.IntDataDefault(group.HealthCheckPort, 0),
			"healthCheckProtocol":        llx.StringData(string(group.HealthCheckProtocol)),
			"thresholdCount":             llx.IntDataDefault(group.ThresholdCount, 0),
			"portOverrides":              llx.ArrayData(portOverrides, types.Any),
			"endpoints":                  llx.ArrayData(endpoints, types.Any),
		})
	if err != nil {
		return nil, err
	}
	endpointIds := make([]string, 0, len(group.EndpointDescriptions))
	for _, ep := range group.EndpointDescriptions {
		if id := convert.ToValue(ep.EndpointId); id != "" {
			endpointIds = append(endpointIds, id)
		}
	}
	mqlGroup.(*mqlAwsGlobalacceleratorEndpointGroup).cacheEndpointIds = endpointIds
	return mqlGroup, nil
}

// elasticIpAllocationPrefix identifies an elastic IP allocation ID in an
// endpoint group's polymorphic endpoint IDs.
const elasticIpAllocationPrefix = "eipalloc-"

type mqlAwsGlobalacceleratorEndpointGroupInternal struct {
	// cacheEndpointIds holds the raw endpoint identifiers, which are polymorphic:
	// a load balancer ARN, an EC2 instance ID, or an elastic IP allocation ID.
	cacheEndpointIds []string
}

// loadBalancers resolves the endpoints that are load balancers. An endpoint ID
// that is not an elasticloadbalancing ARN belongs to another accessor, so it is
// skipped rather than treated as an error.
func (a *mqlAwsGlobalacceleratorEndpointGroup) loadBalancers() ([]any, error) {
	res := []any{}
	for _, endpointId := range a.cacheEndpointIds {
		parsed, err := arn.Parse(endpointId)
		if err != nil || parsed.Service != "elasticloadbalancing" {
			continue
		}
		lb, err := NewResource(a.MqlRuntime, ResourceAwsElbLoadbalancer,
			map[string]*llx.RawData{"arn": llx.StringData(endpointId)})
		if err != nil {
			log.Debug().Err(err).Str("endpoint", endpointId).Msg("cannot resolve global accelerator load balancer endpoint")
			continue
		}
		res = append(res, lb)
	}
	return res, nil
}

// elasticIps resolves the endpoints that are elastic IPs.
//
// An endpoint carries the allocation ID (eipalloc-...), but aws.ec2.eip is keyed
// on region plus public IP, so there is no by-allocation-id lookup to call.
// Matching against the account's elastic IPs instead costs one enumeration,
// which the runtime caches on the aws.ec2 singleton and shares with every other
// reader of that list.
func (a *mqlAwsGlobalacceleratorEndpointGroup) elasticIps() ([]any, error) {
	wanted := map[string]struct{}{}
	for _, endpointId := range a.cacheEndpointIds {
		if strings.HasPrefix(endpointId, elasticIpAllocationPrefix) {
			wanted[endpointId] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return []any{}, nil
	}

	obj, err := CreateResource(a.MqlRuntime, ResourceAwsEc2, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	eips := obj.(*mqlAwsEc2).GetEips()
	if eips.Error != nil {
		return nil, eips.Error
	}

	res := []any{}
	for _, e := range eips.Data {
		eip, ok := e.(*mqlAwsEc2Eip)
		if !ok {
			continue
		}
		if _, found := wanted[eip.AllocationId.Data]; found {
			res = append(res, eip)
		}
	}
	return res, nil
}

// instances resolves the endpoints that are EC2 instances.
//
// initAwsEc2Instance resolves by ARN only, so the bare instance ID the endpoint
// carries is combined with the endpoint group's region (the region its endpoints
// live in) and the connection's account to build one. An empty region yields an
// ARN with no region, which initAwsEc2Instance handles by falling back to its
// cross-region lookup, so the instance still resolves.
func (a *mqlAwsGlobalacceleratorEndpointGroup) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, endpointId := range a.cacheEndpointIds {
		if !strings.HasPrefix(endpointId, "i-") {
			continue
		}
		instanceArn := fmt.Sprintf(ec2InstanceArnPattern, a.Region.Data, conn.AccountId(), endpointId)
		instance, err := NewResource(a.MqlRuntime, ResourceAwsEc2Instance,
			map[string]*llx.RawData{"arn": llx.StringData(instanceArn)})
		if err != nil {
			log.Debug().Err(err).Str("endpoint", endpointId).Msg("cannot resolve global accelerator instance endpoint")
			continue
		}
		res = append(res, instance)
	}
	return res, nil
}
