// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

type mqlAwsEc2VpcEndpointServiceConfigurationInternal struct {
	cacheNlbArns []string
	cacheGlbArns []string
	region       string
}

func (a *mqlAwsEc2VpcEndpointServiceConfiguration) networkLoadBalancers() ([]any, error) {
	res := []any{}
	for _, arn := range a.cacheNlbArns {
		mqlLB, err := NewResource(a.MqlRuntime, "aws.elb.loadbalancer",
			map[string]*llx.RawData{"arn": llx.StringData(arn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlLB)
	}
	return res, nil
}

func (a *mqlAwsEc2VpcEndpointServiceConfiguration) gatewayLoadBalancers() ([]any, error) {
	res := []any{}
	for _, arn := range a.cacheGlbArns {
		mqlLB, err := NewResource(a.MqlRuntime, "aws.elb.loadbalancer",
			map[string]*llx.RawData{"arn": llx.StringData(arn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlLB)
	}
	return res, nil
}

func (a *mqlAwsEc2VpcEndpointServiceConfiguration) allowedPrincipals() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.region)
	ctx := context.Background()

	serviceId := a.Id.Data
	res := []any{}
	paginator := ec2.NewDescribeVpcEndpointServicePermissionsPaginator(svc, &ec2.DescribeVpcEndpointServicePermissionsInput{
		ServiceId: &serviceId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, nil
			}
			return nil, errors.Wrap(err, "could not get vpc endpoint service permissions")
		}
		for _, p := range page.AllowedPrincipals {
			res = append(res, convert.ToValue(p.Principal))
		}
	}
	return res, nil
}

func (a *mqlAwsEc2VpcEndpointServiceConfiguration) connections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.region)
	ctx := context.Background()

	serviceId := a.Id.Data
	res := []any{}
	paginator := ec2.NewDescribeVpcEndpointConnectionsPaginator(svc, &ec2.DescribeVpcEndpointConnectionsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("service-id"),
				Values: []string{serviceId},
			},
		},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, nil
			}
			return nil, errors.Wrap(err, "could not get vpc endpoint connections")
		}
		for _, c := range page.VpcEndpointConnections {
			dnsEntries := make([]any, 0, len(c.DnsEntries))
			for _, entry := range c.DnsEntries {
				dnsEntries = append(dnsEntries, map[string]any{
					"dnsName":      convert.ToValue(entry.DnsName),
					"hostedZoneId": convert.ToValue(entry.HostedZoneId),
				})
			}

			nlbArns := convert.SliceAnyToInterface(c.NetworkLoadBalancerArns)
			glbArns := convert.SliceAnyToInterface(c.GatewayLoadBalancerArns)

			mqlConn, err := CreateResource(a.MqlRuntime, "aws.ec2.vpcEndpointServiceConfiguration.connection",
				map[string]*llx.RawData{
					"id":                      llx.StringData(fmt.Sprintf("%s/%s", serviceId, convert.ToValue(c.VpcEndpointId))),
					"endpointId":              llx.StringDataPtr(c.VpcEndpointId),
					"endpointOwner":           llx.StringDataPtr(c.VpcEndpointOwner),
					"endpointRegion":          llx.StringDataPtr(c.VpcEndpointRegion),
					"endpointState":           llx.StringData(string(c.VpcEndpointState)),
					"ipAddressType":           llx.StringData(string(c.IpAddressType)),
					"dnsEntries":              llx.ArrayData(dnsEntries, types.Any),
					"networkLoadBalancerArns": llx.ArrayData(nlbArns, types.String),
					"gatewayLoadBalancerArns": llx.ArrayData(glbArns, types.String),
					"createdAt":               llx.TimeDataPtr(c.CreationTimestamp),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlConn)
		}
	}
	return res, nil
}

func (a *mqlAwsEc2VpcEndpointServiceConfigurationConnection) id() (string, error) {
	return a.Id.Data, nil
}
