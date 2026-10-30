// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	ecsservice "github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

const (
	ecsGatewayConfigurationHostSharedAlb = "hostSharedAlb"
	ecsGatewayConfigurationUnknown       = "unknown"
)

func (a *mqlAwsEcs) gateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getECSGateways(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsEcs) getECSGateways(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for ri := range regions {
		region := regions[ri]
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ecs(region)
			ctx := context.Background()
			res := []any{}
			paginator := ecsservice.NewListGatewaysPaginator(svc, &ecsservice.ListGatewaysInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for ECS gateways")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("ECS gateways are not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, summary := range page.Gateways {
					if summary.GatewayArn == nil {
						continue
					}
					detail, err := svc.DescribeGateway(ctx, &ecsservice.DescribeGatewayInput{Gateway: summary.GatewayArn})
					if err != nil {
						var notFound *ecstypes.GatewayNotFoundException
						if errors.As(err, &notFound) {
							// Deleted between the list and the describe call.
							continue
						}
						return nil, err
					}
					if detail.Gateway == nil {
						continue
					}
					mqlGw, err := newMqlAwsEcsGateway(a.MqlRuntime, conn.AccountId(), region, detail.Gateway)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlGw)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsEcsGatewayInternal struct {
	region                    string
	accountID                 string
	cacheInfrastructureRole   *string
	cacheSubnetIds            []string
	cacheInboundSecurityGroup string
	cacheWebAclArn            string
	cacheAccessLogsBucket     string
}

// ecsGatewayAlbArgs holds the flattened load balancer settings of a gateway.
// Every field is null unless the configuration is a shared ALB.
type ecsGatewayAlbArgs struct {
	configurationType string
	fields            map[string]*llx.RawData
	subnetIds         []string
	inboundSG         string
	webAclArn         string
	accessLogsBucket  string
}

// flattenEcsGatewayConfiguration maps the gateway configuration union onto the
// flat load balancer fields. A union member this provider does not classify
// reports configurationType unknown with null load balancer fields.
func flattenEcsGatewayConfiguration(cfg ecstypes.DescribeGatewayConfiguration) ecsGatewayAlbArgs {
	out := ecsGatewayAlbArgs{
		configurationType: ecsGatewayConfigurationUnknown,
		fields: map[string]*llx.RawData{
			"scheme":                   llx.NilData,
			"httpDesyncMitigationMode": llx.NilData,
			"listenerProtocol":         llx.NilData,
			"listenerPort":             llx.NilData,
			"maxAlbCount":              llx.NilData,
			"currentAlbCount":          llx.NilData,
			"ipAddressType":            llx.NilData,
			"accessLogsEnabled":        llx.NilData,
			"accessLogsPrefix":         llx.NilData,
		},
	}
	member, ok := cfg.(*ecstypes.DescribeGatewayConfigurationMemberHostSharedAlb)
	if !ok {
		return out
	}
	alb := member.Value
	out.configurationType = ecsGatewayConfigurationHostSharedAlb
	out.fields["scheme"] = llx.StringDataPtr(nonEmptyEnum(alb.Scheme))
	out.fields["httpDesyncMitigationMode"] = llx.StringDataPtr(nonEmptyEnum(alb.HttpDesync))
	out.fields["listenerProtocol"] = llx.StringDataPtr(nonEmptyEnum(alb.Protocol))
	out.fields["listenerPort"] = llx.IntDataPtr(alb.Port)
	out.fields["maxAlbCount"] = llx.IntDataPtr(alb.MaxAlbCount)
	out.fields["currentAlbCount"] = llx.IntDataPtr(alb.CurrentAlbCount)
	out.webAclArn = convert.ToValue(alb.WebACLArn)

	if nc := alb.NetworkConfiguration; nc != nil {
		out.fields["ipAddressType"] = llx.StringDataPtr(nonEmptyEnum(nc.IpAddressType))
		out.subnetIds = nc.Subnets
		out.inboundSG = convert.ToValue(nc.InboundSecurityGroup)
	}

	out.fields["accessLogsEnabled"] = llx.BoolData(false)
	if alb.AccessLogs != nil {
		if s3, ok := alb.AccessLogs.Destination.(*ecstypes.GatewayElbAccessLogDestinationMemberS3); ok {
			out.fields["accessLogsEnabled"] = llx.BoolData(true)
			out.fields["accessLogsPrefix"] = llx.StringDataPtr(s3.Value.Prefix)
			out.accessLogsBucket = convert.ToValue(s3.Value.Bucket)
		} else if alb.AccessLogs.Destination != nil {
			// A destination kind this provider does not model still delivers logs.
			out.fields["accessLogsEnabled"] = llx.BoolData(true)
		}
	}
	return out
}

func newMqlAwsEcsGateway(runtime *plugin.Runtime, accountID string, region string, gw *ecstypes.Gateway) (plugin.Resource, error) {
	alb := flattenEcsGatewayConfiguration(gw.Configuration)
	args := map[string]*llx.RawData{
		"__id":               llx.StringDataPtr(gw.GatewayArn),
		"arn":                llx.StringDataPtr(gw.GatewayArn),
		"name":               llx.StringDataPtr(gw.Name),
		"region":             llx.StringData(region),
		"status":             llx.StringData(string(gw.Status)),
		"statusReason":       llx.StringDataPtr(gw.StatusReason),
		"accessType":         llx.StringDataPtr(nonEmptyEnum(gw.AccessType)),
		"deletionProtection": llx.BoolDataPtr(gw.DeletionProtection),
		"propagateTags":      llx.StringDataPtr(nonEmptyEnum(gw.PropagateTags)),
		"createdAt":          llx.TimeDataPtr(gw.CreatedAt),
		"updatedAt":          llx.TimeDataPtr(gw.UpdatedAt),
		"tags":               llx.MapData(ecsTagsToMap(gw.Tags), types.String),
		"configurationType":  llx.StringData(alb.configurationType),
	}
	for k, v := range alb.fields {
		args[k] = v
	}

	res, err := CreateResource(runtime, ResourceAwsEcsGateway, args)
	if err != nil {
		return nil, err
	}
	mqlGw := res.(*mqlAwsEcsGateway)
	mqlGw.region = region
	mqlGw.accountID = accountID
	mqlGw.cacheInfrastructureRole = gw.InfrastructureRoleArn
	mqlGw.cacheSubnetIds = alb.subnetIds
	mqlGw.cacheInboundSecurityGroup = alb.inboundSG
	mqlGw.cacheWebAclArn = alb.webAclArn
	mqlGw.cacheAccessLogsBucket = alb.accessLogsBucket
	return mqlGw, nil
}

func (a *mqlAwsEcsGateway) infrastructureRole() (*mqlAwsIamRole, error) {
	return ecsIamRoleRef(a.MqlRuntime, a.cacheInfrastructureRole, &a.InfrastructureRole)
}

func (a *mqlAwsEcsGateway) subnets() ([]any, error) {
	res := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		if subnetId == "" {
			continue
		}
		mqlSubnet, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet,
			map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, a.accountID, subnetId))})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsEcsGateway) inboundSecurityGroup() (*mqlAwsEc2Securitygroup, error) {
	if a.cacheInboundSecurityGroup == "" {
		a.InboundSecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Securitygroup,
		map[string]*llx.RawData{"arn": llx.StringData(NewSecurityGroupArn(a.region, a.accountID, a.cacheInboundSecurityGroup))})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Securitygroup), nil
}

func (a *mqlAwsEcsGateway) webAcl() (*mqlAwsWafAcl, error) {
	if a.cacheWebAclArn == "" {
		a.WebAcl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.waf.acl",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheWebAclArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsWafAcl), nil
}

func (a *mqlAwsEcsGateway) accessLogsBucket() (*mqlAwsS3Bucket, error) {
	if a.cacheAccessLogsBucket == "" {
		a.AccessLogsBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{"name": llx.StringData(a.cacheAccessLogsBucket)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}
