// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

const vpcEndpointServiceArnPattern = "arn:aws:ec2:%s:%s:vpc-endpoint-service/%s"

func (a *mqlAwsEc2VpcEndpointServiceConfiguration) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2) vpcEndpointServiceConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getVpcEndpointServiceConfigs(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsEc2) getVpcEndpointServiceConfigs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			paginator := ec2.NewDescribeVpcEndpointServiceConfigurationsPaginator(svc, &ec2.DescribeVpcEndpointServiceConfigurationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, svcCfg := range page.ServiceConfigurations {
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(svcCfg.Tags)) {
						continue
					}

					var serviceType string
					if len(svcCfg.ServiceType) > 0 {
						serviceType = string(svcCfg.ServiceType[0].ServiceType)
					}

					var privateDnsName, privateDnsVerificationState string
					if svcCfg.PrivateDnsNameConfiguration != nil {
						privateDnsName = convert.ToValue(svcCfg.PrivateDnsNameConfiguration.Name)
						privateDnsVerificationState = string(svcCfg.PrivateDnsNameConfiguration.State)
					}

					var supportedIpTypes []any
					for _, t := range svcCfg.SupportedIpAddressTypes {
						supportedIpTypes = append(supportedIpTypes, string(t))
					}

					svcArn := fmt.Sprintf(vpcEndpointServiceArnPattern, region, conn.AccountId(), convert.ToValue(svcCfg.ServiceId))

					mqlSvc, err := CreateResource(a.MqlRuntime, ResourceAwsEc2VpcEndpointServiceConfiguration,
						map[string]*llx.RawData{
							"id":                              llx.StringData(convert.ToValue(svcCfg.ServiceId)),
							"arn":                             llx.StringData(svcArn),
							"region":                          llx.StringData(region),
							"name":                            llx.StringData(convert.ToValue(svcCfg.ServiceName)),
							"state":                           llx.StringData(string(svcCfg.ServiceState)),
							"serviceType":                     llx.StringData(serviceType),
							"acceptanceRequired":              llx.BoolData(convert.ToValue(svcCfg.AcceptanceRequired)),
							"privateDnsName":                  llx.StringData(privateDnsName),
							"privateDnsNameVerificationState": llx.StringData(privateDnsVerificationState),
							"availabilityZones":               llx.ArrayData(convert.SliceAnyToInterface(svcCfg.AvailabilityZones), types.String),
							"gatewayLoadBalancerArns":         llx.ArrayData(convert.SliceAnyToInterface(svcCfg.GatewayLoadBalancerArns), types.String),
							"networkLoadBalancerArns":         llx.ArrayData(convert.SliceAnyToInterface(svcCfg.NetworkLoadBalancerArns), types.String),
							"managesVpcEndpoints":             llx.BoolData(convert.ToValue(svcCfg.ManagesVpcEndpoints)),
							"payerResponsibility":             llx.StringData(string(svcCfg.PayerResponsibility)),
							"supportedIpAddressTypes":         llx.ArrayData(supportedIpTypes, types.String),
							"tags":                            llx.MapData(toInterfaceMap(ec2TagsToMap(svcCfg.Tags)), types.String),
						})
					if err != nil {
						return nil, err
					}
					cast := mqlSvc.(*mqlAwsEc2VpcEndpointServiceConfiguration)
					cast.cacheNlbArns = svcCfg.NetworkLoadBalancerArns
					cast.cacheGlbArns = svcCfg.GatewayLoadBalancerArns
					cast.region = region
					res = append(res, mqlSvc)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}
