// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"errors"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// Placement Groups

func (a *mqlAwsEc2) placementGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getPlacementGroups(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsEc2) getPlacementGroups(conn *connection.AwsConnection) []*jobpool.Job {
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

			resp, err := svc.DescribePlacementGroups(ctx, &ec2.DescribePlacementGroupsInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, err
			}

			for _, pg := range resp.PlacementGroups {
				tags := ec2TagsToMap(pg.Tags)
				if conn.Filters.General.MatchesExcludeTags(tags) {
					continue
				}
				arn := fmt.Sprintf("arn:aws:ec2:%s:%s:placement-group/%s", region, conn.AccountId(), convert.ToValue(pg.GroupName))

				var partitionCount int64
				if pg.PartitionCount != nil {
					partitionCount = int64(*pg.PartitionCount)
				}

				mqlPg, err := CreateResource(a.MqlRuntime, "aws.ec2.placementGroup",
					map[string]*llx.RawData{
						"__id":           llx.StringData(arn),
						"name":           llx.StringDataPtr(pg.GroupName),
						"id":             llx.StringDataPtr(pg.GroupId),
						"arn":            llx.StringData(arn),
						"region":         llx.StringData(region),
						"strategy":       llx.StringData(string(pg.Strategy)),
						"state":          llx.StringData(string(pg.State)),
						"partitionCount": llx.IntData(partitionCount),
						"groupId":        llx.StringDataPtr(pg.GroupId),
						"tags":           llx.MapData(toInterfaceMap(tags), types.String),
					})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlPg)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEc2PlacementGroup) id() (string, error) {
	return a.Arn.Data, nil
}

// Capacity Reservations

func (a *mqlAwsEc2) capacityReservations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCapacityReservations(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsEc2) getCapacityReservations(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := ec2.NewDescribeCapacityReservationsPaginator(svc, &ec2.DescribeCapacityReservationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, cr := range page.CapacityReservations {
					tags := ec2TagsToMap(cr.Tags)
					if conn.Filters.General.MatchesExcludeTags(tags) {
						continue
					}
					mqlCr, err := buildCapacityReservationResource(a.MqlRuntime, region, conn.AccountId(), cr)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCr)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEc2CapacityReservation) id() (string, error) {
	return a.Arn.Data, nil
}

func buildCapacityReservationResource(runtime *plugin.Runtime, region, accountID string, cr ec2types.CapacityReservation) (*mqlAwsEc2CapacityReservation, error) {
	arn := fmt.Sprintf("arn:aws:ec2:%s:%s:capacity-reservation/%s", region, accountID, convert.ToValue(cr.CapacityReservationId))
	mqlCr, err := CreateResource(runtime, "aws.ec2.capacityReservation",
		map[string]*llx.RawData{
			"__id":                   llx.StringData(arn),
			"id":                     llx.StringDataPtr(cr.CapacityReservationId),
			"arn":                    llx.StringData(arn),
			"region":                 llx.StringData(region),
			"instanceType":           llx.StringDataPtr(cr.InstanceType),
			"instancePlatform":       llx.StringData(string(cr.InstancePlatform)),
			"availabilityZone":       llx.StringDataPtr(cr.AvailabilityZone),
			"totalInstanceCount":     llx.IntDataDefault(cr.TotalInstanceCount, 0),
			"availableInstanceCount": llx.IntDataDefault(cr.AvailableInstanceCount, 0),
			"state":                  llx.StringData(string(cr.State)),
			"instanceMatchCriteria":  llx.StringData(string(cr.InstanceMatchCriteria)),
			"endDateType":            llx.StringData(string(cr.EndDateType)),
			"tenancy":                llx.StringData(string(cr.Tenancy)),
			"ebsOptimized":           llx.BoolData(convert.ToValue(cr.EbsOptimized)),
			"ephemeralStorage":       llx.BoolData(convert.ToValue(cr.EphemeralStorage)),
			"createdAt":              llx.TimeDataPtr(cr.CreateDate),
			"tags":                   llx.MapData(toInterfaceMap(ec2TagsToMap(cr.Tags)), types.String),
		})
	if err != nil {
		return nil, err
	}
	return mqlCr.(*mqlAwsEc2CapacityReservation), nil
}

func initAwsEc2CapacityReservation(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil || args["region"] == nil {
		return nil, nil, errors.New("id and region required to fetch aws ec2 capacity reservation")
	}
	id := args["id"].Value.(string)
	region := args["region"].Value.(string)

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	resp, err := svc.DescribeCapacityReservations(context.Background(), &ec2.DescribeCapacityReservationsInput{
		CapacityReservationIds: []string{id},
	})
	if err != nil {
		return nil, nil, classifyAwsError(fmt.Errorf("fetching aws.ec2.capacityReservation with id %q in region %s: %w", id, region, err), "ec2:DescribeCapacityReservations")
	}
	if len(resp.CapacityReservations) == 0 {
		return nil, nil, fmt.Errorf("aws.ec2.capacityReservation with id %q not found", id)
	}
	mqlCr, err := buildCapacityReservationResource(runtime, region, conn.AccountId(), resp.CapacityReservations[0])
	if err != nil {
		return nil, nil, err
	}
	return args, mqlCr, nil
}

// Instance Connect Endpoints

func (a *mqlAwsEc2) instanceConnectEndpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getInstanceConnectEndpoints(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsEc2) getInstanceConnectEndpoints(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := ec2.NewDescribeInstanceConnectEndpointsPaginator(svc, &ec2.DescribeInstanceConnectEndpointsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						return res, nil
					}
					return nil, err
				}

				for _, ep := range page.InstanceConnectEndpoints {
					tags := ec2TagsToMap(ep.Tags)
					if conn.Filters.General.MatchesExcludeTags(tags) {
						continue
					}

					sgIds := make([]any, 0, len(ep.SecurityGroupIds))
					for _, sg := range ep.SecurityGroupIds {
						sgIds = append(sgIds, sg)
					}

					mqlEp, err := CreateResource(a.MqlRuntime, "aws.ec2.instanceConnectEndpoint",
						map[string]*llx.RawData{
							"__id":             llx.StringDataPtr(ep.InstanceConnectEndpointArn),
							"id":               llx.StringDataPtr(ep.InstanceConnectEndpointId),
							"arn":              llx.StringDataPtr(ep.InstanceConnectEndpointArn),
							"region":           llx.StringData(region),
							"state":            llx.StringData(string(ep.State)),
							"preserveClientIp": llx.BoolData(convert.ToValue(ep.PreserveClientIp)),
							"dnsName":          llx.StringDataPtr(ep.DnsName),
							"fipsDnsName":      llx.StringDataPtr(ep.FipsDnsName),
							"createdAt":        llx.TimeDataPtr(ep.CreatedAt),
							"tags":             llx.MapData(toInterfaceMap(tags), types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlEp.(*mqlAwsEc2InstanceConnectEndpoint).cacheSubnetId = convert.ToValue(ep.SubnetId)
					mqlEp.(*mqlAwsEc2InstanceConnectEndpoint).cacheVpcId = convert.ToValue(ep.VpcId)
					mqlEp.(*mqlAwsEc2InstanceConnectEndpoint).cacheSecurityGroupIds = sgIds
					res = append(res, mqlEp)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEc2InstanceConnectEndpoint) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2InstanceConnectEndpoint) subnet() (*mqlAwsVpcSubnet, error) {
	subnetId := a.cacheSubnetId
	if subnetId == "" {
		a.Subnet.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	subnetArn := fmt.Sprintf(subnetArnPattern, region, conn.AccountId(), subnetId)
	res, err := NewResource(a.MqlRuntime, "aws.vpc.subnet", map[string]*llx.RawData{"arn": llx.StringData(subnetArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpcSubnet), nil
}

func (a *mqlAwsEc2InstanceConnectEndpoint) vpc() (*mqlAwsVpc, error) {
	vpcId := a.cacheVpcId
	if vpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	vpcArn := fmt.Sprintf(vpcArnPattern, region, conn.AccountId(), vpcId)
	res, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{"arn": llx.StringData(vpcArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsEc2InstanceConnectEndpoint) securityGroups() ([]any, error) {
	sgIds := a.cacheSecurityGroupIds
	if len(sgIds) == 0 {
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	res := []any{}
	for _, sgIdAny := range sgIds {
		sgId, ok := sgIdAny.(string)
		if !ok || sgId == "" {
			continue
		}
		sgArn := NewSecurityGroupArn(region, conn.AccountId(), sgId)
		mqlSg, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup", map[string]*llx.RawData{"arn": llx.StringData(sgArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSg)
	}
	return res, nil
}

type mqlAwsEc2InstanceConnectEndpointInternal struct {
	cacheSubnetId         string
	cacheVpcId            string
	cacheSecurityGroupIds []any
}
