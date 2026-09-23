// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	mqltypes "go.mondoo.com/mql/types"
)

func (a *mqlAwsEc2Ipam) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2IpamScope) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2IpamPool) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2IpamPoolAllocation) id() (string, error) {
	return a.Id.Data, nil
}

// mqlAwsEc2IpamInternal carries the IPAM region so accessors like scopes()
// and pools() know which Region's EC2 client to call. The IPAM is a
// home-region resource — its scopes and pools live in the same Region as
// the IPAM itself, regardless of where it can allocate.
type mqlAwsEc2IpamInternal struct {
	homeRegion string
}

// mqlAwsEc2IpamPoolInternal carries the pool's home Region for the
// allocations() accessor.
type mqlAwsEc2IpamPoolInternal struct {
	homeRegion string
}

// ipams walks DescribeIpams in every enabled Region in parallel and
// materializes each row as an aws.ec2.ipam resource.
func (a *mqlAwsEc2) ipams() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getIpams(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsEc2) getIpams(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := ec2.NewDescribeIpamsPaginator(svc, &ec2.DescribeIpamsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for i := range page.Ipams {
					ipam := page.Ipams[i]
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(ipam.Tags)) {
						continue
					}
					mqlIpam, err := newMqlAwsEc2Ipam(a.MqlRuntime, region, &ipam)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlIpam)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsEc2Ipam(runtime *plugin.Runtime, region string, ipam *types.Ipam) (*mqlAwsEc2Ipam, error) {
	operatingRegions := make([]any, 0, len(ipam.OperatingRegions))
	for _, r := range ipam.OperatingRegions {
		operatingRegions = append(operatingRegions, convert.ToValue(r.RegionName))
	}

	mqlRes, err := CreateResource(runtime, ResourceAwsEc2Ipam, map[string]*llx.RawData{
		"id":                                    llx.StringData(convert.ToValue(ipam.IpamId)),
		"arn":                                   llx.StringData(convert.ToValue(ipam.IpamArn)),
		"region":                                llx.StringData(region),
		"ownerId":                               llx.StringData(convert.ToValue(ipam.OwnerId)),
		"description":                           llx.StringData(convert.ToValue(ipam.Description)),
		"tier":                                  llx.StringData(string(ipam.Tier)),
		"state":                                 llx.StringData(string(ipam.State)),
		"stateMessage":                          llx.StringData(convert.ToValue(ipam.StateMessage)),
		"operatingRegions":                      llx.ArrayData(operatingRegions, mqltypes.String),
		"enablePrivateGua":                      llx.BoolData(convert.ToValue(ipam.EnablePrivateGua)),
		"meteredAccount":                        llx.StringData(string(ipam.MeteredAccount)),
		"publicDefaultScopeId":                  llx.StringData(convert.ToValue(ipam.PublicDefaultScopeId)),
		"privateDefaultScopeId":                 llx.StringData(convert.ToValue(ipam.PrivateDefaultScopeId)),
		"scopeCount":                            llx.IntData(int64(convert.ToValue(ipam.ScopeCount))),
		"resourceDiscoveryAssociationCount":     llx.IntData(int64(convert.ToValue(ipam.ResourceDiscoveryAssociationCount))),
		"defaultResourceDiscoveryId":            llx.StringData(convert.ToValue(ipam.DefaultResourceDiscoveryId)),
		"defaultResourceDiscoveryAssociationId": llx.StringData(convert.ToValue(ipam.DefaultResourceDiscoveryAssociationId)),
		"tags":                                  llx.MapData(toInterfaceMap(ec2TagsToMap(ipam.Tags)), mqltypes.String),
	})
	if err != nil {
		return nil, err
	}
	out := mqlRes.(*mqlAwsEc2Ipam)
	out.homeRegion = region
	return out, nil
}

// initAwsEc2Ipam supports `aws.ec2.ipam(arn: "…")` direct lookups by
// deriving the home Region from the ARN and calling DescribeIpams once.
func initAwsEc2Ipam(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	arnRaw, ok := args["arn"]
	if !ok || arnRaw == nil || arnRaw.Value == nil {
		return args, nil, nil
	}
	arnVal, ok := arnRaw.Value.(string)
	if !ok || arnVal == "" {
		return args, nil, nil
	}
	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		return args, nil, nil
	}
	parts := strings.Split(arnVal, "/")
	if len(parts) < 2 {
		return args, nil, nil
	}
	id := parts[len(parts)-1]

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	ctx := context.Background()
	resp, err := svc.DescribeIpams(ctx, &ec2.DescribeIpamsInput{IpamIds: []string{id}})
	if err != nil {
		return nil, nil, classifyAwsError(fmt.Errorf("fetching aws.ec2.ipam with id %q in region %s: %w", id, region, err), "ec2:DescribeIpams")
	}
	if len(resp.Ipams) == 0 {
		return nil, nil, fmt.Errorf("aws.ec2.ipam with id %q not found", id)
	}

	mqlIpam, err := newMqlAwsEc2Ipam(runtime, region, &resp.Ipams[0])
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlIpam, nil
}

func (a *mqlAwsEc2Ipam) scopes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.homeRegion
	if region == "" {
		region = a.Region.Data
	}
	svc := conn.Ec2(region)
	ctx := context.Background()
	ipamId := a.Id.Data

	res := []any{}
	paginator := ec2.NewDescribeIpamScopesPaginator(svc, &ec2.DescribeIpamScopesInput{
		Filters: []types.Filter{{Name: stringPtr("ipam-id"), Values: []string{ipamId}}},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "ec2:DescribeIpamScopes")
		}
		for i := range page.IpamScopes {
			scope := page.IpamScopes[i]
			mqlScope, err := CreateResource(a.MqlRuntime, ResourceAwsEc2IpamScope, map[string]*llx.RawData{
				"id":          llx.StringData(convert.ToValue(scope.IpamScopeId)),
				"arn":         llx.StringData(convert.ToValue(scope.IpamScopeArn)),
				"ipamArn":     llx.StringData(convert.ToValue(scope.IpamArn)),
				"region":      llx.StringData(convert.ToValue(scope.IpamRegion)),
				"ownerId":     llx.StringData(convert.ToValue(scope.OwnerId)),
				"description": llx.StringData(convert.ToValue(scope.Description)),
				"type":        llx.StringData(string(scope.IpamScopeType)),
				"isDefault":   llx.BoolData(convert.ToValue(scope.IsDefault)),
				"poolCount":   llx.IntData(int64(convert.ToValue(scope.PoolCount))),
				"state":       llx.StringData(string(scope.State)),
				"tags":        llx.MapData(toInterfaceMap(ec2TagsToMap(scope.Tags)), mqltypes.String),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlScope)
		}
	}
	return res, nil
}

func (a *mqlAwsEc2Ipam) pools() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.homeRegion
	if region == "" {
		region = a.Region.Data
	}
	svc := conn.Ec2(region)
	ctx := context.Background()
	ipamId := a.Id.Data

	res := []any{}
	paginator := ec2.NewDescribeIpamPoolsPaginator(svc, &ec2.DescribeIpamPoolsInput{
		Filters: []types.Filter{{Name: stringPtr("owner-id"), Values: []string{a.OwnerId.Data}}, {Name: stringPtr("ipam-id"), Values: []string{ipamId}}},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "ec2:DescribeIpamPools")
		}
		for i := range page.IpamPools {
			pool := page.IpamPools[i]
			mqlPool, err := newMqlAwsEc2IpamPool(a.MqlRuntime, region, &pool)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPool)
		}
	}
	return res, nil
}

func newMqlAwsEc2IpamPool(runtime *plugin.Runtime, region string, pool *types.IpamPool) (*mqlAwsEc2IpamPool, error) {
	allocationTags := make([]any, 0, len(pool.AllocationResourceTags))
	for _, t := range pool.AllocationResourceTags {
		k := convert.ToValue(t.Key)
		v := convert.ToValue(t.Value)
		allocationTags = append(allocationTags, k+"="+v)
	}

	mqlRes, err := CreateResource(runtime, ResourceAwsEc2IpamPool, map[string]*llx.RawData{
		"id":                             llx.StringData(convert.ToValue(pool.IpamPoolId)),
		"arn":                            llx.StringData(convert.ToValue(pool.IpamPoolArn)),
		"ipamArn":                        llx.StringData(convert.ToValue(pool.IpamArn)),
		"ipamScopeArn":                   llx.StringData(convert.ToValue(pool.IpamScopeArn)),
		"ipamScopeType":                  llx.StringData(string(pool.IpamScopeType)),
		"region":                         llx.StringData(convert.ToValue(pool.IpamRegion)),
		"ownerId":                        llx.StringData(convert.ToValue(pool.OwnerId)),
		"description":                    llx.StringData(convert.ToValue(pool.Description)),
		"addressFamily":                  llx.StringData(string(pool.AddressFamily)),
		"locale":                         llx.StringData(convert.ToValue(pool.Locale)),
		"awsService":                     llx.StringData(string(pool.AwsService)),
		"state":                          llx.StringData(string(pool.State)),
		"stateMessage":                   llx.StringData(convert.ToValue(pool.StateMessage)),
		"publicIpSource":                 llx.StringData(string(pool.PublicIpSource)),
		"publiclyAdvertisable":           llx.BoolData(convert.ToValue(pool.PubliclyAdvertisable)),
		"autoImport":                     llx.BoolData(convert.ToValue(pool.AutoImport)),
		"allocationDefaultNetmaskLength": llx.IntData(int64(convert.ToValue(pool.AllocationDefaultNetmaskLength))),
		"allocationMinNetmaskLength":     llx.IntData(int64(convert.ToValue(pool.AllocationMinNetmaskLength))),
		"allocationMaxNetmaskLength":     llx.IntData(int64(convert.ToValue(pool.AllocationMaxNetmaskLength))),
		"poolDepth":                      llx.IntData(int64(convert.ToValue(pool.PoolDepth))),
		"sourceIpamPoolId":               llx.StringData(convert.ToValue(pool.SourceIpamPoolId)),
		"tags":                           llx.MapData(toInterfaceMap(ec2TagsToMap(pool.Tags)), mqltypes.String),
		"allocationResourceTags":         llx.ArrayData(allocationTags, mqltypes.String),
	})
	if err != nil {
		return nil, err
	}
	out := mqlRes.(*mqlAwsEc2IpamPool)
	out.homeRegion = region
	return out, nil
}

func (a *mqlAwsEc2IpamPool) allocations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.homeRegion
	if region == "" {
		region = a.Region.Data
	}
	svc := conn.Ec2(region)
	ctx := context.Background()
	poolId := a.Id.Data

	res := []any{}
	paginator := ec2.NewGetIpamPoolAllocationsPaginator(svc, &ec2.GetIpamPoolAllocationsInput{
		IpamPoolId: &poolId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "ec2:GetIpamPoolAllocations")
		}
		for i := range page.IpamPoolAllocations {
			alloc := page.IpamPoolAllocations[i]
			mqlAlloc, err := CreateResource(a.MqlRuntime, ResourceAwsEc2IpamPoolAllocation, map[string]*llx.RawData{
				"id":             llx.StringData(convert.ToValue(alloc.IpamPoolAllocationId)),
				"cidr":           llx.StringData(convert.ToValue(alloc.Cidr)),
				"description":    llx.StringData(convert.ToValue(alloc.Description)),
				"resourceId":     llx.StringData(convert.ToValue(alloc.ResourceId)),
				"resourceOwner":  llx.StringData(convert.ToValue(alloc.ResourceOwner)),
				"resourceRegion": llx.StringData(convert.ToValue(alloc.ResourceRegion)),
				"resourceType":   llx.StringData(string(alloc.ResourceType)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAlloc)
		}
	}
	return res, nil
}
