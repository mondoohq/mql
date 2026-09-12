// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"
	memorydb_types "github.com/aws/aws-sdk-go-v2/service/memorydb/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsMemorydb) id() (string, error) {
	return "aws.memorydb", nil
}

func (a *mqlAwsMemorydb) clusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getClusters(conn), 5)
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

func (a *mqlAwsMemorydb) getClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("memorydb>getClusters>calling aws with region %s", region)

			svc := conn.Memorydb(region)
			ctx := context.Background()
			res := []any{}

			paginator := memorydb.NewDescribeClustersPaginator(svc, &memorydb.DescribeClustersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("memorydb service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, cluster := range page.Clusters {
					mqlCluster, err := newMqlAwsMemorydbCluster(a.MqlRuntime, region, conn.AccountId(), cluster)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCluster)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsMemorydbCluster) id() (string, error) {
	return a.Arn.Data, nil
}

func initAwsMemorydbCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// During a discovered-asset scan the resource is queried with no args; recover
	// the cluster's region and name from the ARN carried on the asset.
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformMemorydbCluster); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch memorydb cluster")
	}

	arnVal := args["arn"].Value.(string)

	if cached := cachedByArn(runtime, ResourceAwsMemorydbCluster, arnVal); cached != nil {
		return args, cached, nil
	}

	parsed, err := arn.Parse(arnVal)
	if err != nil {
		return nil, nil, err
	}
	region := parsed.Region
	name := strings.TrimPrefix(parsed.Resource, "cluster/")

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Memorydb(region)
	ctx := context.Background()
	resp, err := svc.DescribeClusters(ctx, &memorydb.DescribeClustersInput{ClusterName: &name})
	if err != nil {
		return nil, nil, err
	}
	if len(resp.Clusters) == 0 {
		return nil, nil, errors.New("aws memorydb cluster not found: " + name)
	}

	mqlCluster, err := newMqlAwsMemorydbCluster(runtime, region, conn.AccountId(), resp.Clusters[0])
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlCluster, nil
}

func newMqlAwsMemorydbCluster(runtime *plugin.Runtime, region string, accountID string, cluster memorydb_types.Cluster) (*mqlAwsMemorydbCluster, error) {
	sgs := []string{}
	for _, sg := range cluster.SecurityGroups {
		if sg.SecurityGroupId != nil {
			sgs = append(sgs, NewSecurityGroupArn(region, accountID, convert.ToValue(sg.SecurityGroupId)))
		}
	}

	resource, err := CreateResource(runtime, "aws.memorydb.cluster",
		map[string]*llx.RawData{
			"__id":                    llx.StringDataPtr(cluster.ARN),
			"arn":                     llx.StringDataPtr(cluster.ARN),
			"name":                    llx.StringDataPtr(cluster.Name),
			"description":             llx.StringDataPtr(cluster.Description),
			"status":                  llx.StringDataPtr(cluster.Status),
			"nodeType":                llx.StringDataPtr(cluster.NodeType),
			"engine":                  llx.StringDataPtr(cluster.Engine),
			"engineVersion":           llx.StringDataPtr(cluster.EngineVersion),
			"enginePatchVersion":      llx.StringDataPtr(cluster.EnginePatchVersion),
			"numberOfShards":          llx.IntDataDefault(cluster.NumberOfShards, 0),
			"tlsEnabled":              llx.BoolDataPtr(cluster.TLSEnabled),
			"aclName":                 llx.StringDataPtr(cluster.ACLName),
			"parameterGroupName":      llx.StringDataPtr(cluster.ParameterGroupName),
			"subnetGroupName":         llx.StringDataPtr(cluster.SubnetGroupName),
			"snapshotRetentionLimit":  llx.IntDataDefault(cluster.SnapshotRetentionLimit, 0),
			"snapshotWindow":          llx.StringDataPtr(cluster.SnapshotWindow),
			"maintenanceWindow":       llx.StringDataPtr(cluster.MaintenanceWindow),
			"autoMinorVersionUpgrade": llx.BoolDataPtr(cluster.AutoMinorVersionUpgrade),
			"region":                  llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}

	mqlCluster := resource.(*mqlAwsMemorydbCluster)
	mqlCluster.cacheKmsKeyId = cluster.KmsKeyId
	mqlCluster.setSecurityGroupArns(sgs)
	return mqlCluster, nil
}

type mqlAwsMemorydbClusterInternal struct {
	securityGroupIdHandler
	cacheKmsKeyId *string
}

func (a *mqlAwsMemorydbCluster) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsMemorydbCluster) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsMemorydbCluster) tags() (map[string]any, error) {
	return memorydbListTags(a.MqlRuntime, a.Arn.Data, a.Region.Data)
}

func memorydbListTags(runtime *plugin.Runtime, arn string, region string) (map[string]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Memorydb(region)
	ctx := context.Background()

	resp, err := svc.ListTags(ctx, &memorydb.ListTagsInput{
		ResourceArn: &arn,
	})
	if err != nil {
		return nil, err
	}

	tags := make(map[string]any)
	for _, tag := range resp.TagList {
		if tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}
	return tags, nil
}

// acls lists all MemoryDB access control lists across all regions
func (a *mqlAwsMemorydb) acls() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAcls(conn), 5)
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

func (a *mqlAwsMemorydb) getAcls(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("memorydb>getAcls>calling aws with region %s", region)

			svc := conn.Memorydb(region)
			ctx := context.Background()
			res := []any{}

			paginator := memorydb.NewDescribeACLsPaginator(svc, &memorydb.DescribeACLsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("memorydb service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, acl := range page.ACLs {
					mqlAcl, err := newMqlAwsMemorydbAcl(a.MqlRuntime, region, acl)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlAcl)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsMemorydbAcl(runtime *plugin.Runtime, region string, acl memorydb_types.ACL) (*mqlAwsMemorydbAcl, error) {
	resource, err := CreateResource(runtime, "aws.memorydb.acl",
		map[string]*llx.RawData{
			"__id":                 llx.StringDataPtr(acl.ARN),
			"arn":                  llx.StringDataPtr(acl.ARN),
			"name":                 llx.StringDataPtr(acl.Name),
			"status":               llx.StringDataPtr(acl.Status),
			"userNames":            llx.ArrayData(convert.SliceAnyToInterface(acl.UserNames), types.String),
			"clusters":             llx.ArrayData(convert.SliceAnyToInterface(acl.Clusters), types.String),
			"minimumEngineVersion": llx.StringDataPtr(acl.MinimumEngineVersion),
			"region":               llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsMemorydbAcl), nil
}

func (a *mqlAwsMemorydbAcl) tags() (map[string]any, error) {
	return memorydbListTags(a.MqlRuntime, a.Arn.Data, a.Region.Data)
}

// users lists all MemoryDB users across all regions
func (a *mqlAwsMemorydb) users() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getUsers(conn), 5)
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

func (a *mqlAwsMemorydb) getUsers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("memorydb>getUsers>calling aws with region %s", region)

			svc := conn.Memorydb(region)
			ctx := context.Background()
			res := []any{}

			paginator := memorydb.NewDescribeUsersPaginator(svc, &memorydb.DescribeUsersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("memorydb service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, user := range page.Users {
					mqlUser, err := newMqlAwsMemorydbUser(a.MqlRuntime, region, user)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlUser)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsMemorydbUser(runtime *plugin.Runtime, region string, user memorydb_types.User) (*mqlAwsMemorydbUser, error) {
	auth, err := convert.JsonToDict(user.Authentication)
	if err != nil {
		return nil, err
	}
	mqlAuth := llx.NilData
	if user.Authentication != nil {
		authRes, err := CreateResource(runtime, "aws.memorydb.authentication", map[string]*llx.RawData{
			"__id":          llx.StringData(convert.ToValue(user.ARN) + "/authentication"),
			"type":          llx.StringData(string(user.Authentication.Type)),
			"passwordCount": llx.IntData(int64(convert.ToValue(user.Authentication.PasswordCount))),
		})
		if err != nil {
			return nil, err
		}
		mqlAuth = llx.ResourceData(authRes, "aws.memorydb.authentication")
	}

	resource, err := CreateResource(runtime, "aws.memorydb.user",
		map[string]*llx.RawData{
			"__id":                 llx.StringDataPtr(user.ARN),
			"arn":                  llx.StringDataPtr(user.ARN),
			"name":                 llx.StringDataPtr(user.Name),
			"status":               llx.StringDataPtr(user.Status),
			"accessString":         llx.StringDataPtr(user.AccessString),
			"aclNames":             llx.ArrayData(convert.SliceAnyToInterface(user.ACLNames), types.String),
			"minimumEngineVersion": llx.StringDataPtr(user.MinimumEngineVersion),
			"authentication":       llx.DictData(auth),
			"authenticationMode":   mqlAuth,
			"region":               llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsMemorydbUser), nil
}

func (a *mqlAwsMemorydbUser) tags() (map[string]any, error) {
	return memorydbListTags(a.MqlRuntime, a.Arn.Data, a.Region.Data)
}

// snapshots lists all MemoryDB snapshots across all regions
func (a *mqlAwsMemorydb) snapshots() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSnapshots(conn), 5)
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

func (a *mqlAwsMemorydb) getSnapshots(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("memorydb>getSnapshots>calling aws with region %s", region)

			svc := conn.Memorydb(region)
			ctx := context.Background()
			res := []any{}

			paginator := memorydb.NewDescribeSnapshotsPaginator(svc, &memorydb.DescribeSnapshotsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("memorydb service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, snapshot := range page.Snapshots {
					mqlSnapshot, err := newMqlAwsMemorydbSnapshot(a.MqlRuntime, region, snapshot)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSnapshot)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsMemorydbSnapshot(runtime *plugin.Runtime, region string, snapshot memorydb_types.Snapshot) (*mqlAwsMemorydbSnapshot, error) {
	clusterConfig, err := convert.JsonToDict(snapshot.ClusterConfiguration)
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, "aws.memorydb.snapshot",
		map[string]*llx.RawData{
			"__id":                 llx.StringDataPtr(snapshot.ARN),
			"arn":                  llx.StringDataPtr(snapshot.ARN),
			"name":                 llx.StringDataPtr(snapshot.Name),
			"status":               llx.StringDataPtr(snapshot.Status),
			"source":               llx.StringDataPtr(snapshot.Source),
			"clusterConfiguration": llx.DictData(clusterConfig),
			"dataTiering":          llx.StringData(string(snapshot.DataTiering)),
			"region":               llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlSnapshot := resource.(*mqlAwsMemorydbSnapshot)
	mqlSnapshot.cacheKmsKeyId = snapshot.KmsKeyId
	return mqlSnapshot, nil
}

type mqlAwsMemorydbSnapshotInternal struct {
	cacheKmsKeyId *string
}

func (a *mqlAwsMemorydbSnapshot) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsMemorydbSnapshot) tags() (map[string]any, error) {
	return memorydbListTags(a.MqlRuntime, a.Arn.Data, a.Region.Data)
}

// subnetGroups lists all MemoryDB subnet groups across all regions
func (a *mqlAwsMemorydb) subnetGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSubnetGroups(conn), 5)
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

func (a *mqlAwsMemorydb) getSubnetGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("memorydb>getSubnetGroups>calling aws with region %s", region)

			svc := conn.Memorydb(region)
			ctx := context.Background()
			res := []any{}

			paginator := memorydb.NewDescribeSubnetGroupsPaginator(svc, &memorydb.DescribeSubnetGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("memorydb service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, sg := range page.SubnetGroups {
					mqlSG, err := newMqlAwsMemorydbSubnetGroup(a.MqlRuntime, region, conn.AccountId(), sg)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSG)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsMemorydbSubnetGroup(runtime *plugin.Runtime, region string, accountID string, sg memorydb_types.SubnetGroup) (*mqlAwsMemorydbSubnetGroup, error) {
	resource, err := CreateResource(runtime, "aws.memorydb.subnetGroup",
		map[string]*llx.RawData{
			"__id":        llx.StringDataPtr(sg.ARN),
			"arn":         llx.StringDataPtr(sg.ARN),
			"name":        llx.StringDataPtr(sg.Name),
			"description": llx.StringDataPtr(sg.Description),
			"region":      llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlSG := resource.(*mqlAwsMemorydbSubnetGroup)
	mqlSG.cacheVpcId = sg.VpcId
	mqlSG.cacheSubnets = sg.Subnets
	mqlSG.region = region
	mqlSG.accountID = accountID
	return mqlSG, nil
}

type mqlAwsMemorydbSubnetGroupInternal struct {
	cacheVpcId   *string
	cacheSubnets []memorydb_types.Subnet
	region       string
	accountID    string
}

func (a *mqlAwsMemorydbSubnetGroup) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlVpc, err := NewResource(a.MqlRuntime, "aws.vpc",
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.region, a.accountID, *a.cacheVpcId)),
		})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

func (a *mqlAwsMemorydbSubnetGroup) subnets() ([]any, error) {
	res := []any{}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	for _, subnet := range a.cacheSubnets {
		if subnet.Identifier == nil {
			continue
		}
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, conn.AccountId(), convert.ToValue(subnet.Identifier))),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsMemorydbSubnetGroup) tags() (map[string]any, error) {
	return memorydbListTags(a.MqlRuntime, a.Arn.Data, a.Region.Data)
}
