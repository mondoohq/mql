// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticache_types "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsElasticache) id() (string, error) {
	return "aws.elasticache", nil
}

func (a *mqlAwsElasticache) cacheClusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCacheClusters(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for _, job := range poolOfJobs.Jobs {
		if job.Result != nil {
			res = append(res, job.Result.([]any)...)
		}
	}

	return res, nil
}

func (a *mqlAwsElasticache) getCacheClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("elasticache>getCacheClusters>calling aws with region %s", region)

			svc := conn.Elasticache(region)
			ctx := context.Background()
			res := []any{}

			// "By default, abbreviated information about the clusters is
			// returned. You can use the optional ShowCacheNodeInfo flag to
			// retrieve detailed information about the cache nodes." Without it
			// CacheNodes is always empty, so aws.elasticache.cluster.cacheNodes
			// reported [] for every cluster.
			params := &elasticache.DescribeCacheClustersInput{ShowCacheNodeInfo: aws.Bool(true)}
			paginator := elasticache.NewDescribeCacheClustersPaginator(svc, params)
			for paginator.HasMorePages() {
				clusters, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("elasticache service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, cluster := range clusters.CacheClusters {
					mqlCluster, err := newMqlAwsElasticacheCluster(a.MqlRuntime, region, conn.AccountId(), cluster)
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

type mqlAwsElasticacheClusterInternal struct {
	securityGroupIdHandler
	cacheReplicationGroupId *string
	region                  string
}

// elasticacheSecurityGroupArns builds the security group arns for a cache
// cluster, skipping any membership the API reports without an id. Every value
// it reads is optional, including the cluster id it logs the skip with.
func elasticacheSecurityGroupArns(region, accountID string, cluster elasticache_types.CacheCluster) []string {
	sgs := []string{}
	for _, sg := range cluster.SecurityGroups {
		if sg.SecurityGroupId == nil {
			log.Debug().Msgf("elasticache>newMqlAwsElasticacheCluster>missing security group id for cluster %s", convert.ToValue(cluster.CacheClusterId))
			continue
		}
		sgs = append(sgs, NewSecurityGroupArn(region, accountID, convert.ToValue(sg.SecurityGroupId)))
	}
	return sgs
}

func newMqlAwsElasticacheCluster(runtime *plugin.Runtime, region string, accountID string, cluster elasticache_types.CacheCluster) (*mqlAwsElasticacheCluster, error) {
	cacheNodes := []any{}
	for i := range cluster.CacheNodes {
		cacheNodes = append(cacheNodes, convert.ToValue(cluster.CacheNodes[i].CacheNodeId))
	}
	cacheSecurityGroups := []any{}
	for _, sg := range cluster.CacheSecurityGroups {
		cacheSecurityGroups = append(cacheSecurityGroups, convert.ToValue(sg.CacheSecurityGroupName))
	}
	logDeliveryConfigurations, err := convert.JsonToDictSlice(cluster.LogDeliveryConfigurations)
	if err != nil {
		return nil, err
	}
	var notificationConfiguration string
	if cluster.NotificationConfiguration != nil {
		notificationConfiguration = convert.ToValue(cluster.NotificationConfiguration.TopicArn)
	}

	cacheParameterGroupName := ""
	if cluster.CacheParameterGroup != nil {
		cacheParameterGroupName = convert.ToValue(cluster.CacheParameterGroup.CacheParameterGroupName)
	}

	configurationEndpointAddress := ""
	configurationEndpointPort := int64(0)
	if cluster.ConfigurationEndpoint != nil {
		configurationEndpointAddress = convert.ToValue(cluster.ConfigurationEndpoint.Address)
		configurationEndpointPort = int64(convert.ToValue(cluster.ConfigurationEndpoint.Port))
	}

	sgs := elasticacheSecurityGroupArns(region, accountID, cluster)

	resource, err := CreateResource(runtime, "aws.elasticache.cluster",
		map[string]*llx.RawData{
			"__id":                               llx.StringDataPtr(cluster.ARN),
			"arn":                                llx.StringDataPtr(cluster.ARN),
			"atRestEncryptionEnabled":            llx.BoolDataPtr(cluster.AtRestEncryptionEnabled),
			"authTokenEnabled":                   llx.BoolDataPtr(cluster.AuthTokenEnabled),
			"authTokenLastModifiedDate":          llx.TimeDataPtr(cluster.AuthTokenLastModifiedDate),
			"autoMinorVersionUpgrade":            llx.BoolDataPtr(cluster.AutoMinorVersionUpgrade),
			"cacheClusterCreateTime":             llx.TimeDataPtr(cluster.CacheClusterCreateTime),
			"cacheClusterId":                     llx.StringDataPtr(cluster.CacheClusterId),
			"cacheClusterStatus":                 llx.StringDataPtr(cluster.CacheClusterStatus),
			"cacheNodeType":                      llx.StringDataPtr(cluster.CacheNodeType),
			"cacheNodes":                         llx.ArrayData(cacheNodes, types.String),
			"cacheSecurityGroups":                llx.ArrayData(cacheSecurityGroups, types.String),
			"cacheSubnetGroupName":               llx.StringDataPtr(cluster.CacheSubnetGroupName),
			"clientDownloadLandingPage":          llx.StringDataPtr(cluster.ClientDownloadLandingPage),
			"nodeType":                           llx.StringDataPtr(cluster.CacheNodeType),
			"engine":                             llx.StringDataPtr(cluster.Engine),
			"engineVersion":                      llx.StringDataPtr(cluster.EngineVersion),
			"ipDiscovery":                        llx.StringData(string(cluster.IpDiscovery)),
			"logDeliveryConfigurations":          llx.ArrayData(logDeliveryConfigurations, types.Any),
			"networkType":                        llx.StringData(string(cluster.NetworkType)),
			"notificationConfiguration":          llx.StringData(notificationConfiguration),
			"numCacheNodes":                      llx.IntDataDefault(cluster.NumCacheNodes, 0),
			"preferredAvailabilityZone":          llx.StringDataPtr(cluster.PreferredAvailabilityZone),
			"region":                             llx.StringData(region),
			"snapshotRetentionLimit":             llx.IntDataDefault(cluster.SnapshotRetentionLimit, 0),
			"snapshotWindow":                     llx.StringDataPtr(cluster.SnapshotWindow),
			"transitEncryptionEnabled":           llx.BoolDataPtr(cluster.TransitEncryptionEnabled),
			"transitEncryptionMode":              llx.StringData(string(cluster.TransitEncryptionMode)),
			"preferredMaintenanceWindow":         llx.StringDataPtr(cluster.PreferredMaintenanceWindow),
			"replicationGroupLogDeliveryEnabled": llx.BoolDataPtr(cluster.ReplicationGroupLogDeliveryEnabled),
			"replicationGroupId":                 llx.StringDataPtr(cluster.ReplicationGroupId),
			"cacheParameterGroupName":            llx.StringData(cacheParameterGroupName),
			"configurationEndpointAddress":       llx.StringData(configurationEndpointAddress),
			"configurationEndpointPort":          llx.IntData(configurationEndpointPort),
		})
	if err != nil {
		return nil, err
	}

	mqlCluster := resource.(*mqlAwsElasticacheCluster)
	mqlCluster.setSecurityGroupArns(sgs)
	mqlCluster.cacheReplicationGroupId = cluster.ReplicationGroupId
	mqlCluster.region = region
	return mqlCluster, nil
}

func (a *mqlAwsElasticacheCluster) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsElasticacheCluster) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Elasticache(a.region)
	ctx := context.Background()
	arnVal := a.Arn.Data

	resp, err := svc.ListTagsForResource(ctx, &elasticache.ListTagsForResourceInput{
		ResourceName: &arnVal,
	})
	if err != nil {
		return nil, classifyAwsError(err, "elasticache:ListTagsForResource")
	}
	tags := make(map[string]any)
	for _, t := range resp.TagList {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

func elasticacheTagsToMap(tags []elasticache_types.Tag) map[string]any {
	return tagsToMap(tags,
		func(t elasticache_types.Tag) *string { return t.Key },
		func(t elasticache_types.Tag) *string { return t.Value })
}

// elasticacheTagsForArn reads the tags of any ElastiCache resource. None of the
// describe responses carry tags, so every resource resolves them here.
func elasticacheTagsForArn(runtime *plugin.Runtime, region, resourceArn string) (map[string]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Elasticache(region)
	resp, err := svc.ListTagsForResource(context.Background(), &elasticache.ListTagsForResourceInput{
		ResourceName: &resourceArn,
	})
	if err != nil {
		return nil, classifyAwsError(err, "elasticache:ListTagsForResource")
	}
	return elasticacheTagsToMap(resp.TagList), nil
}

func (a *mqlAwsElasticacheCluster) kmsKey() (*mqlAwsKmsKey, error) {
	// The KMS key protecting a cluster's data at rest lives on its replication
	// group, so delegate through the group rather than fetching replication
	// groups a second time. A cluster with no replication group has no key.
	if a.cacheReplicationGroupId == nil || *a.cacheReplicationGroupId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	rg := a.GetReplicationGroup()
	if rg.Error != nil {
		return nil, rg.Error
	}
	if rg.Data == nil {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	key := rg.Data.GetKmsKey()
	if key.Error != nil {
		return nil, key.Error
	}
	if key.Data == nil {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return key.Data, nil
}

func (a *mqlAwsElasticacheCluster) notificationTopic() (*mqlAwsSnsTopic, error) {
	arnVal := a.NotificationConfiguration.Data
	if arnVal == "" {
		a.NotificationTopic.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sns.topic",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSnsTopic), nil
}

func (a *mqlAwsElasticacheCluster) subnetGroup() (*mqlAwsElasticacheSubnetGroup, error) {
	name := a.CacheSubnetGroupName.Data
	if name == "" {
		a.SubnetGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	parent, err := CreateResource(a.MqlRuntime, "aws.elasticache", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	groups := parent.(*mqlAwsElasticache).GetSubnetGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}
	for _, g := range groups.Data {
		sg := g.(*mqlAwsElasticacheSubnetGroup)
		if sg.Name.Data == name && sg.Region.Data == a.region {
			return sg, nil
		}
	}
	a.SubnetGroup.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsElasticacheCluster) parameterGroup() (*mqlAwsElasticacheParameterGroup, error) {
	name := a.CacheParameterGroupName.Data
	if name == "" {
		a.ParameterGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	parent, err := CreateResource(a.MqlRuntime, "aws.elasticache", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	groups := parent.(*mqlAwsElasticache).GetParameterGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}
	for _, g := range groups.Data {
		pg := g.(*mqlAwsElasticacheParameterGroup)
		if pg.Name.Data == name && pg.Region.Data == a.region {
			return pg, nil
		}
	}
	a.ParameterGroup.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsElasticacheCluster) replicationGroup() (*mqlAwsElasticacheReplicationGroup, error) {
	if a.cacheReplicationGroupId == nil || *a.cacheReplicationGroupId == "" {
		a.ReplicationGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	parent, err := CreateResource(a.MqlRuntime, "aws.elasticache", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	rgs := parent.(*mqlAwsElasticache).GetReplicationGroups()
	if rgs.Error != nil {
		return nil, rgs.Error
	}
	for _, r := range rgs.Data {
		rg := r.(*mqlAwsElasticacheReplicationGroup)
		if rg.ReplicationGroupId.Data == *a.cacheReplicationGroupId && rg.Region.Data == a.region {
			return rg, nil
		}
	}
	a.ReplicationGroup.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsElasticache) replicationGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getReplicationGroups(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for _, job := range poolOfJobs.Jobs {
		if job.Result != nil {
			res = append(res, job.Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsElasticache) getReplicationGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Elasticache(region)
			ctx := context.Background()
			res := []any{}

			paginator := elasticache.NewDescribeReplicationGroupsPaginator(svc, &elasticache.DescribeReplicationGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("elasticache service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, rg := range page.ReplicationGroups {
					mqlRg, err := newMqlAwsElasticacheReplicationGroup(a.MqlRuntime, region, rg)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsElasticacheReplicationGroupInternal struct {
	lazyTags
	cacheKmsKeyId       *string
	cacheMemberClusters []string
}

func (a *mqlAwsElasticacheReplicationGroup) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return elasticacheTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

func newMqlAwsElasticacheReplicationGroup(runtime *plugin.Runtime, region string, rg elasticache_types.ReplicationGroup) (*mqlAwsElasticacheReplicationGroup, error) {
	nodeGroups, err := convert.JsonToDictSlice(rg.NodeGroups)
	if err != nil {
		return nil, err
	}
	logDeliveryConfigurations, err := convert.JsonToDictSlice(rg.LogDeliveryConfigurations)
	if err != nil {
		return nil, err
	}
	configurationEndpoint, err := convert.JsonToDict(rg.ConfigurationEndpoint)
	if err != nil {
		return nil, err
	}
	globalReplicationGroupInfo, err := convert.JsonToDict(rg.GlobalReplicationGroupInfo)
	if err != nil {
		return nil, err
	}
	pendingModifiedValues, err := convert.JsonToDict(rg.PendingModifiedValues)
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, "aws.elasticache.replicationGroup",
		map[string]*llx.RawData{
			"__id":                       llx.StringDataPtr(rg.ARN),
			"arn":                        llx.StringDataPtr(rg.ARN),
			"replicationGroupId":         llx.StringDataPtr(rg.ReplicationGroupId),
			"region":                     llx.StringData(region),
			"description":                llx.StringDataPtr(rg.Description),
			"status":                     llx.StringDataPtr(rg.Status),
			"engine":                     llx.StringDataPtr(rg.Engine),
			"cacheNodeType":              llx.StringDataPtr(rg.CacheNodeType),
			"clusterEnabled":             llx.BoolDataPtr(rg.ClusterEnabled),
			"clusterMode":                llx.StringData(string(rg.ClusterMode)),
			"automaticFailover":          llx.StringData(string(rg.AutomaticFailover)),
			"multiAZ":                    llx.StringData(string(rg.MultiAZ)),
			"dataTiering":                llx.StringData(string(rg.DataTiering)),
			"atRestEncryptionEnabled":    llx.BoolDataPtr(rg.AtRestEncryptionEnabled),
			"transitEncryptionEnabled":   llx.BoolDataPtr(rg.TransitEncryptionEnabled),
			"transitEncryptionMode":      llx.StringData(string(rg.TransitEncryptionMode)),
			"authTokenEnabled":           llx.BoolDataPtr(rg.AuthTokenEnabled),
			"authTokenLastModifiedAt":    llx.TimeDataPtr(rg.AuthTokenLastModifiedDate),
			"autoMinorVersionUpgrade":    llx.BoolDataPtr(rg.AutoMinorVersionUpgrade),
			"snapshotRetentionLimit":     llx.IntDataDefault(rg.SnapshotRetentionLimit, 0),
			"snapshotWindow":             llx.StringDataPtr(rg.SnapshotWindow),
			"snapshottingClusterId":      llx.StringDataPtr(rg.SnapshottingClusterId),
			"replicationGroupCreatedAt":  llx.TimeDataPtr(rg.ReplicationGroupCreateTime),
			"userGroupIds":               llx.ArrayData(convert.SliceAnyToInterface(rg.UserGroupIds), types.String),
			"networkType":                llx.StringData(string(rg.NetworkType)),
			"ipDiscovery":                llx.StringData(string(rg.IpDiscovery)),
			"storageEncryptionType":      llx.StringData(string(rg.StorageEncryptionType)),
			"durability":                 llx.StringData(string(rg.Durability)),
			"effectiveDurability":        llx.StringData(string(rg.EffectiveDurability)),
			"configurationEndpoint":      llx.DictData(configurationEndpoint),
			"globalReplicationGroupInfo": llx.DictData(globalReplicationGroupInfo),
			"nodeGroups":                 llx.ArrayData(nodeGroups, types.Any),
			"logDeliveryConfigurations":  llx.ArrayData(logDeliveryConfigurations, types.Any),
			"pendingModifiedValues":      llx.DictData(pendingModifiedValues),
		})
	if err != nil {
		return nil, err
	}
	mqlRg := resource.(*mqlAwsElasticacheReplicationGroup)
	mqlRg.cacheKmsKeyId = rg.KmsKeyId
	mqlRg.cacheMemberClusters = rg.MemberClusters
	return mqlRg, nil
}

func (a *mqlAwsElasticacheReplicationGroup) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsElasticacheReplicationGroup) memberClusters() ([]any, error) {
	if len(a.cacheMemberClusters) == 0 {
		return []any{}, nil
	}
	parent, err := CreateResource(a.MqlRuntime, "aws.elasticache", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	clusters := parent.(*mqlAwsElasticache).GetCacheClusters()
	if clusters.Error != nil {
		return nil, clusters.Error
	}
	wanted := map[string]struct{}{}
	for _, id := range a.cacheMemberClusters {
		wanted[id] = struct{}{}
	}
	res := []any{}
	for _, c := range clusters.Data {
		cluster := c.(*mqlAwsElasticacheCluster)
		if _, ok := wanted[cluster.CacheClusterId.Data]; ok && cluster.Region.Data == a.Region.Data {
			res = append(res, cluster)
		}
	}
	return res, nil
}

func (a *mqlAwsElasticacheReplicationGroup) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsElasticache) serverlessCaches() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getServerlessCaches(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}

	return res, nil
}

func (a *mqlAwsElasticache) getServerlessCaches(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("elasticache>getServerlessClusters>calling aws with region %s", region)

			svc := conn.Elasticache(region)
			ctx := context.Background()
			res := []any{}

			params := &elasticache.DescribeServerlessCachesInput{}
			paginator := elasticache.NewDescribeServerlessCachesPaginator(svc, params)
			for paginator.HasMorePages() {
				caches, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("elasticache service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, cache := range caches.ServerlessCaches {
					mqlCache, err := newMqlAwsElasticacheServerlessCache(a.MqlRuntime, region, conn.AccountId(), cache)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCache)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsElasticacheServerlessCacheInternal struct {
	securityGroupIdHandler
	lazyTags
	region        string
	accountID     string
	subnetIds     []string
	cacheKmsKeyId *string
}

func (a *mqlAwsElasticacheServerlessCache) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return elasticacheTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

func newMqlAwsElasticacheServerlessCache(runtime *plugin.Runtime, region string, accountID string, cache elasticache_types.ServerlessCache) (*mqlAwsElasticacheServerlessCache, error) {
	sgArgs := []string{}
	for i := range cache.SecurityGroupIds {
		sgId := cache.SecurityGroupIds[i]
		sgArgs = append(sgArgs, NewSecurityGroupArn(region, accountID, sgId))
	}

	resource, err := CreateResource(runtime, "aws.elasticache.serverlessCache",
		map[string]*llx.RawData{
			"__id":                   llx.StringDataPtr(cache.ARN),
			"arn":                    llx.StringDataPtr(cache.ARN),
			"name":                   llx.StringDataPtr(cache.ServerlessCacheName),
			"description":            llx.StringDataPtr(cache.Description),
			"engine":                 llx.StringDataPtr(cache.Engine),
			"engineVersion":          llx.StringDataPtr(cache.FullEngineVersion),
			"majorEngineVersion":     llx.StringDataPtr(cache.MajorEngineVersion),
			"region":                 llx.StringData(region),
			"snapshotRetentionLimit": llx.IntDataDefault(cache.SnapshotRetentionLimit, 0),
			"dailySnapshotTime":      llx.StringDataPtr(cache.DailySnapshotTime),
			"createdAt":              llx.TimeDataPtr(cache.CreateTime),
			"status":                 llx.StringDataPtr(cache.Status),
		})
	if err != nil {
		return nil, err
	}

	mqlCache := resource.(*mqlAwsElasticacheServerlessCache)
	mqlCache.setSecurityGroupArns(sgArgs)
	mqlCache.region = region
	mqlCache.accountID = accountID
	mqlCache.subnetIds = cache.SubnetIds
	mqlCache.cacheKmsKeyId = cache.KmsKeyId
	return mqlCache, nil
}

func (a *mqlAwsElasticacheServerlessCache) kmsKey() (*mqlAwsKmsKey, error) {
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

func (a *mqlAwsElasticacheServerlessCache) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsElasticacheServerlessCache) subnets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, subnetId := range a.subnetIds {
		mqlSubnet, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, conn.AccountId(), subnetId)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func initAwsElasticacheCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformElasticacheCluster); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch elasticache cluster")
	}

	obj, err := CreateResource(runtime, "aws.elasticache", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	ec := obj.(*mqlAwsElasticache)
	rawResources := ec.GetCacheClusters()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal, ok := args["arn"].Value.(string)
	if !ok {
		return nil, nil, errors.New("arn must be a string")
	}
	for _, rawResource := range rawResources.Data {
		cluster := rawResource.(*mqlAwsElasticacheCluster)
		if cluster.Arn.Data == arnVal {
			return args, cluster, nil
		}
	}
	return nil, nil, errors.New("elasticache cluster does not exist")
}

// ── Parameter Groups ────────────────────────────────────────────────────────

func (a *mqlAwsElasticache) parameterGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getParameterGroups(conn), 5)
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

func (a *mqlAwsElasticache) getParameterGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Elasticache(region)
			ctx := context.Background()
			res := []any{}
			paginator := elasticache.NewDescribeCacheParameterGroupsPaginator(svc, &elasticache.DescribeCacheParameterGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, pg := range page.CacheParameterGroups {
					mqlPg, err := CreateResource(a.MqlRuntime, ResourceAwsElasticacheParameterGroup,
						map[string]*llx.RawData{
							"arn":         llx.StringDataPtr(pg.ARN),
							"name":        llx.StringDataPtr(pg.CacheParameterGroupName),
							"region":      llx.StringData(region),
							"family":      llx.StringDataPtr(pg.CacheParameterGroupFamily),
							"description": llx.StringDataPtr(pg.Description),
							"isGlobal":    llx.BoolDataPtr(pg.IsGlobal),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsElasticacheParameterGroupInternal struct {
	lazyTags
}

func (a *mqlAwsElasticacheParameterGroup) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsElasticacheParameterGroup) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return elasticacheTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

// ── Subnet Groups ───────────────────────────────────────────────────────────

func (a *mqlAwsElasticache) subnetGroups() ([]any, error) {
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

func (a *mqlAwsElasticache) getSubnetGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Elasticache(region)
			ctx := context.Background()
			res := []any{}
			paginator := elasticache.NewDescribeCacheSubnetGroupsPaginator(svc, &elasticache.DescribeCacheSubnetGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, sg := range page.CacheSubnetGroups {
					subnets, err := convert.JsonToDictSlice(sg.Subnets)
					if err != nil {
						return nil, err
					}
					netTypes := make([]any, len(sg.SupportedNetworkTypes))
					for i, t := range sg.SupportedNetworkTypes {
						netTypes[i] = string(t)
					}
					mqlSg, err := CreateResource(a.MqlRuntime, ResourceAwsElasticacheSubnetGroup,
						map[string]*llx.RawData{
							"arn":                   llx.StringDataPtr(sg.ARN),
							"name":                  llx.StringDataPtr(sg.CacheSubnetGroupName),
							"region":                llx.StringData(region),
							"description":           llx.StringDataPtr(sg.CacheSubnetGroupDescription),
							"subnets":               llx.ArrayData(subnets, types.Dict),
							"supportedNetworkTypes": llx.ArrayData(netTypes, types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlSgRes := mqlSg.(*mqlAwsElasticacheSubnetGroup)
					mqlSgRes.cacheVpcId = sg.VpcId
					res = append(res, mqlSgRes)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsElasticacheSubnetGroupInternal struct {
	lazyTags
	cacheVpcId *string
}

func (a *mqlAwsElasticacheSubnetGroup) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return elasticacheTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

func (a *mqlAwsElasticacheSubnetGroup) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsElasticacheSubnetGroup) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	vpcArn := fmt.Sprintf(vpcArnPattern, region, conn.AccountId(), *a.cacheVpcId)
	res, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{"arn": llx.StringData(vpcArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

// ── Users ───────────────────────────────────────────────────────────────────

func (a *mqlAwsElasticache) users() ([]any, error) {
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

func (a *mqlAwsElasticache) getUsers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Elasticache(region)
			ctx := context.Background()
			res := []any{}
			paginator := elasticache.NewDescribeUsersPaginator(svc, &elasticache.DescribeUsersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, user := range page.Users {
					groupIds := make([]any, len(user.UserGroupIds))
					for i, g := range user.UserGroupIds {
						groupIds[i] = g
					}
					auth, err := convert.JsonToDict(user.Authentication)
					if err != nil {
						return nil, err
					}
					mqlAuth := llx.NilData
					if user.Authentication != nil {
						authRes, err := CreateResource(a.MqlRuntime, "aws.elasticache.authentication", map[string]*llx.RawData{
							"__id":          llx.StringData(convert.ToValue(user.ARN) + "/authentication"),
							"type":          llx.StringData(string(user.Authentication.Type)),
							"passwordCount": llx.IntData(int64(convert.ToValue(user.Authentication.PasswordCount))),
						})
						if err != nil {
							return nil, err
						}
						mqlAuth = llx.ResourceData(authRes, "aws.elasticache.authentication")
					}
					mqlUser, err := CreateResource(a.MqlRuntime, ResourceAwsElasticacheUser,
						map[string]*llx.RawData{
							"arn":                  llx.StringDataPtr(user.ARN),
							"userId":               llx.StringDataPtr(user.UserId),
							"userName":             llx.StringDataPtr(user.UserName),
							"region":               llx.StringData(region),
							"accessString":         llx.StringDataPtr(user.AccessString),
							"engine":               llx.StringDataPtr(user.Engine),
							"minimumEngineVersion": llx.StringDataPtr(user.MinimumEngineVersion),
							"status":               llx.StringDataPtr(user.Status),
							"userGroupIds":         llx.ArrayData(groupIds, types.String),
							"authentication":       llx.DictData(auth),
							"authenticationMode":   mqlAuth,
						})
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

type mqlAwsElasticacheUserInternal struct {
	lazyTags
}

func (a *mqlAwsElasticacheUser) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsElasticacheUser) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return elasticacheTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

// ── Service Updates ─────────────────────────────────────────────────────────

func (a *mqlAwsElasticache) serviceUpdates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regions, err := conn.Regions()
	if err != nil {
		return nil, err
	}
	if len(regions) == 0 {
		return nil, nil
	}
	// Service updates are global; fetch from the first available region.
	region := regions[0]
	svc := conn.Elasticache(region)
	ctx := context.Background()
	res := []any{}
	paginator := elasticache.NewDescribeServiceUpdatesPaginator(svc, &elasticache.DescribeServiceUpdatesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "elasticache:DescribeServiceUpdates")
		}
		for _, su := range page.ServiceUpdates {
			mqlSu, err := CreateResource(a.MqlRuntime, ResourceAwsElasticacheServiceUpdate,
				map[string]*llx.RawData{
					"__id":                                  llx.StringData(fmt.Sprintf("elasticache/serviceupdate/%s", convert.ToValue(su.ServiceUpdateName))),
					"name":                                  llx.StringDataPtr(su.ServiceUpdateName),
					"region":                                llx.StringData(region),
					"description":                           llx.StringDataPtr(su.ServiceUpdateDescription),
					"engine":                                llx.StringDataPtr(su.Engine),
					"engineVersion":                         llx.StringDataPtr(su.EngineVersion),
					"severity":                              llx.StringData(string(su.ServiceUpdateSeverity)),
					"status":                                llx.StringData(string(su.ServiceUpdateStatus)),
					"updateType":                            llx.StringData(string(su.ServiceUpdateType)),
					"releaseDate":                           llx.TimeDataPtr(su.ServiceUpdateReleaseDate),
					"recommendedApplyByDate":                llx.TimeDataPtr(su.ServiceUpdateRecommendedApplyByDate),
					"endDate":                               llx.TimeDataPtr(su.ServiceUpdateEndDate),
					"estimatedUpdateTime":                   llx.StringDataPtr(su.EstimatedUpdateTime),
					"autoUpdateAfterRecommendedApplyByDate": llx.BoolDataPtr(su.AutoUpdateAfterRecommendedApplyByDate),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSu)
		}
	}
	return res, nil
}

func (a *mqlAwsElasticacheServiceUpdate) id() (string, error) {
	return a.__id, nil
}

// ── Snapshots ───────────────────────────────────────────────────────────────

func (a *mqlAwsElasticache) snapshots() ([]any, error) {
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

func (a *mqlAwsElasticache) getSnapshots(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Elasticache(region)
			ctx := context.Background()
			res := []any{}
			paginator := elasticache.NewDescribeSnapshotsPaginator(svc, &elasticache.DescribeSnapshotsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, snap := range page.Snapshots {
					mqlSnap, err := CreateResource(a.MqlRuntime, ResourceAwsElasticacheSnapshot,
						map[string]*llx.RawData{
							"arn":                    llx.StringDataPtr(snap.ARN),
							"name":                   llx.StringDataPtr(snap.SnapshotName),
							"region":                 llx.StringData(region),
							"cacheClusterId":         llx.StringDataPtr(snap.CacheClusterId),
							"replicationGroupId":     llx.StringDataPtr(snap.ReplicationGroupId),
							"status":                 llx.StringDataPtr(snap.SnapshotStatus),
							"snapshotSource":         llx.StringDataPtr(snap.SnapshotSource),
							"engine":                 llx.StringDataPtr(snap.Engine),
							"engineVersion":          llx.StringDataPtr(snap.EngineVersion),
							"cacheNodeType":          llx.StringDataPtr(snap.CacheNodeType),
							"numCacheNodes":          llx.IntDataDefault(snap.NumCacheNodes, 0),
							"snapshotRetentionLimit": llx.IntDataDefault(snap.SnapshotRetentionLimit, 0),
							"cacheClusterCreatedAt":  llx.TimeDataPtr(snap.CacheClusterCreateTime),
						})
					if err != nil {
						return nil, err
					}
					mqlSnapRes := mqlSnap.(*mqlAwsElasticacheSnapshot)
					mqlSnapRes.cacheKmsKeyId = snap.KmsKeyId
					mqlSnapRes.cacheVpcId = snap.VpcId
					res = append(res, mqlSnapRes)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsElasticacheSnapshotInternal struct {
	lazyTags
	cacheKmsKeyId *string
	cacheVpcId    *string
}

func (a *mqlAwsElasticacheSnapshot) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return elasticacheTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

func (a *mqlAwsElasticacheSnapshot) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsElasticacheSnapshot) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsElasticacheSnapshot) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	vpcArn := fmt.Sprintf(vpcArnPattern, region, conn.AccountId(), *a.cacheVpcId)
	res, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{"arn": llx.StringData(vpcArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}
