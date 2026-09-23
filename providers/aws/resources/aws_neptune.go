// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptune_types "github.com/aws/aws-sdk-go-v2/service/neptune/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsNeptune) id() (string, error) {
	return "aws.neptune", nil
}

func (a *mqlAwsNeptune) clusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDbClusters(conn), 5)
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

func (a *mqlAwsNeptune) getDbClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("neptune>getDbClusters>calling aws with region %s", region)

			svc := conn.Neptune(region)
			ctx := context.Background()
			res := []any{}

			params := &neptune.DescribeDBClustersInput{
				Filters: []neptune_types.Filter{
					{
						// we need to filter by engine since the neptune client also returns rds instances - rofl
						Name:   aws.String("engine"),
						Values: []string{"neptune"},
					},
				},
			}
			paginator := neptune.NewDescribeDBClustersPaginator(svc, params)
			for paginator.HasMorePages() {
				cluster, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, cluster := range cluster.DBClusters {
					mqlCluster, err := newMqlAwsNeptuneCluster(a.MqlRuntime, region, conn.AccountId(), cluster)
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

type mqlAwsNeptuneClusterInternal struct {
	cacheKmsKeyId string
	securityGroupIdHandler
	cacheRoleArns []string
}

func newMqlAwsNeptuneCluster(runtime *plugin.Runtime, region string, accountID string, cluster neptune_types.DBCluster) (*mqlAwsNeptuneCluster, error) {
	resource, err := CreateResource(runtime, "aws.neptune.cluster",
		map[string]*llx.RawData{
			"__id":                             llx.StringDataPtr(cluster.DBClusterArn),
			"arn":                              llx.StringDataPtr(cluster.DBClusterArn),
			"name":                             llx.StringDataPtr(cluster.DatabaseName),
			"clusterIdentifier":                llx.StringDataPtr(cluster.DBClusterIdentifier),
			"globalClusterIdentifier":          llx.StringDataPtr(cluster.GlobalClusterIdentifier),
			"engine":                           llx.StringDataPtr(cluster.Engine),
			"engineVersion":                    llx.StringDataPtr(cluster.EngineVersion),
			"region":                           llx.StringData(region),
			"automaticRestartTime":             llx.TimeDataPtr(cluster.AutomaticRestartTime),
			"availabilityZones":                llx.ArrayData(convert.SliceAnyToInterface(cluster.AvailabilityZones), types.String),
			"backupRetentionPeriod":            llx.IntDataPtr(cluster.BackupRetentionPeriod),
			"createdAt":                        llx.TimeDataPtr(cluster.ClusterCreateTime),
			"crossAccountClone":                llx.BoolDataPtr(cluster.CrossAccountClone),
			"clusterParameterGroup":            llx.StringDataPtr(cluster.DBClusterParameterGroup),
			"subnetGroup":                      llx.StringDataPtr(cluster.DBSubnetGroup),
			"clusterResourceId":                llx.StringDataPtr(cluster.DbClusterResourceId),
			"deletionProtection":               llx.BoolDataPtr(cluster.DeletionProtection),
			"earliestRestorableTime":           llx.TimeDataPtr(cluster.EarliestRestorableTime),
			"enabledCloudwatchLogsExports":     llx.ArrayData(convert.SliceAnyToInterface(cluster.EnabledCloudwatchLogsExports), types.String),
			"endpoint":                         llx.StringDataPtr(cluster.Endpoint),
			"readerEndpoint":                   llx.StringDataPtr(cluster.ReaderEndpoint),
			"iamDatabaseAuthenticationEnabled": llx.BoolDataPtr(cluster.IAMDatabaseAuthenticationEnabled),
			"latestRestorableTime":             llx.TimeDataPtr(cluster.LatestRestorableTime),
			"masterUsername":                   llx.StringDataPtr(cluster.MasterUsername),
			"multiAZ":                          llx.BoolDataPtr(cluster.MultiAZ),
			"port":                             llx.IntDataPtr(cluster.Port),
			"preferredBackupWindow":            llx.StringDataPtr(cluster.PreferredBackupWindow),
			"preferredMaintenanceWindow":       llx.StringDataPtr(cluster.PreferredMaintenanceWindow),
			"status":                           llx.StringDataPtr(cluster.Status),
			"storageEncrypted":                 llx.BoolDataPtr(cluster.StorageEncrypted),
			"storageType":                      llx.StringDataPtr(cluster.StorageType),
			"networkType":                      llx.StringDataPtr(cluster.NetworkType),
		})
	if err != nil {
		return nil, err
	}
	resource.(*mqlAwsNeptuneCluster).cacheKmsKeyId = convert.ToValue(cluster.KmsKeyId)
	sgsArn := []string{}
	for _, sg := range cluster.VpcSecurityGroups {
		if sg.VpcSecurityGroupId != nil {
			sgsArn = append(sgsArn, NewSecurityGroupArn(region, accountID, *sg.VpcSecurityGroupId))
		}
	}
	roleArns := []string{}
	for _, r := range cluster.AssociatedRoles {
		if r.RoleArn != nil {
			roleArns = append(roleArns, *r.RoleArn)
		}
	}
	mqlCluster := resource.(*mqlAwsNeptuneCluster)
	mqlCluster.setSecurityGroupArns(sgsArn)
	mqlCluster.cacheRoleArns = roleArns
	return mqlCluster, nil
}

func (a *mqlAwsNeptuneCluster) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Neptune(a.Region.Data)
	ctx := context.Background()
	arnVal := a.Arn.Data
	resp, err := svc.ListTagsForResource(ctx, &neptune.ListTagsForResourceInput{ResourceName: &arnVal})
	if err != nil {
		return nil, classifyAwsError(err, "rds:ListTagsForResource")
	}
	tags := map[string]any{}
	for _, t := range resp.TagList {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

func (a *mqlAwsNeptuneCluster) iamRoles() ([]any, error) {
	res := []any{}
	for _, roleArn := range a.cacheRoleArns {
		ref, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
			map[string]*llx.RawData{"arn": llx.StringData(roleArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func (a *mqlAwsNeptuneCluster) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func initAwsNeptuneCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformNeptuneCluster); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch neptune cluster")
	}

	obj, err := CreateResource(runtime, "aws.neptune", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	n := obj.(*mqlAwsNeptune)

	rawResources := n.GetClusters()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal, ok := args["arn"].Value.(string)
	if !ok {
		return nil, nil, errors.New("arn must be a string")
	}
	for _, rawResource := range rawResources.Data {
		cluster := rawResource.(*mqlAwsNeptuneCluster)
		if cluster.Arn.Data == arnVal {
			return args, cluster, nil
		}
	}
	return nil, nil, errors.New("neptune cluster does not exist")
}

func (a *mqlAwsNeptune) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDbInstances(conn), 5)
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

func (a *mqlAwsNeptune) getDbInstances(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("neptune>getDbInstances>calling aws with region %s", region)

			svc := conn.Neptune(region)
			ctx := context.Background()
			res := []any{}

			params := &neptune.DescribeDBInstancesInput{
				Filters: []neptune_types.Filter{
					{
						// we need to filter by engine since the neptune client also returns rds instances - rofl
						Name:   aws.String("engine"),
						Values: []string{"neptune"},
					},
				},
			}
			paginator := neptune.NewDescribeDBInstancesPaginator(svc, params)
			for paginator.HasMorePages() {
				cluster, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, instance := range cluster.DBInstances {
					mqlNeptuneInstance, err := newMqlAwsNeptuneInstance(a.MqlRuntime, region, instance)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlNeptuneInstance)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsNeptuneInstance(runtime *plugin.Runtime, region string, instance neptune_types.DBInstance) (*mqlAwsNeptuneInstance, error) {
	endpoint, _ := convert.JsonToDict(instance.Endpoint)
	mqlEndpoint := llx.NilData
	if instance.Endpoint != nil {
		endpointRes, err := CreateResource(runtime, "aws.neptune.endpoint", map[string]*llx.RawData{
			"__id":         llx.StringData(convert.ToValue(instance.DBInstanceArn) + "/endpoint"),
			"address":      llx.StringData(convert.ToValue(instance.Endpoint.Address)),
			"port":         llx.IntData(int64(convert.ToValue(instance.Endpoint.Port))),
			"hostedZoneId": llx.StringData(convert.ToValue(instance.Endpoint.HostedZoneId)),
		})
		if err != nil {
			return nil, err
		}
		mqlEndpoint = llx.ResourceData(endpointRes, "aws.neptune.endpoint")
	}

	resource, err := CreateResource(runtime, "aws.neptune.instance",
		map[string]*llx.RawData{
			"__id":                             llx.StringDataPtr(instance.DBInstanceArn),
			"arn":                              llx.StringDataPtr(instance.DBInstanceArn),
			"name":                             llx.StringDataPtr(instance.DBName),
			"clusterIdentifier":                llx.StringDataPtr(instance.DBClusterIdentifier),
			"engine":                           llx.StringDataPtr(instance.Engine),
			"engineVersion":                    llx.StringDataPtr(instance.EngineVersion),
			"region":                           llx.StringData(region),
			"autoMinorVersionUpgrade":          llx.BoolDataPtr(instance.AutoMinorVersionUpgrade),
			"availabilityZone":                 llx.StringDataPtr(instance.AvailabilityZone),
			"backupRetentionPeriod":            llx.IntDataPtr(instance.BackupRetentionPeriod),
			"createdAt":                        llx.TimeDataPtr(instance.InstanceCreateTime),
			"instanceClass":                    llx.StringDataPtr(instance.DBInstanceClass),
			"deletionProtection":               llx.BoolDataPtr(instance.DeletionProtection),
			"monitoringInterval":               llx.IntDataPtr(instance.MonitoringInterval),
			"latestRestorableTime":             llx.TimeDataPtr(instance.LatestRestorableTime),
			"enabledCloudwatchLogsExports":     llx.ArrayData(convert.SliceAnyToInterface(instance.EnabledCloudwatchLogsExports), types.String),
			"enhancedMonitoringResourceArn":    llx.StringDataPtr(instance.EnhancedMonitoringResourceArn),
			"endpoint":                         llx.DictData(endpoint),
			"connectionEndpoint":               mqlEndpoint,
			"iamDatabaseAuthenticationEnabled": llx.BoolDataPtr(instance.IAMDatabaseAuthenticationEnabled),
			"masterUsername":                   llx.StringDataPtr(instance.MasterUsername),
			"multiAZ":                          llx.BoolDataPtr(instance.MultiAZ),
			"port":                             llx.IntDataPtr(instance.DbInstancePort),
			"preferredBackupWindow":            llx.StringDataPtr(instance.PreferredBackupWindow),
			"preferredMaintenanceWindow":       llx.StringDataPtr(instance.PreferredMaintenanceWindow),
			"promotionTier":                    llx.IntDataPtr(instance.PromotionTier),
			"status":                           llx.StringDataPtr(instance.DBInstanceStatus),
			"storageType":                      llx.StringDataPtr(instance.StorageType),
			"storageEncrypted":                 llx.BoolDataPtr(instance.StorageEncrypted),
			"tdeCredentialArn":                 llx.StringDataPtr(instance.TdeCredentialArn),
			"publiclyAccessible":               llx.BoolDataPtr(instance.PubliclyAccessible),
			"certificateAuthority":             llx.StringDataPtr(instance.CACertificateIdentifier),
			"networkType":                      llx.StringDataPtr(instance.NetworkType),
		})
	if err != nil {
		return nil, err
	}
	resource.(*mqlAwsNeptuneInstance).cacheKmsKeyId = convert.ToValue(instance.KmsKeyId)
	resource.(*mqlAwsNeptuneInstance).cacheMonitoringRoleArn = convert.ToValue(instance.MonitoringRoleArn)
	return resource.(*mqlAwsNeptuneInstance), nil
}

func (a *mqlAwsNeptuneCluster) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringData(a.cacheKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsNeptuneInstance) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringData(a.cacheKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsNeptuneInstance) monitoringRole() (*mqlAwsIamRole, error) {
	arnVal := a.cacheMonitoringRoleArn
	if arnVal == "" {
		a.MonitoringRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsNeptuneSnapshot) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsNeptuneCluster) snapshots() ([]any, error) {
	clusterIdentifier := a.ClusterIdentifier.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Neptune(region)
	ctx := context.Background()
	res := []any{}

	paginator := neptune.NewDescribeDBClusterSnapshotsPaginator(svc, &neptune.DescribeDBClusterSnapshotsInput{
		DBClusterIdentifier: &clusterIdentifier,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, snapshot := range page.DBClusterSnapshots {
			mqlSnapshot, err := newMqlAwsNeptuneSnapshot(a.MqlRuntime, region, snapshot)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSnapshot)
		}
	}
	return res, nil
}

func newMqlAwsNeptuneSnapshot(runtime *plugin.Runtime, region string, snapshot neptune_types.DBClusterSnapshot) (*mqlAwsNeptuneSnapshot, error) {
	resource, err := CreateResource(runtime, ResourceAwsNeptuneSnapshot,
		map[string]*llx.RawData{
			"__id":              llx.StringDataPtr(snapshot.DBClusterSnapshotArn),
			"arn":               llx.StringDataPtr(snapshot.DBClusterSnapshotArn),
			"id":                llx.StringDataPtr(snapshot.DBClusterSnapshotIdentifier),
			"clusterIdentifier": llx.StringDataPtr(snapshot.DBClusterIdentifier),
			"engine":            llx.StringDataPtr(snapshot.Engine),
			"engineVersion":     llx.StringDataPtr(snapshot.EngineVersion),
			"status":            llx.StringDataPtr(snapshot.Status),
			"snapshotType":      llx.StringDataPtr(snapshot.SnapshotType),
			"sourceSnapshot":    llx.StringDataPtr(snapshot.SourceDBClusterSnapshotArn),
			"port":              llx.IntDataPtr(snapshot.Port),
			"allocatedStorage":  llx.IntDataPtr(snapshot.AllocatedStorage),
			"storageEncrypted":  llx.BoolDataPtr(snapshot.StorageEncrypted),
			"storageType":       llx.StringDataPtr(snapshot.StorageType),
			"availabilityZones": llx.ArrayData(convert.SliceAnyToInterface(snapshot.AvailabilityZones), types.String),
			"createdAt":         llx.TimeDataPtr(snapshot.SnapshotCreateTime),
			"clusterCreatedAt":  llx.TimeDataPtr(snapshot.ClusterCreateTime),
			"region":            llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlSnapshot := resource.(*mqlAwsNeptuneSnapshot)
	mqlSnapshot.cacheKmsKeyId = snapshot.KmsKeyId
	return mqlSnapshot, nil
}

type mqlAwsNeptuneSnapshotInternal struct {
	cacheKmsKeyId *string
}

func (a *mqlAwsNeptuneSnapshot) kmsKey() (*mqlAwsKmsKey, error) {
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
