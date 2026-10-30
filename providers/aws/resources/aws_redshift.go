// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"

	"go.mondoo.com/mql/types"
)

func (a *mqlAwsRedshift) id() (string, error) {
	return ResourceAwsRedshift, nil
}

const (
	redshiftClusterArnPattern = "arn:aws:redshift:%s:%s:cluster/%s"
)

func (a *mqlAwsRedshift) clusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getClusters(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsRedshift) getClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)

	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("redshift>getClusters>calling aws with region %s", region)

			svc := conn.Redshift(region)
			ctx := context.Background()
			res := []any{}

			params := &redshift.DescribeClustersInput{}
			paginator := redshift.NewDescribeClustersPaginator(svc, params)
			for paginator.HasMorePages() {
				clusters, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, cluster := range clusters.Clusters {
					var names []any
					for _, group := range cluster.ClusterParameterGroups {
						names = append(names, convert.ToValue(group.ParameterGroupName))
					}

					if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(redshiftTagsToMap(cluster.Tags))) {
						log.Debug().Interface("cluster", cluster.ClusterIdentifier).Msg("skipping redshift cluster due to filters")
						continue
					}

					var endpointAddress string
					var endpointPort int64
					endpointVpcEndpoints := []any{}
					if cluster.Endpoint != nil {
						endpointAddress = convert.ToValue(cluster.Endpoint.Address)
						if cluster.Endpoint.Port != nil {
							endpointPort = int64(*cluster.Endpoint.Port)
						}
						if len(cluster.Endpoint.VpcEndpoints) > 0 {
							endpointVpcEndpoints, err = convert.JsonToDictSlice(cluster.Endpoint.VpcEndpoints)
							if err != nil {
								return nil, err
							}
						}
					}

					// Restore-from-snapshot lineage
					var restoreStatus string
					if cluster.RestoreStatus != nil {
						restoreStatus = convert.ToValue(cluster.RestoreStatus.Status)
					}

					// Cross-region snapshot copy configuration
					var snapshotCopyDestinationRegion, snapshotCopyGrantName string
					var snapshotCopyRetentionPeriod, snapshotCopyManualRetentionPeriod *int64
					if scs := cluster.ClusterSnapshotCopyStatus; scs != nil {
						snapshotCopyDestinationRegion = convert.ToValue(scs.DestinationRegion)
						snapshotCopyGrantName = convert.ToValue(scs.SnapshotCopyGrantName)
						snapshotCopyRetentionPeriod = scs.RetentionPeriod
						if scs.ManualSnapshotRetentionPeriod != nil {
							v := int64(*scs.ManualSnapshotRetentionPeriod)
							snapshotCopyManualRetentionPeriod = &v
						}
					}

					var elasticIp string
					if cluster.ElasticIpStatus != nil {
						elasticIp = convert.ToValue(cluster.ElasticIpStatus.ElasticIp)
					}

					// VPC security group IDs assembled into ARNs for typed resolution
					sgArns := make([]string, 0, len(cluster.VpcSecurityGroups))
					for _, sg := range cluster.VpcSecurityGroups {
						if sg.VpcSecurityGroupId != nil && *sg.VpcSecurityGroupId != "" {
							sgArns = append(sgArns, fmt.Sprintf(securityGroupArnPattern, region, conn.AccountId(), *sg.VpcSecurityGroupId))
						}
					}

					sysTables := redshiftSystemTables(cluster)

					mqlDBInstance, err := CreateResource(a.MqlRuntime, ResourceAwsRedshiftCluster,
						map[string]*llx.RawData{
							"restoredFromSnapshot":                    llx.BoolData(cluster.RestoreStatus != nil),
							"restoreStatus":                           llx.StringData(restoreStatus),
							"restoreProgressPercent":                  llx.FloatData(redshiftRestoreProgressPercent(cluster.RestoreStatus)),
							"clusterNamespaceArn":                     llx.StringDataPtr(cluster.ClusterNamespaceArn),
							"crossRegionSnapshotCopyEnabled":          llx.BoolData(cluster.ClusterSnapshotCopyStatus != nil),
							"snapshotCopyDestinationRegion":           llx.StringData(snapshotCopyDestinationRegion),
							"snapshotCopyRetentionPeriod":             llx.IntDataDefault(snapshotCopyRetentionPeriod, 0),
							"snapshotCopyManualRetentionPeriod":       llx.IntDataDefault(snapshotCopyManualRetentionPeriod, 0),
							"snapshotCopyGrantName":                   llx.StringData(snapshotCopyGrantName),
							"expectedNextSnapshotScheduleAt":          llx.TimeDataPtr(cluster.ExpectedNextSnapshotScheduleTime),
							"expectedNextSnapshotScheduleStatus":      llx.StringDataPtr(cluster.ExpectedNextSnapshotScheduleTimeStatus),
							"snapshotScheduleState":                   llx.StringData(string(cluster.SnapshotScheduleState)),
							"customDomainName":                        llx.StringDataPtr(cluster.CustomDomainName),
							"customDomainCertificateExpiresAt":        llx.TimeDataPtr(cluster.CustomDomainCertificateExpiryDate),
							"availabilityZoneRelocationStatus":        llx.StringDataPtr(cluster.AvailabilityZoneRelocationStatus),
							"elasticIp":                               llx.StringData(elasticIp),
							"allowVersionUpgrade":                     llx.BoolDataPtr(cluster.AllowVersionUpgrade),
							"arn":                                     llx.StringData(fmt.Sprintf(redshiftClusterArnPattern, region, conn.AccountId(), convert.ToValue(cluster.ClusterIdentifier))),
							"automatedSnapshotRetentionPeriod":        llx.IntDataDefault(cluster.AutomatedSnapshotRetentionPeriod, 0),
							"availabilityZone":                        llx.StringDataPtr(cluster.AvailabilityZone),
							"clusterParameterGroupNames":              llx.ArrayData(names, types.String),
							"clusterRevisionNumber":                   llx.StringDataPtr(cluster.ClusterRevisionNumber),
							"clusterStatus":                           llx.StringDataPtr(cluster.ClusterStatus),
							"clusterSubnetGroupName":                  llx.StringDataPtr(cluster.ClusterSubnetGroupName),
							"clusterVersion":                          llx.StringDataPtr(cluster.ClusterVersion),
							"createdAt":                               llx.TimeDataPtr(cluster.ClusterCreateTime),
							"dbName":                                  llx.StringDataPtr(cluster.DBName),
							"encrypted":                               llx.BoolDataPtr(cluster.Encrypted),
							"enhancedVpcRouting":                      llx.BoolDataPtr(cluster.EnhancedVpcRouting),
							"masterUsername":                          llx.StringDataPtr(cluster.MasterUsername),
							"name":                                    llx.StringDataPtr(cluster.ClusterIdentifier),
							"nextMaintenanceWindowStartTime":          llx.TimeDataPtr(cluster.NextMaintenanceWindowStartTime),
							"nodeType":                                llx.StringDataPtr(cluster.NodeType),
							"numberOfNodes":                           llx.IntDataDefault(cluster.NumberOfNodes, 0),
							"preferredMaintenanceWindow":              llx.StringDataPtr(cluster.PreferredMaintenanceWindow),
							"publiclyAccessible":                      llx.BoolDataPtr(cluster.PubliclyAccessible),
							"endpointAddress":                         llx.StringData(endpointAddress),
							"endpointPort":                            llx.IntData(endpointPort),
							"endpointVpcEndpoints":                    llx.ArrayData(endpointVpcEndpoints, types.Dict),
							"region":                                  llx.StringData(region),
							"tags":                                    llx.MapData(redshiftTagsToMap(cluster.Tags), types.String),
							"clusterAvailabilityStatus":               llx.StringDataPtr(cluster.ClusterAvailabilityStatus),
							"totalStorageCapacityInMegaBytes":         llx.IntDataDefault(cluster.TotalStorageCapacityInMegaBytes, 0),
							"multiAZ":                                 llx.BoolData(strings.EqualFold(convert.ToValue(cluster.MultiAZ), "enabled")),
							"manualSnapshotRetentionPeriod":           llx.IntDataDefault(cluster.ManualSnapshotRetentionPeriod, 0),
							"ipAddressType":                           llx.StringDataPtr(cluster.IpAddressType),
							"maintenanceTrackName":                    llx.StringDataPtr(cluster.MaintenanceTrackName),
							"hsmStatus":                               llx.DictData(redshiftHsmStatusToDict(cluster.HsmStatus)),
							"modifyStatus":                            llx.StringDataPtr(cluster.ModifyStatus),
							"snapshotScheduleIdentifier":              llx.StringDataPtr(cluster.SnapshotScheduleIdentifier),
							"systemTablePublishingEnabledAll":         llx.BoolDataPtr(sysTables.enabledAll),
							"systemTablePublishingGranularity":        llx.StringDataPtr(sysTables.granularity),
							"systemTablePublishingNamespace":          llx.StringDataPtr(sysTables.namespace),
							"systemTablePublishingTables":             llx.ArrayData(sysTables.tables, types.String),
							"systemTablePublishingLastIngestionTimes": llx.MapData(sysTables.lastIngestion, types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlDBInstance.(*mqlAwsRedshiftCluster).cacheVpcId = convert.ToValue(cluster.VpcId)
					mqlCluster := mqlDBInstance.(*mqlAwsRedshiftCluster)
					mqlCluster.cacheKmsKeyId = cluster.KmsKeyId
					mqlCluster.cacheMasterPasswordSecretKmsKey = cluster.MasterPasswordSecretKmsKeyId
					mqlCluster.cacheDefaultIamRoleArn = cluster.DefaultIamRoleArn
					mqlCluster.cacheMasterPasswordSecretArn = cluster.MasterPasswordSecretArn
					mqlCluster.cacheCustomDomainCertificateArn = cluster.CustomDomainCertificateArn
					iamRoleArns := make([]string, 0, len(cluster.IamRoles))
					for _, role := range cluster.IamRoles {
						if role.IamRoleArn != nil && *role.IamRoleArn != "" {
							iamRoleArns = append(iamRoleArns, *role.IamRoleArn)
						}
					}
					mqlCluster.cacheIamRoleArns = iamRoleArns
					mqlCluster.setSecurityGroupArns(sgArns)
					res = append(res, mqlCluster)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func redshiftHsmStatusToDict(hsm *redshifttypes.HsmStatus) map[string]any {
	if hsm == nil {
		return nil
	}
	return map[string]any{
		"hsmClientCertificateIdentifier": convert.ToValue(hsm.HsmClientCertificateIdentifier),
		"hsmConfigurationIdentifier":     convert.ToValue(hsm.HsmConfigurationIdentifier),
		"status":                         convert.ToValue(hsm.Status),
	}
}

func redshiftTagsToMap(tags []redshifttypes.Tag) map[string]any {
	return tagsToMap(tags, func(t redshifttypes.Tag) *string { return t.Key }, func(t redshifttypes.Tag) *string { return t.Value })
}

type mqlAwsRedshiftClusterInternal struct {
	cacheVpcId string
	securityGroupIdHandler
	cacheKmsKeyId                   *string
	cacheMasterPasswordSecretKmsKey *string
	cacheIamRoleArns                []string
	cacheDefaultIamRoleArn          *string
	cacheMasterPasswordSecretArn    *string
	cacheCustomDomainCertificateArn *string

	loggingStatusOnce sync.Once
	loggingStatus     *redshift.DescribeLoggingStatusOutput
	loggingStatusErr  error
}

// redshiftRestoreProgressPercent computes how far a restore-from-snapshot has
// progressed, or 0 when the cluster wasn't restored or the snapshot size is
// unknown.
func redshiftRestoreProgressPercent(rs *redshifttypes.RestoreStatus) float64 {
	if rs == nil || rs.SnapshotSizeInMegaBytes == nil || *rs.SnapshotSizeInMegaBytes <= 0 {
		return 0
	}
	return float64(convert.ToValue(rs.ProgressInMegaBytes)) / float64(*rs.SnapshotSizeInMegaBytes) * 100
}

func (a *mqlAwsRedshiftCluster) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsRedshiftCluster) vpc() (*mqlAwsVpc, error) {
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

func (a *mqlAwsRedshiftCluster) kmsKey() (*mqlAwsKmsKey, error) {
	// Clusters without a customer-referenceable key report the sentinel
	// "AWS_OWNED_KMS_KEY" instead of a key ARN; resolving it as a key errors.
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" || *a.cacheKmsKeyId == "AWS_OWNED_KMS_KEY" {
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

func (a *mqlAwsRedshiftCluster) masterPasswordSecretKmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheMasterPasswordSecretKmsKey == nil || *a.cacheMasterPasswordSecretKmsKey == "" {
		a.MasterPasswordSecretKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheMasterPasswordSecretKmsKey),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsRedshiftCluster) iamRoles() ([]any, error) {
	res := make([]any, 0, len(a.cacheIamRoleArns))
	for _, roleArn := range a.cacheIamRoleArns {
		mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
			map[string]*llx.RawData{"arn": llx.StringData(roleArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRole)
	}
	return res, nil
}

func (a *mqlAwsRedshiftCluster) defaultIamRole() (*mqlAwsIamRole, error) {
	if a.cacheDefaultIamRoleArn == nil || *a.cacheDefaultIamRoleArn == "" {
		a.DefaultIamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheDefaultIamRoleArn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsRedshiftCluster) masterPasswordSecret() (*mqlAwsSecretsmanagerSecret, error) {
	if a.cacheMasterPasswordSecretArn == nil || *a.cacheMasterPasswordSecretArn == "" {
		a.MasterPasswordSecret.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.secretsmanager.secret",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheMasterPasswordSecretArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecretsmanagerSecret), nil
}

func (a *mqlAwsRedshiftCluster) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsRedshiftCluster) customDomainCertificate() (*mqlAwsAcmCertificate, error) {
	if a.cacheCustomDomainCertificateArn == nil || *a.cacheCustomDomainCertificateArn == "" {
		a.CustomDomainCertificate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.acm.certificate",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheCustomDomainCertificateArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAcmCertificate), nil
}

func (a *mqlAwsRedshiftCluster) managedBy() (string, error) {
	return managedByFromTags(a.Tags.Data), nil
}

func (a *mqlAwsRedshiftCluster) cloudformationStack() (*mqlAwsCloudformationStack, error) {
	stack, err := cloudformationStackForTags(a.MqlRuntime, a.Region.Data, a.Tags.Data)
	if err != nil {
		return nil, err
	}
	if stack == nil {
		a.CloudformationStack.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return stack, nil
}

func initAwsRedshiftCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformRedshiftCluster); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch redshift cluster")
	}

	// load all rds db instances
	obj, err := CreateResource(runtime, "aws.redshift", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	redshift := obj.(*mqlAwsRedshift)

	rawResources := redshift.GetClusters()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		cluster := rawResource.(*mqlAwsRedshiftCluster)
		if cluster.Arn.Data == arnVal {
			return args, cluster, nil
		}
	}
	return nil, nil, errors.New("redshift cluster does not exist")
}

func (a *mqlAwsRedshiftCluster) parameters() ([]any, error) {
	clusterGroupNames := a.ClusterParameterGroupNames.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Redshift(region)
	ctx := context.Background()
	res := []redshifttypes.Parameter{}
	for _, name := range clusterGroupNames {
		stringName := name.(string)
		paginator := redshift.NewDescribeClusterParametersPaginator(svc, &redshift.DescribeClusterParametersInput{
			ParameterGroupName: &stringName,
		})
		for paginator.HasMorePages() {
			params, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			res = append(res, params.Parameters...)
		}
	}
	return convert.JsonToDictSlice(res)
}

// fetchLoggingStatus reads the cluster's audit-log delivery status once and
// hands the same response to every field derived from it. Nine fields read
// this, and DescribeLoggingStatus is one call per cluster per read.
func (a *mqlAwsRedshiftCluster) fetchLoggingStatus() (*redshift.DescribeLoggingStatusOutput, error) {
	a.loggingStatusOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Redshift(a.Region.Data)
		name := a.Name.Data
		a.loggingStatus, a.loggingStatusErr = svc.DescribeLoggingStatus(context.Background(),
			&redshift.DescribeLoggingStatusInput{ClusterIdentifier: &name})
	})
	return a.loggingStatus, a.loggingStatusErr
}

func (a *mqlAwsRedshiftCluster) logging() (any, error) {
	params, err := a.fetchLoggingStatus()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(params)
}

func (a *mqlAwsRedshiftCluster) auditLogging() (*mqlAwsRedshiftClusterLoggingStatus, error) {
	params, err := a.fetchLoggingStatus()
	if err != nil {
		return nil, err
	}
	if params == nil {
		a.AuditLogging.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(a.MqlRuntime, "aws.redshift.cluster.loggingStatus", map[string]*llx.RawData{
		"__id":                     llx.StringData(a.Arn.Data + "/loggingStatus"),
		"enabled":                  llx.BoolData(convert.ToValue(params.LoggingEnabled)),
		"destinationType":          llx.StringData(string(params.LogDestinationType)),
		"logExports":               llx.ArrayData(convert.SliceAnyToInterface(params.LogExports), types.String),
		"s3KeyPrefix":              llx.StringData(convert.ToValue(params.S3KeyPrefix)),
		"lastSuccessfulDeliveryAt": llx.TimeDataPtr(params.LastSuccessfulDeliveryTime),
		"lastFailureMessage":       llx.StringData(convert.ToValue(params.LastFailureMessage)),
		"lastFailureAt":            llx.TimeDataPtr(params.LastFailureTime),
	})
	if err != nil {
		return nil, err
	}
	mqlStatus := res.(*mqlAwsRedshiftClusterLoggingStatus)
	mqlStatus.cacheBucketName = convert.ToValue(params.BucketName)
	return mqlStatus, nil
}

type mqlAwsRedshiftClusterLoggingStatusInternal struct {
	cacheBucketName string
}

func (a *mqlAwsRedshiftClusterLoggingStatus) bucket() (*mqlAwsS3Bucket, error) {
	if a.cacheBucketName == "" {
		a.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.s3.bucket", map[string]*llx.RawData{
		"name": llx.StringData(a.cacheBucketName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsRedshiftSnapshot) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsRedshiftCluster) snapshots() ([]any, error) {
	clusterName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Redshift(region)
	ctx := context.Background()
	res := []any{}

	paginator := redshift.NewDescribeClusterSnapshotsPaginator(svc, &redshift.DescribeClusterSnapshotsInput{ClusterIdentifier: &clusterName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, snapshot := range page.Snapshots {
			mqlSnapshot, err := newMqlAwsRedshiftSnapshot(a.MqlRuntime, region, snapshot)
			if err != nil {
				return nil, err
			}
			mqlSnapshot.cacheKmsKeyId = snapshot.KmsKeyId
			res = append(res, mqlSnapshot)
		}
	}
	return res, nil
}

func newMqlAwsRedshiftSnapshot(runtime *plugin.Runtime, region string, snapshot redshifttypes.Snapshot) (*mqlAwsRedshiftSnapshot, error) {
	resource, err := CreateResource(runtime, ResourceAwsRedshiftSnapshot,
		map[string]*llx.RawData{
			"__id":                          llx.StringDataPtr(snapshot.SnapshotArn),
			"arn":                           llx.StringDataPtr(snapshot.SnapshotArn),
			"id":                            llx.StringDataPtr(snapshot.SnapshotIdentifier),
			"clusterIdentifier":             llx.StringDataPtr(snapshot.ClusterIdentifier),
			"ownerAccount":                  llx.StringDataPtr(snapshot.OwnerAccount),
			"accountsWithRestoreAccess":     llx.ArrayData(redshiftRestoreAccessToDicts(snapshot.AccountsWithRestoreAccess), types.Dict),
			"region":                        llx.StringData(region),
			"snapshotType":                  llx.StringDataPtr(snapshot.SnapshotType),
			"sourceRegion":                  llx.StringDataPtr(snapshot.SourceRegion),
			"status":                        llx.StringDataPtr(snapshot.Status),
			"encrypted":                     llx.BoolDataPtr(snapshot.Encrypted),
			"encryptedWithHSM":              llx.BoolDataPtr(snapshot.EncryptedWithHSM),
			"port":                          llx.IntDataDefault(snapshot.Port, 0),
			"nodeType":                      llx.StringDataPtr(snapshot.NodeType),
			"numberOfNodes":                 llx.IntDataDefault(snapshot.NumberOfNodes, 0),
			"masterUsername":                llx.StringDataPtr(snapshot.MasterUsername),
			"dbName":                        llx.StringDataPtr(snapshot.DBName),
			"availabilityZone":              llx.StringDataPtr(snapshot.AvailabilityZone),
			"clusterVersion":                llx.StringDataPtr(snapshot.ClusterVersion),
			"engineFullVersion":             llx.StringDataPtr(snapshot.EngineFullVersion),
			"enhancedVpcRouting":            llx.BoolDataPtr(snapshot.EnhancedVpcRouting),
			"manualSnapshotRetentionPeriod": llx.IntDataDefault(snapshot.ManualSnapshotRetentionPeriod, 0),
			"totalBackupSizeInMegaBytes":    llx.FloatData(convert.ToValue(snapshot.TotalBackupSizeInMegaBytes)),
			"createdAt":                     llx.TimeDataPtr(snapshot.SnapshotCreateTime),
			"clusterCreatedAt":              llx.TimeDataPtr(snapshot.ClusterCreateTime),
			"tags":                          llx.MapData(redshiftTagsToMap(snapshot.Tags), types.String),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsRedshiftSnapshot), nil
}

type mqlAwsRedshiftSnapshotInternal struct {
	cacheKmsKeyId *string
}

// redshiftRestoreAccessToDicts converts the accounts authorized to restore a
// snapshot into a slice of dicts, each carrying the account id and optional
// account alias.
func redshiftRestoreAccessToDicts(accounts []redshifttypes.AccountWithRestoreAccess) []any {
	res := make([]any, 0, len(accounts))
	for _, acc := range accounts {
		res = append(res, map[string]any{
			"accountId":    convert.ToValue(acc.AccountId),
			"accountAlias": convert.ToValue(acc.AccountAlias),
		})
	}
	return res
}

// cluster resolves the source cluster the snapshot was taken from, when it is
// still present in this account.
func (a *mqlAwsRedshiftSnapshot) cluster() (*mqlAwsRedshiftCluster, error) {
	if !a.ClusterIdentifier.IsSet() || a.ClusterIdentifier.Data == "" {
		a.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := fmt.Sprintf(redshiftClusterArnPattern, a.Region.Data, conn.AccountId(), a.ClusterIdentifier.Data)
	res, err := NewResource(a.MqlRuntime, "aws.redshift.cluster",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		a.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsRedshiftCluster), nil
}

func (a *mqlAwsRedshiftSnapshot) kmsKey() (*mqlAwsKmsKey, error) {
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

// ── Subnet Groups ───────────────────────────────────────────────────────────

func (a *mqlAwsRedshift) subnetGroups() ([]any, error) {
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

func (a *mqlAwsRedshift) getSubnetGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Redshift(region)
			ctx := context.Background()
			res := []any{}
			paginator := redshift.NewDescribeClusterSubnetGroupsPaginator(svc, &redshift.DescribeClusterSubnetGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, sg := range page.ClusterSubnetGroups {
					subnets, err := convert.JsonToDictSlice(sg.Subnets)
					if err != nil {
						return nil, err
					}
					ipTypes := make([]any, len(sg.SupportedClusterIpAddressTypes))
					for i, t := range sg.SupportedClusterIpAddressTypes {
						ipTypes[i] = t
					}
					mqlSg, err := CreateResource(a.MqlRuntime, ResourceAwsRedshiftSubnetGroup,
						map[string]*llx.RawData{
							"__id":                           llx.StringData(fmt.Sprintf("redshift/subnetgroup/%s/%s", region, convert.ToValue(sg.ClusterSubnetGroupName))),
							"name":                           llx.StringDataPtr(sg.ClusterSubnetGroupName),
							"description":                    llx.StringDataPtr(sg.Description),
							"region":                         llx.StringData(region),
							"status":                         llx.StringDataPtr(sg.SubnetGroupStatus),
							"subnets":                        llx.ArrayData(subnets, types.Dict),
							"supportedClusterIpAddressTypes": llx.ArrayData(ipTypes, types.String),
							"tags":                           llx.MapData(redshiftTagsToMap(sg.Tags), types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlSgRes := mqlSg.(*mqlAwsRedshiftSubnetGroup)
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

type mqlAwsRedshiftSubnetGroupInternal struct {
	cacheVpcId *string
}

func (a *mqlAwsRedshiftSubnetGroup) id() (string, error) {
	return a.__id, nil
}

const (
	redshiftSubnetGroupArnPattern       = "arn:aws:redshift:%s:%s:subnetgroup:%s"
	redshiftEventSubscriptionArnPattern = "arn:aws:redshift:%s:%s:eventsubscription:%s"
)

func (a *mqlAwsRedshiftSubnetGroup) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(redshiftSubnetGroupArnPattern, a.Region.Data, conn.AccountId(), a.Name.Data), nil
}

func (a *mqlAwsRedshiftSubnetGroup) vpc() (*mqlAwsVpc, error) {
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

// ── Event Subscriptions ─────────────────────────────────────────────────────

func (a *mqlAwsRedshift) eventSubscriptions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEventSubscriptions(conn), 5)
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

func (a *mqlAwsRedshift) getEventSubscriptions(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Redshift(region)
			ctx := context.Background()
			res := []any{}
			paginator := redshift.NewDescribeEventSubscriptionsPaginator(svc, &redshift.DescribeEventSubscriptionsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, sub := range page.EventSubscriptionsList {
					categories := make([]any, len(sub.EventCategoriesList))
					for i, c := range sub.EventCategoriesList {
						categories[i] = c
					}
					sourceIds := make([]any, len(sub.SourceIdsList))
					for i, s := range sub.SourceIdsList {
						sourceIds[i] = s
					}
					mqlSub, err := CreateResource(a.MqlRuntime, ResourceAwsRedshiftEventSubscription,
						map[string]*llx.RawData{
							"__id":            llx.StringData(fmt.Sprintf("redshift/eventsubscription/%s/%s", region, convert.ToValue(sub.CustSubscriptionId))),
							"name":            llx.StringDataPtr(sub.CustSubscriptionId),
							"region":          llx.StringData(region),
							"enabled":         llx.BoolDataPtr(sub.Enabled),
							"eventCategories": llx.ArrayData(categories, types.String),
							"severity":        llx.StringDataPtr(sub.Severity),
							"sourceIds":       llx.ArrayData(sourceIds, types.String),
							"sourceType":      llx.StringDataPtr(sub.SourceType),
							"status":          llx.StringDataPtr(sub.Status),
							"createdAt":       llx.TimeDataPtr(sub.SubscriptionCreationTime),
							"tags":            llx.MapData(redshiftTagsToMap(sub.Tags), types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlSub.(*mqlAwsRedshiftEventSubscription).cacheSnsTopicArn = convert.ToValue(sub.SnsTopicArn)
					res = append(res, mqlSub)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsRedshiftEventSubscription) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsRedshiftEventSubscription) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(redshiftEventSubscriptionArnPattern, a.Region.Data, conn.AccountId(), a.Name.Data), nil
}

func (a *mqlAwsRedshiftEventSubscription) snsTopic() (*mqlAwsSnsTopic, error) {
	arn := a.cacheSnsTopicArn
	if arn == "" {
		a.SnsTopic.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlTopic, err := NewResource(a.MqlRuntime, "aws.sns.topic",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return mqlTopic.(*mqlAwsSnsTopic), nil
}

// ── Scheduled Actions ───────────────────────────────────────────────────────

func (a *mqlAwsRedshift) scheduledActions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getScheduledActions(conn), 5)
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

func (a *mqlAwsRedshift) getScheduledActions(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Redshift(region)
			ctx := context.Background()
			res := []any{}
			paginator := redshift.NewDescribeScheduledActionsPaginator(svc, &redshift.DescribeScheduledActionsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, action := range page.ScheduledActions {
					targetAction, err := convert.JsonToDict(action.TargetAction)
					if err != nil {
						return nil, err
					}
					mqlAction, err := CreateResource(a.MqlRuntime, ResourceAwsRedshiftScheduledAction,
						map[string]*llx.RawData{
							"__id":         llx.StringData(fmt.Sprintf("redshift/scheduledaction/%s/%s", region, convert.ToValue(action.ScheduledActionName))),
							"name":         llx.StringDataPtr(action.ScheduledActionName),
							"region":       llx.StringData(region),
							"description":  llx.StringDataPtr(action.ScheduledActionDescription),
							"schedule":     llx.StringDataPtr(action.Schedule),
							"state":        llx.StringData(string(action.State)),
							"iamRole":      llx.StringDataPtr(action.IamRole),
							"startTime":    llx.TimeDataPtr(action.StartTime),
							"endTime":      llx.TimeDataPtr(action.EndTime),
							"targetAction": llx.DictData(targetAction),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlAction)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsRedshiftScheduledAction) id() (string, error) {
	return a.__id, nil
}

// ── Snapshot Schedules ──────────────────────────────────────────────────────

func (a *mqlAwsRedshift) snapshotSchedules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSnapshotSchedules(conn), 5)
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

func (a *mqlAwsRedshift) getSnapshotSchedules(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Redshift(region)
			ctx := context.Background()
			res := []any{}
			paginator := redshift.NewDescribeSnapshotSchedulesPaginator(svc, &redshift.DescribeSnapshotSchedulesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, sched := range page.SnapshotSchedules {
					defs := make([]any, len(sched.ScheduleDefinitions))
					for i, d := range sched.ScheduleDefinitions {
						defs[i] = d
					}
					mqlSched, err := CreateResource(a.MqlRuntime, ResourceAwsRedshiftSnapshotSchedule,
						map[string]*llx.RawData{
							"__id":                   llx.StringData(fmt.Sprintf("redshift/snapshotschedule/%s/%s", region, convert.ToValue(sched.ScheduleIdentifier))),
							"id":                     llx.StringDataPtr(sched.ScheduleIdentifier),
							"region":                 llx.StringData(region),
							"description":            llx.StringDataPtr(sched.ScheduleDescription),
							"scheduleDefinitions":    llx.ArrayData(defs, types.String),
							"associatedClusterCount": llx.IntDataDefault(sched.AssociatedClusterCount, 0),
							"tags":                   llx.MapData(redshiftTagsToMap(sched.Tags), types.String),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSched)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsRedshiftSnapshotSchedule) id() (string, error) {
	return a.__id, nil
}

type mqlAwsRedshiftEventSubscriptionInternal struct {
	cacheSnsTopicArn string
}

// redshiftSystemTablePublishing is the flattened view of a cluster's system
// table publishing status.
//
// DescribeClusters omits LoggingPublishStatus entirely when publishing is not
// configured, so each scalar stays a pointer: nil reports null, which keeps
// "not configured" distinguishable from "configured and switched off".
type redshiftSystemTablePublishing struct {
	enabledAll    *bool
	granularity   *string
	namespace     *string
	tables        []any
	lastIngestion map[string]any
}

func redshiftSystemTables(cluster redshifttypes.Cluster) redshiftSystemTablePublishing {
	out := redshiftSystemTablePublishing{
		tables:        []any{},
		lastIngestion: map[string]any{},
	}
	if cluster.LoggingPublishStatus == nil || cluster.LoggingPublishStatus.S3Tables == nil {
		return out
	}

	st := cluster.LoggingPublishStatus.S3Tables
	out.enabledAll = st.EnabledAll
	out.granularity = st.S3TableGranularity
	out.namespace = st.S3TableNamespace
	for _, t := range st.S3Tables {
		out.tables = append(out.tables, t)
	}
	for k, v := range st.LastIngestionTimes {
		out.lastIngestion[k] = v
	}
	return out
}
