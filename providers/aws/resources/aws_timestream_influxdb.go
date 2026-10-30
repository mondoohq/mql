// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/timestreaminfluxdb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsTimestreamInfluxdb) id() (string, error) {
	return "aws.timestream.influxdb", nil
}

func (a *mqlAwsTimestreamInfluxdb) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getInstances(conn), 5)
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

func (a *mqlAwsTimestreamInfluxdb) getInstances(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("timestream.influxdb>getInstances>calling aws with region %s", region)

			svc := conn.TimestreamInfluxDB(region)
			ctx := context.Background()
			res := []any{}

			paginator := timestreaminfluxdb.NewListDbInstancesPaginator(svc, &timestreaminfluxdb.ListDbInstancesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("timestream influxdb service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, instance := range page.Items {
					mqlInstance, err := CreateResource(a.MqlRuntime, "aws.timestream.influxdb.instance",
						map[string]*llx.RawData{
							"__id":             llx.StringDataPtr(instance.Arn),
							"arn":              llx.StringDataPtr(instance.Arn),
							"id":               llx.StringDataPtr(instance.Id),
							"name":             llx.StringDataPtr(instance.Name),
							"allocatedStorage": llx.IntDataDefault(instance.AllocatedStorage, 0),
							"dbInstanceType":   llx.StringData(string(instance.DbInstanceType)),
							"dbStorageType":    llx.StringData(string(instance.DbStorageType)),
							"deploymentType":   llx.StringData(string(instance.DeploymentType)),
							"endpoint":         llx.StringDataPtr(instance.Endpoint),
							"networkType":      llx.StringData(string(instance.NetworkType)),
							"port":             llx.IntDataDefault(instance.Port, 0),
							"status":           llx.StringData(string(instance.Status)),
							"region":           llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlInstance)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsTimestreamInfluxdb) clusters() ([]any, error) {
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

func (a *mqlAwsTimestreamInfluxdb) getClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("timestream.influxdb>getClusters>calling aws with region %s", region)

			svc := conn.TimestreamInfluxDB(region)
			ctx := context.Background()
			res := []any{}

			paginator := timestreaminfluxdb.NewListDbClustersPaginator(svc, &timestreaminfluxdb.ListDbClustersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("timestream influxdb service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, cluster := range page.Items {
					mqlCluster, err := CreateResource(a.MqlRuntime, "aws.timestream.influxdb.cluster",
						map[string]*llx.RawData{
							"__id":             llx.StringDataPtr(cluster.Arn),
							"arn":              llx.StringDataPtr(cluster.Arn),
							"id":               llx.StringDataPtr(cluster.Id),
							"name":             llx.StringDataPtr(cluster.Name),
							"allocatedStorage": llx.IntDataDefault(cluster.AllocatedStorage, 0),
							"dbInstanceType":   llx.StringData(string(cluster.DbInstanceType)),
							"dbStorageType":    llx.StringData(string(cluster.DbStorageType)),
							"deploymentType":   llx.StringData(string(cluster.DeploymentType)),
							"endpoint":         llx.StringDataPtr(cluster.Endpoint),
							"readerEndpoint":   llx.StringDataPtr(cluster.ReaderEndpoint),
							"networkType":      llx.StringData(string(cluster.NetworkType)),
							"port":             llx.IntDataDefault(cluster.Port, 0),
							"status":           llx.StringData(string(cluster.Status)),
							"region":           llx.StringData(region),
							"engineType":       llx.StringData(string(cluster.EngineType)),
						})
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

// Instance detail caching

type mqlAwsTimestreamInfluxdbInstanceInternal struct {
	securityGroupIdHandler
	detailOnce sync.Once
	detailErr  error
	detail     *timestreaminfluxdb.GetDbInstanceOutput
}

func (a *mqlAwsTimestreamInfluxdbInstance) fetchDetail() (*timestreaminfluxdb.GetDbInstanceOutput, error) {
	a.detailOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.TimestreamInfluxDB(a.Region.Data)
		ctx := context.Background()
		id := a.Id.Data
		a.detail, a.detailErr = svc.GetDbInstance(ctx, &timestreaminfluxdb.GetDbInstanceInput{
			Identifier: &id,
		})
		if a.detailErr == nil && a.detail != nil {
			accountID := conn.AccountId()
			region := a.Region.Data
			sgs := make([]string, 0, len(a.detail.VpcSecurityGroupIds))
			for _, sgID := range a.detail.VpcSecurityGroupIds {
				sgs = append(sgs, NewSecurityGroupArn(region, accountID, sgID))
			}
			a.setSecurityGroupArns(sgs)
		}
	})
	return a.detail, a.detailErr
}

func (a *mqlAwsTimestreamInfluxdbInstance) publiclyAccessible() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	return convert.ToValue(detail.PubliclyAccessible), nil
}

func (a *mqlAwsTimestreamInfluxdbInstance) vpcSubnets() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	accountID := conn.AccountId()
	res := make([]any, 0, len(detail.VpcSubnetIds))
	for _, subnetID := range detail.VpcSubnetIds {
		sub, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet, map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, region, accountID, subnetID)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, sub)
	}
	return res, nil
}

func (a *mqlAwsTimestreamInfluxdbInstance) securityGroups() ([]any, error) {
	if _, err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsTimestreamInfluxdbInstance) influxAuthParametersSecretArn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(detail.InfluxAuthParametersSecretArn), nil
}

func (a *mqlAwsTimestreamInfluxdbInstance) logDeliveryEnabled() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if detail.LogDeliveryConfiguration != nil && detail.LogDeliveryConfiguration.S3Configuration != nil {
		return convert.ToValue(detail.LogDeliveryConfiguration.S3Configuration.Enabled), nil
	}
	return false, nil
}

func (a *mqlAwsTimestreamInfluxdbInstance) logDeliveryS3Bucket() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail.LogDeliveryConfiguration != nil && detail.LogDeliveryConfiguration.S3Configuration != nil {
		return convert.ToValue(detail.LogDeliveryConfiguration.S3Configuration.BucketName), nil
	}
	return "", nil
}

func (a *mqlAwsTimestreamInfluxdbInstance) dbParameterGroupIdentifier() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(detail.DbParameterGroupIdentifier), nil
}

func (a *mqlAwsTimestreamInfluxdbInstance) availabilityZone() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(detail.AvailabilityZone), nil
}

func (a *mqlAwsTimestreamInfluxdbInstance) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.TimestreamInfluxDB(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data

	resp, err := svc.ListTagsForResource(ctx, &timestreaminfluxdb.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]any)
	for k, v := range resp.Tags {
		tags[k] = v
	}
	return tags, nil
}

// Cluster detail caching

type mqlAwsTimestreamInfluxdbClusterInternal struct {
	securityGroupIdHandler
	detailOnce sync.Once
	detailErr  error
	detail     *timestreaminfluxdb.GetDbClusterOutput
}

func (a *mqlAwsTimestreamInfluxdbCluster) fetchDetail() (*timestreaminfluxdb.GetDbClusterOutput, error) {
	a.detailOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.TimestreamInfluxDB(a.Region.Data)
		ctx := context.Background()
		id := a.Id.Data
		a.detail, a.detailErr = svc.GetDbCluster(ctx, &timestreaminfluxdb.GetDbClusterInput{
			DbClusterId: &id,
		})
		if a.detailErr == nil && a.detail != nil {
			accountID := conn.AccountId()
			region := a.Region.Data
			sgs := make([]string, 0, len(a.detail.VpcSecurityGroupIds))
			for _, sgID := range a.detail.VpcSecurityGroupIds {
				sgs = append(sgs, NewSecurityGroupArn(region, accountID, sgID))
			}
			a.setSecurityGroupArns(sgs)
		}
	})
	return a.detail, a.detailErr
}

func (a *mqlAwsTimestreamInfluxdbCluster) publiclyAccessible() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	return convert.ToValue(detail.PubliclyAccessible), nil
}

func (a *mqlAwsTimestreamInfluxdbCluster) vpcSubnets() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	accountID := conn.AccountId()
	res := make([]any, 0, len(detail.VpcSubnetIds))
	for _, subnetID := range detail.VpcSubnetIds {
		sub, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet, map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, region, accountID, subnetID)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, sub)
	}
	return res, nil
}

func (a *mqlAwsTimestreamInfluxdbCluster) securityGroups() ([]any, error) {
	if _, err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsTimestreamInfluxdbCluster) influxAuthParametersSecretArn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(detail.InfluxAuthParametersSecretArn), nil
}

func (a *mqlAwsTimestreamInfluxdbCluster) logDeliveryEnabled() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if detail.LogDeliveryConfiguration != nil && detail.LogDeliveryConfiguration.S3Configuration != nil {
		return convert.ToValue(detail.LogDeliveryConfiguration.S3Configuration.Enabled), nil
	}
	return false, nil
}

func (a *mqlAwsTimestreamInfluxdbCluster) logDeliveryS3Bucket() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail.LogDeliveryConfiguration != nil && detail.LogDeliveryConfiguration.S3Configuration != nil {
		return convert.ToValue(detail.LogDeliveryConfiguration.S3Configuration.BucketName), nil
	}
	return "", nil
}

func (a *mqlAwsTimestreamInfluxdbCluster) dbParameterGroupIdentifier() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(detail.DbParameterGroupIdentifier), nil
}

func (a *mqlAwsTimestreamInfluxdbCluster) failoverMode() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(detail.FailoverMode), nil
}

func (a *mqlAwsTimestreamInfluxdbCluster) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.TimestreamInfluxDB(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data

	resp, err := svc.ListTagsForResource(ctx, &timestreaminfluxdb.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]any)
	for k, v := range resp.Tags {
		tags[k] = v
	}
	return tags, nil
}

func (a *mqlAwsTimestreamInfluxdb) backups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getBackups(conn), 5)
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

func (a *mqlAwsTimestreamInfluxdb) getBackups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("timestream.influxdb>getBackups>calling aws with region %s", region)

			svc := conn.TimestreamInfluxDB(region)
			ctx := context.Background()
			res := []any{}

			// Listing without a DbResourceId returns every backup in the region,
			// so this stays one call per region rather than one per instance.
			paginator := timestreaminfluxdb.NewListDbBackupsPaginator(svc, &timestreaminfluxdb.ListDbBackupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS API")
						return jobpool.JobResult(res), nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("timestream influxdb service not available in region")
						return jobpool.JobResult(res), nil
					}
					return nil, err
				}
				for _, backup := range page.Items {
					mqlBackup, err := CreateResource(a.MqlRuntime, "aws.timestream.influxdb.backup",
						map[string]*llx.RawData{
							"__id":           llx.StringDataPtr(backup.Arn),
							"arn":            llx.StringDataPtr(backup.Arn),
							"id":             llx.StringDataPtr(backup.Id),
							"name":           llx.StringDataPtr(backup.Name),
							"status":         llx.StringData(string(backup.Status)),
							"type":           llx.StringData(string(backup.Type)),
							"engineType":     llx.StringData(string(backup.EngineType)),
							"deploymentType": llx.StringData(string(backup.DeploymentType)),
							"createdAt":      llx.TimeDataPtr(backup.CreatedAt),
							"expiresAfter":   llx.TimeDataPtr(parseInfluxdbExpiry(backup.ExpiresAfter)),
							"region":         llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					mqlB := mqlBackup.(*mqlAwsTimestreamInfluxdbBackup)
					mqlB.cacheDbResourceId = backup.DbResourceId
					mqlB.cacheKmsKeyId = backup.KmsKeyId
					res = append(res, mqlBackup)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// parseInfluxdbExpiry converts the backup expiry, which the API reports as an
// RFC3339 string rather than a timestamp, into the time form MQL wants.
func parseInfluxdbExpiry(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}

type mqlAwsTimestreamInfluxdbBackupInternal struct {
	lazyTags
	cacheDbResourceId *string
	cacheKmsKeyId     *string
}

func (a *mqlAwsTimestreamInfluxdbBackup) dbInstance() (*mqlAwsTimestreamInfluxdbInstance, error) {
	if a.cacheDbResourceId == nil || *a.cacheDbResourceId == "" {
		a.DbInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlInstance, err := NewResource(a.MqlRuntime, "aws.timestream.influxdb.instance",
		map[string]*llx.RawData{
			"id":     llx.StringDataPtr(a.cacheDbResourceId),
			"region": llx.StringData(a.Region.Data),
		})
	if err != nil {
		return nil, err
	}
	return mqlInstance.(*mqlAwsTimestreamInfluxdbInstance), nil
}

func (a *mqlAwsTimestreamInfluxdbBackup) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// initAwsTimestreamInfluxdbInstance resolves a single instance by id so a
// backup can point at the instance it was taken from without listing every
// instance in the region.
func initAwsTimestreamInfluxdbInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// region selects the regional client for the lookup. It is also a field on
	// the resource, so it can stay in args when the lookup falls through.
	var region string
	if r := args["region"]; r != nil {
		region, _ = r.Value.(string)
	}

	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil || region == "" {
		return args, nil, nil
	}
	id, _ := args["id"].Value.(string)
	if id == "" {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.TimestreamInfluxDB(region)
	resp, err := svc.GetDbInstance(context.Background(), &timestreaminfluxdb.GetDbInstanceInput{
		Identifier: &id,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp.Id == nil {
		return nil, nil, fmt.Errorf("aws.timestream.influxdb.instance with id %q not found", id)
	}

	mqlInstance, err := CreateResource(runtime, "aws.timestream.influxdb.instance",
		map[string]*llx.RawData{
			"__id":             llx.StringDataPtr(resp.Arn),
			"arn":              llx.StringDataPtr(resp.Arn),
			"id":               llx.StringDataPtr(resp.Id),
			"name":             llx.StringDataPtr(resp.Name),
			"allocatedStorage": llx.IntDataDefault(resp.AllocatedStorage, 0),
			"dbInstanceType":   llx.StringData(string(resp.DbInstanceType)),
			"dbStorageType":    llx.StringData(string(resp.DbStorageType)),
			"deploymentType":   llx.StringData(string(resp.DeploymentType)),
			"endpoint":         llx.StringDataPtr(resp.Endpoint),
			"networkType":      llx.StringData(string(resp.NetworkType)),
			"port":             llx.IntDataDefault(resp.Port, 0),
			"status":           llx.StringData(string(resp.Status)),
			"region":           llx.StringData(region),
		})
	if err != nil {
		return nil, nil, err
	}
	return args, mqlInstance, nil
}

func (a *mqlAwsTimestreamInfluxdbBackup) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.TimestreamInfluxDB(a.Region.Data)
		arn := a.Arn.Data
		resp, err := svc.ListTagsForResource(context.Background(), &timestreaminfluxdb.ListTagsForResourceInput{ResourceArn: &arn})
		if err != nil {
			if Is400AccessDeniedError(err) {
				if plugin.StructuredErrors() {
					return nil, llx.Forbidden(err, llx.WithPermissions("timestream-influxdb:ListTagsForResource"))
				}
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		return toInterfaceMap(resp.Tags), nil
	})
}
