// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsservice "github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/slicesx"
	"go.mondoo.com/mql/utils/stringx"
)

func (a *mqlAwsEcs) id() (string, error) {
	return "aws.ecs", nil
}

func (a *mqlAwsEcs) containers() ([]any, error) {
	obj, err := CreateResource(a.MqlRuntime, "aws.ecs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	ecs := obj.(*mqlAwsEcs)

	clusters, err := ecs.clusters()
	if err != nil {
		return nil, err
	}
	containers := []any{}

	for i := range clusters {
		tasks, err := clusters[i].(*mqlAwsEcsCluster).tasks()
		if err != nil {
			return nil, err
		}
		for i := range tasks {
			t := tasks[i].(*mqlAwsEcsTask)
			c := t.GetContainers()
			if c.Error != nil {
				return nil, c.Error
			}
			containers = append(containers, c.Data...)
		}
	}
	return containers, nil
}

func (a *mqlAwsEcs) containerInstances() ([]any, error) {
	obj, err := CreateResource(a.MqlRuntime, "aws.ecs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	ecs := obj.(*mqlAwsEcs)

	clusters, err := ecs.clusters()
	if err != nil {
		return nil, err
	}
	containerInstances := []any{}

	for i := range clusters {
		c := clusters[i].(*mqlAwsEcsCluster)
		ci := c.GetContainerInstances()
		if ci.Error != nil {
			return nil, ci.Error
		}
		containerInstances = append(containerInstances, ci.Data...)

	}
	return containerInstances, nil
}

func (a *mqlAwsEcsInstance) ec2Instance() (*mqlAwsEc2Instance, error) {
	return a.Ec2Instance.Data, nil
}

func (a *mqlAwsEcs) clusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getECSClusters(conn), 5)
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

func (a *mqlAwsEcs) getECSClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	var err error
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}} // return the error
	}
	log.Debug().Msgf("regions being called for ecs clusters list are: %v", regions)
	for ri := range regions {
		region := regions[ri]
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ecs(region)
			ctx := context.Background()
			res := []any{}

			params := &ecsservice.ListClustersInput{}
			paginator := ecsservice.NewListClustersPaginator(svc, params)
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ecs cluster information")
				}
				for _, clusterArn := range resp.ClusterArns {
					mqlCluster, err := NewResource(a.MqlRuntime, "aws.ecs.cluster",
						map[string]*llx.RawData{
							"arn": llx.StringData(clusterArn),
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

func initAwsEcsCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch ecs cluster")
	}
	a := args["arn"].Value.(string)
	conn := runtime.Connection.(*connection.AwsConnection)

	// Validate and parse ARN if provided
	parsedARN, err := validateAndParseARN(a, "ecs")
	if err != nil {
		return nil, nil, err
	}

	region := parsedARN.Region

	svc := conn.Ecs(region)
	ctx := context.Background()
	clusterDetails, err := svc.DescribeClusters(ctx, &ecs.DescribeClustersInput{Clusters: []string{a}, Include: []ecstypes.ClusterField{ecstypes.ClusterFieldConfigurations, ecstypes.ClusterFieldSettings, ecstypes.ClusterFieldStatistics, ecstypes.ClusterFieldTags}})
	if err != nil {
		return nil, nil, err
	}
	if len(clusterDetails.Clusters) != 1 {
		return nil, nil, errors.Newf("only expected one cluster, got %d", len(clusterDetails.Clusters))
	}
	c := clusterDetails.Clusters[0]
	configuration, err := convert.JsonToDict(c.Configuration)
	if err != nil {
		return nil, nil, err
	}
	args["activeServicesCount"] = llx.IntData(int64(c.ActiveServicesCount))
	args["configuration"] = llx.MapData(configuration, types.String)
	args["name"] = llx.StringDataPtr(c.ClusterName)
	args["pendingTasksCount"] = llx.IntData(int64(c.PendingTasksCount))
	args["region"] = llx.StringData(region)
	args["registeredContainerInstancesCount"] = llx.IntData(int64(c.RegisteredContainerInstancesCount))
	args["runningTasksCount"] = llx.IntData(int64(c.RunningTasksCount))
	args["status"] = llx.StringDataPtr(c.Status)
	args["tags"] = llx.MapData(ecsTagsToMap(c.Tags), types.String)
	settingsMap := make(map[string]any)
	for _, s := range c.Settings {
		if s.Value != nil {
			settingsMap[string(s.Name)] = *s.Value
		}
	}
	args["settings"] = llx.MapData(settingsMap, types.String)

	capacityProviders := make([]any, len(c.CapacityProviders))
	for i, cp := range c.CapacityProviders {
		capacityProviders[i] = cp
	}
	args["capacityProviders"] = llx.ArrayData(capacityProviders, types.String)

	statisticsMap := make(map[string]any)
	for _, s := range c.Statistics {
		if s.Name != nil && s.Value != nil {
			statisticsMap[*s.Name] = *s.Value
		}
	}
	args["statistics"] = llx.MapData(statisticsMap, types.String)

	clusterArn := a
	strategyItems := make([]any, 0, len(c.DefaultCapacityProviderStrategy))
	for _, item := range c.DefaultCapacityProviderStrategy {
		cpName := ""
		if item.CapacityProvider != nil {
			cpName = *item.CapacityProvider
		}
		r, err := CreateResource(runtime, "aws.ecs.cluster.capacityProviderStrategyItem",
			map[string]*llx.RawData{
				"__id":             llx.StringData(clusterArn + "/capacityProviderStrategy/" + cpName),
				"capacityProvider": llx.StringDataPtr(item.CapacityProvider),
				"base":             llx.IntData(int64(item.Base)),
				"weight":           llx.IntData(int64(item.Weight)),
			})
		if err != nil {
			return nil, nil, err
		}
		strategyItems = append(strategyItems, r)
	}
	args["defaultCapacityProviderStrategy"] = llx.ArrayData(strategyItems, types.Resource("aws.ecs.cluster.capacityProviderStrategyItem"))

	if c.ServiceConnectDefaults != nil {
		args["serviceConnectNamespace"] = llx.StringDataPtr(c.ServiceConnectDefaults.Namespace)
	} else {
		args["serviceConnectNamespace"] = llx.NilData
	}

	execCfg, err := newMqlEcsExecuteCommandConfiguration(runtime, a, region, conn.AccountId(), c.Configuration)
	if err != nil {
		return nil, nil, err
	}
	if execCfg != nil {
		args["executeCommandConfiguration"] = llx.ResourceData(execCfg, "aws.ecs.cluster.executeCommandConfiguration")
	} else {
		args["executeCommandConfiguration"] = llx.NilData
	}

	managedStorage, err := newMqlEcsManagedStorageConfiguration(runtime, a, c.Configuration)
	if err != nil {
		return nil, nil, err
	}
	args["managedStorage"] = managedStorage

	return args, nil, nil
}

// newMqlEcsExecuteCommandConfiguration builds the ECS Exec configuration
// resource for a cluster, or returns nil when the cluster reports none.
func newMqlEcsExecuteCommandConfiguration(runtime *plugin.Runtime, clusterArn, region, accountID string, cfg *ecstypes.ClusterConfiguration) (plugin.Resource, error) {
	if cfg == nil || cfg.ExecuteCommandConfiguration == nil {
		return nil, nil
	}
	ec := cfg.ExecuteCommandConfiguration

	var logGroupName, s3Bucket, s3KeyPrefix string
	var cwEncrypted, s3Encrypted bool
	if ec.LogConfiguration != nil {
		logGroupName = convert.ToValue(ec.LogConfiguration.CloudWatchLogGroupName)
		s3Bucket = convert.ToValue(ec.LogConfiguration.S3BucketName)
		s3KeyPrefix = convert.ToValue(ec.LogConfiguration.S3KeyPrefix)
		cwEncrypted = ec.LogConfiguration.CloudWatchEncryptionEnabled
		s3Encrypted = ec.LogConfiguration.S3EncryptionEnabled
	}

	res, err := CreateResource(runtime, "aws.ecs.cluster.executeCommandConfiguration", map[string]*llx.RawData{
		"__id":                        llx.StringData(clusterArn + "/executeCommandConfiguration"),
		"logging":                     llx.StringData(string(ec.Logging)),
		"cloudWatchEncryptionEnabled": llx.BoolData(cwEncrypted),
		"s3EncryptionEnabled":         llx.BoolData(s3Encrypted),
		"s3KeyPrefix":                 llx.StringData(s3KeyPrefix),
	})
	if err != nil {
		return nil, err
	}
	mqlCfg := res.(*mqlAwsEcsClusterExecuteCommandConfiguration)
	mqlCfg.region = region
	mqlCfg.accountID = accountID
	mqlCfg.cacheKmsKeyId = convert.ToValue(ec.KmsKeyId)
	mqlCfg.cacheLogGroupName = logGroupName
	mqlCfg.cacheS3BucketName = s3Bucket
	return mqlCfg, nil
}

type mqlAwsEcsClusterExecuteCommandConfigurationInternal struct {
	region            string
	accountID         string
	cacheKmsKeyId     string
	cacheLogGroupName string
	cacheS3BucketName string
}

func (a *mqlAwsEcsClusterExecuteCommandConfiguration) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey, map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheKmsKeyId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsEcsClusterExecuteCommandConfiguration) cloudWatchLogGroup() (*mqlAwsCloudwatchLoggroup, error) {
	if a.cacheLogGroupName == "" {
		a.CloudWatchLogGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// ECS reports the log group by name; the log group init only accepts an
	// ARN, so build one from the cluster's own region and account.
	res, err := NewResource(a.MqlRuntime, "aws.cloudwatch.loggroup", map[string]*llx.RawData{
		"arn": llx.StringData(fmt.Sprintf(logGroupArnPattern, a.region, a.accountID, a.cacheLogGroupName)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCloudwatchLoggroup), nil
}

func (a *mqlAwsEcsClusterExecuteCommandConfiguration) s3Bucket() (*mqlAwsS3Bucket, error) {
	if a.cacheS3BucketName == "" {
		a.S3Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.s3.bucket", map[string]*llx.RawData{
		"name": llx.StringData(a.cacheS3BucketName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsEcsCluster) defaultCapacityProviderStrategy() ([]any, error) {
	return nil, errors.New("defaultCapacityProviderStrategy not set during init")
}

func (a *mqlAwsEcsCluster) executeCommandConfiguration() (*mqlAwsEcsClusterExecuteCommandConfiguration, error) {
	return nil, errors.New("executeCommandConfiguration not set during init")
}

func (a *mqlAwsEcsCluster) managedStorage() (*mqlAwsEcsClusterManagedStorageConfiguration, error) {
	return nil, errors.New("managedStorage not set during init")
}

// newMqlEcsManagedStorageConfiguration builds the cluster's managed storage
// encryption settings. A cluster with no ManagedStorageConfiguration names no
// key of its own, which is reported as null rather than as a resource with two
// empty keys.
func newMqlEcsManagedStorageConfiguration(runtime *plugin.Runtime, clusterArn string, cfg *ecstypes.ClusterConfiguration) (*llx.RawData, error) {
	if cfg == nil || cfg.ManagedStorageConfiguration == nil {
		return llx.NilData, nil
	}
	msc := cfg.ManagedStorageConfiguration
	res, err := CreateResource(runtime, "aws.ecs.cluster.managedStorageConfiguration", map[string]*llx.RawData{
		"__id": llx.StringData(clusterArn + "/managedStorageConfiguration"),
	})
	if err != nil {
		return nil, err
	}
	mqlMsc := res.(*mqlAwsEcsClusterManagedStorageConfiguration)
	mqlMsc.cacheKmsKeyId = convert.ToValue(msc.KmsKeyId)
	mqlMsc.cacheFargateEphemeralStorageKmsKeyId = convert.ToValue(msc.FargateEphemeralStorageKmsKeyId)
	return llx.ResourceData(mqlMsc, "aws.ecs.cluster.managedStorageConfiguration"), nil
}

type mqlAwsEcsClusterManagedStorageConfigurationInternal struct {
	cacheKmsKeyId                        string
	cacheFargateEphemeralStorageKmsKeyId string
}

func (a *mqlAwsEcsClusterManagedStorageConfiguration) kmsKey() (*mqlAwsKmsKey, error) {
	return resolveEcsManagedStorageKey(a.MqlRuntime, a.cacheKmsKeyId, &a.KmsKey.State)
}

func (a *mqlAwsEcsClusterManagedStorageConfiguration) fargateEphemeralStorageKmsKey() (*mqlAwsKmsKey, error) {
	return resolveEcsManagedStorageKey(a.MqlRuntime, a.cacheFargateEphemeralStorageKmsKeyId, &a.FargateEphemeralStorageKmsKey.State)
}

func resolveEcsManagedStorageKey(runtime *plugin.Runtime, keyId string, state *plugin.State) (*mqlAwsKmsKey, error) {
	if keyId == "" {
		*state = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, ResourceAwsKmsKey, map[string]*llx.RawData{
		"arn": llx.StringData(keyId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsEcsCluster) fargateEphemeralStorageKmsKey() (*mqlAwsKmsKey, error) {
	config, ok := a.Configuration.Data.(map[string]any)
	if !ok || config == nil {
		a.FargateEphemeralStorageKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	msc, ok := config["ManagedStorageConfiguration"].(map[string]any)
	if !ok {
		a.FargateEphemeralStorageKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	keyId, ok := msc["FargateEphemeralStorageKmsKeyId"].(string)
	if !ok || keyId == "" {
		a.FargateEphemeralStorageKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey, map[string]*llx.RawData{
		"arn": llx.StringData(keyId),
	})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsEcsCluster) containerInstances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	clustera := a.Arn.Data
	region := ""
	if arn.IsARN(clustera) {
		if val, err := arn.Parse(clustera); err == nil {
			region = val.Region
		}
	}
	svc := conn.Ecs(region)
	ctx := context.Background()
	res := []any{}

	var allContainerInstanceArns []string
	var nextToken *string
	for {
		containerInstances, err := svc.ListContainerInstances(ctx, &ecsservice.ListContainerInstancesInput{
			Cluster:   &clustera,
			NextToken: nextToken,
		})
		if err != nil {
			log.Error().Err(err).Msg("cannot list container instances")
			break
		}
		allContainerInstanceArns = append(allContainerInstanceArns, containerInstances.ContainerInstanceArns...)
		if containerInstances.NextToken == nil {
			break
		}
		nextToken = containerInstances.NextToken
	}
	// DescribeContainerInstances accepts at most 100 entries per request, so a
	// cluster with more registered instances than that used to fail the call
	// outright -- and the error was only logged, so the cluster reported zero
	// container instances.
	for _, batch := range slicesx.Batch(allContainerInstanceArns, 100) {
		containerInstancesDetail, err := svc.DescribeContainerInstances(ctx, &ecsservice.DescribeContainerInstancesInput{Cluster: &clustera, ContainerInstances: batch, Include: []ecstypes.ContainerInstanceField{ecstypes.ContainerInstanceFieldTags}})
		if err == nil {
			for _, ci := range containerInstancesDetail.ContainerInstances {
				versionInfo, err := convert.JsonToDict(ci.VersionInfo)
				if err != nil {
					return nil, err
				}
				attributes, err := convert.JsonToDictSlice(ci.Attributes)
				if err != nil {
					return nil, err
				}
				healthStatus := ""
				if ci.HealthStatus != nil {
					healthStatus = string(ci.HealthStatus.OverallStatus)
				}
				// container instance assets
				args := map[string]*llx.RawData{
					"arn":               llx.StringData(convert.ToValue(ci.ContainerInstanceArn)),
					"agentConnected":    llx.BoolData(ci.AgentConnected),
					"id":                llx.StringData(convert.ToValue(ci.Ec2InstanceId)),
					"capacityProvider":  llx.StringData(convert.ToValue(ci.CapacityProviderName)),
					"region":            llx.StringData(region),
					"status":            llx.StringData(convert.ToValue(ci.Status)),
					"statusReason":      llx.StringData(convert.ToValue(ci.StatusReason)),
					"healthStatus":      llx.StringData(healthStatus),
					"runningTasksCount": llx.IntData(int64(ci.RunningTasksCount)),
					"pendingTasksCount": llx.IntData(int64(ci.PendingTasksCount)),
					"registeredAt":      llx.TimeDataPtr(ci.RegisteredAt),
					"versionInfo":       llx.DictData(versionInfo),
					"attributes":        llx.ArrayData(attributes, types.Dict),
					"tags":              llx.MapData(ecsTagsToMap(ci.Tags), types.String),
					"version":           llx.IntData(ci.Version),
				}
				if strings.HasPrefix(convert.ToValue(ci.Ec2InstanceId), "i-") {
					mqlInstanceResource, err := CreateResource(a.MqlRuntime, "aws.ec2.instance",
						map[string]*llx.RawData{
							"arn": llx.StringData(fmt.Sprintf(ec2InstanceArnPattern, region, conn.AccountId(), convert.ToValue(ci.Ec2InstanceId))),
						})
					if err == nil && mqlInstanceResource != nil {
						mqlInstance := mqlInstanceResource.(*mqlAwsEc2Instance)
						args["ec2Instance"] = llx.ResourceData(mqlInstance, mqlInstance.MqlName())
					}
				} else {
					args["ec2Instance"] = llx.NilData
				}

				mqlEcsInstance, err := CreateResource(a.MqlRuntime, "aws.ecs.instance", args)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlEcsInstance)
			}
		} else {
			log.Error().Err(err).Msg("could not gather ecs container instances")
		}
	}
	return res, nil
}

func (s *mqlAwsEcsInstance) id() (string, error) {
	return s.Arn.Data, nil
}

func (s *mqlAwsEcsCluster) id() (string, error) {
	return s.Arn.Data, nil
}

func (a *mqlAwsEcsCluster) tasks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	clustera := a.Arn.Data
	name := a.Arn.Data

	region := ""
	if arn.IsARN(clustera) {
		if val, err := arn.Parse(clustera); err == nil {
			region = val.Region
		}
	}
	svc := conn.Ecs(region)
	ctx := context.Background()
	res := []any{}

	params := &ecsservice.ListTasksInput{Cluster: &clustera}
	paginator := ecsservice.NewListTasksPaginator(svc, params)
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "could not gather ecs tasks information")
		}
		for _, taskArn := range resp.TaskArns {
			mqlTask, err := NewResource(a.MqlRuntime, "aws.ecs.task",
				map[string]*llx.RawData{
					"arn":         llx.StringData(taskArn),
					"clusterName": llx.StringData(name),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTask)
		}
	}
	return res, nil
}

func (s *mqlAwsEcsTask) id() (string, error) {
	return s.Arn.Data, nil
}

func initAwsEcsTask(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch ecs task")
	}
	a := args["arn"].Value.(string)
	conn := runtime.Connection.(*connection.AwsConnection)

	parsedARN, err := validateAndParseARN(a, "ecs")
	if err != nil {
		return nil, nil, err
	}

	region := parsedARN.Region
	clusterName := ""
	if res := strings.Split(parsedARN.Resource, "/"); len(res) == 3 {
		clusterName = res[1]
	}

	svc := conn.Ecs(region)
	ctx := context.Background()
	params := &ecs.DescribeTasksInput{Tasks: []string{a}, Cluster: &clusterName, Include: []ecstypes.TaskField{ecstypes.TaskFieldTags}}
	taskDetails, err := svc.DescribeTasks(ctx, params)
	if err != nil {
		return nil, nil, err
	}
	if len(taskDetails.Tasks) != 1 {
		return nil, nil, errors.Newf("only expected one task, got %d", len(taskDetails.Tasks))
	}

	t := taskDetails.Tasks[0]
	args["clusterName"] = llx.StringData(clusterName)
	args["connectivity"] = llx.StringData(string(t.Connectivity))
	args["lastStatus"] = llx.StringData(convert.ToValue(t.LastStatus))
	args["platformFamily"] = llx.StringData(convert.ToValue(t.PlatformFamily))
	args["platformVersion"] = llx.StringData(convert.ToValue(t.PlatformVersion))
	args["tags"] = llx.MapData(ecsTagsToMap(t.Tags), types.String)
	args["region"] = llx.StringData(region)
	args["containerInstanceArn"] = llx.StringData(convert.ToValue(t.ContainerInstanceArn))
	args["cpu"] = llx.StringData(convert.ToValue(t.Cpu))
	args["memory"] = llx.StringData(convert.ToValue(t.Memory))
	args["healthStatus"] = llx.StringData(string(t.HealthStatus))
	args["launchType"] = llx.StringData(string(t.LaunchType))
	args["capacityProviderName"] = llx.StringData(convert.ToValue(t.CapacityProviderName))
	args["group"] = llx.StringData(convert.ToValue(t.Group))
	args["startedBy"] = llx.StringData(convert.ToValue(t.StartedBy))
	args["enableExecuteCommand"] = llx.BoolData(t.EnableExecuteCommand)
	args["stopCode"] = llx.StringData(string(t.StopCode))
	args["stoppedReason"] = llx.StringData(convert.ToValue(t.StoppedReason))
	args["createdAt"] = llx.TimeDataPtr(t.CreatedAt)
	args["startedAt"] = llx.TimeDataPtr(t.StartedAt)
	args["stoppedAt"] = llx.TimeDataPtr(t.StoppedAt)

	// Ephemeral storage size: prefer the Fargate-specific value (which also
	// carries the encryption key), otherwise the generic task ephemeral
	// storage. The API only reports these when explicitly configured, so leave
	// the field null otherwise rather than implying 0 GiB is allocated.
	switch {
	case t.FargateEphemeralStorage != nil:
		args["ephemeralStorageSizeInGiB"] = llx.IntData(int64(t.FargateEphemeralStorage.SizeInGiB))
	case t.EphemeralStorage != nil:
		args["ephemeralStorageSizeInGiB"] = llx.IntData(int64(t.EphemeralStorage.SizeInGiB))
	default:
		args["ephemeralStorageSizeInGiB"] = llx.NilData
	}

	res, err := CreateResource(runtime, "aws.ecs.task", args)
	if err != nil {
		return args, nil, err
	}
	res.(*mqlAwsEcsTask).cacheContainers = t.Containers
	res.(*mqlAwsEcsTask).region = region
	res.(*mqlAwsEcsTask).attachments = t.Attachments
	res.(*mqlAwsEcsTask).clusterName = clusterName
	res.(*mqlAwsEcsTask).taskDefArn = t.TaskDefinitionArn
	if t.FargateEphemeralStorage != nil {
		res.(*mqlAwsEcsTask).fargateEphemeralStorageKmsKeyId = t.FargateEphemeralStorage.KmsKeyId
	}

	return args, res, nil
}

type mqlAwsEcsTaskInternal struct {
	cacheContainers                 []ecstypes.Container
	region                          string
	attachments                     []ecstypes.Attachment
	clusterName                     string
	taskDefArn                      *string
	fargateEphemeralStorageKmsKeyId *string
}

func (t *mqlAwsEcsTask) fargateEphemeralStorageKmsKey() (*mqlAwsKmsKey, error) {
	if t.fargateEphemeralStorageKmsKeyId == nil || *t.fargateEphemeralStorageKmsKeyId == "" {
		t.FargateEphemeralStorageKmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(t.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(t.fargateEphemeralStorageKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsEcsTask) taskDefinition() (*mqlAwsEcsTaskDefinition, error) {
	if a.taskDefArn == nil || *a.taskDefArn == "" {
		a.TaskDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// Create the resource directly with arn + region so fields resolve lazily
	// via fetchDetail, avoiding a full task-definition listing.
	res, err := CreateResource(a.MqlRuntime, "aws.ecs.taskDefinition",
		map[string]*llx.RawData{
			"arn":    llx.StringDataPtr(a.taskDefArn),
			"region": llx.StringData(a.region),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEcsTaskDefinition), nil
}

func (t *mqlAwsEcsTask) containers() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()

	svc := conn.Ecs(t.region)
	definition, err := svc.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: t.taskDefArn})
	if err != nil {
		return nil, err
	}
	if definition.TaskDefinition == nil {
		return nil, nil
	}
	containerLogDriverMap := make(map[string]string)
	containerCommandMap := make(map[string][]string)
	containerUserMap := make(map[string]string)
	containerInitProcessMap := make(map[string]bool)
	containerRepoCredsMap := make(map[string]string)

	for i := range definition.TaskDefinition.ContainerDefinitions {
		cd := definition.TaskDefinition.ContainerDefinitions[i]
		if cd.Name != nil {
			containerCommandMap[*cd.Name] = cd.Command
			if cd.LogConfiguration != nil {
				containerLogDriverMap[*cd.Name] = string(cd.LogConfiguration.LogDriver)
			} else {
				containerLogDriverMap[*cd.Name] = "none"
			}
			containerUserMap[*cd.Name] = convert.ToValue(cd.User)
			if cd.LinuxParameters != nil {
				containerInitProcessMap[*cd.Name] = convert.ToValue(cd.LinuxParameters.InitProcessEnabled)
			}
			if cd.RepositoryCredentials != nil {
				containerRepoCredsMap[*cd.Name] = convert.ToValue(cd.RepositoryCredentials.CredentialsParameter)
			}
		}
	}

	// Batch-fetch all ENI public IPs for this task's containers in a single API call.
	eniPublicIPs := batchFetchENIPublicIPs(ctx, conn, t.attachments, t.region)

	containers := []any{}
	for _, c := range t.cacheContainers {
		cmds := []any{}
		for _, cmd := range containerCommandMap[convert.ToValue(c.Name)] {
			cmds = append(cmds, cmd)
		}
		publicIp := getContainerIP(eniPublicIPs, t.attachments, c)
		name := convert.ToValue(c.Name)
		if publicIp != "" {
			name = name + "-" + publicIp
		}

		if !conn.Filters.Ecs.MatchesOnlyRunningContainers(convert.ToValue(c.LastStatus)) {
			log.Debug().Str("container", name).Str("state", convert.ToValue(c.LastStatus)).Msg("skipping ecs container due to not being in a running state")
			continue
		}

		mqlContainer, err := CreateResource(t.MqlRuntime, "aws.ecs.container",
			map[string]*llx.RawData{
				"arn":                llx.StringDataPtr(c.ContainerArn),
				"clusterName":        llx.StringData(t.clusterName),
				"command":            llx.ArrayData(cmds, types.Any),
				"containerName":      llx.StringDataPtr(c.Name),
				"cpuUnits":           llx.StringDataPtr(c.Cpu),
				"image":              llx.StringData(convert.ToValue(c.Image)),
				"imageDigest":        llx.StringDataPtr(c.ImageDigest),
				"logDriver":          llx.StringData(containerLogDriverMap[convert.ToValue(c.Name)]),
				"name":               llx.StringData(name),
				"platformFamily":     llx.StringData(t.PlatformFamily.Data),
				"platformVersion":    llx.StringData(t.PlatformVersion.Data),
				"publicIp":           llx.StringData(publicIp),
				"region":             llx.StringData(t.region),
				"runtimeId":          llx.StringDataPtr(c.RuntimeId),
				"status":             llx.StringDataPtr(c.LastStatus),
				"memorySoftLimit":    llx.StringDataPtr(c.MemoryReservation),
				"memoryHardLimit":    llx.StringDataPtr(c.Memory),
				"reason":             llx.StringDataPtr(c.Reason),
				"user":               llx.StringData(containerUserMap[convert.ToValue(c.Name)]),
				"initProcessEnabled": llx.BoolData(containerInitProcessMap[convert.ToValue(c.Name)]),
			})
		if err != nil {
			return nil, err
		}
		mqlContainer.(*mqlAwsEcsContainer).cacheTaskArn = t.Arn.Data
		mqlContainer.(*mqlAwsEcsContainer).cacheTaskDefinitionArn = convert.ToValue(t.taskDefArn)
		mqlContainer.(*mqlAwsEcsContainer).cacheRepositoryCredentialsArn = containerRepoCredsMap[convert.ToValue(c.Name)]
		containers = append(containers, mqlContainer)
	}
	return containers, nil
}

type mqlAwsEcsContainerInternal struct {
	cacheTaskArn                  string
	cacheTaskDefinitionArn        string
	cacheRepositoryCredentialsArn string
}

// ecrImage resolves the ECR image the container is running, when the image is
// hosted in Elastic Container Registry in this account. The image is frequently
// pulled from Docker Hub, a public registry, or a cross-account ECR repository,
// in which case there is no matching aws.ecr.image and the reference is null.
func (a *mqlAwsEcsContainer) ecrImage() (*mqlAwsEcrImage, error) {
	image := a.Image.Data
	digest := a.ImageDigest.Data
	if digest == "" || !strings.Contains(image, ".dkr.ecr.") {
		a.EcrImage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// <registryId>.dkr.ecr.<region>.amazonaws.com/<repoName>[:tag][@digest]
	host, path, ok := strings.Cut(image, "/")
	if !ok {
		a.EcrImage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	hostParts := strings.Split(host, ".")
	if len(hostParts) < 4 {
		a.EcrImage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	repoName := path
	if i := strings.IndexByte(repoName, '@'); i >= 0 {
		repoName = repoName[:i]
	}
	if i := strings.IndexByte(repoName, ':'); i >= 0 {
		repoName = repoName[:i]
	}
	arnVal := ecrImageArn(ImageInfo{Region: hostParts[3], RegistryId: hostParts[0], RepoName: repoName, Digest: digest})
	res, err := NewResource(a.MqlRuntime, "aws.ecr.image",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		// The image is commonly absent (deleted, or in another account), which
		// surfaces here as an error; log it so genuine API/permission failures
		// are still visible, but leave the reference null rather than failing.
		log.Warn().Err(err).Str("arn", arnVal).Msg("could not resolve ECR image for ECS container")
		a.EcrImage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsEcrImage), nil
}

// repositoryCredentialsSecret resolves the Secrets Manager secret holding the
// private registry credentials used to pull the image. Only set when the task
// definition configures repositoryCredentials.
func (a *mqlAwsEcsContainer) repositoryCredentialsSecret() (*mqlAwsSecretsmanagerSecret, error) {
	if a.cacheRepositoryCredentialsArn == "" {
		a.RepositoryCredentialsSecret.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.secretsmanager.secret",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheRepositoryCredentialsArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecretsmanagerSecret), nil
}

func getContainerIP(eniPublicIPs map[string]string, attachments []ecstypes.Attachment, c ecstypes.Container) string {
	containerAttachmentIds := []string{}
	for _, ca := range c.NetworkInterfaces {
		if ca.AttachmentId != nil {
			containerAttachmentIds = append(containerAttachmentIds, *ca.AttachmentId)
		}
	}
	for _, a := range attachments {
		if a.Id != nil && stringx.Contains(containerAttachmentIds, *a.Id) {
			for _, detail := range a.Details {
				if detail.Name != nil && *detail.Name == "networkInterfaceId" {
					if detail.Value != nil {
						if ip, ok := eniPublicIPs[*detail.Value]; ok {
							return ip
						}
					}
				}
			}
		}
	}
	return ""
}

// batchFetchENIPublicIPs collects all network interface IDs from task attachments
// and fetches their public IPs in a single DescribeNetworkInterfaces call.
func batchFetchENIPublicIPs(ctx context.Context, conn *connection.AwsConnection, attachments []ecstypes.Attachment, region string) map[string]string {
	eniIDs := []string{}
	for _, a := range attachments {
		for _, detail := range a.Details {
			if detail.Name != nil && *detail.Name == "networkInterfaceId" && detail.Value != nil {
				eniIDs = append(eniIDs, *detail.Value)
			}
		}
	}
	result := make(map[string]string)
	if len(eniIDs) == 0 {
		return result
	}

	svc := conn.Ec2(region)
	resp, err := svc.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: eniIDs})
	if err != nil {
		log.Warn().Err(err).Msg("failed to batch-fetch ENI public IPs")
		return result
	}
	for _, ni := range resp.NetworkInterfaces {
		if ni.NetworkInterfaceId != nil && ni.Association != nil && ni.Association.PublicIp != nil {
			result[*ni.NetworkInterfaceId] = *ni.Association.PublicIp
		}
	}
	return result
}

func (s *mqlAwsEcsContainer) id() (string, error) {
	return s.Arn.Data, nil
}

func ecsTagsToMap(tags []ecstypes.Tag) map[string]any {
	return tagsToMap(tags, func(t ecstypes.Tag) *string { return t.Key }, func(t ecstypes.Tag) *string { return t.Value })
}

// validateAndParseARN validates that the given string is a valid ECS ARN
// and returns the parsed ARN structure. Returns an error if the ARN is malformed
// or does not belong to the expectedService.
func validateAndParseARN(arnStr, expectedService string) (*arn.ARN, error) {
	if !strings.HasPrefix(arnStr, "arn:") {
		return nil, errors.Newf("invalid ARN format: %s", arnStr)
	}

	parsedArn, err := arn.Parse(arnStr)
	if err != nil {
		return nil, err
	}

	if parsedArn.Service != expectedService {
		return nil, errors.Newf("invalid ARN (service is %s, expected %s): %s",
			parsedArn.Service, expectedService, arnStr)
	}

	return &parsedArn, nil
}

func (a *mqlAwsEcs) taskDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getECSTaskDefinitions(conn), 5)
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

func (a *mqlAwsEcs) getECSTaskDefinitions(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	var err error
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}} // return the error
	}
	log.Debug().Msgf("regions being called for ecs task definitions list are: %v", regions)
	for ri := range regions {
		region := regions[ri]
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ecs(region)
			ctx := context.Background()
			res := []any{}

			params := &ecsservice.ListTaskDefinitionsInput{}
			paginator := ecsservice.NewListTaskDefinitionsPaginator(svc, params)
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ecs task definition information")
				}
				for _, taskDefArn := range resp.TaskDefinitionArns {
					args := map[string]*llx.RawData{
						"__id":   llx.StringData(taskDefArn),
						"arn":    llx.StringData(taskDefArn),
						"region": llx.StringData(region),
					}
					// Only fetch tags eagerly when tag-based filters are configured
					if conn.Filters.General.HasTags() {
						tagsResp, err := svc.ListTagsForResource(ctx, &ecsservice.ListTagsForResourceInput{ResourceArn: &taskDefArn})
						if err == nil {
							tagsMap := ecsTagsToMap(tagsResp.Tags)
							if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tagsMap)) {
								log.Debug().Str("taskDefinition", taskDefArn).Msg("excluding ecs task definition due to tag filters")
								continue
							}
							// reuse the fetched tags so discovery labels don't refetch
							args["tags"] = llx.MapData(tagsMap, types.String)
						} else {
							log.Warn().Err(err).Str("taskDefinition", taskDefArn).Msg("could not get tags for ecs task definition")
						}
					}

					mqlTaskDef, err := CreateResource(a.MqlRuntime, ResourceAwsEcsTaskDefinition, args)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlTaskDef)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func createTaskDefinitionResource(runtime *plugin.Runtime, region string, td *ecstypes.TaskDefinition) (any, error) {
	// Extract basic fields
	arnVal := ""
	if td.TaskDefinitionArn != nil {
		arnVal = *td.TaskDefinitionArn
	}
	family := ""
	if td.Family != nil {
		family = *td.Family
	}
	revision := int64(td.Revision)
	status := string(td.Status)
	networkMode := ""
	if td.NetworkMode != "" {
		networkMode = string(td.NetworkMode)
	}
	pidMode := ""
	if td.PidMode != "" {
		pidMode = string(td.PidMode)
	}
	ipcMode := ""
	if td.IpcMode != "" {
		ipcMode = string(td.IpcMode)
	}
	taskRoleArn := ""
	if td.TaskRoleArn != nil {
		taskRoleArn = *td.TaskRoleArn
	}
	executionRoleArn := ""
	if td.ExecutionRoleArn != nil {
		executionRoleArn = *td.ExecutionRoleArn
	}

	// Create container definitions
	containerDefs := []any{}
	for i := range td.ContainerDefinitions {
		mqlContainerDef, err := createContainerDefinitionResource(runtime, arnVal, &td.ContainerDefinitions[i])
		if err != nil {
			return nil, err
		}
		containerDefs = append(containerDefs, mqlContainerDef)
	}

	// Create volumes
	volumes := []any{}
	for i := range td.Volumes {
		mqlVolume, err := createVolumeResource(runtime, region, convert.ToValue(td.TaskDefinitionArn), &td.Volumes[i])
		if err != nil {
			return nil, err
		}
		volumes = append(volumes, mqlVolume)
	}

	// Create ephemeral storage
	var ephemeralStorage any
	if td.EphemeralStorage != nil {
		mqlEphemeralStorage, err := createEphemeralStorageResource(runtime, arnVal, td.EphemeralStorage)
		if err != nil {
			return nil, err
		}
		ephemeralStorage = mqlEphemeralStorage
	} else {
		// Create empty ephemeral storage resource
		mqlEphemeralStorage, err := CreateResource(runtime, "aws.ecs.taskDefinition.ephemeralStorage",
			map[string]*llx.RawData{
				"__id":      llx.StringData(arnVal + "/ephemeralStorage"),
				"sizeInGiB": llx.IntData(0),
			})
		if err != nil {
			return nil, err
		}
		ephemeralStorage = mqlEphemeralStorage
	}

	// Type assert ephemeralStorage to Resource
	ephemeralStorageResource, ok := ephemeralStorage.(plugin.Resource)
	if !ok {
		return nil, errors.New("failed to convert ephemeralStorage to Resource")
	}

	res, err := CreateResource(runtime, "aws.ecs.taskDefinition",
		map[string]*llx.RawData{
			"__id":                 llx.StringData(arnVal),
			"arn":                  llx.StringData(arnVal),
			"family":               llx.StringData(family),
			"revision":             llx.IntData(revision),
			"status":               llx.StringData(status),
			"networkMode":          llx.StringData(networkMode),
			"pidMode":              llx.StringData(pidMode),
			"ipcMode":              llx.StringData(ipcMode),
			"taskRoleArn":          llx.StringData(taskRoleArn),
			"executionRoleArn":     llx.StringData(executionRoleArn),
			"containerDefinitions": llx.ArrayData(containerDefs, types.Resource("aws.ecs.taskDefinition.containerDefinition")),
			"volumes":              llx.ArrayData(volumes, types.Resource("aws.ecs.taskDefinition.volume")),
			"ephemeralStorage":     llx.ResourceData(ephemeralStorageResource, "aws.ecs.taskDefinition.ephemeralStorage"),
			"region":               llx.StringData(region),
			"cpu":                  llx.StringDataPtr(td.Cpu),
			"memory":               llx.StringDataPtr(td.Memory),
			"registeredAt":         llx.TimeDataPtr(td.RegisteredAt),
		})
	if err != nil {
		return nil, err
	}
	// Cache the task definition data so fetchDetail() doesn't re-fetch
	mqlTD := res.(*mqlAwsEcsTaskDefinition)
	mqlTD.cachedTD = td
	mqlTD.fetched = true
	return res, nil
}

func createContainerDefinitionResource(runtime *plugin.Runtime, taskDefArn string, cd *ecstypes.ContainerDefinition) (any, error) {
	name := ""
	if cd.Name != nil {
		name = *cd.Name
	}
	image := ""
	if cd.Image != nil {
		image = *cd.Image
	}
	privileged := false
	if cd.Privileged != nil {
		privileged = *cd.Privileged
	}
	readonlyRootFilesystem := false
	if cd.ReadonlyRootFilesystem != nil {
		readonlyRootFilesystem = *cd.ReadonlyRootFilesystem
	}
	user := ""
	if cd.User != nil {
		user = *cd.User
	}
	memory := int64(0)
	if cd.Memory != nil {
		memory = int64(*cd.Memory)
	}
	cpu := int64(cd.Cpu)
	// AWS defaults initProcessEnabled to false when LinuxParameters is nil
	initProcessEnabled := false
	if cd.LinuxParameters != nil && cd.LinuxParameters.InitProcessEnabled != nil {
		initProcessEnabled = *cd.LinuxParameters.InitProcessEnabled
	}

	// Create environment variables
	envVars := []any{}
	if cd.Environment != nil {
		for _, env := range cd.Environment {
			envName := ""
			envValue := ""
			if env.Name != nil {
				envName = *env.Name
			}
			if env.Value != nil {
				envValue = *env.Value
			}
			mqlEnv, err := CreateResource(runtime, ResourceAwsEcsTaskDefinitionContainerDefinitionEnvironmentVariable,
				map[string]*llx.RawData{
					"__id":  llx.StringData(taskDefArn + "/container/" + name + "/env/" + envName),
					"name":  llx.StringData(envName),
					"value": llx.StringData(envValue),
				})
			if err != nil {
				return nil, err
			}
			envVars = append(envVars, mqlEnv)
		}
	}

	// Create secrets
	secrets := []any{}
	if cd.Secrets != nil {
		for _, secret := range cd.Secrets {
			secretName := ""
			valueFrom := ""
			if secret.Name != nil {
				secretName = *secret.Name
			}
			if secret.ValueFrom != nil {
				valueFrom = *secret.ValueFrom
			}
			mqlSecret, err := CreateResource(runtime, ResourceAwsEcsTaskDefinitionContainerDefinitionSecret,
				map[string]*llx.RawData{
					"__id":      llx.StringData(taskDefArn + "/container/" + name + "/secret/" + secretName),
					"name":      llx.StringData(secretName),
					"valueFrom": llx.StringData(valueFrom),
				})
			if err != nil {
				return nil, err
			}
			secrets = append(secrets, mqlSecret)
		}
	}

	// Create log configuration
	var logConfig any
	if cd.LogConfiguration != nil {
		logDriver := string(cd.LogConfiguration.LogDriver)
		options := make(map[string]any)
		if cd.LogConfiguration.Options != nil {
			for k, v := range cd.LogConfiguration.Options {
				options[k] = v
			}
		}
		mqlLogConfig, err := CreateResource(runtime, ResourceAwsEcsTaskDefinitionContainerDefinitionLogConfiguration,
			map[string]*llx.RawData{
				"__id":      llx.StringData(taskDefArn + "/container/" + name + "/logConfiguration"),
				"logDriver": llx.StringData(logDriver),
				"options":   llx.MapData(options, types.String),
			})
		if err != nil {
			return nil, err
		}
		logConfig = mqlLogConfig
	}
	// When the API returns no log configuration, the field stays null. Creating
	// an empty sub-resource here made `logConfiguration != empty` true for
	// EVERY container, so logging checks could never fail.

	// Create port mappings
	portMappings := []any{}
	if cd.PortMappings != nil {
		for _, pm := range cd.PortMappings {
			containerPort := int64(0)
			if pm.ContainerPort != nil {
				containerPort = int64(*pm.ContainerPort)
			}
			hostPort := int64(0)
			if pm.HostPort != nil {
				hostPort = int64(*pm.HostPort)
			}
			protocol := string(pm.Protocol)
			mqlPortMapping, err := CreateResource(runtime, ResourceAwsEcsTaskDefinitionContainerDefinitionPortMapping,
				map[string]*llx.RawData{
					"__id":          llx.StringData(fmt.Sprintf("%s/container/%s/port/%d", taskDefArn, name, containerPort)),
					"containerPort": llx.IntData(containerPort),
					"hostPort":      llx.IntData(hostPort),
					"protocol":      llx.StringData(protocol),
				})
			if err != nil {
				return nil, err
			}
			portMappings = append(portMappings, mqlPortMapping)
		}
	}

	// Accelerator resource requirements, keyed by resource type (GPU,
	// InferenceAccelerator, NeuronDevice)
	resourceRequirements := map[string]any{}
	for _, rr := range cd.ResourceRequirements {
		resourceRequirements[string(rr.Type)] = convert.ToValue(rr.Value)
	}

	// Linux kernel capabilities (add/drop)
	capAdd := []any{}
	capDrop := []any{}
	if cd.LinuxParameters != nil && cd.LinuxParameters.Capabilities != nil {
		capAdd = toAnySlice(cd.LinuxParameters.Capabilities.Add)
		capDrop = toAnySlice(cd.LinuxParameters.Capabilities.Drop)
	}

	dockerLabels := map[string]any{}
	for k, v := range cd.DockerLabels {
		dockerLabels[k] = v
	}

	healthCheck, err := convert.JsonToDict(cd.HealthCheck)
	if err != nil {
		return nil, err
	}
	mountPoints, err := convert.JsonToDictSlice(cd.MountPoints)
	if err != nil {
		return nil, err
	}
	volumesFrom, err := convert.JsonToDictSlice(cd.VolumesFrom)
	if err != nil {
		return nil, err
	}
	dependsOn, err := convert.JsonToDictSlice(cd.DependsOn)
	if err != nil {
		return nil, err
	}
	ulimits, err := convert.JsonToDictSlice(cd.Ulimits)
	if err != nil {
		return nil, err
	}

	repositoryCredentialsParameter := ""
	if cd.RepositoryCredentials != nil {
		repositoryCredentialsParameter = convert.ToValue(cd.RepositoryCredentials.CredentialsParameter)
	}

	// Null when the container has no log configuration.
	logConfigData := llx.NilData
	if logConfigResource, ok := logConfig.(plugin.Resource); ok {
		logConfigData = llx.ResourceData(logConfigResource, "aws.ecs.taskDefinition.containerDefinition.logConfiguration")
	}

	return CreateResource(runtime, ResourceAwsEcsTaskDefinitionContainerDefinition,
		map[string]*llx.RawData{
			"__id":                           llx.StringData(taskDefArn + "/container/" + name),
			"name":                           llx.StringData(name),
			"image":                          llx.StringData(image),
			"privileged":                     llx.BoolData(privileged),
			"readonlyRootFilesystem":         llx.BoolData(readonlyRootFilesystem),
			"user":                           llx.StringData(user),
			"environment":                    llx.ArrayData(envVars, types.Resource("aws.ecs.taskDefinition.containerDefinition.environmentVariable")),
			"secrets":                        llx.ArrayData(secrets, types.Resource("aws.ecs.taskDefinition.containerDefinition.secret")),
			"logConfiguration":               logConfigData,
			"memory":                         llx.IntData(memory),
			"cpu":                            llx.IntData(cpu),
			"portMappings":                   llx.ArrayData(portMappings, types.Resource("aws.ecs.taskDefinition.containerDefinition.portMapping")),
			"initProcessEnabled":             llx.BoolData(initProcessEnabled),
			"resourceRequirements":           llx.MapData(resourceRequirements, types.String),
			"essential":                      llx.BoolData(convert.ToValue(cd.Essential)),
			"linuxCapabilitiesAdd":           llx.ArrayData(capAdd, types.String),
			"linuxCapabilitiesDrop":          llx.ArrayData(capDrop, types.String),
			"entryPoint":                     llx.ArrayData(toAnySlice(cd.EntryPoint), types.String),
			"command":                        llx.ArrayData(toAnySlice(cd.Command), types.String),
			"workingDirectory":               llx.StringData(convert.ToValue(cd.WorkingDirectory)),
			"dockerLabels":                   llx.MapData(dockerLabels, types.String),
			"healthCheck":                    llx.DictData(healthCheck),
			"mountPoints":                    llx.ArrayData(mountPoints, types.Dict),
			"volumesFrom":                    llx.ArrayData(volumesFrom, types.Dict),
			"dependsOn":                      llx.ArrayData(dependsOn, types.Dict),
			"ulimits":                        llx.ArrayData(ulimits, types.Dict),
			"dnsServers":                     llx.ArrayData(toAnySlice(cd.DnsServers), types.String),
			"repositoryCredentialsParameter": llx.StringData(repositoryCredentialsParameter),
			"startTimeout":                   llx.IntData(int64(convert.ToValue(cd.StartTimeout))),
			"stopTimeout":                    llx.IntData(int64(convert.ToValue(cd.StopTimeout))),
			"pseudoTerminal":                 llx.BoolData(convert.ToValue(cd.PseudoTerminal)),
			"interactive":                    llx.BoolData(convert.ToValue(cd.Interactive)),
		})
}

// createVolumeResource builds one task-definition volume. taskDefArn qualifies
// every cache key below: volume names are unique only within a single task
// definition revision, so keying on the bare name collapses same-named volumes
// (data, tmp, config) across every revision in the account onto the first one.
func createVolumeResource(runtime *plugin.Runtime, region string, taskDefArn string, vol *ecstypes.Volume) (any, error) {
	volName := ""
	if vol.Name != nil {
		volName = *vol.Name
	}
	volKey := taskDefArn + "/volume/" + volName

	// Create EFS volume configuration
	var efsVolConfig any
	if vol.EfsVolumeConfiguration != nil {
		efsConfig := vol.EfsVolumeConfiguration
		fileSystemId := ""
		if efsConfig.FileSystemId != nil {
			fileSystemId = *efsConfig.FileSystemId
		}
		rootDirectory := ""
		if efsConfig.RootDirectory != nil {
			rootDirectory = *efsConfig.RootDirectory
		}
		transitEncryption := string(efsConfig.TransitEncryption)
		transitEncryptionPort := int64(0)
		if efsConfig.TransitEncryptionPort != nil {
			transitEncryptionPort = int64(*efsConfig.TransitEncryptionPort)
		}

		// Create authorization config
		var authConfig any
		if efsConfig.AuthorizationConfig != nil {
			accessPointId := ""
			if efsConfig.AuthorizationConfig.AccessPointId != nil {
				accessPointId = *efsConfig.AuthorizationConfig.AccessPointId
			}
			iam := string(efsConfig.AuthorizationConfig.Iam)
			mqlAuthConfig, err := CreateResource(runtime, "aws.ecs.taskDefinition.volume.efsVolumeConfiguration.authorizationConfig",
				map[string]*llx.RawData{
					"__id":          llx.StringData(volKey + "/efs/auth"),
					"accessPointId": llx.StringData(accessPointId),
					"iam":           llx.StringData(iam),
				})
			if err != nil {
				return nil, err
			}
			authConfig = mqlAuthConfig
		} else {
			// Create empty authorization config
			mqlAuthConfig, err := CreateResource(runtime, "aws.ecs.taskDefinition.volume.efsVolumeConfiguration.authorizationConfig",
				map[string]*llx.RawData{
					"__id":          llx.StringData(volKey + "/efs/auth"),
					"accessPointId": llx.StringData(""),
					"iam":           llx.StringData(""),
				})
			if err != nil {
				return nil, err
			}
			authConfig = mqlAuthConfig
		}

		// Type assert authConfig to Resource
		authConfigResource, ok := authConfig.(plugin.Resource)
		if !ok {
			return nil, errors.New("failed to convert authConfig to Resource")
		}
		mqlEfsConfig, err := CreateResource(runtime, "aws.ecs.taskDefinition.volume.efsVolumeConfiguration",
			map[string]*llx.RawData{
				"__id":                  llx.StringData(volKey + "/efs"),
				"rootDirectory":         llx.StringData(rootDirectory),
				"transitEncryption":     llx.StringData(transitEncryption),
				"transitEncryptionPort": llx.IntData(transitEncryptionPort),
				"authorizationConfig":   llx.ResourceData(authConfigResource, "aws.ecs.taskDefinition.volume.efsVolumeConfiguration.authorizationConfig"),
			})
		if err != nil {
			return nil, err
		}
		mqlEfsConfig.(*mqlAwsEcsTaskDefinitionVolumeEfsVolumeConfiguration).cacheFileSystemId = fileSystemId
		mqlEfsConfig.(*mqlAwsEcsTaskDefinitionVolumeEfsVolumeConfiguration).region = region
		efsVolConfig = mqlEfsConfig
	} else {
		// Create empty EFS config
		// Create empty authorization config for empty EFS config
		emptyAuthConfig, err := CreateResource(runtime, "aws.ecs.taskDefinition.volume.efsVolumeConfiguration.authorizationConfig",
			map[string]*llx.RawData{
				"__id":          llx.StringData(volKey + "/efs/auth"),
				"accessPointId": llx.StringData(""),
				"iam":           llx.StringData(""),
			})
		if err != nil {
			return nil, err
		}
		mqlEfsConfig, err := CreateResource(runtime, "aws.ecs.taskDefinition.volume.efsVolumeConfiguration",
			map[string]*llx.RawData{
				"__id":                  llx.StringData(volKey + "/efs"),
				"rootDirectory":         llx.StringData(""),
				"transitEncryption":     llx.StringData(""),
				"transitEncryptionPort": llx.IntData(0),
				"authorizationConfig":   llx.ResourceData(emptyAuthConfig, "aws.ecs.taskDefinition.volume.efsVolumeConfiguration.authorizationConfig"),
			})
		if err != nil {
			return nil, err
		}
		mqlEfsConfig.(*mqlAwsEcsTaskDefinitionVolumeEfsVolumeConfiguration).cacheFileSystemId = ""
		efsVolConfig = mqlEfsConfig
	}

	// Create host volume configuration
	var hostConfig any
	if vol.Host != nil {
		sourcePath := ""
		if vol.Host.SourcePath != nil {
			sourcePath = *vol.Host.SourcePath
		}
		mqlHost, err := CreateResource(runtime, "aws.ecs.taskDefinition.volume.host",
			map[string]*llx.RawData{
				"__id":       llx.StringData(volKey + "/host"),
				"sourcePath": llx.StringData(sourcePath),
			})
		if err != nil {
			return nil, err
		}
		hostConfig = mqlHost
	} else {
		// Create empty host config
		mqlHost, err := CreateResource(runtime, "aws.ecs.taskDefinition.volume.host",
			map[string]*llx.RawData{
				"__id":       llx.StringData(volKey + "/host"),
				"sourcePath": llx.StringData(""),
			})
		if err != nil {
			return nil, err
		}
		hostConfig = mqlHost
	}

	// Create docker volume configuration
	var dockerConfig any
	if vol.DockerVolumeConfiguration != nil {
		dockerVolConfig := vol.DockerVolumeConfiguration
		scope := string(dockerVolConfig.Scope)
		autoprovision := false
		if dockerVolConfig.Autoprovision != nil {
			autoprovision = *dockerVolConfig.Autoprovision
		}
		driver := ""
		if dockerVolConfig.Driver != nil {
			driver = *dockerVolConfig.Driver
		}
		driverOpts := make(map[string]any)
		if dockerVolConfig.DriverOpts != nil {
			for k, v := range dockerVolConfig.DriverOpts {
				driverOpts[k] = v
			}
		}
		labels := make(map[string]any)
		if dockerVolConfig.Labels != nil {
			for k, v := range dockerVolConfig.Labels {
				labels[k] = v
			}
		}
		mqlDocker, err := CreateResource(runtime, "aws.ecs.taskDefinition.volume.dockerVolumeConfiguration",
			map[string]*llx.RawData{
				"__id":          llx.StringData(volKey + "/docker"),
				"scope":         llx.StringData(scope),
				"autoprovision": llx.BoolData(autoprovision),
				"driver":        llx.StringData(driver),
				"driverOpts":    llx.MapData(driverOpts, types.String),
				"labels":        llx.MapData(labels, types.String),
			})
		if err != nil {
			return nil, err
		}
		dockerConfig = mqlDocker
	} else {
		// Create empty docker config
		mqlDocker, err := CreateResource(runtime, "aws.ecs.taskDefinition.volume.dockerVolumeConfiguration",
			map[string]*llx.RawData{
				"__id":          llx.StringData(volKey + "/docker"),
				"scope":         llx.StringData(""),
				"autoprovision": llx.BoolData(false),
				"driver":        llx.StringData(""),
				"driverOpts":    llx.MapData(map[string]any{}, types.String),
				"labels":        llx.MapData(map[string]any{}, types.String),
			})
		if err != nil {
			return nil, err
		}
		dockerConfig = mqlDocker
	}

	// Create S3 Files volume configuration
	var s3filesConfig any
	if vol.S3filesVolumeConfiguration != nil {
		s3filesCfg := vol.S3filesVolumeConfiguration
		fileSystemArn := ""
		if s3filesCfg.FileSystemArn != nil {
			fileSystemArn = *s3filesCfg.FileSystemArn
		}
		accessPointArn := ""
		if s3filesCfg.AccessPointArn != nil {
			accessPointArn = *s3filesCfg.AccessPointArn
		}
		rootDirectory := ""
		if s3filesCfg.RootDirectory != nil {
			rootDirectory = *s3filesCfg.RootDirectory
		}
		transitEncryptionPort := int64(0)
		if s3filesCfg.TransitEncryptionPort != nil {
			transitEncryptionPort = int64(*s3filesCfg.TransitEncryptionPort)
		}
		mqlS3files, err := CreateResource(runtime, "aws.ecs.taskDefinition.volume.s3filesVolumeConfiguration",
			map[string]*llx.RawData{
				"__id":                  llx.StringData(volKey + "/s3files"),
				"fileSystemArn":         llx.StringData(fileSystemArn),
				"accessPointArn":        llx.StringData(accessPointArn),
				"rootDirectory":         llx.StringData(rootDirectory),
				"transitEncryptionPort": llx.IntData(transitEncryptionPort),
			})
		if err != nil {
			return nil, err
		}
		s3filesConfig = mqlS3files
	} else {
		mqlS3files, err := CreateResource(runtime, "aws.ecs.taskDefinition.volume.s3filesVolumeConfiguration",
			map[string]*llx.RawData{
				"__id":                  llx.StringData(volKey + "/s3files"),
				"fileSystemArn":         llx.StringData(""),
				"accessPointArn":        llx.StringData(""),
				"rootDirectory":         llx.StringData(""),
				"transitEncryptionPort": llx.IntData(0),
			})
		if err != nil {
			return nil, err
		}
		s3filesConfig = mqlS3files
	}

	// Type assert volume configs to Resource
	efsVolConfigResource, ok := efsVolConfig.(plugin.Resource)
	if !ok {
		return nil, errors.New("failed to convert efsVolConfig to Resource")
	}
	hostConfigResource, ok := hostConfig.(plugin.Resource)
	if !ok {
		return nil, errors.New("failed to convert hostConfig to Resource")
	}
	dockerConfigResource, ok := dockerConfig.(plugin.Resource)
	if !ok {
		return nil, errors.New("failed to convert dockerConfig to Resource")
	}
	s3filesConfigResource, ok := s3filesConfig.(plugin.Resource)
	if !ok {
		return nil, errors.New("failed to convert s3filesConfig to Resource")
	}

	return CreateResource(runtime, "aws.ecs.taskDefinition.volume",
		map[string]*llx.RawData{
			"__id":                       llx.StringData(volKey),
			"name":                       llx.StringData(volName),
			"efsVolumeConfiguration":     llx.ResourceData(efsVolConfigResource, "aws.ecs.taskDefinition.volume.efsVolumeConfiguration"),
			"host":                       llx.ResourceData(hostConfigResource, "aws.ecs.taskDefinition.volume.host"),
			"dockerVolumeConfiguration":  llx.ResourceData(dockerConfigResource, "aws.ecs.taskDefinition.volume.dockerVolumeConfiguration"),
			"s3filesVolumeConfiguration": llx.ResourceData(s3filesConfigResource, "aws.ecs.taskDefinition.volume.s3filesVolumeConfiguration"),
		})
}

func createEphemeralStorageResource(runtime *plugin.Runtime, taskDefArn string, es *ecstypes.EphemeralStorage) (any, error) {
	sizeInGiB := int64(es.SizeInGiB)

	return CreateResource(runtime, "aws.ecs.taskDefinition.ephemeralStorage",
		map[string]*llx.RawData{
			"__id":      llx.StringData(taskDefArn + "/ephemeralStorage"),
			"sizeInGiB": llx.IntData(sizeInGiB),
		})
}

type mqlAwsEcsTaskDefinitionInternal struct {
	cachedTD *ecstypes.TaskDefinition
	fetched  bool
	fetchErr error
	lock     sync.Mutex

	cacheTags   map[string]any
	tagsErr     error
	tagsFetched bool
	tagsLock    sync.Mutex
}

func (a *mqlAwsEcsTaskDefinition) fetchDetail() error {
	if a.fetched {
		return a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.fetchErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := a.Arn.Data

	// When the resource is initialised with only an ARN (e.g. from a typed-ref
	// accessor in another resource), Region.Data is empty. Fall back to the
	// region encoded in the ARN so DescribeTaskDefinition has a valid endpoint.
	region := a.Region.Data
	if region == "" {
		if parsed, err := arn.Parse(arnVal); err == nil {
			region = parsed.Region
			a.Region = plugin.TValue[string]{Data: region, State: plugin.StateIsSet}
		}
	}

	svc := conn.Ecs(region)
	ctx := context.Background()

	describeResp, err := svc.DescribeTaskDefinition(ctx, &ecsservice.DescribeTaskDefinitionInput{
		TaskDefinition: &arnVal,
	})
	if err != nil {
		a.fetched = true
		a.fetchErr = err
		return err
	}
	if describeResp.TaskDefinition == nil {
		a.fetched = true
		a.fetchErr = errors.New("task definition not found")
		return a.fetchErr
	}

	td := describeResp.TaskDefinition
	a.cachedTD = td

	// Set simple scalar fields
	a.Family = plugin.TValue[string]{Data: convert.ToValue(td.Family), State: plugin.StateIsSet}
	a.Revision = plugin.TValue[int64]{Data: int64(td.Revision), State: plugin.StateIsSet}
	a.Status = plugin.TValue[string]{Data: string(td.Status), State: plugin.StateIsSet}
	a.NetworkMode = plugin.TValue[string]{Data: string(td.NetworkMode), State: plugin.StateIsSet}
	a.PidMode = plugin.TValue[string]{Data: string(td.PidMode), State: plugin.StateIsSet}
	a.IpcMode = plugin.TValue[string]{Data: string(td.IpcMode), State: plugin.StateIsSet}
	a.TaskRoleArn = plugin.TValue[string]{Data: convert.ToValue(td.TaskRoleArn), State: plugin.StateIsSet}
	a.ExecutionRoleArn = plugin.TValue[string]{Data: convert.ToValue(td.ExecutionRoleArn), State: plugin.StateIsSet}
	a.Cpu = plugin.TValue[string]{Data: convert.ToValue(td.Cpu), State: plugin.StateIsSet}
	a.Memory = plugin.TValue[string]{Data: convert.ToValue(td.Memory), State: plugin.StateIsSet}
	if td.RegisteredAt != nil {
		a.RegisteredAt = plugin.TValue[*time.Time]{Data: td.RegisteredAt, State: plugin.StateIsSet}
	} else {
		a.RegisteredAt = plugin.TValue[*time.Time]{Data: &llx.NeverFutureTime, State: plugin.StateIsSet}
	}
	a.RegisteredBy = plugin.TValue[string]{Data: convert.ToValue(td.RegisteredBy), State: plugin.StateIsSet}

	a.fetched = true
	return nil
}

func (a *mqlAwsEcsTaskDefinition) registeredBy() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.RegisteredBy.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) family() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.Family.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) revision() (int64, error) {
	if err := a.fetchDetail(); err != nil {
		return 0, err
	}
	return a.Revision.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) status() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.Status.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) networkMode() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.NetworkMode.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) pidMode() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.PidMode.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) ipcMode() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.IpcMode.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) taskRoleArn() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.TaskRoleArn.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) executionRoleArn() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.ExecutionRoleArn.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) taskRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return ecsIamRoleRef(a.MqlRuntime, a.cachedTD.TaskRoleArn, &a.TaskRole)
}

func (a *mqlAwsEcsTaskDefinition) executionRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return ecsIamRoleRef(a.MqlRuntime, a.cachedTD.ExecutionRoleArn, &a.ExecutionRole)
}

func (a *mqlAwsEcsTaskDefinition) requiresCompatibilities() ([]any, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	compat := make([]any, 0, len(a.cachedTD.RequiresCompatibilities))
	for _, c := range a.cachedTD.RequiresCompatibilities {
		compat = append(compat, string(c))
	}
	return compat, nil
}

func (a *mqlAwsEcsTaskDefinition) runtimePlatformCpuArchitecture() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	if a.cachedTD.RuntimePlatform == nil {
		return "", nil
	}
	return string(a.cachedTD.RuntimePlatform.CpuArchitecture), nil
}

func (a *mqlAwsEcsTaskDefinition) runtimePlatformOsFamily() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	if a.cachedTD.RuntimePlatform == nil {
		return "", nil
	}
	return string(a.cachedTD.RuntimePlatform.OperatingSystemFamily), nil
}

func (a *mqlAwsEcsTaskDefinition) proxyConfiguration() (any, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return convert.JsonToDict(a.cachedTD.ProxyConfiguration)
}

func (a *mqlAwsEcsTaskDefinition) placementConstraints() ([]any, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(a.cachedTD.PlacementConstraints)
}

func (a *mqlAwsEcsTaskDefinition) enableFaultInjection() (bool, error) {
	if err := a.fetchDetail(); err != nil {
		return false, err
	}
	return convert.ToValue(a.cachedTD.EnableFaultInjection), nil
}

func (a *mqlAwsEcsTaskDefinition) cpu() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.Cpu.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) memory() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.Memory.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) registeredAt() (*time.Time, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return a.RegisteredAt.Data, nil
}

func (a *mqlAwsEcsTaskDefinition) tags() (map[string]any, error) {
	if a.tagsFetched {
		return a.cacheTags, a.tagsErr
	}
	a.tagsLock.Lock()
	defer a.tagsLock.Unlock()
	if a.tagsFetched {
		return a.cacheTags, a.tagsErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ecs(a.Region.Data)
	ctx := context.Background()

	arnVal := a.Arn.Data
	tagsResp, err := svc.ListTagsForResource(ctx, &ecsservice.ListTagsForResourceInput{
		ResourceArn: &arnVal,
	})
	if err != nil {
		a.tagsFetched = true
		a.tagsErr = classifyAwsError(err, "ecs:ListTagsForResource")
		return nil, a.tagsErr
	}
	if tagsResp != nil && tagsResp.Tags != nil {
		a.cacheTags = ecsTagsToMap(tagsResp.Tags)
	} else {
		a.cacheTags = map[string]any{}
	}
	a.tagsFetched = true
	return a.cacheTags, nil
}

// Getter methods for task definition resources
func (a *mqlAwsEcsTaskDefinition) containerDefinitions() ([]any, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	td := a.cachedTD
	if td == nil {
		return nil, nil
	}
	arnVal := a.Arn.Data
	containerDefs := []any{}
	for i := range td.ContainerDefinitions {
		mqlContainerDef, err := createContainerDefinitionResource(a.MqlRuntime, arnVal, &td.ContainerDefinitions[i])
		if err != nil {
			return nil, err
		}
		containerDefs = append(containerDefs, mqlContainerDef)
	}
	return containerDefs, nil
}

func (a *mqlAwsEcsTaskDefinition) volumes() ([]any, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	td := a.cachedTD
	if td == nil {
		return nil, nil
	}
	volumes := []any{}
	for i := range td.Volumes {
		mqlVolume, err := createVolumeResource(a.MqlRuntime, a.Region.Data, a.Arn.Data, &td.Volumes[i])
		if err != nil {
			return nil, err
		}
		volumes = append(volumes, mqlVolume)
	}
	return volumes, nil
}

func (a *mqlAwsEcsTaskDefinition) ephemeralStorage() (*mqlAwsEcsTaskDefinitionEphemeralStorage, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	td := a.cachedTD
	if td == nil || td.EphemeralStorage == nil {
		a.EphemeralStorage.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	arnVal := a.Arn.Data
	res, err := createEphemeralStorageResource(a.MqlRuntime, arnVal, td.EphemeralStorage)
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEcsTaskDefinitionEphemeralStorage), nil
}

// id() methods for task definition resources
func (a *mqlAwsEcsTaskDefinition) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEcsTaskDefinitionContainerDefinition) environment() ([]any, error) {
	if !a.Environment.IsSet() {
		return nil, nil
	}
	if a.Environment.Error != nil {
		return nil, a.Environment.Error
	}
	return a.Environment.Data, nil
}

func (a *mqlAwsEcsTaskDefinitionContainerDefinition) secrets() ([]any, error) {
	if !a.Secrets.IsSet() {
		return nil, nil
	}
	if a.Secrets.Error != nil {
		return nil, a.Secrets.Error
	}
	return a.Secrets.Data, nil
}

func (a *mqlAwsEcsTaskDefinitionContainerDefinition) logConfiguration() (*mqlAwsEcsTaskDefinitionContainerDefinitionLogConfiguration, error) {
	if !a.LogConfiguration.IsSet() {
		a.LogConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if a.LogConfiguration.Error != nil {
		return nil, a.LogConfiguration.Error
	}
	return a.LogConfiguration.Data, nil
}

func (a *mqlAwsEcsTaskDefinitionContainerDefinition) portMappings() ([]any, error) {
	if !a.PortMappings.IsSet() {
		return nil, nil
	}
	if a.PortMappings.Error != nil {
		return nil, a.PortMappings.Error
	}
	return a.PortMappings.Data, nil
}

func (a *mqlAwsEcsTaskDefinitionContainerDefinition) id() (string, error) {
	return a.Name.Data, nil
}

func (a *mqlAwsEcsTaskDefinitionVolume) efsVolumeConfiguration() (*mqlAwsEcsTaskDefinitionVolumeEfsVolumeConfiguration, error) {
	if !a.EfsVolumeConfiguration.IsSet() {
		a.EfsVolumeConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if a.EfsVolumeConfiguration.Error != nil {
		return nil, a.EfsVolumeConfiguration.Error
	}
	return a.EfsVolumeConfiguration.Data, nil
}

func (a *mqlAwsEcsTaskDefinitionVolume) host() (*mqlAwsEcsTaskDefinitionVolumeHost, error) {
	if !a.Host.IsSet() {
		a.Host.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if a.Host.Error != nil {
		return nil, a.Host.Error
	}
	return a.Host.Data, nil
}

func (a *mqlAwsEcsTaskDefinitionVolume) dockerVolumeConfiguration() (*mqlAwsEcsTaskDefinitionVolumeDockerVolumeConfiguration, error) {
	if !a.DockerVolumeConfiguration.IsSet() {
		a.DockerVolumeConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if a.DockerVolumeConfiguration.Error != nil {
		return nil, a.DockerVolumeConfiguration.Error
	}
	return a.DockerVolumeConfiguration.Data, nil
}

func (a *mqlAwsEcsTaskDefinitionVolume) s3filesVolumeConfiguration() (*mqlAwsEcsTaskDefinitionVolumeS3filesVolumeConfiguration, error) {
	if !a.S3filesVolumeConfiguration.IsSet() {
		a.S3filesVolumeConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if a.S3filesVolumeConfiguration.Error != nil {
		return nil, a.S3filesVolumeConfiguration.Error
	}
	return a.S3filesVolumeConfiguration.Data, nil
}

// id returns the task-definition-qualified cache key set at construction.
// `name` alone is unique only within one task definition revision.
func (a *mqlAwsEcsTaskDefinitionVolume) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcsTaskDefinitionEphemeralStorage) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcsTaskDefinitionContainerDefinitionEnvironmentVariable) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcsTaskDefinitionContainerDefinitionSecret) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcsTaskDefinitionContainerDefinitionLogConfiguration) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcsTaskDefinitionContainerDefinitionPortMapping) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcsTaskDefinitionVolumeEfsVolumeConfiguration) authorizationConfig() (*mqlAwsEcsTaskDefinitionVolumeEfsVolumeConfigurationAuthorizationConfig, error) {
	if !a.AuthorizationConfig.IsSet() {
		a.AuthorizationConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if a.AuthorizationConfig.Error != nil {
		return nil, a.AuthorizationConfig.Error
	}
	return a.AuthorizationConfig.Data, nil
}

type mqlAwsEcsTaskDefinitionVolumeEfsVolumeConfigurationInternal struct {
	cacheFileSystemId string
	region            string
}

func (a *mqlAwsEcsTaskDefinitionVolumeEfsVolumeConfiguration) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcsTaskDefinitionVolumeEfsVolumeConfiguration) fileSystem() (*mqlAwsEfsFilesystem, error) {
	fsID := a.cacheFileSystemId
	if fsID == "" {
		a.FileSystem.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnStr := fmt.Sprintf(efsFilesystemArnPattern, a.region, conn.AccountId(), fsID)
	res, err := NewResource(a.MqlRuntime, "aws.efs.filesystem",
		map[string]*llx.RawData{"arn": llx.StringData(arnStr)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEfsFilesystem), nil
}

func (a *mqlAwsEcsTaskDefinitionVolumeEfsVolumeConfigurationAuthorizationConfig) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcsTaskDefinitionVolumeHost) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcsTaskDefinitionVolumeDockerVolumeConfiguration) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcsTaskDefinitionVolumeS3filesVolumeConfiguration) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcsCluster) services() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	clusterArn := a.Arn.Data
	if !arn.IsARN(clusterArn) {
		return nil, errors.New("cluster ARN is not a valid ARN")
	}
	parsedARN, err := arn.Parse(clusterArn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse cluster ARN")
	}
	region := parsedARN.Region
	svc := conn.Ecs(region)
	ctx := context.Background()
	res := []any{}

	// List services in this cluster
	serviceParams := &ecsservice.ListServicesInput{
		Cluster: &clusterArn,
	}
	servicePaginator := ecsservice.NewListServicesPaginator(svc, serviceParams)
	serviceArns := []string{}
	for servicePaginator.HasMorePages() {
		serviceResp, err := servicePaginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "ecs:ListServices"), "could not gather ecs services information")
		}
		serviceArns = append(serviceArns, serviceResp.ServiceArns...)
	}

	// Describe services in batches (AWS allows up to 10 services per DescribeServices call)
	batches := slicesx.Batch(serviceArns, 10)
	for _, batch := range batches {
		describeParams := &ecsservice.DescribeServicesInput{
			Cluster:  &clusterArn,
			Services: batch,
			Include:  []ecstypes.ServiceField{ecstypes.ServiceFieldTags},
		}
		describeResp, err := svc.DescribeServices(ctx, describeParams)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", region).Str("cluster", clusterArn).Msg("error describing services")
				continue
			}
			return nil, errors.Wrap(err, "could not describe ecs services")
		}

		for _, service := range describeResp.Services {
			mqlService, err := NewResource(a.MqlRuntime, ResourceAwsEcsService,
				map[string]*llx.RawData{
					"arn": llx.StringData(convert.ToValue(service.ServiceArn)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlService)
		}
	}

	return res, nil
}

func (s *mqlAwsEcsService) id() (string, error) {
	return s.Arn.Data, nil
}

func (s *mqlAwsEcsService) deploymentConfiguration() (*mqlAwsEcsServiceDeploymentConfiguration, error) {
	if !s.DeploymentConfiguration.IsSet() {
		return nil, errors.New("deploymentConfiguration not initialized")
	}
	if s.DeploymentConfiguration.Error != nil {
		return nil, s.DeploymentConfiguration.Error
	}
	return s.DeploymentConfiguration.Data, nil
}

func (s *mqlAwsEcsService) networkConfiguration() (*mqlAwsEcsServiceNetworkConfiguration, error) {
	if !s.NetworkConfiguration.IsSet() {
		return nil, errors.New("networkConfiguration not initialized")
	}
	if s.NetworkConfiguration.Error != nil {
		return nil, s.NetworkConfiguration.Error
	}
	return s.NetworkConfiguration.Data, nil
}

func (d *mqlAwsEcsServiceDeploymentConfiguration) deploymentCircuitBreaker() (*mqlAwsEcsServiceDeploymentConfigurationDeploymentCircuitBreaker, error) {
	if !d.DeploymentCircuitBreaker.IsSet() {
		return nil, errors.New("deploymentCircuitBreaker not initialized")
	}
	if d.DeploymentCircuitBreaker.Error != nil {
		return nil, d.DeploymentCircuitBreaker.Error
	}
	return d.DeploymentCircuitBreaker.Data, nil
}

func (n *mqlAwsEcsServiceNetworkConfiguration) awsVpcConfiguration() (*mqlAwsEcsServiceNetworkConfigurationAwsVpcConfiguration, error) {
	if !n.AwsVpcConfiguration.IsSet() {
		return nil, errors.New("awsVpcConfiguration not initialized")
	}
	if n.AwsVpcConfiguration.Error != nil {
		return nil, n.AwsVpcConfiguration.Error
	}
	return n.AwsVpcConfiguration.Data, nil
}

func initAwsEcsService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch ecs service")
	}
	a := args["arn"].Value.(string)
	conn := runtime.Connection.(*connection.AwsConnection)

	// Validate and parse ARN if provided
	parsedARN, err := validateAndParseARN(a, "ecs")
	if err != nil {
		return nil, nil, err
	}

	region := parsedARN.Region
	clusterName := ""
	serviceName := ""
	if res := strings.Split(parsedARN.Resource, "/"); len(res) >= 2 {
		clusterName = res[1]
		if len(res) >= 3 {
			serviceName = res[2]
		}
	}

	// Extract service name from ARN

	clusterArn := fmt.Sprintf("arn:aws:ecs:%s:%s:cluster/%s", region, parsedARN.AccountID, clusterName)

	svc := conn.Ecs(region)
	ctx := context.Background()

	serviceDetails, err := svc.DescribeServices(ctx, &ecs.DescribeServicesInput{
		Cluster:  &clusterArn,
		Services: []string{serviceName},
		Include:  []ecstypes.ServiceField{ecstypes.ServiceFieldTags},
	})
	if err != nil {
		return nil, nil, err
	}
	if len(serviceDetails.Services) != 1 {
		return nil, nil, errors.Newf("only expected one service, got %d", len(serviceDetails.Services))
	}

	s := serviceDetails.Services[0]

	// Create deployment configuration resource
	var deploymentConfigResource any
	if s.DeploymentConfiguration != nil {
		var err error
		deploymentConfigResource, err = createDeploymentConfigurationResource(runtime, s.DeploymentConfiguration, a)
		if err != nil {
			return nil, nil, err
		}
	}

	// Create network configuration resource
	var networkConfigResource any
	if s.NetworkConfiguration != nil {
		var err error
		networkConfigResource, err = createNetworkConfigurationResource(runtime, s.NetworkConfiguration, a)
		if err != nil {
			return nil, nil, err
		}
	}

	// Extract launch type
	launchType := ""
	if s.LaunchType != "" {
		launchType = string(s.LaunchType)
	}

	// Extract task definition ARN
	taskDefinition := ""
	if s.TaskDefinition != nil {
		taskDefinition = *s.TaskDefinition
	}

	// Extract createdBy
	createdBy := ""
	if s.CreatedBy != nil {
		createdBy = *s.CreatedBy
	}

	args["name"] = llx.StringDataPtr(s.ServiceName)
	args["status"] = llx.StringDataPtr(s.Status)
	args["desiredCount"] = llx.IntData(int64(s.DesiredCount))
	args["runningCount"] = llx.IntData(int64(s.RunningCount))
	args["taskDefinition"] = llx.StringData(taskDefinition)
	args["launchType"] = llx.StringData(launchType)
	// Always set deploymentConfiguration - AWS services should always have this, but handle nil case
	if deploymentConfigResource != nil {
		args["deploymentConfiguration"] = llx.ResourceData(deploymentConfigResource.(plugin.Resource), ResourceAwsEcsServiceDeploymentConfiguration)
	} else {
		// AWS should always return deploymentConfiguration, but if nil, set to nil explicitly
		args["deploymentConfiguration"] = llx.NilData
	}
	// Always set networkConfiguration - AWS services should always have this, but handle nil case
	if networkConfigResource != nil {
		args["networkConfiguration"] = llx.ResourceData(networkConfigResource.(plugin.Resource), ResourceAwsEcsServiceNetworkConfiguration)
	} else {
		// AWS should always return networkConfiguration, but if nil, set to nil explicitly
		args["networkConfiguration"] = llx.NilData
	}
	args["tags"] = llx.MapData(ecsTagsToMap(s.Tags), types.String)
	args["createdAt"] = llx.TimeDataPtr(s.CreatedAt)
	args["createdBy"] = llx.StringData(createdBy)
	args["enableExecuteCommand"] = llx.BoolData(s.EnableExecuteCommand)
	args["enableEcsManagedTags"] = llx.BoolData(s.EnableECSManagedTags)
	args["schedulingStrategy"] = llx.StringData(string(s.SchedulingStrategy))
	args["platformFamily"] = llx.StringDataPtr(s.PlatformFamily)
	args["platformVersion"] = llx.StringDataPtr(s.PlatformVersion)
	args["healthCheckGracePeriodSeconds"] = llx.IntDataDefault(s.HealthCheckGracePeriodSeconds, 0)

	loadBalancers, err := convert.JsonToDictSlice(s.LoadBalancers)
	if err != nil {
		return nil, nil, err
	}
	serviceRegistries, err := convert.JsonToDictSlice(s.ServiceRegistries)
	if err != nil {
		return nil, nil, err
	}
	capacityProviderStrategy, err := convert.JsonToDictSlice(s.CapacityProviderStrategy)
	if err != nil {
		return nil, nil, err
	}
	placementConstraints, err := convert.JsonToDictSlice(s.PlacementConstraints)
	if err != nil {
		return nil, nil, err
	}
	placementStrategy, err := convert.JsonToDictSlice(s.PlacementStrategy)
	if err != nil {
		return nil, nil, err
	}
	deploymentController := ""
	if s.DeploymentController != nil {
		deploymentController = string(s.DeploymentController.Type)
	}
	args["loadBalancers"] = llx.ArrayData(loadBalancers, types.Dict)
	args["serviceRegistries"] = llx.ArrayData(serviceRegistries, types.Dict)
	args["capacityProviderStrategy"] = llx.ArrayData(capacityProviderStrategy, types.Dict)
	args["placementConstraints"] = llx.ArrayData(placementConstraints, types.Dict)
	args["placementStrategy"] = llx.ArrayData(placementStrategy, types.Dict)
	args["deploymentController"] = llx.StringData(deploymentController)
	args["propagateTags"] = llx.StringData(string(s.PropagateTags))
	args["availabilityZoneRebalancing"] = llx.StringData(string(s.AvailabilityZoneRebalancing))

	res, err := CreateResource(runtime, ResourceAwsEcsService, args)
	if err != nil {
		return args, nil, err
	}
	res.(*mqlAwsEcsService).cacheClusterArn = convert.ToValue(s.ClusterArn)
	res.(*mqlAwsEcsService).cacheRoleArn = s.RoleArn
	return args, res, nil
}

type mqlAwsEcsServiceInternal struct {
	cacheClusterArn string
	cacheRoleArn    *string
}

func (a *mqlAwsEcsService) iamRole() (*mqlAwsIamRole, error) {
	return ecsIamRoleRef(a.MqlRuntime, a.cacheRoleArn, &a.IamRole)
}

func createDeploymentConfigurationResource(runtime *plugin.Runtime, dc *ecstypes.DeploymentConfiguration, serviceArn string) (any, error) {
	// Create deployment circuit breaker resource
	var circuitBreakerResource any
	if dc.DeploymentCircuitBreaker != nil {
		cb, err := CreateResource(runtime, ResourceAwsEcsServiceDeploymentConfigurationDeploymentCircuitBreaker,
			map[string]*llx.RawData{
				"__id":     llx.StringData(serviceArn + "/deploymentCircuitBreaker"),
				"enable":   llx.BoolData(dc.DeploymentCircuitBreaker.Enable),
				"rollback": llx.BoolData(dc.DeploymentCircuitBreaker.Rollback),
			})
		if err != nil {
			return nil, err
		}
		circuitBreakerResource = cb
	}

	// Convert optional fields to dicts
	var alarmsDict map[string]any
	if dc.Alarms != nil {
		var err error
		alarmsDict, err = convert.JsonToDict(dc.Alarms)
		if err != nil {
			return nil, err
		}
	}

	var canaryConfigDict map[string]any
	if dc.CanaryConfiguration != nil {
		var err error
		canaryConfigDict, err = convert.JsonToDict(dc.CanaryConfiguration)
		if err != nil {
			return nil, err
		}
	}

	var lifecycleHooksDict map[string]any
	if dc.LifecycleHooks != nil {
		var err error
		lifecycleHooksDict, err = convert.JsonToDict(dc.LifecycleHooks)
		if err != nil {
			return nil, err
		}
	}

	var linearConfigDict map[string]any
	if dc.LinearConfiguration != nil {
		var err error
		linearConfigDict, err = convert.JsonToDict(dc.LinearConfiguration)
		if err != nil {
			return nil, err
		}
	}

	args := map[string]*llx.RawData{
		"__id":                  llx.StringData(serviceArn + "/deploymentConfiguration"),
		"maximumPercent":        llx.IntDataPtr(dc.MaximumPercent),
		"minimumHealthyPercent": llx.IntDataPtr(dc.MinimumHealthyPercent),
		"bakeTimeInMinutes":     llx.IntDataPtr(dc.BakeTimeInMinutes),
		"strategy":              llx.StringData(string(dc.Strategy)),
	}
	// A deployment that sets no early success criteria reports the three fields
	// as null rather than as false/0/"": `enable: false` is a legitimate
	// reading, so a zero value here would report "criteria configured and
	// turned off" for a service that configured nothing.
	if esc := dc.EarlySuccessCriteria; esc != nil {
		args["earlySuccessCriteriaEnabled"] = llx.BoolData(esc.Enable)
		args["earlySuccessCriteriaHealthyPercent"] = llx.IntDataPtr(esc.HealthyPercent)
		args["earlySuccessCriteriaRevisionCleanup"] = llx.StringData(string(esc.SourceServiceRevisionCleanup))
	} else {
		args["earlySuccessCriteriaEnabled"] = llx.NilData
		args["earlySuccessCriteriaHealthyPercent"] = llx.NilData
		args["earlySuccessCriteriaRevisionCleanup"] = llx.NilData
	}
	// Always set deploymentCircuitBreaker, even if nil
	if circuitBreakerResource != nil {
		args["deploymentCircuitBreaker"] = llx.ResourceData(circuitBreakerResource.(plugin.Resource), ResourceAwsEcsServiceDeploymentConfigurationDeploymentCircuitBreaker)
	} else {
		args["deploymentCircuitBreaker"] = llx.NilData
	}
	if alarmsDict != nil {
		args["alarms"] = llx.MapData(alarmsDict, types.String)
	}
	if canaryConfigDict != nil {
		args["canaryConfiguration"] = llx.MapData(canaryConfigDict, types.String)
	}
	if lifecycleHooksDict != nil {
		args["lifecycleHooks"] = llx.MapData(lifecycleHooksDict, types.String)
	}
	if linearConfigDict != nil {
		args["linearConfiguration"] = llx.MapData(linearConfigDict, types.String)
	}

	return CreateResource(runtime, ResourceAwsEcsServiceDeploymentConfiguration, args)
}

func createNetworkConfigurationResource(runtime *plugin.Runtime, nc *ecstypes.NetworkConfiguration, serviceArn string) (any, error) {
	// Create awsvpc configuration resource
	var awsvpcResource any
	if nc.AwsvpcConfiguration != nil {
		awsvpc := nc.AwsvpcConfiguration
		subnets := []any{}
		for _, subnet := range awsvpc.Subnets {
			subnets = append(subnets, subnet)
		}
		securityGroups := []any{}
		for _, sg := range awsvpc.SecurityGroups {
			securityGroups = append(securityGroups, sg)
		}
		awsvpcRes, err := CreateResource(runtime, ResourceAwsEcsServiceNetworkConfigurationAwsVpcConfiguration,
			map[string]*llx.RawData{
				"__id":           llx.StringData(serviceArn + "/networkConfiguration/awsVpc"),
				"subnets":        llx.ArrayData(subnets, types.String),
				"securityGroups": llx.ArrayData(securityGroups, types.String),
				"assignPublicIp": llx.StringData(string(awsvpc.AssignPublicIp)),
			})
		if err != nil {
			return nil, err
		}
		awsvpcResource = awsvpcRes
	}

	args := map[string]*llx.RawData{
		"__id": llx.StringData(serviceArn + "/networkConfiguration"),
	}
	// Always set awsVpcConfiguration, even if nil
	if awsvpcResource != nil {
		args["awsVpcConfiguration"] = llx.ResourceData(awsvpcResource.(plugin.Resource), ResourceAwsEcsServiceNetworkConfigurationAwsVpcConfiguration)
	} else {
		args["awsVpcConfiguration"] = llx.NilData
	}

	return CreateResource(runtime, ResourceAwsEcsServiceNetworkConfiguration, args)
}

func (t *mqlAwsEcsTaskSet) id() (string, error) {
	return t.Arn.Data, nil
}

func (n *mqlAwsEcsTaskSetNetworkConfiguration) id() (string, error) {
	return n.__id, nil
}

func (t *mqlAwsEcsTaskSet) networkConfiguration() (*mqlAwsEcsTaskSetNetworkConfiguration, error) {
	if !t.NetworkConfiguration.IsSet() {
		return nil, errors.New("networkConfiguration not initialized")
	}
	if t.NetworkConfiguration.Error != nil {
		return nil, t.NetworkConfiguration.Error
	}
	return t.NetworkConfiguration.Data, nil
}

func (s *mqlAwsEcsService) taskSets() ([]any, error) {
	conn := s.MqlRuntime.Connection.(*connection.AwsConnection)
	serviceArn := s.Arn.Data
	clusterArn := s.cacheClusterArn

	parsedARN, err := arn.Parse(serviceArn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse service ARN")
	}
	region := parsedARN.Region

	svc := conn.Ecs(region)
	ctx := context.Background()

	resp, err := svc.DescribeTaskSets(ctx, &ecsservice.DescribeTaskSetsInput{
		Cluster: &clusterArn,
		Service: &serviceArn,
		Include: []ecstypes.TaskSetField{ecstypes.TaskSetFieldTags},
	})
	if err != nil {
		// DescribeTaskSets returns InvalidParameterException for services that
		// don't use EXTERNAL or CODE_DEPLOY deployment controllers
		if strings.Contains(err.Error(), "InvalidParameterException") {
			return []any{}, nil
		}
		return nil, errors.Wrap(classifyAwsError(err, "ecs:DescribeTaskSets"), "could not describe task sets")
	}

	res := []any{}
	for _, ts := range resp.TaskSets {
		taskSetArn := convert.ToValue(ts.TaskSetArn)

		// Create network configuration resource
		var networkConfigResource plugin.Resource
		if ts.NetworkConfiguration != nil && ts.NetworkConfiguration.AwsvpcConfiguration != nil {
			ncRes, err := createTaskSetNetworkConfigurationResource(s.MqlRuntime, ts.NetworkConfiguration, taskSetArn)
			if err != nil {
				return nil, err
			}
			networkConfigResource = ncRes.(plugin.Resource)
		}

		args := map[string]*llx.RawData{
			"arn":                  llx.StringData(taskSetArn),
			"id":                   llx.StringData(convert.ToValue(ts.Id)),
			"status":               llx.StringData(convert.ToValue(ts.Status)),
			"taskDefinition":       llx.StringData(convert.ToValue(ts.TaskDefinition)),
			"launchType":           llx.StringData(string(ts.LaunchType)),
			"platformVersion":      llx.StringData(convert.ToValue(ts.PlatformVersion)),
			"platformFamily":       llx.StringData(convert.ToValue(ts.PlatformFamily)),
			"tags":                 llx.MapData(ecsTagsToMap(ts.Tags), types.String),
			"createdAt":            llx.TimeDataPtr(ts.CreatedAt),
			"updatedAt":            llx.TimeDataPtr(ts.UpdatedAt),
			"runningCount":         llx.IntData(int64(ts.RunningCount)),
			"pendingCount":         llx.IntData(int64(ts.PendingCount)),
			"computedDesiredCount": llx.IntData(int64(ts.ComputedDesiredCount)),
			"stabilityStatus":      llx.StringData(string(ts.StabilityStatus)),
			"externalId":           llx.StringData(convert.ToValue(ts.ExternalId)),
			"startedBy":            llx.StringData(convert.ToValue(ts.StartedBy)),
		}

		if networkConfigResource != nil {
			args["networkConfiguration"] = llx.ResourceData(networkConfigResource, ResourceAwsEcsTaskSetNetworkConfiguration)
		} else {
			args["networkConfiguration"] = llx.NilData
		}

		mqlTaskSet, err := CreateResource(s.MqlRuntime, ResourceAwsEcsTaskSet, args)
		if err != nil {
			return nil, err
		}
		mqlTaskSet.(*mqlAwsEcsTaskSet).cacheClusterArn = convert.ToValue(ts.ClusterArn)
		mqlTaskSet.(*mqlAwsEcsTaskSet).cacheServiceArn = convert.ToValue(ts.ServiceArn)
		res = append(res, mqlTaskSet)
	}

	return res, nil
}

func createTaskSetNetworkConfigurationResource(runtime *plugin.Runtime, nc *ecstypes.NetworkConfiguration, taskSetArn string) (any, error) {
	assignPublicIp := ""
	subnets := []any{}
	securityGroups := []any{}

	if nc.AwsvpcConfiguration != nil {
		awsvpc := nc.AwsvpcConfiguration
		assignPublicIp = string(awsvpc.AssignPublicIp)
		for _, subnet := range awsvpc.Subnets {
			subnets = append(subnets, subnet)
		}
		for _, sg := range awsvpc.SecurityGroups {
			securityGroups = append(securityGroups, sg)
		}
	}

	return CreateResource(runtime, ResourceAwsEcsTaskSetNetworkConfiguration,
		map[string]*llx.RawData{
			"__id":           llx.StringData(taskSetArn + "/networkConfiguration"),
			"assignPublicIp": llx.StringData(assignPublicIp),
			"subnets":        llx.ArrayData(subnets, types.String),
			"securityGroups": llx.ArrayData(securityGroups, types.String),
		})
}

func (a *mqlAwsEcsContainer) taskDefinition() (*mqlAwsEcsTaskDefinition, error) {
	arnVal := a.cacheTaskDefinitionArn
	if arnVal == "" {
		a.TaskDefinition.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		return nil, err
	}
	res, err := NewResource(a.MqlRuntime, "aws.ecs.taskDefinition",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal), "region": llx.StringData(region)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEcsTaskDefinition), nil
}

func (a *mqlAwsEcsContainer) task() (*mqlAwsEcsTask, error) {
	arnVal := a.cacheTaskArn
	if arnVal == "" {
		a.Task.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ecs.task",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEcsTask), nil
}

func (a *mqlAwsEcsService) taskDefinitionRef() (*mqlAwsEcsTaskDefinition, error) {
	arnVal := a.TaskDefinition.Data
	if arnVal == "" {
		a.TaskDefinitionRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		return nil, err
	}
	res, err := NewResource(a.MqlRuntime, "aws.ecs.taskDefinition",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal), "region": llx.StringData(region)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEcsTaskDefinition), nil
}

func (a *mqlAwsEcsService) cluster() (*mqlAwsEcsCluster, error) {
	arnVal := a.cacheClusterArn
	if arnVal == "" {
		a.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ecs.cluster",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEcsCluster), nil
}

func (a *mqlAwsEcsTaskSet) cluster() (*mqlAwsEcsCluster, error) {
	arnVal := a.cacheClusterArn
	if arnVal == "" {
		a.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ecs.cluster",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEcsCluster), nil
}

func (a *mqlAwsEcsTaskSet) service() (*mqlAwsEcsService, error) {
	arnVal := a.cacheServiceArn
	if arnVal == "" {
		a.Service.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ecs.service",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEcsService), nil
}

func initAwsEcsTaskDefinition(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformEcsTaskdefinition); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws ecs task definition")
	}

	obj, err := CreateResource(runtime, "aws.ecs", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	ecs := obj.(*mqlAwsEcs)

	rawResources := ecs.GetTaskDefinitions()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal, _ := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		td := rawResource.(*mqlAwsEcsTaskDefinition)
		if td.Arn.Data == arnVal {
			return args, td, nil
		}
	}
	return nil, nil, errors.New("aws ecs task definition does not exist: " + arnVal)
}

func (a *mqlAwsEcs) capacityProviders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getECSCapacityProviders(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsEcs) getECSCapacityProviders(conn *connection.AwsConnection) []*jobpool.Job {
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
			var nextToken *string
			for {
				resp, err := svc.DescribeCapacityProviders(ctx, &ecsservice.DescribeCapacityProvidersInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for ECS capacity providers")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ecs capacity providers")
				}
				for i := range resp.CapacityProviders {
					mqlCP, err := newMqlEcsCapacityProvider(a.MqlRuntime, region, &resp.CapacityProviders[i])
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCP)
				}
				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsEcsCapacityProviderInternal struct {
	cacheAutoScalingGroupArn string
	region                   string
}

func newMqlEcsCapacityProvider(runtime *plugin.Runtime, region string, cp *ecstypes.CapacityProvider) (plugin.Resource, error) {
	var asgArn, managedScalingStatus, managedTerminationProtection, managedDraining string
	var targetCapacity, minStep, maxStep, warmup int64
	if asg := cp.AutoScalingGroupProvider; asg != nil {
		asgArn = convert.ToValue(asg.AutoScalingGroupArn)
		managedTerminationProtection = string(asg.ManagedTerminationProtection)
		managedDraining = string(asg.ManagedDraining)
		if ms := asg.ManagedScaling; ms != nil {
			managedScalingStatus = string(ms.Status)
			targetCapacity = int64(convert.ToValue(ms.TargetCapacity))
			minStep = int64(convert.ToValue(ms.MinimumScalingStepSize))
			maxStep = int64(convert.ToValue(ms.MaximumScalingStepSize))
			warmup = int64(convert.ToValue(ms.InstanceWarmupPeriod))
		}
	}

	managedInstancesProvider, err := convert.JsonToDict(cp.ManagedInstancesProvider)
	if err != nil {
		return nil, err
	}

	mqlCP, err := CreateResource(runtime, ResourceAwsEcsCapacityProvider,
		map[string]*llx.RawData{
			"arn":                                llx.StringDataPtr(cp.CapacityProviderArn),
			"name":                               llx.StringDataPtr(cp.Name),
			"region":                             llx.StringData(region),
			"status":                             llx.StringData(string(cp.Status)),
			"updateStatus":                       llx.StringData(string(cp.UpdateStatus)),
			"tags":                               llx.MapData(ecsTagsToMap(cp.Tags), types.String),
			"autoScalingGroupArn":                llx.StringData(asgArn),
			"managedScalingStatus":               llx.StringData(managedScalingStatus),
			"managedScalingTargetCapacity":       llx.IntData(targetCapacity),
			"managedScalingMinimumStepSize":      llx.IntData(minStep),
			"managedScalingMaximumStepSize":      llx.IntData(maxStep),
			"managedScalingInstanceWarmupPeriod": llx.IntData(warmup),
			"managedTerminationProtection":       llx.StringData(managedTerminationProtection),
			"managedDraining":                    llx.StringData(managedDraining),
			"managedInstancesProvider":           llx.DictData(managedInstancesProvider),
		})
	if err != nil {
		return nil, err
	}
	cpRes := mqlCP.(*mqlAwsEcsCapacityProvider)
	cpRes.cacheAutoScalingGroupArn = asgArn
	cpRes.region = region
	return mqlCP, nil
}

func (a *mqlAwsEcsCapacityProvider) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEcsCapacityProvider) autoScalingGroup() (*mqlAwsAutoscalingGroup, error) {
	if a.cacheAutoScalingGroupArn == "" {
		a.AutoScalingGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// The Auto Scaling group name is the segment after the final "/" in the ARN,
	// e.g. arn:aws:autoscaling:...:autoScalingGroupName/my-asg -> my-asg
	name := a.cacheAutoScalingGroupArn
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	if name == "" {
		a.AutoScalingGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsAutoscalingGroup,
		map[string]*llx.RawData{
			"name":   llx.StringData(name),
			"region": llx.StringData(a.region),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAutoscalingGroup), nil
}

func (a *mqlAwsEcs) accountSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getECSAccountSettings(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsEcs) getECSAccountSettings(conn *connection.AwsConnection) []*jobpool.Job {
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
			var nextToken *string
			for {
				resp, err := svc.ListAccountSettings(ctx, &ecsservice.ListAccountSettingsInput{
					EffectiveSettings: true,
					NextToken:         nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for ECS account settings")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ecs account settings")
				}
				for _, s := range resp.Settings {
					mqlSetting, err := CreateResource(a.MqlRuntime, ResourceAwsEcsAccountSetting,
						map[string]*llx.RawData{
							"name":         llx.StringData(string(s.Name)),
							"value":        llx.StringData(convert.ToValue(s.Value)),
							"region":       llx.StringData(region),
							"principalArn": llx.StringData(convert.ToValue(s.PrincipalArn)),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSetting)
				}
				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEcsAccountSetting) id() (string, error) {
	// principalArn is included so settings scoped to different principals in
	// the same region don't collide (e.g. if a caller fetches non-effective
	// settings).
	return a.Region.Data + "/" + a.Name.Data + "/" + a.PrincipalArn.Data, nil
}

// ecsIamRoleRef resolves an IAM role ARN to a typed aws.iam.role reference,
// marking the field null when the ARN is empty.
func ecsIamRoleRef(runtime *plugin.Runtime, arnPtr *string, field *plugin.TValue[*mqlAwsIamRole]) (*mqlAwsIamRole, error) {
	if arnPtr == nil || *arnPtr == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(arnPtr)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

type mqlAwsEcsTaskSetInternal struct {
	cacheClusterArn string
	cacheServiceArn string
}
