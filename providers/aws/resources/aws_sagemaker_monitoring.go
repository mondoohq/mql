// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakerTypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// ---- Endpoint Configs ----

func (a *mqlAwsSagemaker) endpointConfigs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEndpointConfigs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getEndpointConfigs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListEndpointConfigsPaginator(svc, &sagemaker.ListEndpointConfigsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker endpoint configs")
						return res, nil
					}
					return nil, err
				}

				for _, item := range page.EndpointConfigs {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, item.EndpointConfigArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}
					mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerEndpointConfig,
						map[string]*llx.RawData{
							"arn":       llx.StringDataPtr(item.EndpointConfigArn),
							"name":      llx.StringDataPtr(item.EndpointConfigName),
							"region":    llx.StringData(region),
							"createdAt": llx.TimeDataPtr(item.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					ec := mqlRes.(*mqlAwsSagemakerEndpointConfig)
					if eagerTags != nil {
						ec.cacheTags = eagerTags
						ec.tagsFetched.Store(true)
					}
					res = append(res, mqlRes)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerEndpointConfigInternal struct {
	sagemakerTagsCache
	fetched       bool
	fetchLock     sync.Mutex
	cacheDescribe *sagemaker.DescribeEndpointConfigOutput
}

func (a *mqlAwsSagemakerEndpointConfig) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerEndpointConfig) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerEndpointConfig) fetchDetails() (*sagemaker.DescribeEndpointConfigOutput, error) {
	if a.fetched {
		return a.cacheDescribe, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.cacheDescribe, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeEndpointConfig(ctx, &sagemaker.DescribeEndpointConfigInput{EndpointConfigName: &name})
	if err != nil {
		return nil, err
	}
	a.cacheDescribe = resp
	a.fetched = true
	return resp, nil
}

func (a *mqlAwsSagemakerEndpointConfig) productionVariants() ([]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sagemakerBuildEndpointConfigProductionVariants(a.MqlRuntime, a.Arn.Data, resp.ProductionVariants)
}

func (a *mqlAwsSagemakerEndpointConfig) dataCaptureConfig() (*mqlAwsSagemakerEndpointConfigDataCaptureConfig, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if resp.DataCaptureConfig == nil {
		a.DataCaptureConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	dcc := resp.DataCaptureConfig
	var samplingPct int64
	if dcc.InitialSamplingPercentage != nil {
		samplingPct = int64(*dcc.InitialSamplingPercentage)
	}
	var captureOptions []any
	for _, opt := range dcc.CaptureOptions {
		captureOptions = append(captureOptions, string(opt.CaptureMode))
	}

	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerEndpointConfigDataCaptureConfig,
		map[string]*llx.RawData{
			"__id":                      llx.StringData(a.Arn.Data + "/dataCaptureConfig"),
			"enableCapture":             llx.BoolDataPtr(dcc.EnableCapture),
			"initialSamplingPercentage": llx.IntData(samplingPct),
			"destinationS3Uri":          llx.StringDataPtr(dcc.DestinationS3Uri),
			"captureOptions":            llx.ArrayData(captureOptions, types.String),
		})
	if err != nil {
		return nil, err
	}
	res := mqlRes.(*mqlAwsSagemakerEndpointConfigDataCaptureConfig)
	res.cacheParentArn = a.Arn.Data
	res.cacheKmsKeyId = dcc.KmsKeyId
	res.cacheCaptureContentTypeHeader = dcc.CaptureContentTypeHeader
	return res, nil
}

func (a *mqlAwsSagemakerEndpointConfig) kmsKey() (*mqlAwsKmsKey, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if resp.KmsKeyId == nil || *resp.KmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(resp.KmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSagemakerEndpointConfig) asyncInferenceConfig() (any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if resp.AsyncInferenceConfig == nil {
		return nil, nil
	}
	return convert.JsonToDict(resp.AsyncInferenceConfig)
}

func (a *mqlAwsSagemakerEndpointConfig) enableNetworkIsolation() (bool, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return false, err
	}
	if resp.EnableNetworkIsolation == nil {
		return false, nil
	}
	return *resp.EnableNetworkIsolation, nil
}

func (a *mqlAwsSagemakerEndpointConfig) iamRole() (*mqlAwsIamRole, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sagemakerIamRole(a.MqlRuntime, &a.IamRole, resp.ExecutionRoleArn)
}

func (a *mqlAwsSagemakerEndpointConfig) vpc() (*mqlAwsVpc, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	var subnetIds []string
	if resp.VpcConfig != nil {
		subnetIds = resp.VpcConfig.Subnets
	}
	return sagemakerResolveVpc(a.MqlRuntime, a.Region.Data, subnetIds, &a.Vpc)
}

func (a *mqlAwsSagemakerEndpointConfig) securityGroups() ([]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if resp.VpcConfig == nil {
		return nil, nil
	}
	return sagemakerSecurityGroups(a.MqlRuntime, a.Region.Data, resp.VpcConfig.SecurityGroupIds)
}

func (a *mqlAwsSagemakerEndpointConfig) asyncOutputKmsKey() (*mqlAwsKmsKey, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	var keyId *string
	if resp.AsyncInferenceConfig != nil && resp.AsyncInferenceConfig.OutputConfig != nil {
		keyId = resp.AsyncInferenceConfig.OutputConfig.KmsKeyId
	}
	return sagemakerKmsKey(a.MqlRuntime, &a.AsyncOutputKmsKey, keyId)
}

// ---- Endpoint Config Production Variant ----

type mqlAwsSagemakerEndpointConfigProductionVariantInternal struct {
	cacheParentArn              string
	cacheServerlessConfig       *sagemakerTypes.ProductionVariantServerlessConfig
	cacheManagedInstanceScaling any
	cacheRoutingConfig          any
}

func (a *mqlAwsSagemakerEndpointConfigProductionVariant) id() (string, error) {
	return a.cacheParentArn + "/productionVariant/" + a.VariantName.Data, nil
}

func (a *mqlAwsSagemakerEndpointConfigProductionVariant) serverlessConfig() (*mqlAwsSagemakerEndpointConfigServerlessConfig, error) {
	if a.cacheServerlessConfig == nil {
		a.ServerlessConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	sc := a.cacheServerlessConfig
	var memSize, maxConc, provConc int64
	if sc.MemorySizeInMB != nil {
		memSize = int64(*sc.MemorySizeInMB)
	}
	if sc.MaxConcurrency != nil {
		maxConc = int64(*sc.MaxConcurrency)
	}
	if sc.ProvisionedConcurrency != nil {
		provConc = int64(*sc.ProvisionedConcurrency)
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerEndpointConfigServerlessConfig,
		map[string]*llx.RawData{
			"__id":                   llx.StringData(a.cacheParentArn + "/productionVariant/" + a.VariantName.Data + "/serverlessConfig"),
			"memorySizeInMB":         llx.IntData(memSize),
			"maxConcurrency":         llx.IntData(maxConc),
			"provisionedConcurrency": llx.IntData(provConc),
		})
	if err != nil {
		return nil, err
	}
	scRes := mqlRes.(*mqlAwsSagemakerEndpointConfigServerlessConfig)
	scRes.cacheParentId = a.cacheParentArn + "/productionVariant/" + a.VariantName.Data
	return scRes, nil
}

func (a *mqlAwsSagemakerEndpointConfigProductionVariant) managedInstanceScaling() (any, error) {
	if a.cacheManagedInstanceScaling == nil {
		return nil, nil
	}
	return a.cacheManagedInstanceScaling, nil
}

func (a *mqlAwsSagemakerEndpointConfigProductionVariant) routingConfig() (any, error) {
	if a.cacheRoutingConfig == nil {
		return nil, nil
	}
	return a.cacheRoutingConfig, nil
}

func sagemakerBuildEndpointConfigProductionVariants(runtime *plugin.Runtime, parentArn string, variants []sagemakerTypes.ProductionVariant) ([]any, error) {
	res := make([]any, 0, len(variants))
	for _, v := range variants {
		var initialCount int64
		var initialWeight float64
		var volumeSize int64
		var downloadTimeout int64
		if v.InitialInstanceCount != nil {
			initialCount = int64(*v.InitialInstanceCount)
		}
		if v.InitialVariantWeight != nil {
			initialWeight = float64(*v.InitialVariantWeight)
		}
		if v.VolumeSizeInGB != nil {
			volumeSize = int64(*v.VolumeSizeInGB)
		}
		if v.ModelDataDownloadTimeoutInSeconds != nil {
			downloadTimeout = int64(*v.ModelDataDownloadTimeoutInSeconds)
		}

		mqlPV, err := CreateResource(runtime, ResourceAwsSagemakerEndpointConfigProductionVariant,
			map[string]*llx.RawData{
				"__id":                              llx.StringData(parentArn + "/productionVariant/" + convert.ToValue(v.VariantName)),
				"variantName":                       llx.StringDataPtr(v.VariantName),
				"modelName":                         llx.StringDataPtr(v.ModelName),
				"instanceType":                      llx.StringData(string(v.InstanceType)),
				"initialInstanceCount":              llx.IntData(initialCount),
				"initialVariantWeight":              llx.FloatData(initialWeight),
				"volumeSizeInGB":                    llx.IntData(volumeSize),
				"modelDataDownloadTimeoutInSeconds": llx.IntData(downloadTimeout),
				"acceleratorType":                   llx.StringData(string(v.AcceleratorType)),
			})
		if err != nil {
			return nil, err
		}
		pv := mqlPV.(*mqlAwsSagemakerEndpointConfigProductionVariant)
		pv.cacheParentArn = parentArn
		pv.cacheServerlessConfig = v.ServerlessConfig
		pv.cacheManagedInstanceScaling, _ = convert.JsonToDict(v.ManagedInstanceScaling)
		pv.cacheRoutingConfig, _ = convert.JsonToDict(v.RoutingConfig)
		res = append(res, mqlPV)
	}
	return res, nil
}

// ---- Endpoint Config Serverless Config ----

type mqlAwsSagemakerEndpointConfigServerlessConfigInternal struct {
	cacheParentId string
}

func (a *mqlAwsSagemakerEndpointConfigServerlessConfig) id() (string, error) {
	return a.cacheParentId + "/serverlessConfig", nil
}

// ---- Endpoint Config Data Capture Config ----

type mqlAwsSagemakerEndpointConfigDataCaptureConfigInternal struct {
	cacheParentArn                string
	cacheKmsKeyId                 *string
	cacheCaptureContentTypeHeader *sagemakerTypes.CaptureContentTypeHeader
}

func (a *mqlAwsSagemakerEndpointConfigDataCaptureConfig) id() (string, error) {
	return a.cacheParentArn + "/dataCaptureConfig", nil
}

func (a *mqlAwsSagemakerEndpointConfigDataCaptureConfig) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSagemakerEndpointConfigDataCaptureConfig) captureContentTypeHeader() (any, error) {
	if a.cacheCaptureContentTypeHeader == nil {
		return nil, nil
	}
	return convert.JsonToDict(a.cacheCaptureContentTypeHeader)
}

// ---- Monitoring Schedules ----

func (a *mqlAwsSagemaker) monitoringSchedules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getMonitoringSchedules(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getMonitoringSchedules(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListMonitoringSchedulesPaginator(svc, &sagemaker.ListMonitoringSchedulesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker monitoring schedules")
						return res, nil
					}
					return nil, err
				}

				for _, item := range page.MonitoringScheduleSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, item.MonitoringScheduleArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}
					mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerMonitoringSchedule,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(item.MonitoringScheduleArn),
							"name":           llx.StringDataPtr(item.MonitoringScheduleName),
							"region":         llx.StringData(region),
							"status":         llx.StringData(string(item.MonitoringScheduleStatus)),
							"monitoringType": llx.StringData(string(item.MonitoringType)),
							"createdAt":      llx.TimeDataPtr(item.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(item.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					ms := mqlRes.(*mqlAwsSagemakerMonitoringSchedule)
					if eagerTags != nil {
						ms.cacheTags = eagerTags
						ms.tagsFetched.Store(true)
					}
					res = append(res, mqlRes)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerMonitoringScheduleInternal struct {
	sagemakerTagsCache
	fetched       bool
	fetchLock     sync.Mutex
	cacheDescribe *sagemaker.DescribeMonitoringScheduleOutput
}

func (a *mqlAwsSagemakerMonitoringSchedule) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerMonitoringSchedule) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerMonitoringSchedule) fetchDetails() (*sagemaker.DescribeMonitoringScheduleOutput, error) {
	if a.fetched {
		return a.cacheDescribe, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.cacheDescribe, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeMonitoringSchedule(ctx, &sagemaker.DescribeMonitoringScheduleInput{MonitoringScheduleName: &name})
	if err != nil {
		return nil, err
	}
	a.cacheDescribe = resp
	a.fetched = true
	return resp, nil
}

func (a *mqlAwsSagemakerMonitoringSchedule) scheduleConfig() (*mqlAwsSagemakerMonitoringScheduleScheduleConfig, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if resp.MonitoringScheduleConfig == nil || resp.MonitoringScheduleConfig.ScheduleConfig == nil {
		a.ScheduleConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	sc := resp.MonitoringScheduleConfig.ScheduleConfig
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerMonitoringScheduleScheduleConfig,
		map[string]*llx.RawData{
			"__id":                  llx.StringData(a.Arn.Data + "/scheduleConfig"),
			"scheduleExpression":    llx.StringDataPtr(sc.ScheduleExpression),
			"dataAnalysisStartTime": llx.StringDataPtr(sc.DataAnalysisStartTime),
			"dataAnalysisEndTime":   llx.StringDataPtr(sc.DataAnalysisEndTime),
		})
	if err != nil {
		return nil, err
	}
	res := mqlRes.(*mqlAwsSagemakerMonitoringScheduleScheduleConfig)
	res.cacheParentArn = a.Arn.Data
	return res, nil
}

func (a *mqlAwsSagemakerMonitoringSchedule) monitoringJobDefinitionName() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if resp.MonitoringScheduleConfig != nil {
		return convert.ToValue(resp.MonitoringScheduleConfig.MonitoringJobDefinitionName), nil
	}
	return "", nil
}

func (a *mqlAwsSagemakerMonitoringSchedule) endpointName() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.EndpointName), nil
}

func (a *mqlAwsSagemakerMonitoringSchedule) endpoint() (*mqlAwsSagemakerEndpoint, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if resp.EndpointName == nil || *resp.EndpointName == "" {
		a.Endpoint.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	// Extract partition from the schedule's own ARN to handle aws-cn, aws-us-gov
	partition := "aws"
	if parts := strings.SplitN(a.Arn.Data, ":", 3); len(parts) >= 2 {
		partition = parts[1]
	}
	endpointArn := fmt.Sprintf("arn:%s:sagemaker:%s:%s:endpoint/%s", partition, a.Region.Data, conn.AccountId(), *resp.EndpointName)
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.endpoint",
		map[string]*llx.RawData{"arn": llx.StringData(endpointArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerEndpoint), nil
}

func (a *mqlAwsSagemakerMonitoringSchedule) failureReason() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.FailureReason), nil
}

// ---- Monitoring Schedule Config ----

type mqlAwsSagemakerMonitoringScheduleScheduleConfigInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerMonitoringScheduleScheduleConfig) id() (string, error) {
	return a.cacheParentArn + "/scheduleConfig", nil
}

// ---- Shared Monitoring Job Definition Sub-Resources ----

// monitoringJobDefDetails is a generic struct that extracts the common fields
// from the 4 monitoring job definition Describe outputs.
type monitoringJobDefDetails struct {
	JobDefinitionArn *string
	RoleArn          *string
	Region           string
	AppSpec          monitoringAppSpec
	JobInput         monitoringJobInput
	OutputConfig     *sagemakerTypes.MonitoringOutputConfig
	Resources        *sagemakerTypes.MonitoringResources
	NetworkConfig    *sagemakerTypes.MonitoringNetworkConfig
	BaselineConfig   any
	StoppingCond     any
}

type monitoringAppSpec struct {
	ImageUri                        *string
	ContainerEntrypoint             []string
	ContainerArguments              []string
	PostAnalyticsProcessorSourceUri *string
	RecordPreprocessorSourceUri     *string
	Environment                     map[string]string
}

type monitoringJobInput struct {
	EndpointInput       any
	BatchTransformInput any
}

// monitoringJobSubResources holds the created sub-resources for a monitoring job definition.
type monitoringJobSubResources struct {
	appSpecification *mqlAwsSagemakerMonitoringJobDefinitionAppSpecification
	jobInput         *mqlAwsSagemakerMonitoringJobDefinitionJobInput
	jobOutputConfig  *mqlAwsSagemakerMonitoringJobDefinitionJobOutputConfig
	jobResources     *mqlAwsSagemakerMonitoringJobDefinitionJobResources
	networkConfig    *mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig
	roleArn          *string
	baselineConfig   any
	stoppingCond     any
}

func sagemakerBuildMonitoringJobSubResources(runtime *plugin.Runtime, details monitoringJobDefDetails) (*monitoringJobSubResources, error) {
	parentArn := convert.ToValue(details.JobDefinitionArn)
	result := &monitoringJobSubResources{
		roleArn:        details.RoleArn,
		baselineConfig: details.BaselineConfig,
		stoppingCond:   details.StoppingCond,
	}

	// Build appSpecification
	{
		spec := details.AppSpec
		var entrypoint []any
		for _, e := range spec.ContainerEntrypoint {
			entrypoint = append(entrypoint, e)
		}
		var args []any
		for _, a := range spec.ContainerArguments {
			args = append(args, a)
		}
		env := make(map[string]any, len(spec.Environment))
		for k, v := range spec.Environment {
			env[k] = v
		}
		mqlRes, err := CreateResource(runtime, ResourceAwsSagemakerMonitoringJobDefinitionAppSpecification,
			map[string]*llx.RawData{
				"__id":                            llx.StringData(parentArn + "/appSpecification"),
				"imageUri":                        llx.StringDataPtr(spec.ImageUri),
				"containerEntrypoint":             llx.ArrayData(entrypoint, types.String),
				"containerArguments":              llx.ArrayData(args, types.String),
				"postAnalyticsProcessorSourceUri": llx.StringDataPtr(spec.PostAnalyticsProcessorSourceUri),
				"recordPreprocessorSourceUri":     llx.StringDataPtr(spec.RecordPreprocessorSourceUri),
				"environment":                     llx.MapData(env, types.String),
			})
		if err != nil {
			return nil, err
		}
		appSpec := mqlRes.(*mqlAwsSagemakerMonitoringJobDefinitionAppSpecification)
		appSpec.cacheParentArn = parentArn
		result.appSpecification = appSpec
	}

	// Build jobInput
	{
		endpointDict, _ := convert.JsonToDict(details.JobInput.EndpointInput)
		batchDict, _ := convert.JsonToDict(details.JobInput.BatchTransformInput)
		mqlRes, err := CreateResource(runtime, ResourceAwsSagemakerMonitoringJobDefinitionJobInput,
			map[string]*llx.RawData{
				"__id":                llx.StringData(parentArn + "/jobInput"),
				"endpointInput":       llx.DictData(endpointDict),
				"batchTransformInput": llx.DictData(batchDict),
			})
		if err != nil {
			return nil, err
		}
		ji := mqlRes.(*mqlAwsSagemakerMonitoringJobDefinitionJobInput)
		ji.cacheParentArn = parentArn
		result.jobInput = ji
	}

	// Build jobOutputConfig
	{
		var kmsKeyId *string
		var outputs []sagemakerTypes.MonitoringOutput
		if details.OutputConfig != nil {
			kmsKeyId = details.OutputConfig.KmsKeyId
			outputs = details.OutputConfig.MonitoringOutputs
		}
		mqlRes, err := CreateResource(runtime, ResourceAwsSagemakerMonitoringJobDefinitionJobOutputConfig,
			map[string]*llx.RawData{
				"__id": llx.StringData(parentArn + "/jobOutputConfig"),
			})
		if err != nil {
			return nil, err
		}
		oc := mqlRes.(*mqlAwsSagemakerMonitoringJobDefinitionJobOutputConfig)
		oc.cacheParentArn = parentArn
		oc.cacheKmsKeyId = kmsKeyId
		oc.cacheOutputs = outputs
		result.jobOutputConfig = oc
	}

	// Build jobResources
	{
		var instanceType string
		var instanceCount, volumeSize int64
		var volumeKmsKeyId *string
		if details.Resources != nil && details.Resources.ClusterConfig != nil {
			cc := details.Resources.ClusterConfig
			instanceType = string(cc.InstanceType)
			if cc.InstanceCount != nil {
				instanceCount = int64(*cc.InstanceCount)
			}
			if cc.VolumeSizeInGB != nil {
				volumeSize = int64(*cc.VolumeSizeInGB)
			}
			volumeKmsKeyId = cc.VolumeKmsKeyId
		}
		mqlRes, err := CreateResource(runtime, ResourceAwsSagemakerMonitoringJobDefinitionJobResources,
			map[string]*llx.RawData{
				"__id":           llx.StringData(parentArn + "/jobResources"),
				"instanceType":   llx.StringData(instanceType),
				"instanceCount":  llx.IntData(instanceCount),
				"volumeSizeInGB": llx.IntData(volumeSize),
			})
		if err != nil {
			return nil, err
		}
		jr := mqlRes.(*mqlAwsSagemakerMonitoringJobDefinitionJobResources)
		jr.cacheParentArn = parentArn
		jr.cacheVolumeKmsKeyId = volumeKmsKeyId
		result.jobResources = jr
	}

	// Build networkConfig — only create when actually configured
	if details.NetworkConfig != nil {
		var enableEncrypt, enableIsolation bool
		var subnetIds, sgIds []string
		if details.NetworkConfig.EnableInterContainerTrafficEncryption != nil {
			enableEncrypt = *details.NetworkConfig.EnableInterContainerTrafficEncryption
		}
		if details.NetworkConfig.EnableNetworkIsolation != nil {
			enableIsolation = *details.NetworkConfig.EnableNetworkIsolation
		}
		if details.NetworkConfig.VpcConfig != nil {
			subnetIds = details.NetworkConfig.VpcConfig.Subnets
			sgIds = details.NetworkConfig.VpcConfig.SecurityGroupIds
		}
		mqlRes, err := CreateResource(runtime, ResourceAwsSagemakerMonitoringJobDefinitionNetworkConfig,
			map[string]*llx.RawData{
				"__id":                                  llx.StringData(parentArn + "/networkConfig"),
				"enableInterContainerTrafficEncryption": llx.BoolData(enableEncrypt),
				"enableNetworkIsolation":                llx.BoolData(enableIsolation),
			})
		if err != nil {
			return nil, err
		}
		nc := mqlRes.(*mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig)
		nc.cacheParentArn = parentArn
		nc.cacheSubnetIds = subnetIds
		nc.cacheSecurityGroupIds = sgIds
		nc.region = details.Region
		result.networkConfig = nc
	}

	return result, nil
}

// ---- Monitoring Job Definition App Specification ----

type mqlAwsSagemakerMonitoringJobDefinitionAppSpecificationInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionAppSpecification) id() (string, error) {
	return a.cacheParentArn + "/appSpecification", nil
}

// ---- Monitoring Job Definition Job Input ----

type mqlAwsSagemakerMonitoringJobDefinitionJobInputInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionJobInput) id() (string, error) {
	return a.cacheParentArn + "/jobInput", nil
}

// ---- Monitoring Job Definition Job Output Config ----

type mqlAwsSagemakerMonitoringJobDefinitionJobOutputConfigInternal struct {
	cacheParentArn string
	cacheKmsKeyId  *string
	cacheOutputs   []sagemakerTypes.MonitoringOutput
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionJobOutputConfig) id() (string, error) {
	return a.cacheParentArn + "/jobOutputConfig", nil
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionJobOutputConfig) monitoringOutputs() ([]any, error) {
	res := make([]any, 0, len(a.cacheOutputs))
	for i, output := range a.cacheOutputs {
		if output.S3Output == nil {
			continue
		}
		s3Out := output.S3Output
		mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerMonitoringJobDefinitionMonitoringOutput,
			map[string]*llx.RawData{
				"__id":         llx.StringData(fmt.Sprintf("%s/monitoringOutput/%d", a.cacheParentArn, i)),
				"s3Uri":        llx.StringDataPtr(s3Out.S3Uri),
				"localPath":    llx.StringDataPtr(s3Out.LocalPath),
				"s3UploadMode": llx.StringData(string(s3Out.S3UploadMode)),
			})
		if err != nil {
			return nil, err
		}
		mo := mqlRes.(*mqlAwsSagemakerMonitoringJobDefinitionMonitoringOutput)
		mo.cacheParentArn = a.cacheParentArn
		mo.cacheIndex = i
		res = append(res, mqlRes)
	}
	return res, nil
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionJobOutputConfig) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// ---- Monitoring Output ----

type mqlAwsSagemakerMonitoringJobDefinitionMonitoringOutputInternal struct {
	cacheParentArn string
	cacheIndex     int
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionMonitoringOutput) id() (string, error) {
	return fmt.Sprintf("%s/monitoringOutput/%d", a.cacheParentArn, a.cacheIndex), nil
}

// ---- Monitoring Job Definition Job Resources ----

type mqlAwsSagemakerMonitoringJobDefinitionJobResourcesInternal struct {
	cacheParentArn      string
	cacheVolumeKmsKeyId *string
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionJobResources) id() (string, error) {
	return a.cacheParentArn + "/jobResources", nil
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionJobResources) volumeKmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheVolumeKmsKeyId == nil || *a.cacheVolumeKmsKeyId == "" {
		a.VolumeKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheVolumeKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// ---- Monitoring Job Definition Network Config ----

type mqlAwsSagemakerMonitoringJobDefinitionNetworkConfigInternal struct {
	cacheParentArn        string
	cacheSubnetIds        []string
	cacheSecurityGroupIds []string
	region                string
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig) id() (string, error) {
	return a.cacheParentArn + "/networkConfig", nil
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig) vpc() (*mqlAwsVpc, error) {
	return sagemakerResolveVpc(a.MqlRuntime, a.region, a.cacheSubnetIds, &a.Vpc)
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig) securityGroups() ([]any, error) {
	if len(a.cacheSecurityGroupIds) == 0 {
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	sgs := make([]any, 0, len(a.cacheSecurityGroupIds))
	for _, sgId := range a.cacheSecurityGroupIds {
		sgArn := NewSecurityGroupArn(a.region, conn.AccountId(), sgId)
		mqlSg, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup",
			map[string]*llx.RawData{"arn": llx.StringData(sgArn)})
		if err != nil {
			return nil, err
		}
		sgs = append(sgs, mqlSg)
	}
	return sgs, nil
}

func (a *mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig) subnets() ([]any, error) {
	if len(a.cacheSubnetIds) == 0 {
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := make([]any, 0, len(a.cacheSubnetIds))
	for _, subnetId := range a.cacheSubnetIds {
		arn := fmt.Sprintf(subnetArnPattern, a.region, conn.AccountId(), subnetId)
		mqlSubnet, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet,
			map[string]*llx.RawData{"arn": llx.StringData(arn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

// ---- Data Quality Job Definitions ----

func (a *mqlAwsSagemaker) dataQualityJobDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDataQualityJobDefinitions(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

// monitoringJobDefinitionSource is implemented by every per-kind monitoring
// job definition resource. It lets the unified aws.sagemaker.monitoringJobDefinition
// collection read the shared summary fields and defer to the per-kind resource
// for the network configuration, which requires a kind-specific Describe call.
type monitoringJobDefinitionSource interface {
	GetArn() *plugin.TValue[string]
	GetName() *plugin.TValue[string]
	GetRegion() *plugin.TValue[string]
	GetCreatedAt() *plugin.TValue[*time.Time]
	networkConfig() (*mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig, error)
}

func (a *mqlAwsSagemaker) monitoringJobDefinitions() ([]any, error) {
	sources := []struct {
		typ  string
		list func() ([]any, error)
	}{
		{"DataQuality", a.dataQualityJobDefinitions},
		{"ModelQuality", a.modelQualityJobDefinitions},
		{"ModelBias", a.modelBiasJobDefinitions},
		{"ModelExplainability", a.modelExplainabilityJobDefinitions},
	}

	res := []any{}
	for _, s := range sources {
		items, err := s.list()
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			src := item.(monitoringJobDefinitionSource)
			mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerMonitoringJobDefinition,
				map[string]*llx.RawData{
					"arn":       llx.StringData(src.GetArn().Data),
					"name":      llx.StringData(src.GetName().Data),
					"type":      llx.StringData(s.typ),
					"region":    llx.StringData(src.GetRegion().Data),
					"createdAt": llx.TimeDataPtr(src.GetCreatedAt().Data),
				})
			if err != nil {
				return nil, err
			}
			mqlRes.(*mqlAwsSagemakerMonitoringJobDefinition).source = src
			res = append(res, mqlRes)
		}
	}
	return res, nil
}

type mqlAwsSagemakerMonitoringJobDefinitionInternal struct {
	sagemakerTagsCache
	source monitoringJobDefinitionSource
}

func (a *mqlAwsSagemakerMonitoringJobDefinition) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerMonitoringJobDefinition) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

// jobDefinitionSource returns the per-kind resource backing this entry. The
// collection caches it directly; this rebuilds it from the entry's kind when
// the resource is reached without that cached reference.
func (a *mqlAwsSagemakerMonitoringJobDefinition) jobDefinitionSource() (monitoringJobDefinitionSource, error) {
	if a.source != nil {
		return a.source, nil
	}

	var resourceName string
	switch a.Type.Data {
	case "DataQuality":
		resourceName = ResourceAwsSagemakerDataQualityJobDefinition
	case "ModelQuality":
		resourceName = ResourceAwsSagemakerModelQualityJobDefinition
	case "ModelBias":
		resourceName = ResourceAwsSagemakerModelBiasJobDefinition
	case "ModelExplainability":
		resourceName = ResourceAwsSagemakerModelExplainabilityJobDefinition
	default:
		return nil, fmt.Errorf("unknown monitoring job definition type %q", a.Type.Data)
	}

	res, err := CreateResource(a.MqlRuntime, resourceName, map[string]*llx.RawData{
		"arn":       llx.StringData(a.Arn.Data),
		"name":      llx.StringData(a.Name.Data),
		"region":    llx.StringData(a.Region.Data),
		"createdAt": llx.TimeDataPtr(a.CreatedAt.Data),
	})
	if err != nil {
		return nil, err
	}
	a.source = res.(monitoringJobDefinitionSource)
	return a.source, nil
}

func (a *mqlAwsSagemakerMonitoringJobDefinition) networkConfig() (*mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig, error) {
	src, err := a.jobDefinitionSource()
	if err != nil {
		return nil, err
	}
	nc, err := src.networkConfig()
	if err != nil {
		return nil, err
	}
	if nc == nil {
		a.NetworkConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return nc, nil
}

func (a *mqlAwsSagemaker) getDataQualityJobDefinitions(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListDataQualityJobDefinitionsPaginator(svc, &sagemaker.ListDataQualityJobDefinitionsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker data quality job definitions")
						return res, nil
					}
					return nil, err
				}

				for _, item := range page.JobDefinitionSummaries {
					mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerDataQualityJobDefinition,
						map[string]*llx.RawData{
							"arn":       llx.StringDataPtr(item.MonitoringJobDefinitionArn),
							"name":      llx.StringDataPtr(item.MonitoringJobDefinitionName),
							"region":    llx.StringData(region),
							"createdAt": llx.TimeDataPtr(item.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRes)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerDataQualityJobDefinitionInternal struct {
	sagemakerTagsCache
	fetched   bool
	fetchLock sync.Mutex
	cacheSub  *monitoringJobSubResources
}

func (a *mqlAwsSagemakerDataQualityJobDefinition) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerDataQualityJobDefinition) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerDataQualityJobDefinition) fetchDetails() (*monitoringJobSubResources, error) {
	if a.fetched {
		return a.cacheSub, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.cacheSub, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeDataQualityJobDefinition(ctx, &sagemaker.DescribeDataQualityJobDefinitionInput{JobDefinitionName: &name})
	if err != nil {
		return nil, err
	}

	var appSpec monitoringAppSpec
	if resp.DataQualityAppSpecification != nil {
		s := resp.DataQualityAppSpecification
		appSpec = monitoringAppSpec{
			ImageUri:                        s.ImageUri,
			ContainerEntrypoint:             s.ContainerEntrypoint,
			ContainerArguments:              s.ContainerArguments,
			PostAnalyticsProcessorSourceUri: s.PostAnalyticsProcessorSourceUri,
			RecordPreprocessorSourceUri:     s.RecordPreprocessorSourceUri,
			Environment:                     s.Environment,
		}
	}

	var ji monitoringJobInput
	if resp.DataQualityJobInput != nil {
		ji.EndpointInput = resp.DataQualityJobInput.EndpointInput
		ji.BatchTransformInput = resp.DataQualityJobInput.BatchTransformInput
	}

	baselineConfig, _ := convert.JsonToDict(resp.DataQualityBaselineConfig)
	stoppingCond, _ := convert.JsonToDict(resp.StoppingCondition)

	sub, err := sagemakerBuildMonitoringJobSubResources(a.MqlRuntime, monitoringJobDefDetails{
		JobDefinitionArn: resp.JobDefinitionArn,
		RoleArn:          resp.RoleArn,
		Region:           a.Region.Data,
		AppSpec:          appSpec,
		JobInput:         ji,
		OutputConfig:     resp.DataQualityJobOutputConfig,
		Resources:        resp.JobResources,
		NetworkConfig:    resp.NetworkConfig,
		BaselineConfig:   baselineConfig,
		StoppingCond:     stoppingCond,
	})
	if err != nil {
		return nil, err
	}
	a.cacheSub = sub
	a.fetched = true
	return sub, nil
}

func (a *mqlAwsSagemakerDataQualityJobDefinition) appSpecification() (*mqlAwsSagemakerMonitoringJobDefinitionAppSpecification, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.appSpecification, nil
}

func (a *mqlAwsSagemakerDataQualityJobDefinition) baselineConfig() (any, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.baselineConfig, nil
}

func (a *mqlAwsSagemakerDataQualityJobDefinition) jobInput() (*mqlAwsSagemakerMonitoringJobDefinitionJobInput, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobInput, nil
}

func (a *mqlAwsSagemakerDataQualityJobDefinition) jobOutputConfig() (*mqlAwsSagemakerMonitoringJobDefinitionJobOutputConfig, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobOutputConfig, nil
}

func (a *mqlAwsSagemakerDataQualityJobDefinition) jobResources() (*mqlAwsSagemakerMonitoringJobDefinitionJobResources, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobResources, nil
}

func (a *mqlAwsSagemakerDataQualityJobDefinition) networkConfig() (*mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if sub.networkConfig == nil {
		a.NetworkConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return sub.networkConfig, nil
}

func (a *mqlAwsSagemakerDataQualityJobDefinition) iamRole() (*mqlAwsIamRole, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if sub.roleArn == nil || *sub.roleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(sub.roleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerDataQualityJobDefinition) stoppingCondition() (any, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.stoppingCond, nil
}

// ---- Model Quality Job Definitions ----

func (a *mqlAwsSagemaker) modelQualityJobDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getModelQualityJobDefinitions(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getModelQualityJobDefinitions(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListModelQualityJobDefinitionsPaginator(svc, &sagemaker.ListModelQualityJobDefinitionsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker model quality job definitions")
						return res, nil
					}
					return nil, err
				}

				for _, item := range page.JobDefinitionSummaries {
					mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerModelQualityJobDefinition,
						map[string]*llx.RawData{
							"arn":       llx.StringDataPtr(item.MonitoringJobDefinitionArn),
							"name":      llx.StringDataPtr(item.MonitoringJobDefinitionName),
							"region":    llx.StringData(region),
							"createdAt": llx.TimeDataPtr(item.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRes)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerModelQualityJobDefinitionInternal struct {
	sagemakerTagsCache
	fetched   bool
	fetchLock sync.Mutex
	cacheSub  *monitoringJobSubResources
}

func (a *mqlAwsSagemakerModelQualityJobDefinition) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerModelQualityJobDefinition) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerModelQualityJobDefinition) fetchDetails() (*monitoringJobSubResources, error) {
	if a.fetched {
		return a.cacheSub, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.cacheSub, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeModelQualityJobDefinition(ctx, &sagemaker.DescribeModelQualityJobDefinitionInput{JobDefinitionName: &name})
	if err != nil {
		return nil, err
	}

	var appSpec monitoringAppSpec
	if resp.ModelQualityAppSpecification != nil {
		s := resp.ModelQualityAppSpecification
		appSpec = monitoringAppSpec{
			ImageUri:                        s.ImageUri,
			ContainerEntrypoint:             s.ContainerEntrypoint,
			ContainerArguments:              s.ContainerArguments,
			PostAnalyticsProcessorSourceUri: s.PostAnalyticsProcessorSourceUri,
			RecordPreprocessorSourceUri:     s.RecordPreprocessorSourceUri,
			Environment:                     s.Environment,
		}
	}

	var ji monitoringJobInput
	if resp.ModelQualityJobInput != nil {
		ji.EndpointInput = resp.ModelQualityJobInput.EndpointInput
		ji.BatchTransformInput = resp.ModelQualityJobInput.BatchTransformInput
	}

	baselineConfig, _ := convert.JsonToDict(resp.ModelQualityBaselineConfig)
	stoppingCond, _ := convert.JsonToDict(resp.StoppingCondition)

	sub, err := sagemakerBuildMonitoringJobSubResources(a.MqlRuntime, monitoringJobDefDetails{
		JobDefinitionArn: resp.JobDefinitionArn,
		RoleArn:          resp.RoleArn,
		Region:           a.Region.Data,
		AppSpec:          appSpec,
		JobInput:         ji,
		OutputConfig:     resp.ModelQualityJobOutputConfig,
		Resources:        resp.JobResources,
		NetworkConfig:    resp.NetworkConfig,
		BaselineConfig:   baselineConfig,
		StoppingCond:     stoppingCond,
	})
	if err != nil {
		return nil, err
	}
	a.cacheSub = sub
	a.fetched = true
	return sub, nil
}

func (a *mqlAwsSagemakerModelQualityJobDefinition) appSpecification() (*mqlAwsSagemakerMonitoringJobDefinitionAppSpecification, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.appSpecification, nil
}

func (a *mqlAwsSagemakerModelQualityJobDefinition) baselineConfig() (any, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.baselineConfig, nil
}

func (a *mqlAwsSagemakerModelQualityJobDefinition) jobInput() (*mqlAwsSagemakerMonitoringJobDefinitionJobInput, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobInput, nil
}

func (a *mqlAwsSagemakerModelQualityJobDefinition) jobOutputConfig() (*mqlAwsSagemakerMonitoringJobDefinitionJobOutputConfig, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobOutputConfig, nil
}

func (a *mqlAwsSagemakerModelQualityJobDefinition) jobResources() (*mqlAwsSagemakerMonitoringJobDefinitionJobResources, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobResources, nil
}

func (a *mqlAwsSagemakerModelQualityJobDefinition) networkConfig() (*mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if sub.networkConfig == nil {
		a.NetworkConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return sub.networkConfig, nil
}

func (a *mqlAwsSagemakerModelQualityJobDefinition) iamRole() (*mqlAwsIamRole, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if sub.roleArn == nil || *sub.roleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(sub.roleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerModelQualityJobDefinition) stoppingCondition() (any, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.stoppingCond, nil
}

// ---- Model Bias Job Definitions ----

func (a *mqlAwsSagemaker) modelBiasJobDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getModelBiasJobDefinitions(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getModelBiasJobDefinitions(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListModelBiasJobDefinitionsPaginator(svc, &sagemaker.ListModelBiasJobDefinitionsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker model bias job definitions")
						return res, nil
					}
					return nil, err
				}

				for _, item := range page.JobDefinitionSummaries {
					mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerModelBiasJobDefinition,
						map[string]*llx.RawData{
							"arn":       llx.StringDataPtr(item.MonitoringJobDefinitionArn),
							"name":      llx.StringDataPtr(item.MonitoringJobDefinitionName),
							"region":    llx.StringData(region),
							"createdAt": llx.TimeDataPtr(item.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRes)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerModelBiasJobDefinitionInternal struct {
	sagemakerTagsCache
	fetched   bool
	fetchLock sync.Mutex
	cacheSub  *monitoringJobSubResources
}

func (a *mqlAwsSagemakerModelBiasJobDefinition) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerModelBiasJobDefinition) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerModelBiasJobDefinition) fetchDetails() (*monitoringJobSubResources, error) {
	if a.fetched {
		return a.cacheSub, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.cacheSub, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeModelBiasJobDefinition(ctx, &sagemaker.DescribeModelBiasJobDefinitionInput{JobDefinitionName: &name})
	if err != nil {
		return nil, err
	}

	var appSpec monitoringAppSpec
	if resp.ModelBiasAppSpecification != nil {
		s := resp.ModelBiasAppSpecification
		appSpec = monitoringAppSpec{
			ImageUri:    s.ImageUri,
			Environment: s.Environment,
		}
	}

	var ji monitoringJobInput
	if resp.ModelBiasJobInput != nil {
		ji.EndpointInput = resp.ModelBiasJobInput.EndpointInput
		ji.BatchTransformInput = resp.ModelBiasJobInput.BatchTransformInput
	}

	baselineConfig, _ := convert.JsonToDict(resp.ModelBiasBaselineConfig)
	stoppingCond, _ := convert.JsonToDict(resp.StoppingCondition)

	sub, err := sagemakerBuildMonitoringJobSubResources(a.MqlRuntime, monitoringJobDefDetails{
		JobDefinitionArn: resp.JobDefinitionArn,
		RoleArn:          resp.RoleArn,
		Region:           a.Region.Data,
		AppSpec:          appSpec,
		JobInput:         ji,
		OutputConfig:     resp.ModelBiasJobOutputConfig,
		Resources:        resp.JobResources,
		NetworkConfig:    resp.NetworkConfig,
		BaselineConfig:   baselineConfig,
		StoppingCond:     stoppingCond,
	})
	if err != nil {
		return nil, err
	}
	a.cacheSub = sub
	a.fetched = true
	return sub, nil
}

func (a *mqlAwsSagemakerModelBiasJobDefinition) appSpecification() (*mqlAwsSagemakerMonitoringJobDefinitionAppSpecification, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.appSpecification, nil
}

func (a *mqlAwsSagemakerModelBiasJobDefinition) baselineConfig() (any, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.baselineConfig, nil
}

func (a *mqlAwsSagemakerModelBiasJobDefinition) jobInput() (*mqlAwsSagemakerMonitoringJobDefinitionJobInput, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobInput, nil
}

func (a *mqlAwsSagemakerModelBiasJobDefinition) jobOutputConfig() (*mqlAwsSagemakerMonitoringJobDefinitionJobOutputConfig, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobOutputConfig, nil
}

func (a *mqlAwsSagemakerModelBiasJobDefinition) jobResources() (*mqlAwsSagemakerMonitoringJobDefinitionJobResources, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobResources, nil
}

func (a *mqlAwsSagemakerModelBiasJobDefinition) networkConfig() (*mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if sub.networkConfig == nil {
		a.NetworkConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return sub.networkConfig, nil
}

func (a *mqlAwsSagemakerModelBiasJobDefinition) iamRole() (*mqlAwsIamRole, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if sub.roleArn == nil || *sub.roleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(sub.roleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerModelBiasJobDefinition) stoppingCondition() (any, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.stoppingCond, nil
}

// ---- Model Explainability Job Definitions ----

func (a *mqlAwsSagemaker) modelExplainabilityJobDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getModelExplainabilityJobDefinitions(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getModelExplainabilityJobDefinitions(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListModelExplainabilityJobDefinitionsPaginator(svc, &sagemaker.ListModelExplainabilityJobDefinitionsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker model explainability job definitions")
						return res, nil
					}
					return nil, err
				}

				for _, item := range page.JobDefinitionSummaries {
					mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerModelExplainabilityJobDefinition,
						map[string]*llx.RawData{
							"arn":       llx.StringDataPtr(item.MonitoringJobDefinitionArn),
							"name":      llx.StringDataPtr(item.MonitoringJobDefinitionName),
							"region":    llx.StringData(region),
							"createdAt": llx.TimeDataPtr(item.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRes)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerModelExplainabilityJobDefinitionInternal struct {
	sagemakerTagsCache
	fetched   bool
	fetchLock sync.Mutex
	cacheSub  *monitoringJobSubResources
}

func (a *mqlAwsSagemakerModelExplainabilityJobDefinition) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerModelExplainabilityJobDefinition) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerModelExplainabilityJobDefinition) fetchDetails() (*monitoringJobSubResources, error) {
	if a.fetched {
		return a.cacheSub, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.cacheSub, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeModelExplainabilityJobDefinition(ctx, &sagemaker.DescribeModelExplainabilityJobDefinitionInput{JobDefinitionName: &name})
	if err != nil {
		return nil, err
	}

	var appSpec monitoringAppSpec
	if resp.ModelExplainabilityAppSpecification != nil {
		s := resp.ModelExplainabilityAppSpecification
		appSpec = monitoringAppSpec{
			ImageUri:    s.ImageUri,
			Environment: s.Environment,
		}
	}

	var ji monitoringJobInput
	if resp.ModelExplainabilityJobInput != nil {
		ji.EndpointInput = resp.ModelExplainabilityJobInput.EndpointInput
		ji.BatchTransformInput = resp.ModelExplainabilityJobInput.BatchTransformInput
	}

	baselineConfig, _ := convert.JsonToDict(resp.ModelExplainabilityBaselineConfig)
	stoppingCond, _ := convert.JsonToDict(resp.StoppingCondition)

	sub, err := sagemakerBuildMonitoringJobSubResources(a.MqlRuntime, monitoringJobDefDetails{
		JobDefinitionArn: resp.JobDefinitionArn,
		RoleArn:          resp.RoleArn,
		Region:           a.Region.Data,
		AppSpec:          appSpec,
		JobInput:         ji,
		OutputConfig:     resp.ModelExplainabilityJobOutputConfig,
		Resources:        resp.JobResources,
		NetworkConfig:    resp.NetworkConfig,
		BaselineConfig:   baselineConfig,
		StoppingCond:     stoppingCond,
	})
	if err != nil {
		return nil, err
	}
	a.cacheSub = sub
	a.fetched = true
	return sub, nil
}

func (a *mqlAwsSagemakerModelExplainabilityJobDefinition) appSpecification() (*mqlAwsSagemakerMonitoringJobDefinitionAppSpecification, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.appSpecification, nil
}

func (a *mqlAwsSagemakerModelExplainabilityJobDefinition) baselineConfig() (any, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.baselineConfig, nil
}

func (a *mqlAwsSagemakerModelExplainabilityJobDefinition) jobInput() (*mqlAwsSagemakerMonitoringJobDefinitionJobInput, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobInput, nil
}

func (a *mqlAwsSagemakerModelExplainabilityJobDefinition) jobOutputConfig() (*mqlAwsSagemakerMonitoringJobDefinitionJobOutputConfig, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobOutputConfig, nil
}

func (a *mqlAwsSagemakerModelExplainabilityJobDefinition) jobResources() (*mqlAwsSagemakerMonitoringJobDefinitionJobResources, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.jobResources, nil
}

func (a *mqlAwsSagemakerModelExplainabilityJobDefinition) networkConfig() (*mqlAwsSagemakerMonitoringJobDefinitionNetworkConfig, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if sub.networkConfig == nil {
		a.NetworkConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return sub.networkConfig, nil
}

func (a *mqlAwsSagemakerModelExplainabilityJobDefinition) iamRole() (*mqlAwsIamRole, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if sub.roleArn == nil || *sub.roleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(sub.roleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerModelExplainabilityJobDefinition) stoppingCondition() (any, error) {
	sub, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sub.stoppingCond, nil
}
