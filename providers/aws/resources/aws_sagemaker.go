// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakerTypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/transport/http"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsSagemaker) id() (string, error) {
	return ResourceAwsSagemaker, nil
}

func (a *mqlAwsSagemaker) endpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEndpoints(conn), 5)
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

func (a *mqlAwsSagemaker) getEndpoints(conn *connection.AwsConnection) []*jobpool.Job {
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

			params := &sagemaker.ListEndpointsInput{}
			paginator := sagemaker.NewListEndpointsPaginator(svc, params)
			for paginator.HasMorePages() {
				endpoints, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, endpoint := range endpoints.Endpoints {
					// Only fetch tags eagerly when tag-based filters are configured
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, endpoint.EndpointArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("endpoint", endpoint.EndpointArn).Msg("skipping sagemaker endpoint due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlEndpoint, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerEndpoint,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(endpoint.EndpointArn),
							"name":           llx.StringDataPtr(endpoint.EndpointName),
							"region":         llx.StringData(region),
							"createdAt":      llx.TimeDataPtr(endpoint.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(endpoint.LastModifiedTime),
							"status":         llx.StringData(string(endpoint.EndpointStatus)),
						})
					if err != nil {
						return nil, err
					}
					ep := mqlEndpoint.(*mqlAwsSagemakerEndpoint)
					if eagerTags != nil {
						ep.cacheTags = eagerTags
						ep.tagsFetched = true
					}
					res = append(res, mqlEndpoint)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// endpointConfig resolves the endpoint's configuration as a typed
// aws.sagemaker.endpointConfig resource, priming its detail cache so downstream
// accessors (production variants, KMS, network isolation, VPC) reuse the
// DescribeEndpointConfig response fetched here.
func (a *mqlAwsSagemakerEndpoint) endpointConfig() (*mqlAwsSagemakerEndpointConfig, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if details.EndpointConfigName == nil || *details.EndpointConfigName == "" {
		a.EndpointConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(region)
	ctx := context.Background()
	cfg, err := svc.DescribeEndpointConfig(ctx, &sagemaker.DescribeEndpointConfigInput{EndpointConfigName: details.EndpointConfigName})
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerEndpointConfig,
		map[string]*llx.RawData{
			"arn":       llx.StringDataPtr(cfg.EndpointConfigArn),
			"name":      llx.StringDataPtr(cfg.EndpointConfigName),
			"region":    llx.StringData(region),
			"createdAt": llx.TimeDataPtr(cfg.CreationTime),
		})
	if err != nil {
		return nil, err
	}
	ec := res.(*mqlAwsSagemakerEndpointConfig)
	ec.cacheDescribe = cfg
	ec.fetched = true
	return ec, nil
}

func (a *mqlAwsSagemaker) notebookInstances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getNotebookInstances(conn), 5)
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

func (a *mqlAwsSagemaker) getNotebookInstances(conn *connection.AwsConnection) []*jobpool.Job {
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

			params := &sagemaker.ListNotebookInstancesInput{}
			paginator := sagemaker.NewListNotebookInstancesPaginator(svc, params)
			for paginator.HasMorePages() {
				notebookInstances, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, instance := range notebookInstances.NotebookInstances {
					// Only fetch tags eagerly when tag-based filters are configured
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, instance.NotebookInstanceArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("notebook", instance.NotebookInstanceArn).Msg("skipping sagemaker notebook instance due to filters")
							continue
						}
						eagerTags = tags
					}

					var additionalRepos []any
					for _, r := range instance.AdditionalCodeRepositories {
						additionalRepos = append(additionalRepos, r)
					}

					mqlNb, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerNotebookinstance,
						map[string]*llx.RawData{
							"arn":                        llx.StringData(convert.ToValue(instance.NotebookInstanceArn)),
							"name":                       llx.StringData(convert.ToValue(instance.NotebookInstanceName)),
							"region":                     llx.StringData(region),
							"createdAt":                  llx.TimeDataPtr(instance.CreationTime),
							"lastModifiedAt":             llx.TimeDataPtr(instance.LastModifiedTime),
							"status":                     llx.StringData(string(instance.NotebookInstanceStatus)),
							"url":                        llx.StringDataPtr(instance.Url),
							"instanceType":               llx.StringData(string(instance.InstanceType)),
							"lifecycleConfigName":        llx.StringDataPtr(instance.NotebookInstanceLifecycleConfigName),
							"defaultCodeRepository":      llx.StringDataPtr(instance.DefaultCodeRepository),
							"additionalCodeRepositories": llx.ArrayData(additionalRepos, types.String),
						})
					if err != nil {
						return nil, err
					}
					nb := mqlNb.(*mqlAwsSagemakerNotebookinstance)
					if eagerTags != nil {
						nb.cacheTags = eagerTags
						nb.tagsFetched = true
					}
					res = append(res, mqlNb)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func initAwsSagemakerNotebookinstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformSagemakerNotebookinstance); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch sagemaker notebookinstance")
	}

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetNotebookInstances()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		ni := rawResource.(*mqlAwsSagemakerNotebookinstance)
		if ni.Arn.Data == arnVal {
			return args, ni, nil
		}
	}
	return nil, nil, errors.New("sagemaker notebookinstance does not exist")
}

func (a *mqlAwsSagemakerNotebookinstance) details() (*mqlAwsSagemakerNotebookinstancedetails, error) {
	name := a.Name.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(region)
	ctx := context.Background()
	instanceDetails, err := svc.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{NotebookInstanceName: &name})
	if err != nil {
		return nil, err
	}
	args := map[string]*llx.RawData{
		"arn":                  llx.StringDataPtr(instanceDetails.NotebookInstanceArn),
		"directInternetAccess": llx.BoolData(string(instanceDetails.DirectInternetAccess) == "Enabled"),
		"rootAccess":           llx.BoolData(string(instanceDetails.RootAccess) == "Enabled"),
	}
	if instanceDetails.InstanceMetadataServiceConfiguration != nil {
		args["minimumInstanceMetadataServiceVersion"] = llx.StringDataPtr(instanceDetails.InstanceMetadataServiceConfiguration.MinimumInstanceMetadataServiceVersion)
	} else {
		args["minimumInstanceMetadataServiceVersion"] = llx.StringData("1")
	}

	mqlInstanceDetails, err := CreateResource(a.MqlRuntime, "aws.sagemaker.notebookinstancedetails", args)
	if err != nil {
		return nil, err
	}
	details := mqlInstanceDetails.(*mqlAwsSagemakerNotebookinstancedetails)
	details.cacheKmsKey = instanceDetails.KmsKeyId
	details.cacheSubnetId = instanceDetails.SubnetId
	details.cacheRoleArn = instanceDetails.RoleArn
	details.cacheSecurityGroups = instanceDetails.SecurityGroups
	details.cacheFailureReason = instanceDetails.FailureReason
	details.cacheIpAddressType = string(instanceDetails.IpAddressType)
	details.cachePlatformId = instanceDetails.PlatformIdentifier
	if instanceDetails.VolumeSizeInGB != nil {
		details.cacheVolumeSizeInGB = int64(*instanceDetails.VolumeSizeInGB)
	}
	details.securityGroupsFilled = true
	details.region = region
	return details, nil
}

type mqlAwsSagemakerNotebookinstancedetailsInternal struct {
	cacheKmsKey          *string
	cacheSubnetId        *string
	cacheRoleArn         *string
	cacheSecurityGroups  []string
	cacheFailureReason   *string
	cacheIpAddressType   string
	cachePlatformId      *string
	cacheVolumeSizeInGB  int64
	region               string
	securityGroupsFilled bool
}

func (a *mqlAwsSagemakerNotebookinstancedetails) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKey != nil && *a.cacheKmsKey != "" {
		mqlKeyResource, err := NewResource(a.MqlRuntime, "aws.kms.key",
			map[string]*llx.RawData{"arn": llx.StringData(convert.ToValue(a.cacheKmsKey))},
		)
		if err != nil {
			return nil, err
		}
		return mqlKeyResource.(*mqlAwsKmsKey), nil
	}
	a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsSagemakerNotebookinstancedetails) subnet() (*mqlAwsVpcSubnet, error) {
	if a.cacheSubnetId != nil && *a.cacheSubnetId != "" {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		arn := fmt.Sprintf(subnetArnPattern, a.region, conn.AccountId(), *a.cacheSubnetId)
		res, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet, map[string]*llx.RawData{"arn": llx.StringData(arn)})
		if err != nil {
			return nil, err
		}
		return res.(*mqlAwsVpcSubnet), nil
	}
	a.Subnet.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsSagemakerNotebookinstancedetails) ipAddressType() (string, error) {
	return a.cacheIpAddressType, nil
}

func (a *mqlAwsSagemakerNotebookinstancedetails) platformIdentifier() (string, error) {
	return convert.ToValue(a.cachePlatformId), nil
}

func (a *mqlAwsSagemakerNotebookinstancedetails) volumeSizeInGB() (int64, error) {
	return a.cacheVolumeSizeInGB, nil
}

func (a *mqlAwsSagemakerNotebookinstancedetails) failureReason() (string, error) {
	return convert.ToValue(a.cacheFailureReason), nil
}

func (a *mqlAwsSagemakerNotebookinstancedetails) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerNotebookinstancedetails) securityGroups() ([]any, error) {
	if len(a.cacheSecurityGroups) == 0 {
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	sgs := make([]any, 0, len(a.cacheSecurityGroups))
	for _, sgId := range a.cacheSecurityGroups {
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

// sagemakerTagsCache provides lazy-loaded tag caching with double-check locking.
// Embed in Internal structs for SageMaker resources that need lazy tags.
type sagemakerTagsCache struct {
	cacheTags   map[string]any
	tagsFetched bool
	tagsLock    sync.Mutex
}

func (c *sagemakerTagsCache) fetchTags(conn *connection.AwsConnection, region, arn string) (map[string]any, error) {
	if c.tagsFetched {
		return c.cacheTags, nil
	}
	c.tagsLock.Lock()
	defer c.tagsLock.Unlock()
	if c.tagsFetched {
		return c.cacheTags, nil
	}

	svc := conn.Sagemaker(region)
	ctx := context.Background()
	tags, err := getSagemakerTags(ctx, svc, &arn)
	if err != nil {
		return nil, err
	}
	c.cacheTags = tags
	c.tagsFetched = true
	return tags, nil
}

type mqlAwsSagemakerEndpointInternal struct {
	sagemakerTagsCache
	fetched       bool
	fetchLock     sync.Mutex
	cacheDescribe *sagemaker.DescribeEndpointOutput
}

func (a *mqlAwsSagemakerEndpoint) fetchDetails() (*sagemaker.DescribeEndpointOutput, error) {
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
	resp, err := svc.DescribeEndpoint(ctx, &sagemaker.DescribeEndpointInput{EndpointName: &name})
	if err != nil {
		return nil, err
	}
	a.cacheDescribe = resp
	a.fetched = true
	return resp, nil
}

func (a *mqlAwsSagemakerEndpoint) endpointConfigName() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.EndpointConfigName), nil
}

func (a *mqlAwsSagemakerEndpoint) productionVariants() ([]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sagemakerBuildProductionVariants(a.MqlRuntime, a.Arn.Data, resp.ProductionVariants, convert.ToValue(resp.EndpointConfigName))
}

func (a *mqlAwsSagemakerEndpoint) shadowProductionVariants() ([]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return sagemakerBuildProductionVariants(a.MqlRuntime, a.Arn.Data+"/shadow", resp.ShadowProductionVariants, convert.ToValue(resp.EndpointConfigName))
}

func (a *mqlAwsSagemakerEndpoint) dataCaptureConfig() (*mqlAwsSagemakerEndpointDataCaptureConfig, error) {
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
	if dcc.CurrentSamplingPercentage != nil {
		samplingPct = int64(*dcc.CurrentSamplingPercentage)
	}
	// Get capture options from the endpoint config
	var captureOptions []any
	configResp, configErr := a.MqlRuntime.Connection.(*connection.AwsConnection).Sagemaker(a.Region.Data).DescribeEndpointConfig(
		context.Background(), &sagemaker.DescribeEndpointConfigInput{EndpointConfigName: resp.EndpointConfigName})
	if configErr == nil && configResp.DataCaptureConfig != nil {
		for _, opt := range configResp.DataCaptureConfig.CaptureOptions {
			captureOptions = append(captureOptions, string(opt.CaptureMode))
		}
	}
	mqlRes, err := CreateResource(a.MqlRuntime, "aws.sagemaker.endpoint.dataCaptureConfig",
		map[string]*llx.RawData{
			"__id":                      llx.StringData(a.Arn.Data + "/dataCaptureConfig"),
			"enableCapture":             llx.BoolDataPtr(dcc.EnableCapture),
			"captureStatus":             llx.StringData(string(dcc.CaptureStatus)),
			"currentSamplingPercentage": llx.IntData(samplingPct),
			"destinationS3Uri":          llx.StringDataPtr(dcc.DestinationS3Uri),
			"captureOptions":            llx.ArrayData(captureOptions, types.String),
		})
	if err != nil {
		return nil, err
	}
	res := mqlRes.(*mqlAwsSagemakerEndpointDataCaptureConfig)
	res.cacheEndpointArn = a.Arn.Data
	res.cacheKmsKeyId = dcc.KmsKeyId
	return res, nil
}

type mqlAwsSagemakerEndpointDataCaptureConfigInternal struct {
	cacheEndpointArn string
	cacheKmsKeyId    *string
}

func (a *mqlAwsSagemakerEndpointDataCaptureConfig) id() (string, error) {
	return a.cacheEndpointArn + "/dataCaptureConfig", nil
}

func (a *mqlAwsSagemakerEndpointDataCaptureConfig) kmsKey() (*mqlAwsKmsKey, error) {
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

type mqlAwsSagemakerEndpointProductionVariantInternal struct {
	cacheParentId                string
	cacheEndpointConfigName      string
	cacheCurrentServerlessConfig any
	cacheDesiredServerlessConfig any
	cacheManagedInstanceScaling  any
	cacheRoutingConfig           any
	cacheVariantStatuses         []any
	configFetched                bool
	configLock                   sync.Mutex
	cacheModelName               string
	cacheInstanceType            string
}

func (a *mqlAwsSagemakerEndpointProductionVariant) id() (string, error) {
	return a.cacheParentId + "/" + a.VariantName.Data, nil
}

func (a *mqlAwsSagemakerEndpointProductionVariant) fetchConfig() error {
	if a.configFetched {
		return nil
	}
	a.configLock.Lock()
	defer a.configLock.Unlock()
	if a.configFetched {
		return nil
	}
	if a.cacheEndpointConfigName == "" {
		a.configFetched = true
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	// Extract region from parent ID (ARN format: arn:aws:sagemaker:REGION:...)
	region := ""
	if parts := strings.SplitN(a.cacheParentId, ":", 5); len(parts) >= 4 {
		region = parts[3]
	}
	if region == "" {
		a.configFetched = true
		return nil
	}
	svc := conn.Sagemaker(region)
	ctx := context.Background()
	resp, err := svc.DescribeEndpointConfig(ctx, &sagemaker.DescribeEndpointConfigInput{
		EndpointConfigName: &a.cacheEndpointConfigName,
	})
	if err != nil {
		a.configFetched = true
		return nil // Gracefully degrade — don't fail the whole resource
	}
	variantName := a.VariantName.Data
	for _, pv := range resp.ProductionVariants {
		if convert.ToValue(pv.VariantName) == variantName {
			a.cacheModelName = convert.ToValue(pv.ModelName)
			a.cacheInstanceType = string(pv.InstanceType)
			break
		}
	}
	a.configFetched = true
	return nil
}

func (a *mqlAwsSagemakerEndpointProductionVariant) modelName() (string, error) {
	if err := a.fetchConfig(); err != nil {
		return "", err
	}
	return a.cacheModelName, nil
}

func (a *mqlAwsSagemakerEndpointProductionVariant) instanceType() (string, error) {
	if err := a.fetchConfig(); err != nil {
		return "", err
	}
	return a.cacheInstanceType, nil
}

func (a *mqlAwsSagemakerEndpointProductionVariant) currentServerlessConfig() (map[string]any, error) {
	if a.cacheCurrentServerlessConfig == nil {
		return nil, nil
	}
	return a.cacheCurrentServerlessConfig.(map[string]any), nil
}

func (a *mqlAwsSagemakerEndpointProductionVariant) desiredServerlessConfig() (map[string]any, error) {
	if a.cacheDesiredServerlessConfig == nil {
		return nil, nil
	}
	return a.cacheDesiredServerlessConfig.(map[string]any), nil
}

func (a *mqlAwsSagemakerEndpointProductionVariant) variantStatuses() ([]any, error) {
	return a.cacheVariantStatuses, nil
}

func (a *mqlAwsSagemakerEndpointProductionVariant) managedInstanceScaling() (map[string]any, error) {
	if a.cacheManagedInstanceScaling == nil {
		return nil, nil
	}
	return a.cacheManagedInstanceScaling.(map[string]any), nil
}

func (a *mqlAwsSagemakerEndpointProductionVariant) routingConfig() (map[string]any, error) {
	if a.cacheRoutingConfig == nil {
		return nil, nil
	}
	return a.cacheRoutingConfig.(map[string]any), nil
}

type mqlAwsSagemakerEndpointProductionVariantStatusInternal struct {
	cacheParentId string
}

func (a *mqlAwsSagemakerEndpointProductionVariantStatus) id() (string, error) {
	return a.cacheParentId + "/status/" + a.Status.Data, nil
}

func sagemakerBuildProductionVariants(runtime *plugin.Runtime, parentId string, variants []sagemakerTypes.ProductionVariantSummary, endpointConfigName string) ([]any, error) {
	res := make([]any, 0, len(variants))
	for _, v := range variants {
		var currentCount, desiredCount int64
		var currentWeight, desiredWeight float64
		if v.CurrentInstanceCount != nil {
			currentCount = int64(*v.CurrentInstanceCount)
		}
		if v.DesiredInstanceCount != nil {
			desiredCount = int64(*v.DesiredInstanceCount)
		}
		if v.CurrentWeight != nil {
			currentWeight = float64(*v.CurrentWeight)
		}
		if v.DesiredWeight != nil {
			desiredWeight = float64(*v.DesiredWeight)
		}

		mqlPV, err := CreateResource(runtime, "aws.sagemaker.endpoint.productionVariant",
			map[string]*llx.RawData{
				"__id":                 llx.StringData(parentId + "/" + convert.ToValue(v.VariantName)),
				"variantName":          llx.StringDataPtr(v.VariantName),
				"currentInstanceCount": llx.IntData(currentCount),
				"desiredInstanceCount": llx.IntData(desiredCount),
				"currentWeight":        llx.FloatData(currentWeight),
				"desiredWeight":        llx.FloatData(desiredWeight),
			})
		if err != nil {
			return nil, err
		}
		pv := mqlPV.(*mqlAwsSagemakerEndpointProductionVariant)
		pv.cacheParentId = parentId
		pv.cacheEndpointConfigName = endpointConfigName
		pv.cacheCurrentServerlessConfig, _ = convert.JsonToDict(v.CurrentServerlessConfig)
		pv.cacheDesiredServerlessConfig, _ = convert.JsonToDict(v.DesiredServerlessConfig)
		pv.cacheManagedInstanceScaling, _ = convert.JsonToDict(v.ManagedInstanceScaling)
		pv.cacheRoutingConfig, _ = convert.JsonToDict(v.RoutingConfig)

		// Build variant statuses
		variantStatuses := make([]any, 0, len(v.VariantStatus))
		variantId := parentId + "/" + convert.ToValue(v.VariantName)
		for _, vs := range v.VariantStatus {
			mqlVS, err := CreateResource(runtime, "aws.sagemaker.endpoint.productionVariant.status",
				map[string]*llx.RawData{
					"__id":          llx.StringData(variantId + "/status/" + string(vs.Status)),
					"status":        llx.StringData(string(vs.Status)),
					"statusMessage": llx.StringDataPtr(vs.StatusMessage),
					"startTime":     llx.TimeDataPtr(vs.StartTime),
				})
			if err != nil {
				return nil, err
			}
			vsRes := mqlVS.(*mqlAwsSagemakerEndpointProductionVariantStatus)
			vsRes.cacheParentId = variantId
			variantStatuses = append(variantStatuses, mqlVS)
		}
		pv.cacheVariantStatuses = variantStatuses
		res = append(res, mqlPV)
	}
	return res, nil
}

func (a *mqlAwsSagemakerEndpoint) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerEndpoint) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsSagemakerNotebookinstanceInternal struct {
	sagemakerTagsCache
}

func (a *mqlAwsSagemakerNotebookinstance) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerNotebookinstance) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerNotebookinstancedetails) id() (string, error) {
	return a.Arn.Data, nil
}

// ---- Models ----

func (a *mqlAwsSagemaker) models() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getModels(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getModels(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListModelsPaginator(svc, &sagemaker.ListModelsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, model := range page.Models {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, model.ModelArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("model", model.ModelArn).Msg("skipping sagemaker model due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlModel, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerModel,
						map[string]*llx.RawData{
							"arn":       llx.StringDataPtr(model.ModelArn),
							"name":      llx.StringDataPtr(model.ModelName),
							"region":    llx.StringData(region),
							"createdAt": llx.TimeDataPtr(model.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					m := mqlModel.(*mqlAwsSagemakerModel)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched = true
					}
					res = append(res, mqlModel)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerModelInternal struct {
	sagemakerTagsCache
	detailsFetched              bool
	detailsLock                 sync.Mutex
	cacheRoleArn                *string
	cacheEnableNetworkIsolation bool
	cachePrimaryContainer       any
	cachePrimaryContainerDef    *sagemakerTypes.ContainerDefinition
	cacheVpcConfig              any
	cacheVpcSubnetIds           []string
	cacheVpcSecurityGroupIds    []string
	cacheContainers             []sagemakerTypes.ContainerDefinition
	cacheInferExecConfig        any
}

func (a *mqlAwsSagemakerModel) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerModel) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerModel) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeModel(ctx, &sagemaker.DescribeModelInput{ModelName: &name})
	if err != nil {
		return err
	}

	a.cacheRoleArn = resp.ExecutionRoleArn
	if resp.EnableNetworkIsolation != nil {
		a.cacheEnableNetworkIsolation = *resp.EnableNetworkIsolation
	}
	a.cachePrimaryContainer, _ = convert.JsonToDict(resp.PrimaryContainer)
	a.cachePrimaryContainerDef = resp.PrimaryContainer
	a.cacheVpcConfig, _ = convert.JsonToDict(resp.VpcConfig)
	if resp.VpcConfig != nil {
		a.cacheVpcSubnetIds = resp.VpcConfig.Subnets
		a.cacheVpcSecurityGroupIds = resp.VpcConfig.SecurityGroupIds
	}
	a.cacheContainers = resp.Containers
	a.cacheInferExecConfig, _ = convert.JsonToDict(resp.InferenceExecutionConfig)
	a.detailsFetched = true
	return nil
}

// buildContainer maps a SageMaker ContainerDefinition to the typed
// aws.sagemaker.model.container resource. Shared by containers() (inference
// pipeline) and primaryContainerRef() (the primary serving container).
func (a *mqlAwsSagemakerModel) buildContainer(c sagemakerTypes.ContainerDefinition) (*mqlAwsSagemakerModelContainer, error) {
	env := make(map[string]any, len(c.Environment))
	for k, v := range c.Environment {
		env[k] = v
	}
	mqlC, err := CreateResource(a.MqlRuntime, "aws.sagemaker.model.container",
		map[string]*llx.RawData{
			"__id": llx.StringData(sagemakerModelContainerID(
				a.Arn.Data, convert.ToValue(c.ContainerHostname), convert.ToValue(c.Image))),
			"containerHostname": llx.StringDataPtr(c.ContainerHostname),
			"image":             llx.StringDataPtr(c.Image),
			"modelDataUrl":      llx.StringDataPtr(c.ModelDataUrl),
			"mode":              llx.StringData(string(c.Mode)),
			"environment":       llx.MapData(env, types.String),
		})
	if err != nil {
		return nil, err
	}
	container := mqlC.(*mqlAwsSagemakerModelContainer)
	container.cacheModelArn = a.Arn.Data
	container.cacheImageConfig = c.ImageConfig
	container.cacheMultiModelConfig = c.MultiModelConfig
	return container, nil
}

func (a *mqlAwsSagemakerModel) containers() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	res := make([]any, 0, len(a.cacheContainers))
	for _, c := range a.cacheContainers {
		container, err := a.buildContainer(c)
		if err != nil {
			return nil, err
		}
		res = append(res, container)
	}
	return res, nil
}

func (a *mqlAwsSagemakerModel) primaryContainerRef() (*mqlAwsSagemakerModelContainer, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cachePrimaryContainerDef == nil {
		a.PrimaryContainerRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return a.buildContainer(*a.cachePrimaryContainerDef)
}

func (a *mqlAwsSagemakerModel) securityGroups() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return sagemakerSecurityGroups(a.MqlRuntime, a.Region.Data, a.cacheVpcSecurityGroupIds)
}

func (a *mqlAwsSagemakerModel) inferenceExecutionConfig() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheInferExecConfig == nil {
		return nil, nil
	}
	return a.cacheInferExecConfig.(map[string]any), nil
}

type mqlAwsSagemakerModelContainerInternal struct {
	cacheModelArn         string
	cacheImageConfig      any
	cacheMultiModelConfig any
}

// sagemakerModelContainerID builds the parent-qualified cache key for a model
// container. The model ARN is required: ContainerHostname is "ignored for
// models that contain only a PrimaryContainer", so it is empty for most models
// and the key falls back to the image -- which every model sharing a base
// inference image has in common. Without the ARN prefix those models all
// collide and each one returns the first model's container.
func sagemakerModelContainerID(modelArn, containerHostname, image string) string {
	hostname := containerHostname
	if hostname == "" {
		hostname = image
	}
	return modelArn + "/container/" + hostname
}

func (a *mqlAwsSagemakerModelContainer) id() (string, error) {
	// cacheModelArn is assigned after CreateResource returns, so it is empty
	// while the generated constructor runs. buildContainer therefore passes an
	// explicit "__id" (which wins over this method); this remains only as the
	// codegen-required fallback.
	return sagemakerModelContainerID(a.cacheModelArn, a.ContainerHostname.Data, a.Image.Data), nil
}

func (a *mqlAwsSagemakerModelContainer) imageConfig() (map[string]any, error) {
	if a.cacheImageConfig == nil {
		return nil, nil
	}
	return convert.JsonToDict(a.cacheImageConfig)
}

func (a *mqlAwsSagemakerModelContainer) multiModelConfig() (map[string]any, error) {
	if a.cacheMultiModelConfig == nil {
		return nil, nil
	}
	return convert.JsonToDict(a.cacheMultiModelConfig)
}

func (a *mqlAwsSagemakerModelContainer) modelDataBucket() (*mqlAwsS3Bucket, error) {
	return s3BucketRefFromUri(a.MqlRuntime, a.ModelDataUrl.Data, &a.ModelDataBucket)
}

// ecrRepository resolves the repository the container's serving image is pulled
// from. Inference images are frequently served from a public registry or a
// SageMaker-owned account, in which case the URI names no repository we can
// resolve and the reference stays null.
func (a *mqlAwsSagemakerModelContainer) ecrRepository() (*mqlAwsEcrRepository, error) {
	repoArn := ecrRepositoryArnFromImageUri(a.Image.Data)
	if repoArn == "" {
		a.EcrRepository.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ecr.repository",
		map[string]*llx.RawData{"arn": llx.StringData(repoArn)})
	if err != nil {
		// A cross-account or deleted repository surfaces as a lookup error; log it
		// so genuine permission failures stay visible, but leave the reference null
		// rather than failing the whole query.
		log.Warn().Err(err).Str("arn", repoArn).Msg("could not resolve ECR repository for sagemaker model container")
		a.EcrRepository.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsEcrRepository), nil
}

func (a *mqlAwsSagemakerModel) enableNetworkIsolation() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.cacheEnableNetworkIsolation, nil
}

func (a *mqlAwsSagemakerModel) iamRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerModel) vpc() (*mqlAwsVpc, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return sagemakerResolveVpc(a.MqlRuntime, a.Region.Data, a.cacheVpcSubnetIds, &a.Vpc)
}

// ---- Training Jobs ----

func (a *mqlAwsSagemaker) trainingJobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTrainingJobs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getTrainingJobs(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListTrainingJobsPaginator(svc, &sagemaker.ListTrainingJobsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, job := range page.TrainingJobSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, job.TrainingJobArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("trainingjob", job.TrainingJobArn).Msg("skipping sagemaker training job due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlJob, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerTrainingjob,
						map[string]*llx.RawData{
							"arn":             llx.StringDataPtr(job.TrainingJobArn),
							"name":            llx.StringDataPtr(job.TrainingJobName),
							"region":          llx.StringData(region),
							"status":          llx.StringData(string(job.TrainingJobStatus)),
							"createdAt":       llx.TimeDataPtr(job.CreationTime),
							"lastModifiedAt":  llx.TimeDataPtr(job.LastModifiedTime),
							"trainingEndTime": llx.TimeDataPtr(job.TrainingEndTime),
						})
					if err != nil {
						return nil, err
					}
					tj := mqlJob.(*mqlAwsSagemakerTrainingjob)
					if eagerTags != nil {
						tj.cacheTags = eagerTags
						tj.tagsFetched = true
					}
					res = append(res, mqlJob)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerTrainingjobInternal struct {
	sagemakerTagsCache
	detailsFetched                   bool
	detailsLock                      sync.Mutex
	cacheRoleArn                     *string
	cacheAlgorithmSpec               any
	cacheHyperParams                 map[string]string
	cacheEnableNetworkIsolation      bool
	cacheEnableInterContainerEncrypt bool
	cacheFailureReason               *string
	cacheBillableTime                int64
	cacheVpcConfig                   any
	cacheVpcSubnetIds                []string
	cacheOutputDataConfig            any
	cacheOutputS3Uri                 string
	cacheOutputKmsKeyId              string
	cacheResourceConfig              any
	cacheStoppingCondition           any
	cacheSecondaryStatusTransitions  []sagemakerTypes.SecondaryStatusTransition
	cacheFinalMetrics                []sagemakerTypes.MetricData
	cacheCheckpointConfig            any
	cacheWallClockTime               int64
	cacheInputDataConfig             []sagemakerTypes.Channel
	cacheModelArtifactsUrl           string
	cacheTuningJobArn                string
	cacheAutoMLJobArn                string
	cacheLabelingJobArn              string
	cacheTrainingStartTime           *time.Time
}

func (a *mqlAwsSagemakerTrainingjob) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerTrainingjob) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerTrainingjob) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeTrainingJob(ctx, &sagemaker.DescribeTrainingJobInput{TrainingJobName: &name})
	if err != nil {
		return err
	}

	a.cacheRoleArn = resp.RoleArn
	a.cacheAlgorithmSpec, _ = convert.JsonToDict(resp.AlgorithmSpecification)
	a.cacheHyperParams = resp.HyperParameters
	if resp.EnableNetworkIsolation != nil {
		a.cacheEnableNetworkIsolation = *resp.EnableNetworkIsolation
	}
	if resp.EnableInterContainerTrafficEncryption != nil {
		a.cacheEnableInterContainerEncrypt = *resp.EnableInterContainerTrafficEncryption
	}
	a.cacheFailureReason = resp.FailureReason
	if resp.BillableTimeInSeconds != nil {
		a.cacheBillableTime = int64(*resp.BillableTimeInSeconds)
	}
	a.cacheVpcConfig, _ = convert.JsonToDict(resp.VpcConfig)
	if resp.VpcConfig != nil {
		a.cacheVpcSubnetIds = resp.VpcConfig.Subnets
	}
	a.cacheOutputDataConfig, _ = convert.JsonToDict(resp.OutputDataConfig)
	if resp.OutputDataConfig != nil {
		a.cacheOutputS3Uri = convert.ToValue(resp.OutputDataConfig.S3OutputPath)
		a.cacheOutputKmsKeyId = convert.ToValue(resp.OutputDataConfig.KmsKeyId)
	}
	a.cacheResourceConfig, _ = convert.JsonToDict(resp.ResourceConfig)
	a.cacheStoppingCondition, _ = convert.JsonToDict(resp.StoppingCondition)
	a.cacheSecondaryStatusTransitions = resp.SecondaryStatusTransitions
	a.cacheFinalMetrics = resp.FinalMetricDataList
	a.cacheCheckpointConfig, _ = convert.JsonToDict(resp.CheckpointConfig)
	if resp.TrainingTimeInSeconds != nil {
		a.cacheWallClockTime = int64(*resp.TrainingTimeInSeconds)
	}
	a.cacheInputDataConfig = resp.InputDataConfig
	if resp.ModelArtifacts != nil {
		a.cacheModelArtifactsUrl = convert.ToValue(resp.ModelArtifacts.S3ModelArtifacts)
	}
	a.cacheTuningJobArn = convert.ToValue(resp.TuningJobArn)
	a.cacheAutoMLJobArn = convert.ToValue(resp.AutoMLJobArn)
	a.cacheLabelingJobArn = convert.ToValue(resp.LabelingJobArn)
	a.cacheTrainingStartTime = resp.TrainingStartTime
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerTrainingjob) inputDataConfig() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	res := make([]any, 0, len(a.cacheInputDataConfig))
	for _, ch := range a.cacheInputDataConfig {
		var s3Uri, s3DataType, s3Dist, fsId string
		if ch.DataSource != nil {
			if ch.DataSource.S3DataSource != nil {
				s3Uri = convert.ToValue(ch.DataSource.S3DataSource.S3Uri)
				s3DataType = string(ch.DataSource.S3DataSource.S3DataType)
				s3Dist = string(ch.DataSource.S3DataSource.S3DataDistributionType)
			}
			if ch.DataSource.FileSystemDataSource != nil {
				fsId = convert.ToValue(ch.DataSource.FileSystemDataSource.FileSystemId)
			}
		}
		mqlCh, err := CreateResource(a.MqlRuntime, "aws.sagemaker.trainingjob.channel",
			map[string]*llx.RawData{
				"__id":                   llx.StringData(a.Arn.Data + "/channel/" + convert.ToValue(ch.ChannelName)),
				"channelName":            llx.StringDataPtr(ch.ChannelName),
				"s3Uri":                  llx.StringData(s3Uri),
				"s3DataType":             llx.StringData(s3DataType),
				"s3DataDistributionType": llx.StringData(s3Dist),
				"fileSystemId":           llx.StringData(fsId),
				"contentType":            llx.StringDataPtr(ch.ContentType),
				"compressionType":        llx.StringData(string(ch.CompressionType)),
				"recordWrapperType":      llx.StringData(string(ch.RecordWrapperType)),
				"inputMode":              llx.StringData(string(ch.InputMode)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCh)
	}
	return res, nil
}

func (a *mqlAwsSagemakerTrainingjob) modelArtifactsUrl() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheModelArtifactsUrl, nil
}

func (a *mqlAwsSagemakerTrainingjob) tuningJobArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheTuningJobArn, nil
}

func (a *mqlAwsSagemakerTrainingjob) autoMLJobArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheAutoMLJobArn, nil
}

func (a *mqlAwsSagemakerTrainingjob) labelingJobArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheLabelingJobArn, nil
}

func (a *mqlAwsSagemakerTrainingjob) trainingStartTime() (*time.Time, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheTrainingStartTime, nil
}

func (a *mqlAwsSagemakerTrainingjob) secondaryStatusTransitions() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	res := make([]any, 0, len(a.cacheSecondaryStatusTransitions))
	for i, t := range a.cacheSecondaryStatusTransitions {
		mqlT, err := CreateResource(a.MqlRuntime, "aws.sagemaker.trainingjob.statusTransition",
			map[string]*llx.RawData{
				"__id":          llx.StringData(fmt.Sprintf("%s/statusTransition/%d/%s", a.Arn.Data, i, string(t.Status))),
				"status":        llx.StringData(string(t.Status)),
				"startTime":     llx.TimeDataPtr(t.StartTime),
				"endTime":       llx.TimeDataPtr(t.EndTime),
				"statusMessage": llx.StringDataPtr(t.StatusMessage),
			})
		if err != nil {
			return nil, err
		}
		st := mqlT.(*mqlAwsSagemakerTrainingjobStatusTransition)
		st.cacheParentArn = a.Arn.Data
		res = append(res, mqlT)
	}
	return res, nil
}

func (a *mqlAwsSagemakerTrainingjob) finalMetrics() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	res := make([]any, 0, len(a.cacheFinalMetrics))
	for i, m := range a.cacheFinalMetrics {
		var value float64
		if m.Value != nil {
			value = float64(*m.Value)
		}
		mqlM, err := CreateResource(a.MqlRuntime, "aws.sagemaker.trainingjob.metricData",
			map[string]*llx.RawData{
				"__id":       llx.StringData(fmt.Sprintf("%s/metric/%d/%s", a.Arn.Data, i, convert.ToValue(m.MetricName))),
				"metricName": llx.StringDataPtr(m.MetricName),
				"value":      llx.FloatData(value),
				"timestamp":  llx.TimeDataPtr(m.Timestamp),
			})
		if err != nil {
			return nil, err
		}
		md := mqlM.(*mqlAwsSagemakerTrainingjobMetricData)
		md.cacheParentArn = a.Arn.Data
		res = append(res, mqlM)
	}
	return res, nil
}

func (a *mqlAwsSagemakerTrainingjob) checkpointConfig() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheCheckpointConfig == nil {
		return nil, nil
	}
	return a.cacheCheckpointConfig.(map[string]any), nil
}

func (a *mqlAwsSagemakerTrainingjob) wallClockTimeInSeconds() (int64, error) {
	if err := a.fetchDetails(); err != nil {
		return 0, err
	}
	return a.cacheWallClockTime, nil
}

type mqlAwsSagemakerTrainingjobStatusTransitionInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerTrainingjobStatusTransition) id() (string, error) {
	return a.cacheParentArn + "/statusTransition/" + a.Status.Data + "/" + a.StartTime.Data.String(), nil
}

type mqlAwsSagemakerTrainingjobMetricDataInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerTrainingjobMetricData) id() (string, error) {
	return a.cacheParentArn + "/metric/" + a.MetricName.Data + "/" + a.Timestamp.Data.String(), nil
}

func (a *mqlAwsSagemakerTrainingjob) iamRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerTrainingjob) algorithmSpecification() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheAlgorithmSpec == nil {
		return nil, nil
	}
	return a.cacheAlgorithmSpec.(map[string]any), nil
}

func (a *mqlAwsSagemakerTrainingjob) hyperParameters() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheHyperParams == nil {
		return nil, nil
	}
	result := make(map[string]any, len(a.cacheHyperParams))
	for k, v := range a.cacheHyperParams {
		result[k] = v
	}
	return result, nil
}

func (a *mqlAwsSagemakerTrainingjob) enableNetworkIsolation() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.cacheEnableNetworkIsolation, nil
}

func (a *mqlAwsSagemakerTrainingjob) enableInterContainerTrafficEncryption() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.cacheEnableInterContainerEncrypt, nil
}

func (a *mqlAwsSagemakerTrainingjob) failureReason() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheFailureReason), nil
}

func (a *mqlAwsSagemakerTrainingjob) billableTimeInSeconds() (int64, error) {
	if err := a.fetchDetails(); err != nil {
		return 0, err
	}
	return a.cacheBillableTime, nil
}

func (a *mqlAwsSagemakerTrainingjob) vpc() (*mqlAwsVpc, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return sagemakerResolveVpc(a.MqlRuntime, a.Region.Data, a.cacheVpcSubnetIds, &a.Vpc)
}

func (a *mqlAwsSagemakerTrainingjob) outputDataConfig() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheOutputDataConfig == nil {
		return nil, nil
	}
	return a.cacheOutputDataConfig.(map[string]any), nil
}

func (a *mqlAwsSagemakerTrainingjob) outputDataBucket() (*mqlAwsS3Bucket, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return s3BucketRefFromUri(a.MqlRuntime, a.cacheOutputS3Uri, &a.OutputDataBucket)
}

func (a *mqlAwsSagemakerTrainingjob) outputKmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return sagemakerKmsKey(a.MqlRuntime, &a.OutputKmsKey, &a.cacheOutputKmsKeyId)
}

func (a *mqlAwsSagemakerTrainingjobChannel) bucket() (*mqlAwsS3Bucket, error) {
	return s3BucketRefFromUri(a.MqlRuntime, a.S3Uri.Data, &a.Bucket)
}

func (a *mqlAwsSagemakerTrainingjob) resourceConfig() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheResourceConfig == nil {
		return nil, nil
	}
	return a.cacheResourceConfig.(map[string]any), nil
}

func (a *mqlAwsSagemakerTrainingjob) stoppingCondition() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheStoppingCondition == nil {
		return nil, nil
	}
	return a.cacheStoppingCondition.(map[string]any), nil
}

// ---- Processing Jobs ----

func (a *mqlAwsSagemaker) processingJobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getProcessingJobs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getProcessingJobs(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListProcessingJobsPaginator(svc, &sagemaker.ListProcessingJobsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, job := range page.ProcessingJobSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, job.ProcessingJobArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("processingjob", job.ProcessingJobArn).Msg("skipping sagemaker processing job due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlJob, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerProcessingjob,
						map[string]*llx.RawData{
							"arn":               llx.StringDataPtr(job.ProcessingJobArn),
							"name":              llx.StringDataPtr(job.ProcessingJobName),
							"region":            llx.StringData(region),
							"status":            llx.StringData(string(job.ProcessingJobStatus)),
							"createdAt":         llx.TimeDataPtr(job.CreationTime),
							"lastModifiedAt":    llx.TimeDataPtr(job.LastModifiedTime),
							"processingEndTime": llx.TimeDataPtr(job.ProcessingEndTime),
							"failureReason":     llx.StringDataPtr(job.FailureReason),
							"exitMessage":       llx.StringDataPtr(job.ExitMessage),
						})
					if err != nil {
						return nil, err
					}
					pj := mqlJob.(*mqlAwsSagemakerProcessingjob)
					if eagerTags != nil {
						pj.cacheTags = eagerTags
						pj.tagsFetched = true
					}
					res = append(res, mqlJob)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerProcessingjobInternal struct {
	sagemakerTagsCache
	detailsFetched                   bool
	detailsLock                      sync.Mutex
	cacheRoleArn                     *string
	cacheEnableNetworkIsolation      bool
	cacheEnableInterContainerEncrypt bool
	cacheVpcConfig                   any
	cacheVpcSubnetIds                []string
	cacheProcessingResources         any
	cacheEnvironment                 map[string]string
	cacheProcessingInputs            []any
	cacheImageUri                    string
	cacheTrainingJobArn              string
	cacheAutoMLJobArn                string
	cacheMonitoringScheduleArn       string
	cacheProcessingStartTime         *time.Time
}

func (a *mqlAwsSagemakerProcessingjob) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerProcessingjob) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerProcessingjob) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeProcessingJob(ctx, &sagemaker.DescribeProcessingJobInput{ProcessingJobName: &name})
	if err != nil {
		return err
	}

	a.cacheRoleArn = resp.RoleArn
	if resp.NetworkConfig != nil {
		if resp.NetworkConfig.EnableNetworkIsolation != nil {
			a.cacheEnableNetworkIsolation = *resp.NetworkConfig.EnableNetworkIsolation
		}
		if resp.NetworkConfig.EnableInterContainerTrafficEncryption != nil {
			a.cacheEnableInterContainerEncrypt = *resp.NetworkConfig.EnableInterContainerTrafficEncryption
		}
		a.cacheVpcConfig, _ = convert.JsonToDict(resp.NetworkConfig.VpcConfig)
		if resp.NetworkConfig.VpcConfig != nil {
			a.cacheVpcSubnetIds = resp.NetworkConfig.VpcConfig.Subnets
		}
	}
	a.cacheProcessingResources, _ = convert.JsonToDict(resp.ProcessingResources)
	a.cacheEnvironment = resp.Environment
	a.cacheProcessingInputs, _ = convert.JsonToDictSlice(resp.ProcessingInputs)
	if resp.AppSpecification != nil {
		a.cacheImageUri = convert.ToValue(resp.AppSpecification.ImageUri)
	}
	a.cacheTrainingJobArn = convert.ToValue(resp.TrainingJobArn)
	a.cacheAutoMLJobArn = convert.ToValue(resp.AutoMLJobArn)
	a.cacheMonitoringScheduleArn = convert.ToValue(resp.MonitoringScheduleArn)
	a.cacheProcessingStartTime = resp.ProcessingStartTime
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerProcessingjob) processingInputs() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheProcessingInputs, nil
}

func (a *mqlAwsSagemakerProcessingjob) imageUri() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheImageUri, nil
}

func (a *mqlAwsSagemakerProcessingjob) trainingJob() (*mqlAwsSagemakerTrainingjob, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheTrainingJobArn == "" {
		a.TrainingJob.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.trainingjob",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheTrainingJobArn)})
	if err != nil {
		// The source training job is commonly deleted while the processing job
		// remains (not-found), or unreadable due to permissions. Treat only
		// those as a null reference; propagate anything else (transient network
		// errors, throttling) so genuine failures aren't hidden.
		var notFound *sagemakerTypes.ResourceNotFound
		if errors.As(err, &notFound) || Is400AccessDeniedError(err) {
			log.Warn().Err(err).Str("trainingJobArn", a.cacheTrainingJobArn).Msg("could not resolve source training job for processing job")
			a.TrainingJob.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlAwsSagemakerTrainingjob), nil
}

func (a *mqlAwsSagemakerProcessingjob) autoMLJobArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheAutoMLJobArn, nil
}

func (a *mqlAwsSagemakerProcessingjob) monitoringScheduleArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheMonitoringScheduleArn, nil
}

func (a *mqlAwsSagemakerProcessingjob) processingStartTime() (*time.Time, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheProcessingStartTime, nil
}

func (a *mqlAwsSagemakerProcessingjob) iamRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerProcessingjob) enableNetworkIsolation() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.cacheEnableNetworkIsolation, nil
}

func (a *mqlAwsSagemakerProcessingjob) enableInterContainerTrafficEncryption() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.cacheEnableInterContainerEncrypt, nil
}

func (a *mqlAwsSagemakerProcessingjob) vpc() (*mqlAwsVpc, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return sagemakerResolveVpc(a.MqlRuntime, a.Region.Data, a.cacheVpcSubnetIds, &a.Vpc)
}

func (a *mqlAwsSagemakerProcessingjob) processingResources() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheProcessingResources == nil {
		return nil, nil
	}
	return a.cacheProcessingResources.(map[string]any), nil
}

func (a *mqlAwsSagemakerProcessingjob) environment() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheEnvironment == nil {
		return nil, nil
	}
	result := make(map[string]any, len(a.cacheEnvironment))
	for k, v := range a.cacheEnvironment {
		result[k] = v
	}
	return result, nil
}

// ---- Pipelines ----

func (a *mqlAwsSagemaker) pipelines() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getPipelines(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getPipelines(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListPipelinesPaginator(svc, &sagemaker.ListPipelinesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, pipeline := range page.PipelineSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, pipeline.PipelineArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("pipeline", pipeline.PipelineArn).Msg("skipping sagemaker pipeline due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlPipeline, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerPipeline,
						map[string]*llx.RawData{
							"arn":               llx.StringDataPtr(pipeline.PipelineArn),
							"name":              llx.StringDataPtr(pipeline.PipelineName),
							"displayName":       llx.StringDataPtr(pipeline.PipelineDisplayName),
							"description":       llx.StringDataPtr(pipeline.PipelineDescription),
							"region":            llx.StringData(region),
							"createdAt":         llx.TimeDataPtr(pipeline.CreationTime),
							"lastModifiedAt":    llx.TimeDataPtr(pipeline.LastModifiedTime),
							"lastExecutionTime": llx.TimeDataPtr(pipeline.LastExecutionTime),
						})
					if err != nil {
						return nil, err
					}
					p := mqlPipeline.(*mqlAwsSagemakerPipeline)
					p.cacheRoleArn = pipeline.RoleArn
					if eagerTags != nil {
						p.cacheTags = eagerTags
						p.tagsFetched = true
					}
					res = append(res, mqlPipeline)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerPipelineInternal struct {
	sagemakerTagsCache
	detailsFetched         bool
	detailsLock            sync.Mutex
	cacheRoleArn           *string
	cachePipelineStatus    *string
	cacheDefinition        *string
	cacheParallelismConfig any
}

func (a *mqlAwsSagemakerPipeline) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerPipeline) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerPipeline) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribePipeline(ctx, &sagemaker.DescribePipelineInput{PipelineName: &name})
	if err != nil {
		return err
	}

	a.cacheRoleArn = resp.RoleArn
	status := string(resp.PipelineStatus)
	a.cachePipelineStatus = &status
	a.cacheDefinition = resp.PipelineDefinition
	a.cacheParallelismConfig, _ = convert.JsonToDict(resp.ParallelismConfiguration)
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerPipeline) iamRole() (*mqlAwsIamRole, error) {
	// RoleArn is eagerly cached from the list summary; fall back to fetchDetails
	if a.cacheRoleArn == nil {
		if err := a.fetchDetails(); err != nil {
			return nil, err
		}
	}
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerPipeline) pipelineStatus() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cachePipelineStatus), nil
}

func (a *mqlAwsSagemakerPipeline) definition() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheDefinition), nil
}

func (a *mqlAwsSagemakerPipeline) parallelismConfiguration() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheParallelismConfig == nil {
		return nil, nil
	}
	return a.cacheParallelismConfig.(map[string]any), nil
}

// ---- Domains ----

func (a *mqlAwsSagemaker) domains() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDomains(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getDomains(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListDomainsPaginator(svc, &sagemaker.ListDomainsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, domain := range page.Domains {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, domain.DomainArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("domain", domain.DomainArn).Msg("skipping sagemaker domain due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlDomain, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerDomain,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(domain.DomainArn),
							"domainId":       llx.StringDataPtr(domain.DomainId),
							"name":           llx.StringDataPtr(domain.DomainName),
							"region":         llx.StringData(region),
							"status":         llx.StringData(string(domain.Status)),
							"url":            llx.StringDataPtr(domain.Url),
							"createdAt":      llx.TimeDataPtr(domain.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(domain.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					d := mqlDomain.(*mqlAwsSagemakerDomain)
					if eagerTags != nil {
						d.cacheTags = eagerTags
						d.tagsFetched = true
					}
					res = append(res, mqlDomain)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func initAwsSagemakerDomain(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformSagemakerDomain); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch sagemaker domain")
	}

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetDomains()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		d := rawResource.(*mqlAwsSagemakerDomain)
		if d.Arn.Data == arnVal {
			return args, d, nil
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.domain with arn %q not found", arnVal)
}

type mqlAwsSagemakerDomainInternal struct {
	sagemakerTagsCache
	detailsFetched            bool
	detailsLock               sync.Mutex
	cacheAuthMode             *string
	cacheAppNetworkAccess     *string
	cacheVpcId                *string
	cacheKmsKeyId             *string
	cacheHomeEfsId            *string
	cacheDefaultUserSettings  any
	cacheDefaultExecutionRole *string
	cacheExecRoleSessionMode  string
	cacheSGForBoundary        *string
	cacheAppSGMgmt            string
	cacheTagPropagation       string
	cacheSSOAppArn            *string
	cacheFailureReason        *string
	cacheSubnetIds            []string

	cacheDockerAccessEnabled       bool
	cacheRootlessDocker            bool
	cacheDockerVpcOnlyTrusted      []string
	cacheExecRoleIdentityConfig    string
	cacheDomainSecurityGroups      []string
	cacheRStudioExecRole           *string
	cacheAmazonQStatus             string
	cacheAmazonQProfileArn         *string
	cacheDefaultUserSecurityGroups []string
	cacheDefaultUserSharedKms      *string
	cacheDefaultSpaceExecRole      *string
	cacheDefaultSpaceSecurityGrps  []string
}

func (a *mqlAwsSagemakerDomain) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerDomain) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerDomain) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	domainId := a.DomainId.Data
	resp, err := svc.DescribeDomain(ctx, &sagemaker.DescribeDomainInput{DomainId: &domainId})
	if err != nil {
		return err
	}

	authMode := string(resp.AuthMode)
	a.cacheAuthMode = &authMode
	appNetworkAccess := string(resp.AppNetworkAccessType)
	a.cacheAppNetworkAccess = &appNetworkAccess
	a.cacheVpcId = resp.VpcId
	a.cacheKmsKeyId = resp.KmsKeyId
	a.cacheHomeEfsId = resp.HomeEfsFileSystemId
	a.cacheDefaultUserSettings, _ = convert.JsonToDict(resp.DefaultUserSettings)
	if resp.DefaultUserSettings != nil {
		a.cacheDefaultExecutionRole = resp.DefaultUserSettings.ExecutionRole
		if resp.DefaultUserSettings.StudioWebPortalSettings != nil {
			a.cacheExecRoleSessionMode = string(resp.DefaultUserSettings.StudioWebPortalSettings.ExecutionRoleSessionNameMode)
		}
	}
	a.cacheSGForBoundary = resp.SecurityGroupIdForDomainBoundary
	a.cacheAppSGMgmt = string(resp.AppSecurityGroupManagement)
	a.cacheTagPropagation = string(resp.TagPropagation)
	a.cacheSSOAppArn = resp.SingleSignOnApplicationArn
	a.cacheFailureReason = resp.FailureReason
	a.cacheSubnetIds = resp.SubnetIds

	if ds := resp.DomainSettings; ds != nil {
		if ds.DockerSettings != nil {
			a.cacheDockerAccessEnabled = ds.DockerSettings.EnableDockerAccess == sagemakerTypes.FeatureStatusEnabled
			a.cacheRootlessDocker = ds.DockerSettings.RootlessDocker == sagemakerTypes.FeatureStatusEnabled
			a.cacheDockerVpcOnlyTrusted = ds.DockerSettings.VpcOnlyTrustedAccounts
		}
		a.cacheExecRoleIdentityConfig = string(ds.ExecutionRoleIdentityConfig)
		a.cacheDomainSecurityGroups = ds.SecurityGroupIds
		if ds.RStudioServerProDomainSettings != nil {
			a.cacheRStudioExecRole = ds.RStudioServerProDomainSettings.DomainExecutionRoleArn
		}
		if ds.AmazonQSettings != nil {
			a.cacheAmazonQStatus = string(ds.AmazonQSettings.Status)
			a.cacheAmazonQProfileArn = ds.AmazonQSettings.QProfileArn
		}
	}
	if us := resp.DefaultUserSettings; us != nil {
		a.cacheDefaultUserSecurityGroups = us.SecurityGroups
		if us.SharingSettings != nil {
			a.cacheDefaultUserSharedKms = us.SharingSettings.S3KmsKeyId
		}
	}
	if ss := resp.DefaultSpaceSettings; ss != nil {
		a.cacheDefaultSpaceExecRole = ss.ExecutionRole
		a.cacheDefaultSpaceSecurityGrps = ss.SecurityGroups
	}

	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerDomain) authMode() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheAuthMode), nil
}

func (a *mqlAwsSagemakerDomain) appNetworkAccessType() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheAppNetworkAccess), nil
}

func (a *mqlAwsSagemakerDomain) vpc() (*mqlAwsVpc, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.vpc",
		map[string]*llx.RawData{"id": llx.StringDataPtr(a.cacheVpcId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsSagemakerDomain) kmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSagemakerDomain) homeEfsFileSystemId() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheHomeEfsId), nil
}

func (a *mqlAwsSagemakerDomain) defaultUserSettings() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDefaultUserSettings == nil {
		return nil, nil
	}
	return a.cacheDefaultUserSettings.(map[string]any), nil
}

func (a *mqlAwsSagemakerDomain) securityGroupForDomainBoundary() (*mqlAwsEc2Securitygroup, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheSGForBoundary == nil || *a.cacheSGForBoundary == "" {
		a.SecurityGroupForDomainBoundary.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	sgArn := NewSecurityGroupArn(a.Region.Data, conn.AccountId(), *a.cacheSGForBoundary)
	res, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup",
		map[string]*llx.RawData{"arn": llx.StringData(sgArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Securitygroup), nil
}

func (a *mqlAwsSagemakerDomain) appSecurityGroupManagement() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheAppSGMgmt, nil
}

func (a *mqlAwsSagemakerDomain) executionRoleSessionNameMode() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheExecRoleSessionMode, nil
}

func (a *mqlAwsSagemakerDomain) tagPropagation() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheTagPropagation, nil
}

func (a *mqlAwsSagemakerDomain) singleSignOnApplicationArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheSSOAppArn), nil
}

func (a *mqlAwsSagemakerDomain) failureReason() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheFailureReason), nil
}

func (a *mqlAwsSagemakerDomain) subnets() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if len(a.cacheSubnetIds) == 0 {
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := make([]any, 0, len(a.cacheSubnetIds))
	for _, subnetId := range a.cacheSubnetIds {
		arn := fmt.Sprintf(subnetArnPattern, a.Region.Data, conn.AccountId(), subnetId)
		mqlSubnet, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet,
			map[string]*llx.RawData{"arn": llx.StringData(arn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsSagemakerDomain) defaultExecutionRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDefaultExecutionRole == nil || *a.cacheDefaultExecutionRole == "" {
		a.DefaultExecutionRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheDefaultExecutionRole)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerDomain) dockerAccessEnabled() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.cacheDockerAccessEnabled, nil
}

func (a *mqlAwsSagemakerDomain) rootlessDocker() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.cacheRootlessDocker, nil
}

func (a *mqlAwsSagemakerDomain) dockerVpcOnlyTrustedAccounts() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(a.cacheDockerVpcOnlyTrusted), nil
}

func (a *mqlAwsSagemakerDomain) executionRoleIdentityConfig() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheExecRoleIdentityConfig, nil
}

func (a *mqlAwsSagemakerDomain) domainSecurityGroups() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return sagemakerSecurityGroups(a.MqlRuntime, a.Region.Data, a.cacheDomainSecurityGroups)
}

func (a *mqlAwsSagemakerDomain) rstudioDomainExecutionRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return sagemakerIamRole(a.MqlRuntime, &a.RstudioDomainExecutionRole, a.cacheRStudioExecRole)
}

func (a *mqlAwsSagemakerDomain) amazonQStatus() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheAmazonQStatus, nil
}

func (a *mqlAwsSagemakerDomain) amazonQProfileArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheAmazonQProfileArn), nil
}

func (a *mqlAwsSagemakerDomain) defaultUserSecurityGroups() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return sagemakerSecurityGroups(a.MqlRuntime, a.Region.Data, a.cacheDefaultUserSecurityGroups)
}

func (a *mqlAwsSagemakerDomain) defaultUserSharedNotebookKmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return sagemakerKmsKey(a.MqlRuntime, &a.DefaultUserSharedNotebookKmsKey, a.cacheDefaultUserSharedKms)
}

func (a *mqlAwsSagemakerDomain) defaultSpaceExecutionRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return sagemakerIamRole(a.MqlRuntime, &a.DefaultSpaceExecutionRole, a.cacheDefaultSpaceExecRole)
}

func (a *mqlAwsSagemakerDomain) defaultSpaceSecurityGroups() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return sagemakerSecurityGroups(a.MqlRuntime, a.Region.Data, a.cacheDefaultSpaceSecurityGrps)
}

// ---- Inference Components ----

func (a *mqlAwsSagemaker) inferenceComponents() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getInferenceComponents(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getInferenceComponents(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListInferenceComponentsPaginator(svc, &sagemaker.ListInferenceComponentsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker inference components")
						return res, nil
					}
					return nil, err
				}

				for _, ic := range page.InferenceComponents {
					mqlIC, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerInferenceComponent,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(ic.InferenceComponentArn),
							"name":           llx.StringDataPtr(ic.InferenceComponentName),
							"endpointName":   llx.StringDataPtr(ic.EndpointName),
							"endpointArn":    llx.StringDataPtr(ic.EndpointArn),
							"variantName":    llx.StringDataPtr(ic.VariantName),
							"status":         llx.StringData(string(ic.InferenceComponentStatus)),
							"createdAt":      llx.TimeDataPtr(ic.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(ic.LastModifiedTime),
							"region":         llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlIC)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerInferenceComponentInternal struct {
	sagemakerTagsCache
	fetched       bool
	fetchErr      error
	fetchLock     sync.Mutex
	cacheDescribe *sagemaker.DescribeInferenceComponentOutput
}

func (a *mqlAwsSagemakerInferenceComponent) fetchDetails() (*sagemaker.DescribeInferenceComponentOutput, error) {
	if a.fetched {
		return a.cacheDescribe, a.fetchErr
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.cacheDescribe, a.fetchErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data

	resp, err := svc.DescribeInferenceComponent(ctx, &sagemaker.DescribeInferenceComponentInput{
		InferenceComponentName: &name,
	})
	a.fetched = true
	a.cacheDescribe = resp
	a.fetchErr = err
	return resp, err
}

func (a *mqlAwsSagemakerInferenceComponent) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerInferenceComponent) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerInferenceComponent) endpoint() (*mqlAwsSagemakerEndpoint, error) {
	endpointArn := a.EndpointArn.Data
	if endpointArn == "" {
		a.Endpoint.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsSagemakerEndpoint,
		map[string]*llx.RawData{"arn": llx.StringData(endpointArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerEndpoint), nil
}

func (a *mqlAwsSagemakerInferenceComponent) placementStrategy() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if resp.Specification != nil && resp.Specification.SchedulingConfig != nil {
		return string(resp.Specification.SchedulingConfig.PlacementStrategy), nil
	}
	return "", nil
}

func (a *mqlAwsSagemakerInferenceComponent) copyCount() (int64, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return 0, err
	}
	if resp.RuntimeConfig != nil && resp.RuntimeConfig.CurrentCopyCount != nil {
		return int64(*resp.RuntimeConfig.CurrentCopyCount), nil
	}
	return 0, nil
}

func (a *mqlAwsSagemakerInferenceComponent) runtimeConfig() (map[string]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(resp.RuntimeConfig)
}

func (a *mqlAwsSagemakerInferenceComponent) specification() (map[string]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(resp.Specification)
}

func (a *mqlAwsSagemakerInferenceComponent) failureReason() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.FailureReason), nil
}

// ---- Clusters (HyperPod) ----

func (a *mqlAwsSagemaker) clusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getClusters(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getClusters(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListClustersPaginator(svc, &sagemaker.ListClustersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker clusters")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("SageMaker HyperPod clusters not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, cluster := range page.ClusterSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, cluster.ClusterArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("cluster", cluster.ClusterArn).Msg("skipping sagemaker cluster due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlCluster, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerCluster,
						map[string]*llx.RawData{
							"arn":       llx.StringDataPtr(cluster.ClusterArn),
							"name":      llx.StringDataPtr(cluster.ClusterName),
							"region":    llx.StringData(region),
							"status":    llx.StringData(string(cluster.ClusterStatus)),
							"createdAt": llx.TimeDataPtr(cluster.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					c := mqlCluster.(*mqlAwsSagemakerCluster)
					if eagerTags != nil {
						c.cacheTags = eagerTags
						c.tagsFetched = true
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

type mqlAwsSagemakerClusterInternal struct {
	sagemakerTagsCache
	fetched       bool
	fetchLock     sync.Mutex
	cacheDescribe *sagemaker.DescribeClusterOutput
}

func (a *mqlAwsSagemakerCluster) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerCluster) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerCluster) fetchDetails() (*sagemaker.DescribeClusterOutput, error) {
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

	resp, err := svc.DescribeCluster(ctx, &sagemaker.DescribeClusterInput{
		ClusterName: &name,
	})
	if err != nil {
		return nil, err
	}
	a.cacheDescribe = resp
	a.fetched = true
	return resp, nil
}

func (a *mqlAwsSagemakerCluster) iamRole() (*mqlAwsIamRole, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if resp.ClusterRole == nil || *resp.ClusterRole == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(resp.ClusterRole)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerCluster) instanceGroups() ([]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(resp.InstanceGroups))
	for _, ig := range resp.InstanceGroups {
		var currentCount, targetCount, threadsPerCore int64
		if ig.CurrentCount != nil {
			currentCount = int64(*ig.CurrentCount)
		}
		if ig.TargetCount != nil {
			targetCount = int64(*ig.TargetCount)
		}
		if ig.ThreadsPerCore != nil {
			threadsPerCore = int64(*ig.ThreadsPerCore)
		}
		instanceRequirements, err := convert.JsonToDict(ig.InstanceRequirements)
		if err != nil {
			return nil, err
		}
		instanceTypeDetails := make([]any, 0, len(ig.InstanceTypeDetails))
		igName := convert.ToValue(ig.InstanceGroupName)
		for _, itd := range ig.InstanceTypeDetails {
			var itdCurrentCount, itdThreadsPerCore int64
			if itd.CurrentCount != nil {
				itdCurrentCount = int64(*itd.CurrentCount)
			}
			if itd.ThreadsPerCore != nil {
				itdThreadsPerCore = int64(*itd.ThreadsPerCore)
			}
			mqlITD, err := CreateResource(a.MqlRuntime, "aws.sagemaker.clusterInstanceGroup.instanceTypeDetail",
				map[string]*llx.RawData{
					"__id":           llx.StringData(a.Region.Data + "/" + a.Name.Data + "/" + igName + "/instanceTypeDetail/" + string(itd.InstanceType)),
					"instanceType":   llx.StringData(string(itd.InstanceType)),
					"currentCount":   llx.IntData(itdCurrentCount),
					"threadsPerCore": llx.IntData(itdThreadsPerCore),
				})
			if err != nil {
				return nil, err
			}
			itdRes := mqlITD.(*mqlAwsSagemakerClusterInstanceGroupInstanceTypeDetail)
			itdRes.cacheParentGroupID = a.Region.Data + "/" + a.Name.Data + "/" + igName
			instanceTypeDetails = append(instanceTypeDetails, mqlITD)
		}
		var networkInterfaceType string
		if ig.NetworkInterface != nil {
			networkInterfaceType = string(ig.NetworkInterface.InterfaceType)
		}
		mqlIG, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerClusterInstanceGroup,
			map[string]*llx.RawData{
				"__id":                 llx.StringData(a.Region.Data + "/" + a.Name.Data + "/" + convert.ToValue(ig.InstanceGroupName)),
				"instanceGroupName":    llx.StringDataPtr(ig.InstanceGroupName),
				"instanceType":         llx.StringData(string(ig.InstanceType)),
				"region":               llx.StringData(a.Region.Data),
				"status":               llx.StringData(string(ig.Status)),
				"currentCount":         llx.IntData(currentCount),
				"targetCount":          llx.IntData(targetCount),
				"threadsPerCore":       llx.IntData(threadsPerCore),
				"instanceRequirements": llx.DictData(instanceRequirements),
				"instanceTypeDetails":  llx.ArrayData(instanceTypeDetails, types.Resource("aws.sagemaker.clusterInstanceGroup.instanceTypeDetail")),
				"networkInterfaceType": llx.StringData(networkInterfaceType),
				"imageVersionStatus":   llx.StringData(string(ig.ImageVersionStatus)),
			})
		if err != nil {
			return nil, err
		}
		igRes := mqlIG.(*mqlAwsSagemakerClusterInstanceGroup)
		igRes.cacheClusterName = a.Name.Data
		igRes.cacheExecutionRole = ig.ExecutionRole
		igRes.cacheLifecycleConfig = ig.LifeCycleConfig
		res = append(res, mqlIG)
	}
	return res, nil
}

func (a *mqlAwsSagemakerCluster) orchestrator() (map[string]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(resp.Orchestrator)
}

func (a *mqlAwsSagemakerCluster) vpc() (*mqlAwsVpc, error) {
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

func (a *mqlAwsSagemakerCluster) nodeRecovery() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return string(resp.NodeRecovery), nil
}

func (a *mqlAwsSagemakerCluster) nodeProvisioningMode() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return string(resp.NodeProvisioningMode), nil
}

func (a *mqlAwsSagemakerCluster) failureMessage() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.FailureMessage), nil
}

func (a *mqlAwsSagemakerCluster) nodes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	clusterName := a.Name.Data

	res := []any{}
	paginator := sagemaker.NewListClusterNodesPaginator(svc, &sagemaker.ListClusterNodesInput{
		ClusterName: &clusterName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "sagemaker:ListClusterNodes")
		}
		for _, node := range page.ClusterNodeSummaries {
			var status, statusMsg string
			if node.InstanceStatus != nil {
				status = string(node.InstanceStatus.Status)
				statusMsg = convert.ToValue(node.InstanceStatus.Message)
			}

			mqlNode, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerClusterNode,
				map[string]*llx.RawData{
					"__id":               llx.StringData(a.Region.Data + "/" + clusterName + "/" + convert.ToValue(node.InstanceGroupName) + "/" + convert.ToValue(node.InstanceId)),
					"instanceId":         llx.StringDataPtr(node.InstanceId),
					"instanceGroupName":  llx.StringDataPtr(node.InstanceGroupName),
					"instanceType":       llx.StringData(string(node.InstanceType)),
					"status":             llx.StringData(status),
					"statusMessage":      llx.StringData(statusMsg),
					"launchedAt":         llx.TimeDataPtr(node.LaunchTime),
					"privateDnsHostname": llx.StringDataPtr(node.PrivateDnsHostname),
					"region":             llx.StringData(a.Region.Data),
					"imageVersionStatus": llx.StringData(string(node.ImageVersionStatus)),
				})
			if err != nil {
				return nil, err
			}
			nodeRes := mqlNode.(*mqlAwsSagemakerClusterNode)
			nodeRes.cacheClusterName = clusterName
			res = append(res, mqlNode)
		}
	}
	return res, nil
}

func (a *mqlAwsSagemakerCluster) tieredStorageEnabled() (bool, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return false, err
	}
	if resp.TieredStorageConfig == nil {
		return false, nil
	}
	return resp.TieredStorageConfig.Mode == sagemakerTypes.ClusterConfigModeEnable, nil
}

func (a *mqlAwsSagemakerCluster) tieredStorageMemoryAllocationPercentage() (int64, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return 0, err
	}
	if resp.TieredStorageConfig == nil || resp.TieredStorageConfig.InstanceMemoryAllocationPercentage == nil {
		return 0, nil
	}
	return int64(*resp.TieredStorageConfig.InstanceMemoryAllocationPercentage), nil
}

func (a *mqlAwsSagemakerCluster) restrictedInstanceGroups() ([]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(resp.RestrictedInstanceGroups))
	for _, rig := range resp.RestrictedInstanceGroups {
		var currentCount, targetCount int64
		if rig.CurrentCount != nil {
			currentCount = int64(*rig.CurrentCount)
		}
		if rig.TargetCount != nil {
			targetCount = int64(*rig.TargetCount)
		}

		var fsxThroughput, fsxSize int64
		var s3OutputPath string
		if rig.EnvironmentConfig != nil {
			s3OutputPath = convert.ToValue(rig.EnvironmentConfig.S3OutputPath)
			if fsx := rig.EnvironmentConfig.FSxLustreConfig; fsx != nil {
				if fsx.PerUnitStorageThroughput != nil {
					fsxThroughput = int64(*fsx.PerUnitStorageThroughput)
				}
				if fsx.SizeInGiB != nil {
					fsxSize = int64(*fsx.SizeInGiB)
				}
			}
		}

		deepHealthChecks := make([]any, 0, len(rig.OnStartDeepHealthChecks))
		for _, dhc := range rig.OnStartDeepHealthChecks {
			deepHealthChecks = append(deepHealthChecks, string(dhc))
		}

		instanceStorageConfigs, err := convert.JsonToDictSlice(rig.InstanceStorageConfigs)
		if err != nil {
			return nil, err
		}
		scheduledUpdateConfig, err := convert.JsonToDict(rig.ScheduledUpdateConfig)
		if err != nil {
			return nil, err
		}

		mqlRIG, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerClusterRestrictedInstanceGroup,
			map[string]*llx.RawData{
				"__id":                              llx.StringData(a.Region.Data + "/" + a.Name.Data + "/" + convert.ToValue(rig.InstanceGroupName)),
				"instanceGroupName":                 llx.StringDataPtr(rig.InstanceGroupName),
				"instanceType":                      llx.StringData(string(rig.InstanceType)),
				"region":                            llx.StringData(a.Region.Data),
				"status":                            llx.StringData(string(rig.Status)),
				"currentCount":                      llx.IntData(currentCount),
				"targetCount":                       llx.IntData(targetCount),
				"fsxLustrePerUnitStorageThroughput": llx.IntData(fsxThroughput),
				"fsxLustreSizeInGiB":                llx.IntData(fsxSize),
				"s3OutputPath":                      llx.StringData(s3OutputPath),
				"onStartDeepHealthChecks":           llx.ArrayData(deepHealthChecks, types.String),
				"instanceStorageConfigs":            llx.ArrayData(instanceStorageConfigs, types.Dict),
				"scheduledUpdateConfig":             llx.DictData(scheduledUpdateConfig),
			})
		if err != nil {
			return nil, err
		}
		rigRes := mqlRIG.(*mqlAwsSagemakerClusterRestrictedInstanceGroup)
		rigRes.cacheClusterName = a.Name.Data
		rigRes.cacheExecutionRole = rig.ExecutionRole
		if rig.OverrideVpcConfig != nil {
			rigRes.cacheOverrideSubnets = rig.OverrideVpcConfig.Subnets
		}
		res = append(res, mqlRIG)
	}
	return res, nil
}

type mqlAwsSagemakerClusterRestrictedInstanceGroupInternal struct {
	cacheClusterName     string
	cacheExecutionRole   *string
	cacheOverrideSubnets []string
}

func (a *mqlAwsSagemakerClusterRestrictedInstanceGroup) id() (string, error) {
	return a.Region.Data + "/" + a.cacheClusterName + "/" + a.InstanceGroupName.Data, nil
}

func (a *mqlAwsSagemakerClusterRestrictedInstanceGroup) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheExecutionRole == nil || *a.cacheExecutionRole == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheExecutionRole)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerClusterRestrictedInstanceGroup) vpc() (*mqlAwsVpc, error) {
	return sagemakerResolveVpc(a.MqlRuntime, a.Region.Data, a.cacheOverrideSubnets, &a.Vpc)
}

type mqlAwsSagemakerClusterInstanceGroupInternal struct {
	cacheClusterName     string
	cacheExecutionRole   *string
	cacheLifecycleConfig any
}

func (a *mqlAwsSagemakerClusterInstanceGroup) id() (string, error) {
	return a.Region.Data + "/" + a.cacheClusterName + "/" + a.InstanceGroupName.Data, nil
}

func (a *mqlAwsSagemakerClusterInstanceGroup) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheExecutionRole == nil || *a.cacheExecutionRole == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheExecutionRole)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerClusterInstanceGroup) lifecycleConfig() (map[string]any, error) {
	if a.cacheLifecycleConfig == nil {
		return nil, nil
	}
	return convert.JsonToDict(a.cacheLifecycleConfig)
}

type mqlAwsSagemakerClusterInstanceGroupInstanceTypeDetailInternal struct {
	cacheParentGroupID string
}

func (a *mqlAwsSagemakerClusterInstanceGroupInstanceTypeDetail) id() (string, error) {
	return a.cacheParentGroupID + "/instanceTypeDetail/" + a.InstanceType.Data, nil
}

type mqlAwsSagemakerClusterNodeInternal struct {
	cacheClusterName string
	fetched          bool
	fetchErr         error
	fetchLock        sync.Mutex
	cacheDescribe    *sagemakerTypes.ClusterNodeDetails
}

func (a *mqlAwsSagemakerClusterNode) fetchDetails() (*sagemakerTypes.ClusterNodeDetails, error) {
	if a.fetched {
		return a.cacheDescribe, a.fetchErr
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.cacheDescribe, a.fetchErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	clusterName := a.cacheClusterName
	nodeId := a.InstanceId.Data

	resp, err := svc.DescribeClusterNode(ctx, &sagemaker.DescribeClusterNodeInput{
		ClusterName: &clusterName,
		NodeId:      &nodeId,
	})
	if err != nil {
		a.fetched = true
		a.fetchErr = classifyAwsError(err, "sagemaker:DescribeClusterNode")
		return nil, a.fetchErr
	}
	a.cacheDescribe = resp.NodeDetails
	a.fetched = true
	return a.cacheDescribe, nil
}

func (a *mqlAwsSagemakerClusterNode) networkInterfaceType() (string, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if details == nil || details.NetworkInterface == nil {
		return "", nil
	}
	return string(details.NetworkInterface.InterfaceType), nil
}

func (a *mqlAwsSagemakerClusterNode) id() (string, error) {
	return a.Region.Data + "/" + a.cacheClusterName + "/" + a.InstanceGroupName.Data + "/" + a.InstanceId.Data, nil
}

// ---- Feature Groups ----

func (a *mqlAwsSagemaker) featureGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getFeatureGroups(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getFeatureGroups(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListFeatureGroupsPaginator(svc, &sagemaker.ListFeatureGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker feature groups")
						return res, nil
					}
					return nil, err
				}

				for _, fg := range page.FeatureGroupSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, fg.FeatureGroupArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("featureGroup", fg.FeatureGroupArn).Msg("skipping sagemaker feature group due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlFG, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerFeatureGroup,
						map[string]*llx.RawData{
							"arn":       llx.StringDataPtr(fg.FeatureGroupArn),
							"name":      llx.StringDataPtr(fg.FeatureGroupName),
							"region":    llx.StringData(region),
							"status":    llx.StringData(string(fg.FeatureGroupStatus)),
							"createdAt": llx.TimeDataPtr(fg.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					fgRes := mqlFG.(*mqlAwsSagemakerFeatureGroup)
					if eagerTags != nil {
						fgRes.cacheTags = eagerTags
						fgRes.tagsFetched = true
					}
					res = append(res, mqlFG)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerFeatureGroupInternal struct {
	sagemakerTagsCache
	fetched       bool
	fetchLock     sync.Mutex
	cacheDescribe *sagemaker.DescribeFeatureGroupOutput
}

func (a *mqlAwsSagemakerFeatureGroup) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerFeatureGroup) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerFeatureGroup) fetchDetails() (*sagemaker.DescribeFeatureGroupOutput, error) {
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

	resp, err := svc.DescribeFeatureGroup(ctx, &sagemaker.DescribeFeatureGroupInput{
		FeatureGroupName: &name,
	})
	if err != nil {
		return nil, err
	}
	a.cacheDescribe = resp
	a.fetched = true
	return resp, nil
}

func (a *mqlAwsSagemakerFeatureGroup) iamRole() (*mqlAwsIamRole, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if resp.RoleArn == nil || *resp.RoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(resp.RoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerFeatureGroup) description() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.Description), nil
}

func (a *mqlAwsSagemakerFeatureGroup) featureDefinitions() ([]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(resp.FeatureDefinitions))
	for _, fd := range resp.FeatureDefinitions {
		mqlFD, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerFeatureDefinition,
			map[string]*llx.RawData{
				"__id":           llx.StringData(a.Arn.Data + "/" + convert.ToValue(fd.FeatureName) + "/" + string(fd.FeatureType)),
				"featureName":    llx.StringDataPtr(fd.FeatureName),
				"featureType":    llx.StringData(string(fd.FeatureType)),
				"collectionType": llx.StringData(string(fd.CollectionType)),
			})
		if err != nil {
			return nil, err
		}
		fdRes := mqlFD.(*mqlAwsSagemakerFeatureDefinition)
		fdRes.cacheFeatureGroupArn = a.Arn.Data
		res = append(res, mqlFD)
	}
	return res, nil
}

type mqlAwsSagemakerFeatureDefinitionInternal struct {
	cacheFeatureGroupArn string
}

func (a *mqlAwsSagemakerFeatureDefinition) id() (string, error) {
	return a.cacheFeatureGroupArn + "/" + a.FeatureName.Data + "/" + a.FeatureType.Data, nil
}

func (a *mqlAwsSagemakerFeatureGroup) eventTimeFeatureName() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.EventTimeFeatureName), nil
}

func (a *mqlAwsSagemakerFeatureGroup) recordIdentifierFeatureName() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.RecordIdentifierFeatureName), nil
}

func (a *mqlAwsSagemakerFeatureGroup) offlineStoreConfig() (map[string]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(resp.OfflineStoreConfig)
}

func (a *mqlAwsSagemakerFeatureGroup) onlineStoreConfig() (map[string]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(resp.OnlineStoreConfig)
}

func (a *mqlAwsSagemakerFeatureGroup) failureReason() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.FailureReason), nil
}

func (a *mqlAwsSagemakerFeatureGroup) offlineStoreStatus() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if resp.OfflineStoreStatus != nil {
		return string(resp.OfflineStoreStatus.Status), nil
	}
	return "", nil
}

func (a *mqlAwsSagemakerFeatureGroup) onlineStoreTotalSizeBytes() (int64, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return 0, err
	}
	if resp.OnlineStoreTotalSizeBytes != nil {
		return *resp.OnlineStoreTotalSizeBytes, nil
	}
	return 0, nil
}

// ---- Model Packages ----

func (a *mqlAwsSagemaker) modelPackages() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getModelPackages(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getModelPackages(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListModelPackagesPaginator(svc, &sagemaker.ListModelPackagesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker model packages")
						return res, nil
					}
					return nil, err
				}

				for _, mp := range page.ModelPackageSummaryList {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, mp.ModelPackageArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("modelPackage", mp.ModelPackageArn).Msg("skipping sagemaker model package due to filters")
							continue
						}
						eagerTags = tags
					}

					var version int64
					if mp.ModelPackageVersion != nil {
						version = int64(*mp.ModelPackageVersion)
					}

					mqlMP, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerModelPackage,
						map[string]*llx.RawData{
							"arn":                   llx.StringDataPtr(mp.ModelPackageArn),
							"name":                  llx.StringDataPtr(mp.ModelPackageName),
							"region":                llx.StringData(region),
							"status":                llx.StringData(string(mp.ModelPackageStatus)),
							"approvalStatus":        llx.StringData(string(mp.ModelApprovalStatus)),
							"createdAt":             llx.TimeDataPtr(mp.CreationTime),
							"description":           llx.StringDataPtr(mp.ModelPackageDescription),
							"modelPackageGroupName": llx.StringDataPtr(mp.ModelPackageGroupName),
							"modelPackageVersion":   llx.IntData(version),
						})
					if err != nil {
						return nil, err
					}
					m := mqlMP.(*mqlAwsSagemakerModelPackage)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched = true
					}
					res = append(res, mqlMP)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerModelPackageInternal struct {
	sagemakerTagsCache
	fetched       bool
	fetchLock     sync.Mutex
	cacheDescribe *sagemaker.DescribeModelPackageOutput
}

func (a *mqlAwsSagemakerModelPackage) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerModelPackage) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerModelPackage) fetchDetails() (*sagemaker.DescribeModelPackageOutput, error) {
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
	arn := a.Arn.Data

	// Use ARN as input since it works for both versioned and unversioned packages
	resp, err := svc.DescribeModelPackage(ctx, &sagemaker.DescribeModelPackageInput{
		ModelPackageName: &arn,
	})
	if err != nil {
		return nil, err
	}
	a.cacheDescribe = resp
	a.fetched = true
	return resp, nil
}

func (a *mqlAwsSagemakerModelPackage) modelPackageGroup() (*mqlAwsSagemakerModelPackageGroup, error) {
	groupName := a.ModelPackageGroupName.Data
	if groupName == "" {
		a.ModelPackageGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	groupArn := fmt.Sprintf("arn:aws:sagemaker:%s:%s:model-package-group/%s", a.Region.Data, conn.AccountId(), groupName)
	res, err := NewResource(a.MqlRuntime, ResourceAwsSagemakerModelPackageGroup,
		map[string]*llx.RawData{"arn": llx.StringData(groupArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerModelPackageGroup), nil
}

func (a *mqlAwsSagemakerModelPackage) certifyForMarketplace() (bool, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return false, err
	}
	if resp.CertifyForMarketplace != nil {
		return *resp.CertifyForMarketplace, nil
	}
	return false, nil
}

func (a *mqlAwsSagemakerModelPackage) kmsKey() (*mqlAwsKmsKey, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if resp.SecurityConfig == nil || resp.SecurityConfig.KmsKeyId == nil || *resp.SecurityConfig.KmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(resp.SecurityConfig.KmsKeyId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSagemakerModelPackage) inferenceSpecification() (map[string]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(resp.InferenceSpecification)
}

func (a *mqlAwsSagemakerModelPackage) approvalDescription() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.ApprovalDescription), nil
}

func (a *mqlAwsSagemakerModelPackage) modelMetrics() (map[string]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(resp.ModelMetrics)
}

func (a *mqlAwsSagemakerModelPackage) sourceUri() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.SourceUri), nil
}

func (a *mqlAwsSagemakerModelPackage) customerMetadataProperties() (map[string]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if resp.CustomerMetadataProperties == nil {
		return nil, nil
	}
	result := make(map[string]any, len(resp.CustomerMetadataProperties))
	for k, v := range resp.CustomerMetadataProperties {
		result[k] = v
	}
	return result, nil
}

func (a *mqlAwsSagemakerModelPackage) skipModelValidation() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return string(resp.SkipModelValidation), nil
}

func (a *mqlAwsSagemakerModelPackage) lastModifiedTime() (*time.Time, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return resp.LastModifiedTime, nil
}

// ---- Model Package Groups ----

func (a *mqlAwsSagemaker) modelPackageGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getModelPackageGroups(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getModelPackageGroups(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListModelPackageGroupsPaginator(svc, &sagemaker.ListModelPackageGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker model package groups")
						return res, nil
					}
					return nil, err
				}

				for _, mpg := range page.ModelPackageGroupSummaryList {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, mpg.ModelPackageGroupArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("modelPackageGroup", mpg.ModelPackageGroupArn).Msg("skipping sagemaker model package group due to filters")
							continue
						}
						eagerTags = tags
					}

					var managedStorageType string
					if mpg.ManagedConfiguration != nil {
						managedStorageType = string(mpg.ManagedConfiguration.ManagedStorageType)
					}

					mqlMPG, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerModelPackageGroup,
						map[string]*llx.RawData{
							"arn":                llx.StringDataPtr(mpg.ModelPackageGroupArn),
							"name":               llx.StringDataPtr(mpg.ModelPackageGroupName),
							"region":             llx.StringData(region),
							"status":             llx.StringData(string(mpg.ModelPackageGroupStatus)),
							"createdAt":          llx.TimeDataPtr(mpg.CreationTime),
							"managedStorageType": llx.StringData(managedStorageType),
						})
					if err != nil {
						return nil, err
					}
					g := mqlMPG.(*mqlAwsSagemakerModelPackageGroup)
					if eagerTags != nil {
						g.cacheTags = eagerTags
						g.tagsFetched = true
					}
					res = append(res, mqlMPG)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func initAwsSagemakerModelPackageGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch sagemaker model package group")
	}

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetModelPackageGroups()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		g := rawResource.(*mqlAwsSagemakerModelPackageGroup)
		if g.Arn.Data == arnVal {
			return args, g, nil
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.modelPackageGroup with arn %q not found", arnVal)
}

type mqlAwsSagemakerModelPackageGroupInternal struct {
	sagemakerTagsCache
	fetched          bool
	fetchLock        sync.Mutex
	cacheDescription *string
}

func (a *mqlAwsSagemakerModelPackageGroup) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerModelPackageGroup) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerModelPackageGroup) fetchDetails() error {
	if a.fetched {
		return nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data

	resp, err := svc.DescribeModelPackageGroup(ctx, &sagemaker.DescribeModelPackageGroupInput{
		ModelPackageGroupName: &name,
	})
	if err != nil {
		return err
	}
	a.cacheDescription = resp.ModelPackageGroupDescription
	a.fetched = true
	return nil
}

func (a *mqlAwsSagemakerModelPackageGroup) description() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheDescription), nil
}

func (a *mqlAwsSagemakerModelPackageGroup) resourcePolicy() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	name := a.Name.Data
	resp, err := svc.GetModelPackageGroupPolicy(context.Background(), &sagemaker.GetModelPackageGroupPolicyInput{ModelPackageGroupName: &name})
	if err != nil {
		// A group with no resource policy attached returns a validation error;
		// treat that as "no policy" rather than failing.
		if isSagemakerNoPolicyError(err) {
			return "", nil
		}
		return "", classifyAwsError(err, "sagemaker:GetModelPackageGroupPolicy")
	}
	return convert.ToValue(resp.ResourcePolicy), nil
}

func (a *mqlAwsSagemakerModelPackageGroup) policyStatements() ([]any, error) {
	policy := a.GetResourcePolicy()
	if policy.Error != nil {
		return nil, policy.Error
	}
	return newPolicyStatementResources(a.MqlRuntime, a.Arn.Data, policy.Data)
}

func (a *mqlAwsSagemakerModelPackageGroup) isPublic() (bool, error) {
	return resourceIsPublic(a.GetPolicyStatements())
}

// isSagemakerNoPolicyError reports whether a GetModelPackageGroupPolicy error
// indicates the group simply has no resource policy attached rather than a real
// failure. SageMaker returns a ValidationException in that case; matching the
// error code (like isCodeArtifactValidation) is resilient to SDK message
// wording changes. The group name always comes from a prior list call, so a
// ValidationException here reliably means "no policy" rather than a bad name.
func isSagemakerNoPolicyError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "ValidationException"
	}
	return false
}

// ---- Model Cards ----

func (a *mqlAwsSagemaker) modelCards() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getModelCards(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getModelCards(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListModelCardsPaginator(svc, &sagemaker.ListModelCardsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker model cards")
						return res, nil
					}
					return nil, err
				}

				for _, mc := range page.ModelCardSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, mc.ModelCardArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("modelCard", mc.ModelCardArn).Msg("skipping sagemaker model card due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlMC, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerModelCard,
						map[string]*llx.RawData{
							"arn":             llx.StringDataPtr(mc.ModelCardArn),
							"name":            llx.StringDataPtr(mc.ModelCardName),
							"region":          llx.StringData(region),
							"modelCardStatus": llx.StringData(string(mc.ModelCardStatus)),
							"createdAt":       llx.TimeDataPtr(mc.CreationTime),
							"lastModifiedAt":  llx.TimeDataPtr(mc.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					c := mqlMC.(*mqlAwsSagemakerModelCard)
					if eagerTags != nil {
						c.cacheTags = eagerTags
						c.tagsFetched = true
					}
					res = append(res, mqlMC)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerModelCardInternal struct {
	sagemakerTagsCache
	fetched       bool
	fetchLock     sync.Mutex
	cacheDescribe *sagemaker.DescribeModelCardOutput
}

func (a *mqlAwsSagemakerModelCard) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerModelCard) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerModelCard) fetchDetails() (*sagemaker.DescribeModelCardOutput, error) {
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

	resp, err := svc.DescribeModelCard(ctx, &sagemaker.DescribeModelCardInput{
		ModelCardName: &name,
	})
	if err != nil {
		return nil, err
	}
	a.cacheDescribe = resp
	a.fetched = true
	return resp, nil
}

func (a *mqlAwsSagemakerModelCard) kmsKey() (*mqlAwsKmsKey, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if resp.SecurityConfig == nil || resp.SecurityConfig.KmsKeyId == nil || *resp.SecurityConfig.KmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(resp.SecurityConfig.KmsKeyId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSagemakerModelCard) content() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.Content), nil
}

func (a *mqlAwsSagemakerModelCard) modelCardVersion() (int64, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return 0, err
	}
	if resp.ModelCardVersion != nil {
		return int64(*resp.ModelCardVersion), nil
	}
	return 0, nil
}

func (a *mqlAwsSagemakerModelCard) modelCardProcessingStatus() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return string(resp.ModelCardProcessingStatus), nil
}

// ---- Spaces ----

func (a *mqlAwsSagemaker) spaces() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSpaces(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getSpaces(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListSpacesPaginator(svc, &sagemaker.ListSpacesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker spaces")
						return res, nil
					}
					return nil, err
				}

				for _, space := range page.Spaces {
					domainId := convert.ToValue(space.DomainId)
					spaceName := convert.ToValue(space.SpaceName)
					spaceArn := fmt.Sprintf("arn:aws:sagemaker:%s:%s:space/%s/%s", region, conn.AccountId(), domainId, spaceName)

					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						arnPtr := &spaceArn
						tags, err := getSagemakerTags(ctx, svc, arnPtr)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Str("space", spaceArn).Msg("skipping sagemaker space due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlSpace, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerSpace,
						map[string]*llx.RawData{
							"arn":            llx.StringData(spaceArn),
							"name":           llx.StringData(spaceName),
							"region":         llx.StringData(region),
							"status":         llx.StringData(string(space.Status)),
							"displayName":    llx.StringDataPtr(space.SpaceDisplayName),
							"createdAt":      llx.TimeDataPtr(space.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(space.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					s := mqlSpace.(*mqlAwsSagemakerSpace)
					s.cacheDomainId = domainId
					if eagerTags != nil {
						s.cacheTags = eagerTags
						s.tagsFetched = true
					}
					res = append(res, mqlSpace)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerSpaceInternal struct {
	sagemakerTagsCache
	fetched       bool
	fetchLock     sync.Mutex
	cacheDomainId string
	cacheDescribe *sagemaker.DescribeSpaceOutput
}

func (a *mqlAwsSagemakerSpace) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerSpace) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerSpace) fetchDetails() (*sagemaker.DescribeSpaceOutput, error) {
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
	domainId := a.cacheDomainId
	spaceName := a.Name.Data

	resp, err := svc.DescribeSpace(ctx, &sagemaker.DescribeSpaceInput{
		DomainId:  &domainId,
		SpaceName: &spaceName,
	})
	if err != nil {
		return nil, err
	}
	a.cacheDescribe = resp
	a.fetched = true
	return resp, nil
}

func (a *mqlAwsSagemakerSpace) domain() (*mqlAwsSagemakerDomain, error) {
	domainId := a.cacheDomainId
	if domainId == "" {
		a.Domain.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	domainArn := fmt.Sprintf("arn:aws:sagemaker:%s:%s:domain/%s", a.Region.Data, conn.AccountId(), domainId)
	res, err := NewResource(a.MqlRuntime, ResourceAwsSagemakerDomain,
		map[string]*llx.RawData{"arn": llx.StringData(domainArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerDomain), nil
}

func (a *mqlAwsSagemakerSpace) ownerUserProfileName() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if resp.OwnershipSettings != nil && resp.OwnershipSettings.OwnerUserProfileName != nil {
		return *resp.OwnershipSettings.OwnerUserProfileName, nil
	}
	return "", nil
}

func (a *mqlAwsSagemakerSpace) sharingType() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if resp.SpaceSharingSettings != nil {
		return string(resp.SpaceSharingSettings.SharingType), nil
	}
	return "", nil
}

func (a *mqlAwsSagemakerSpace) spaceUrl() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.Url), nil
}

func (a *mqlAwsSagemakerSpace) settings() (map[string]any, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(resp.SpaceSettings)
}

func (a *mqlAwsSagemakerSpace) failureReason() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.FailureReason), nil
}

// ---- User Profiles ----

func (a *mqlAwsSagemaker) userProfiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getUserProfiles(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getUserProfiles(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListUserProfilesPaginator(svc, &sagemaker.ListUserProfilesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS SageMaker user profiles")
						return res, nil
					}
					return nil, err
				}

				for _, up := range page.UserProfiles {
					domainId := convert.ToValue(up.DomainId)
					profileName := convert.ToValue(up.UserProfileName)
					profileArn := fmt.Sprintf("arn:aws:sagemaker:%s:%s:user-profile/%s/%s", region, conn.AccountId(), domainId, profileName)

					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						arnPtr := &profileArn
						tags, err := getSagemakerTags(ctx, svc, arnPtr)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Str("userProfile", profileArn).Msg("skipping sagemaker user profile due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlUP, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerUserProfile,
						map[string]*llx.RawData{
							"arn":            llx.StringData(profileArn),
							"name":           llx.StringData(profileName),
							"region":         llx.StringData(region),
							"status":         llx.StringData(string(up.Status)),
							"createdAt":      llx.TimeDataPtr(up.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(up.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					u := mqlUP.(*mqlAwsSagemakerUserProfile)
					u.cacheDomainId = domainId
					if eagerTags != nil {
						u.cacheTags = eagerTags
						u.tagsFetched = true
					}
					res = append(res, mqlUP)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerUserProfileInternal struct {
	sagemakerTagsCache
	fetched       bool
	fetchLock     sync.Mutex
	cacheDomainId string
	cacheDescribe *sagemaker.DescribeUserProfileOutput
}

func (a *mqlAwsSagemakerUserProfile) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerUserProfile) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerUserProfile) fetchDetails() (*sagemaker.DescribeUserProfileOutput, error) {
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
	domainId := a.cacheDomainId
	profileName := a.Name.Data

	resp, err := svc.DescribeUserProfile(ctx, &sagemaker.DescribeUserProfileInput{
		DomainId:        &domainId,
		UserProfileName: &profileName,
	})
	if err != nil {
		return nil, err
	}
	a.cacheDescribe = resp
	a.fetched = true
	return resp, nil
}

func (a *mqlAwsSagemakerUserProfile) domain() (*mqlAwsSagemakerDomain, error) {
	domainId := a.cacheDomainId
	if domainId == "" {
		a.Domain.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	domainArn := fmt.Sprintf("arn:aws:sagemaker:%s:%s:domain/%s", a.Region.Data, conn.AccountId(), domainId)
	res, err := NewResource(a.MqlRuntime, ResourceAwsSagemakerDomain,
		map[string]*llx.RawData{"arn": llx.StringData(domainArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerDomain), nil
}

func (a *mqlAwsSagemakerUserProfile) failureReason() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.FailureReason), nil
}

func (a *mqlAwsSagemakerUserProfile) singleSignOnUserIdentifier() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.SingleSignOnUserIdentifier), nil
}

func (a *mqlAwsSagemakerUserProfile) singleSignOnUserValue() (string, error) {
	resp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.SingleSignOnUserValue), nil
}

// sagemakerResolveVpc looks up the VPC ID from the first subnet in the list and
// returns an aws.vpc resource. If subnetIds is empty, it marks the field as null.
func sagemakerResolveVpc(runtime *plugin.Runtime, region string, subnetIds []string, field *plugin.TValue[*mqlAwsVpc]) (*mqlAwsVpc, error) {
	return awsResolveVpcFromSubnets(runtime, region, subnetIds, field)
}

// sagemakerSecurityGroups resolves a list of security-group IDs to typed
// aws.ec2.securitygroup resources. Returns nil (empty list) when there are no
// IDs. Shared by the model, domain, and endpoint-config accessors.
func sagemakerSecurityGroups(runtime *plugin.Runtime, region string, sgIds []string) ([]any, error) {
	return awsSecurityGroupRefs(runtime, region, sgIds)
}

// sagemakerIamRole resolves a role ARN to a typed aws.iam.role, marking the
// field null when the ARN is empty. field is the resource's role TValue so the
// runtime learns the field is set even when null.
func sagemakerIamRole(runtime *plugin.Runtime, field *plugin.TValue[*mqlAwsIamRole], roleArn *string) (*mqlAwsIamRole, error) {
	if roleArn == nil || *roleArn == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(roleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

// sagemakerKmsKey resolves a KMS key ID/ARN to a typed aws.kms.key, marking the
// field null when the key is empty.
func sagemakerKmsKey(runtime *plugin.Runtime, field *plugin.TValue[*mqlAwsKmsKey], keyId *string) (*mqlAwsKmsKey, error) {
	if keyId == nil || *keyId == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(keyId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func getSagemakerTags(ctx context.Context, svc *sagemaker.Client, arn *string) (map[string]any, error) {
	tags := make(map[string]any)
	paginator := sagemaker.NewListTagsPaginator(svc, &sagemaker.ListTagsInput{ResourceArn: arn})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		var respErr *http.ResponseError
		if err != nil {
			if errors.As(err, &respErr) {
				if respErr.HTTPStatusCode() == 404 {
					return nil, nil
				}
			}
			return nil, err
		}
		for _, t := range resp.Tags {
			if t.Key != nil && t.Value != nil {
				tags[*t.Key] = *t.Value
			}
		}
	}
	return tags, nil
}

func initAwsSagemakerTrainingjob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformSagemakerTrainingjob); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil && args["name"] == nil {
		return nil, nil, errors.New("arn or name required to fetch sagemaker training job")
	}

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetTrainingJobs()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	var arnVal, nameVal string
	if args["arn"] != nil {
		arnVal, _ = args["arn"].Value.(string)
	}
	if args["name"] != nil {
		nameVal, _ = args["name"].Value.(string)
	}
	for _, rawResource := range rawResources.Data {
		tj := rawResource.(*mqlAwsSagemakerTrainingjob)
		if (arnVal != "" && tj.Arn.Data == arnVal) || (nameVal != "" && tj.Name.Data == nameVal) {
			return args, tj, nil
		}
	}
	return nil, nil, errors.New("sagemaker training job does not exist")
}

func initAwsSagemakerProcessingjob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformSagemakerProcessingjob); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil && args["name"] == nil {
		return nil, nil, errors.New("arn or name required to fetch sagemaker processing job")
	}

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetProcessingJobs()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	var arnVal, nameVal string
	if args["arn"] != nil {
		arnVal, _ = args["arn"].Value.(string)
	}
	if args["name"] != nil {
		nameVal, _ = args["name"].Value.(string)
	}
	for _, rawResource := range rawResources.Data {
		pj := rawResource.(*mqlAwsSagemakerProcessingjob)
		if (arnVal != "" && pj.Arn.Data == arnVal) || (nameVal != "" && pj.Name.Data == nameVal) {
			return args, pj, nil
		}
	}
	return nil, nil, errors.New("sagemaker processing job does not exist")
}
