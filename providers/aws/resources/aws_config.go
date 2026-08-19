// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/configservice"
	cstypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/types"
)

func (a *mqlAwsConfig) id() (string, error) {
	return "aws.config", nil
}

func configTagsToMap(tags []cstypes.Tag) map[string]any {
	return tagsToMap(tags,
		func(t cstypes.Tag) *string { return t.Key },
		func(t cstypes.Tag) *string { return t.Value })
}

// configTagsForArn reads the tags of a Config resource. ListTagsForResource
// covers config rules, conformance packs, and aggregators, none of which carry
// tags in their describe responses.
func configTagsForArn(runtime *plugin.Runtime, region, resourceArn string) (map[string]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.ConfigService(region)
	ctx := context.Background()

	tags := map[string]any{}
	var nextToken *string
	for {
		resp, err := svc.ListTagsForResource(ctx, &configservice.ListTagsForResourceInput{
			ResourceArn: &resourceArn,
			NextToken:   nextToken,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		for k, v := range configTagsToMap(resp.Tags) {
			tags[k] = v
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return tags, nil
}

func (a *mqlAwsConfigRule) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return configTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

func (a *mqlAwsConfigConformancePack) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return configTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

func (a *mqlAwsConfigAggregator) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return configTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

func (a *mqlAwsConfig) recorders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getRecorders(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for _, job := range poolOfJobs.Jobs {
		res = append(res, job.Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsConfig) getRecorders(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("config>getRecorders>calling aws with region %s", region)

			svc := conn.ConfigService(region)
			ctx := context.Background()
			res := []any{}

			params := &configservice.DescribeConfigurationRecordersInput{}
			configRecorders, err := svc.DescribeConfigurationRecorders(ctx, params)
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, err
			}
			recorderStatusMap, err := a.describeConfigRecorderStatus(svc, region)
			if err != nil {
				return nil, err
			}
			for _, r := range configRecorders.ConfigurationRecorders {
				var recording bool
				var lastStatus string
				name := getName(convert.ToValue(r.Name), region)
				if val, ok := recorderStatusMap[name]; ok {
					recording = val.recording
					lastStatus = val.lastStatus
				}
				var resourceTypesInterface []any
				var allSupported, includeGlobalResourceTypes bool
				if r.RecordingGroup != nil {
					resourceTypesInterface = make([]any, len(r.RecordingGroup.ResourceTypes))
					for i, resourceType := range r.RecordingGroup.ResourceTypes {
						resourceTypesInterface[i] = string(resourceType)
					}
					allSupported = r.RecordingGroup.AllSupported
					includeGlobalResourceTypes = r.RecordingGroup.IncludeGlobalResourceTypes
				}
				mqlRecorder, err := CreateResource(a.MqlRuntime, "aws.config.recorder",
					map[string]*llx.RawData{
						"name":                       llx.StringDataPtr(r.Name),
						"roleArn":                    llx.StringDataPtr(r.RoleARN),
						"allSupported":               llx.BoolData(allSupported),
						"includeGlobalResourceTypes": llx.BoolData(includeGlobalResourceTypes),
						"resourceTypes":              llx.ArrayData(resourceTypesInterface, types.String),
						"recording":                  llx.BoolData(recording),
						"region":                     llx.StringData(region),
						"lastStatus":                 llx.StringData(lastStatus),
					})
				if err != nil {
					return nil, err
				}
				mqlRecorderRes := mqlRecorder.(*mqlAwsConfigRecorder)
				mqlRecorderRes.cacheRoleArn = r.RoleARN
				mqlRecorderRes.cacheRecordingGroup = r.RecordingGroup
				res = append(res, mqlRecorderRes)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsConfigRecorderInternal struct {
	cacheRoleArn        *string
	cacheRecordingGroup *cstypes.RecordingGroup
}

func (a *mqlAwsConfigRecorder) iamRole() (*mqlAwsIamRole, error) {
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

func (a *mqlAwsConfig) deliveryChannels() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDeliveryChannels(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}

	for _, job := range poolOfJobs.Jobs {
		res = append(res, job.Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsConfig) getDeliveryChannels(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("config>getDeliveryChannels>calling aws with region %s", region)

			svc := conn.ConfigService(region)
			ctx := context.Background()
			res := []any{}

			deliveryChannelsParams := &configservice.DescribeDeliveryChannelsInput{}
			deliveryChannels, err := svc.DescribeDeliveryChannels(ctx, deliveryChannelsParams)
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, err
			}

			for _, channel := range deliveryChannels.DeliveryChannels {
				mqlDeliveryChannel, err := CreateResource(a.MqlRuntime, "aws.config.deliverychannel",
					map[string]*llx.RawData{
						"name":         llx.StringDataPtr(channel.Name),
						"s3BucketName": llx.StringDataPtr(channel.S3BucketName),
						"s3KeyPrefix":  llx.StringDataPtr(channel.S3KeyPrefix),
						"snsTopicARN":  llx.StringDataPtr(channel.SnsTopicARN),
						"region":       llx.StringData(region),
					})
				if err != nil {
					return nil, err
				}
				mqlChRes := mqlDeliveryChannel.(*mqlAwsConfigDeliverychannel)
				if channel.ConfigSnapshotDeliveryProperties != nil {
					mqlChRes.cacheDeliveryFrequency = string(channel.ConfigSnapshotDeliveryProperties.DeliveryFrequency)
				}
				res = append(res, mqlChRes)
			}

			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func getName(name string, region string) string {
	return name + "/" + region
}

func (a *mqlAwsConfig) describeConfigRecorderStatus(svc *configservice.Client, regionVal string) (map[string]recorder, error) {
	statusMap := make(map[string]recorder)
	ctx := context.Background()

	params := &configservice.DescribeConfigurationRecorderStatusInput{}
	configRecorderStatus, err := svc.DescribeConfigurationRecorderStatus(ctx, params)
	if err != nil {
		return statusMap, err
	}
	for _, r := range configRecorderStatus.ConfigurationRecordersStatus {
		name := getName(convert.ToValue(r.Name), regionVal)
		statusMap[name] = recorder{recording: r.Recording, lastStatus: string(r.LastStatus)}
	}
	return statusMap, nil
}

type recorder struct {
	recording  bool
	lastStatus string
}

func (a *mqlAwsConfigRecorder) id() (string, error) {
	name := a.Name.Data
	region := a.Region.Data
	return getName(name, region), nil
}

func (a *mqlAwsConfig) rules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getRules(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for _, job := range poolOfJobs.Jobs {
		res = append(res, job.Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsConfig) getRules(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("config>getRules>calling aws with region %s", region)

			svc := conn.ConfigService(region)
			ctx := context.Background()
			res := []any{}

			paginator := configservice.NewDescribeConfigRulesPaginator(svc, &configservice.DescribeConfigRulesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return jobpool.JobResult(res), nil
					}
					return nil, err
				}
				for _, r := range page.ConfigRules {
					jsonSource, err := convert.JsonToDict(r.Source)
					if err != nil {
						return nil, err
					}
					mqlRule, err := CreateResource(a.MqlRuntime, "aws.config.rule",
						map[string]*llx.RawData{
							"arn":         llx.StringDataPtr(r.ConfigRuleArn),
							"name":        llx.StringDataPtr(r.ConfigRuleName),
							"description": llx.StringDataPtr(r.Description),
							"id":          llx.StringDataPtr(r.ConfigRuleId),
							"source":      llx.MapData(jsonSource, types.Any),
							"state":       llx.StringData(string(r.ConfigRuleState)),
							"region":      llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRule)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsConfigRule) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsConfigRule) complianceStatus() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ruleName := a.Name.Data
	region := a.Region.Data
	svc := conn.ConfigService(region)
	ctx := context.Background()

	resp, err := svc.DescribeComplianceByConfigRule(ctx, &configservice.DescribeComplianceByConfigRuleInput{
		ConfigRuleNames: []string{ruleName},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return "", nil
		}
		return "", err
	}
	if len(resp.ComplianceByConfigRules) > 0 && resp.ComplianceByConfigRules[0].Compliance != nil {
		return string(resp.ComplianceByConfigRules[0].Compliance.ComplianceType), nil
	}
	return "INSUFFICIENT_DATA", nil
}

func (a *mqlAwsConfig) aggregators() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAggregators(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for _, job := range poolOfJobs.Jobs {
		res = append(res, job.Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsConfig) getAggregators(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("config>getAggregators>calling aws with region %s", region)

			svc := conn.ConfigService(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeConfigurationAggregators(ctx, &configservice.DescribeConfigurationAggregatorsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, agg := range resp.ConfigurationAggregators {
					// Build account aggregation sources
					accountSources := []any{}
					for i, src := range agg.AccountAggregationSources {
						accountIds := make([]any, len(src.AccountIds))
						for j, id := range src.AccountIds {
							accountIds[j] = id
						}
						awsRegions := make([]any, len(src.AwsRegions))
						for j, r := range src.AwsRegions {
							awsRegions[j] = r
						}
						mqlSrc, err := CreateResource(a.MqlRuntime, ResourceAwsConfigAggregatorAccountAggregationSource,
							map[string]*llx.RawData{
								"__id":          llx.StringData(convert.ToValue(agg.ConfigurationAggregatorArn) + "/accountSource/" + fmt.Sprintf("%d", i)),
								"accountIds":    llx.ArrayData(accountIds, types.String),
								"allAwsRegions": llx.BoolData(src.AllAwsRegions),
								"awsRegions":    llx.ArrayData(awsRegions, types.String),
							})
						if err != nil {
							return nil, err
						}
						accountSources = append(accountSources, mqlSrc)
					}

					mqlAgg, err := CreateResource(a.MqlRuntime, "aws.config.aggregator",
						map[string]*llx.RawData{
							"arn":                       llx.StringDataPtr(agg.ConfigurationAggregatorArn),
							"name":                      llx.StringDataPtr(agg.ConfigurationAggregatorName),
							"region":                    llx.StringData(region),
							"accountAggregationSources": llx.ArrayData(accountSources, types.Resource("aws.config.aggregator.accountAggregationSource")),
							"createdAt":                 llx.TimeDataPtr(agg.CreationTime),
							"lastUpdatedAt":             llx.TimeDataPtr(agg.LastUpdatedTime),
						})
					if err != nil {
						return nil, err
					}

					// Cache the org source role ARN for lazy loading
					mqlAggRes := mqlAgg.(*mqlAwsConfigAggregator)
					if agg.OrganizationAggregationSource != nil {
						mqlAggRes.cacheOrgRoleArn = agg.OrganizationAggregationSource.RoleArn
						mqlAggRes.cacheOrgAllAwsRegions = agg.OrganizationAggregationSource.AllAwsRegions
						mqlAggRes.cacheOrgAwsRegions = agg.OrganizationAggregationSource.AwsRegions
					}

					res = append(res, mqlAggRes)
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

type mqlAwsConfigAggregatorInternal struct {
	lazyTags
	cacheOrgRoleArn       *string
	cacheOrgAllAwsRegions bool
	cacheOrgAwsRegions    []string
}

type mqlAwsConfigRuleInternal struct {
	lazyTags
}

type mqlAwsConfigConformancePackInternal struct {
	lazyTags
}

func (a *mqlAwsConfigAggregator) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsConfigAggregator) organizationAggregationSource() (*mqlAwsConfigAggregatorOrganizationAggregationSource, error) {
	if a.cacheOrgRoleArn == nil {
		a.OrganizationAggregationSource.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	awsRegions := make([]any, len(a.cacheOrgAwsRegions))
	for i, r := range a.cacheOrgAwsRegions {
		awsRegions[i] = r
	}

	mqlSrc, err := CreateResource(a.MqlRuntime, ResourceAwsConfigAggregatorOrganizationAggregationSource,
		map[string]*llx.RawData{
			"__id":          llx.StringData(a.Arn.Data + "/orgSource"),
			"allAwsRegions": llx.BoolData(a.cacheOrgAllAwsRegions),
			"awsRegions":    llx.ArrayData(awsRegions, types.String),
		})
	if err != nil {
		return nil, err
	}
	mqlSrcRes := mqlSrc.(*mqlAwsConfigAggregatorOrganizationAggregationSource)
	mqlSrcRes.cacheRoleArn = a.cacheOrgRoleArn
	return mqlSrcRes, nil
}

type mqlAwsConfigAggregatorOrganizationAggregationSourceInternal struct {
	cacheRoleArn *string
}

func (a *mqlAwsConfigAggregatorOrganizationAggregationSource) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsConfigAggregatorOrganizationAggregationSource) iamRole() (*mqlAwsIamRole, error) {
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

func (a *mqlAwsConfigAggregatorAccountAggregationSource) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsConfigRecorder) recordingStrategy() (string, error) {
	if a.cacheRecordingGroup == nil || a.cacheRecordingGroup.RecordingStrategy == nil {
		return "", nil
	}
	return string(a.cacheRecordingGroup.RecordingStrategy.UseOnly), nil
}

func (a *mqlAwsConfigRecorder) exclusionByResourceTypes() ([]any, error) {
	if a.cacheRecordingGroup == nil || a.cacheRecordingGroup.ExclusionByResourceTypes == nil {
		return []any{}, nil
	}
	res := make([]any, len(a.cacheRecordingGroup.ExclusionByResourceTypes.ResourceTypes))
	for i, rt := range a.cacheRecordingGroup.ExclusionByResourceTypes.ResourceTypes {
		res[i] = string(rt)
	}
	return res, nil
}

func (a *mqlAwsConfigDeliverychannel) id() (string, error) {
	name := a.Name.Data
	region := a.Region.Data
	return getName(name, region), nil
}

func (a *mqlAwsConfigDeliverychannel) deliveryFrequency() (string, error) {
	return a.cacheDeliveryFrequency, nil
}

func (a *mqlAwsConfigDeliverychannel) getDeliveryStatus() (*cstypes.DeliveryChannelStatus, error) {
	if a.deliveryStatusFetched {
		return a.cachedDeliveryStatus, nil
	}
	a.deliveryStatusLock.Lock()
	defer a.deliveryStatusLock.Unlock()
	if a.deliveryStatusFetched {
		return a.cachedDeliveryStatus, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.ConfigService(a.Region.Data)
	ctx := context.Background()

	channelName := a.Name.Data
	resp, err := svc.DescribeDeliveryChannelStatus(ctx, &configservice.DescribeDeliveryChannelStatusInput{
		DeliveryChannelNames: []string{channelName},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.deliveryStatusFetched = true
			return nil, nil
		}
		return nil, err
	}
	if len(resp.DeliveryChannelsStatus) > 0 {
		a.cachedDeliveryStatus = &resp.DeliveryChannelsStatus[0]
	}
	a.deliveryStatusFetched = true
	return a.cachedDeliveryStatus, nil
}

func (a *mqlAwsConfigDeliverychannel) lastSuccessfulDeliveryTime() (*time.Time, error) {
	status, err := a.getDeliveryStatus()
	if err != nil || status == nil {
		return nil, err
	}
	if status.ConfigSnapshotDeliveryInfo != nil {
		return status.ConfigSnapshotDeliveryInfo.LastSuccessfulTime, nil
	}
	return nil, nil
}

func (a *mqlAwsConfigDeliverychannel) lastFailedDeliveryTime() (*time.Time, error) {
	status, err := a.getDeliveryStatus()
	if err != nil || status == nil {
		return nil, err
	}
	if status.ConfigSnapshotDeliveryInfo != nil {
		return status.ConfigSnapshotDeliveryInfo.LastAttemptTime, nil
	}
	return nil, nil
}

func (a *mqlAwsConfigDeliverychannel) lastDeliveryStatus() (string, error) {
	status, err := a.getDeliveryStatus()
	if err != nil || status == nil {
		return "", err
	}
	if status.ConfigSnapshotDeliveryInfo != nil {
		return string(status.ConfigSnapshotDeliveryInfo.LastStatus), nil
	}
	return "", nil
}

type mqlAwsConfigDeliverychannelInternal struct {
	cachedDeliveryStatus   *cstypes.DeliveryChannelStatus
	cacheDeliveryFrequency string
	deliveryStatusFetched  bool
	deliveryStatusLock     sync.Mutex
}

func (a *mqlAwsConfigDeliverychannel) snsTopic() (*mqlAwsSnsTopic, error) {
	arnVal := a.SnsTopicARN.Data
	if arnVal == "" {
		a.SnsTopic.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sns.topic",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSnsTopic), nil
}

// configComplianceDetailID builds the cache key for a compliance detail. Every
// component of it is optional in the API response, including the recorded time,
// which is why the time is read through a nil check rather than dereferenced.
func configComplianceDetailID(ruleArn, resourceType, resourceID string, resultRecordedTime *time.Time) string {
	var recordedNanos int64
	if resultRecordedTime != nil {
		recordedNanos = resultRecordedTime.UnixNano()
	}
	return fmt.Sprintf("%s/complianceDetail/%s/%s/%d", ruleArn, resourceType, resourceID, recordedNanos)
}

func (a *mqlAwsConfigRule) complianceDetails() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ruleName := a.Name.Data
	region := a.Region.Data
	svc := conn.ConfigService(region)
	ctx := context.Background()

	res := []any{}
	var nextToken *string
	for {
		resp, err := svc.GetComplianceDetailsByConfigRule(ctx, &configservice.GetComplianceDetailsByConfigRuleInput{
			ConfigRuleName: &ruleName,
			NextToken:      nextToken,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}

		for _, eval := range resp.EvaluationResults {
			var resourceType, resourceId string
			var orderingTimestamp *time.Time
			if eval.EvaluationResultIdentifier != nil {
				if eval.EvaluationResultIdentifier.EvaluationResultQualifier != nil {
					resourceType = convert.ToValue(eval.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType)
					resourceId = convert.ToValue(eval.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId)
				}
				orderingTimestamp = eval.EvaluationResultIdentifier.OrderingTimestamp
			}

			mqlDetail, err := CreateResource(a.MqlRuntime, "aws.config.rule.complianceDetail",
				map[string]*llx.RawData{
					"__id":               llx.StringData(configComplianceDetailID(a.Arn.Data, resourceType, resourceId, eval.ResultRecordedTime)),
					"resourceType":       llx.StringData(resourceType),
					"resourceId":         llx.StringData(resourceId),
					"complianceType":     llx.StringData(string(eval.ComplianceType)),
					"annotation":         llx.StringDataPtr(eval.Annotation),
					"orderingTimestamp":  llx.TimeDataPtr(orderingTimestamp),
					"resultRecordedTime": llx.TimeDataPtr(eval.ResultRecordedTime),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDetail)
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return res, nil
}

func (a *mqlAwsConfigRule) remediation() (*mqlAwsConfigRuleRemediation, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ruleName := a.Name.Data
	region := a.Region.Data
	svc := conn.ConfigService(region)
	ctx := context.Background()

	resp, err := svc.DescribeRemediationConfigurations(ctx, &configservice.DescribeRemediationConfigurationsInput{
		ConfigRuleNames: []string{ruleName},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.Remediation.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	if len(resp.RemediationConfigurations) == 0 {
		a.Remediation.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	rem := resp.RemediationConfigurations[0]
	params, _ := convert.JsonToDict(rem.Parameters)

	var maxConcPct, maxErrPct string
	var retrySeconds int64
	if rem.ExecutionControls != nil && rem.ExecutionControls.SsmControls != nil {
		if rem.ExecutionControls.SsmControls.ConcurrentExecutionRatePercentage != nil {
			maxConcPct = fmt.Sprintf("%d", *rem.ExecutionControls.SsmControls.ConcurrentExecutionRatePercentage)
		}
		if rem.ExecutionControls.SsmControls.ErrorPercentage != nil {
			maxErrPct = fmt.Sprintf("%d", *rem.ExecutionControls.SsmControls.ErrorPercentage)
		}
	}
	if rem.RetryAttemptSeconds != nil {
		retrySeconds = *rem.RetryAttemptSeconds
	}

	mqlRem, err := CreateResource(a.MqlRuntime, "aws.config.rule.remediation",
		map[string]*llx.RawData{
			"__id":                    llx.StringData(fmt.Sprintf("%s/remediation", a.Arn.Data)),
			"targetType":              llx.StringData(string(rem.TargetType)),
			"targetId":                llx.StringDataPtr(rem.TargetId),
			"automatic":               llx.BoolData(rem.Automatic),
			"maxConcurrentPercentage": llx.StringData(maxConcPct),
			"maxErrorPercentage":      llx.StringData(maxErrPct),
			"retryAttemptSeconds":     llx.IntData(retrySeconds),
			"parameters":              llx.MapData(params, types.Any),
		})
	if err != nil {
		return nil, err
	}
	return mqlRem.(*mqlAwsConfigRuleRemediation), nil
}

func (a *mqlAwsConfigRuleComplianceDetail) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsConfigRuleRemediation) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsConfig) conformancePacks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getConformancePacks(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for _, job := range poolOfJobs.Jobs {
		res = append(res, job.Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsConfig) getConformancePacks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("config>getConformancePacks>calling aws with region %s", region)

			svc := conn.ConfigService(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeConformancePacks(ctx, &configservice.DescribeConformancePacksInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, pack := range resp.ConformancePackDetails {
					inputParams, _ := convert.JsonToDictSlice(pack.ConformancePackInputParameters)

					mqlPack, err := CreateResource(a.MqlRuntime, "aws.config.conformancePack",
						map[string]*llx.RawData{
							"name":                    llx.StringDataPtr(pack.ConformancePackName),
							"arn":                     llx.StringDataPtr(pack.ConformancePackArn),
							"region":                  llx.StringData(region),
							"deliveryS3Bucket":        llx.StringDataPtr(pack.DeliveryS3Bucket),
							"deliveryS3KeyPrefix":     llx.StringDataPtr(pack.DeliveryS3KeyPrefix),
							"inputParameters":         llx.ArrayData(inputParams, types.Dict),
							"lastUpdateRequestedTime": llx.TimeDataPtr(pack.LastUpdateRequestedTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPack)
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

func (a *mqlAwsConfigConformancePack) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsConfigConformancePack) complianceStatus() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.ConfigService(a.Region.Data)
	ctx := context.Background()

	packName := a.Name.Data
	resp, err := svc.GetConformancePackComplianceSummary(ctx, &configservice.GetConformancePackComplianceSummaryInput{
		ConformancePackNames: []string{packName},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return "INSUFFICIENT_DATA", nil
		}
		return "", err
	}
	if len(resp.ConformancePackComplianceSummaryList) > 0 {
		return string(resp.ConformancePackComplianceSummaryList[0].ConformancePackComplianceStatus), nil
	}
	return "INSUFFICIENT_DATA", nil
}

func (a *mqlAwsConfigConformancePack) ruleCompliance() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.ConfigService(a.Region.Data)
	ctx := context.Background()

	packName := a.Name.Data
	res := []any{}
	var nextToken *string
	for {
		resp, err := svc.DescribeConformancePackCompliance(ctx, &configservice.DescribeConformancePackComplianceInput{
			ConformancePackName: &packName,
			NextToken:           nextToken,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}

		for _, rule := range resp.ConformancePackRuleComplianceList {
			mqlRule, err := CreateResource(a.MqlRuntime, "aws.config.conformancePack.ruleCompliance",
				map[string]*llx.RawData{
					"__id":           llx.StringData(fmt.Sprintf("%s/ruleCompliance/%s", a.Arn.Data, convert.ToValue(rule.ConfigRuleName))),
					"ruleName":       llx.StringDataPtr(rule.ConfigRuleName),
					"complianceType": llx.StringData(string(rule.ComplianceType)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRule)
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return res, nil
}

func (a *mqlAwsConfigConformancePackRuleCompliance) id() (string, error) {
	return a.__id, nil
}
