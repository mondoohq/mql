// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// bedrockRegionJobs fans a per-region collector across the connection's regions,
// tolerating the two failures every Bedrock region loop hits: the service being
// absent from a region, and the account lacking access to it.
func bedrockRegionJobs(conn *connection.AwsConnection, collect func(svc *bedrock.Client, region string) ([]any, error)) []*jobpool.Job {
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		region := region
		tasks = append(tasks, jobpool.NewJob(func() (jobpool.JobResult, error) {
			res, err := collect(conn.Bedrock(region), region)
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return []any{}, nil
				}
				if IsServiceNotAvailableInRegionError(err) {
					log.Debug().Str("region", region).Msg("bedrock is not available in region")
					return []any{}, nil
				}
				return nil, err
			}
			return jobpool.JobResult(res), nil
		}))
	}
	return tasks
}

// --- Account-wide enforced guardrails ---

func (a *mqlAwsBedrock) enforcedGuardrails() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return bedrockCollectRegionJobs(jobpool.CreatePool(bedrockRegionJobs(conn, a.collectEnforcedGuardrails), 5))
}

func (a *mqlAwsBedrock) collectEnforcedGuardrails(svc *bedrock.Client, region string) ([]any, error) {
	ctx := context.Background()
	res := []any{}
	var nextToken *string
	for {
		page, err := svc.ListEnforcedGuardrailsConfiguration(ctx, &bedrock.ListEnforcedGuardrailsConfigurationInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}
		for _, g := range page.GuardrailsConfig {
			configId := convert.ToValue(g.ConfigId)
			modelEnforcement, _ := convert.JsonToDict(g.ModelEnforcement)
			selectiveContentGuarding, _ := convert.JsonToDict(g.SelectiveContentGuarding)

			mqlEG, err := CreateResource(a.MqlRuntime, "aws.bedrock.enforcedGuardrail",
				map[string]*llx.RawData{
					"__id":                     llx.StringData("aws.bedrock.enforcedGuardrail/" + region + "/" + configId),
					"configId":                 llx.StringData(configId),
					"region":                   llx.StringData(region),
					"guardrailId":              llx.StringDataPtr(g.GuardrailId),
					"guardrailVersion":         llx.StringDataPtr(g.GuardrailVersion),
					"owner":                    llx.StringData(string(g.Owner)),
					"modelEnforcement":         llx.DictData(modelEnforcement),
					"selectiveContentGuarding": llx.DictData(selectiveContentGuarding),
					"createdBy":                llx.StringDataPtr(g.CreatedBy),
					"updatedBy":                llx.StringDataPtr(g.UpdatedBy),
					"createdAt":                llx.TimeDataPtr(g.CreatedAt),
					"updatedAt":                llx.TimeDataPtr(g.UpdatedAt),
				})
			if err != nil {
				return nil, err
			}
			mqlEGRes := mqlEG.(*mqlAwsBedrockEnforcedGuardrail)
			mqlEGRes.cacheGuardrailArn = convert.ToValue(g.GuardrailArn)
			res = append(res, mqlEGRes)
		}
		if page.NextToken == nil {
			break
		}
		nextToken = page.NextToken
	}
	return res, nil
}

type mqlAwsBedrockEnforcedGuardrailInternal struct {
	cacheGuardrailArn string
}

func (a *mqlAwsBedrockEnforcedGuardrail) id() (string, error) {
	return "aws.bedrock.enforcedGuardrail/" + a.Region.Data + "/" + a.ConfigId.Data, nil
}

func (a *mqlAwsBedrockEnforcedGuardrail) guardrail() (*mqlAwsBedrockGuardrail, error) {
	args := map[string]*llx.RawData{}
	switch {
	case a.cacheGuardrailArn != "":
		args["arn"] = llx.StringData(a.cacheGuardrailArn)
	case a.GuardrailId.Data != "":
		args["id"] = llx.StringData(a.GuardrailId.Data)
		args["region"] = llx.StringData(a.Region.Data)
	default:
		a.Guardrail.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.bedrock.guardrail", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBedrockGuardrail), nil
}

// --- Account data retention ---

func (a *mqlAwsBedrock) dataRetentionConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return bedrockCollectRegionJobs(jobpool.CreatePool(bedrockRegionJobs(conn, a.collectDataRetention), 5))
}

func (a *mqlAwsBedrock) collectDataRetention(svc *bedrock.Client, region string) ([]any, error) {
	resp, err := svc.GetAccountDataRetention(context.Background(), &bedrock.GetAccountDataRetentionInput{})
	if err != nil {
		// Retention control is newer than Bedrock itself, so a region that serves
		// Bedrock may still reject the call. Report no setting for that region
		// rather than failing the whole account's retention query.
		if isResourceNotFoundError(err) || isOperationNotSupportedError(err) {
			log.Debug().Str("region", region).Msg("bedrock account data retention is not available in region")
			return []any{}, nil
		}
		return nil, err
	}
	if resp == nil {
		return []any{}, nil
	}
	mqlDR, err := CreateResource(a.MqlRuntime, "aws.bedrock.dataRetentionConfiguration",
		map[string]*llx.RawData{
			"__id":      llx.StringData("aws.bedrock.dataRetentionConfiguration/" + region),
			"region":    llx.StringData(region),
			"mode":      llx.StringData(string(resp.Mode)),
			"updatedAt": llx.TimeDataPtr(resp.UpdatedAt),
		})
	if err != nil {
		return nil, err
	}
	return []any{mqlDR}, nil
}

func (a *mqlAwsBedrockDataRetentionConfiguration) id() (string, error) {
	return "aws.bedrock.dataRetentionConfiguration/" + a.Region.Data, nil
}

// --- Model customization jobs ---

func (a *mqlAwsBedrock) modelCustomizationJobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return bedrockCollectRegionJobs(jobpool.CreatePool(bedrockRegionJobs(conn, a.collectModelCustomizationJobs), 5))
}

func (a *mqlAwsBedrock) collectModelCustomizationJobs(svc *bedrock.Client, region string) ([]any, error) {
	ctx := context.Background()
	res := []any{}
	paginator := bedrock.NewListModelCustomizationJobsPaginator(svc, &bedrock.ListModelCustomizationJobsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, j := range page.ModelCustomizationJobSummaries {
			mqlJob, err := CreateResource(a.MqlRuntime, "aws.bedrock.modelCustomizationJob",
				map[string]*llx.RawData{
					"__id":              llx.StringDataPtr(j.JobArn),
					"jobArn":            llx.StringDataPtr(j.JobArn),
					"jobName":           llx.StringDataPtr(j.JobName),
					"region":            llx.StringData(region),
					"status":            llx.StringData(string(j.Status)),
					"customizationType": llx.StringData(string(j.CustomizationType)),
					"customModelName":   llx.StringDataPtr(j.CustomModelName),
					"createdAt":         llx.TimeDataPtr(j.CreationTime),
					"lastModifiedAt":    llx.TimeDataPtr(j.LastModifiedTime),
					"endTime":           llx.TimeDataPtr(j.EndTime),
				})
			if err != nil {
				return nil, err
			}
			mqlJobRes := mqlJob.(*mqlAwsBedrockModelCustomizationJob)
			mqlJobRes.cacheRegion = region
			mqlJobRes.cacheBaseModelArn = convert.ToValue(j.BaseModelArn)
			mqlJobRes.cacheCustomModelArn = convert.ToValue(j.CustomModelArn)
			res = append(res, mqlJobRes)
		}
	}
	return res, nil
}

type mqlAwsBedrockModelCustomizationJobInternal struct {
	cacheRegion         string
	cacheBaseModelArn   string
	cacheCustomModelArn string
	fetchLock           sync.Mutex
	fetched             bool
	detail              *bedrock.GetModelCustomizationJobOutput
	detailErr           error
}

func (a *mqlAwsBedrockModelCustomizationJob) id() (string, error) {
	return a.JobArn.Data, nil
}

func (a *mqlAwsBedrockModelCustomizationJob) fetchDetail() (*bedrock.GetModelCustomizationJobOutput, error) {
	if a.fetched {
		return a.detail, a.detailErr
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, a.detailErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Bedrock(a.cacheRegion)
	jobId := a.JobArn.Data
	detail, err := svc.GetModelCustomizationJob(context.Background(), &bedrock.GetModelCustomizationJobInput{
		JobIdentifier: &jobId,
	})
	if err != nil {
		a.fetched = true
		a.detailErr = classifyAwsError(err, "bedrock:GetModelCustomizationJob")
		return nil, a.detailErr
	}
	a.detail = detail
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsBedrockModelCustomizationJob) baseModel() (*mqlAwsBedrockFoundationModel, error) {
	if a.cacheBaseModelArn == "" {
		a.BaseModel.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.bedrock.foundationModel",
		map[string]*llx.RawData{"modelArn": llx.StringData(a.cacheBaseModelArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBedrockFoundationModel), nil
}

// customModel resolves the model the job produced. Null while the job is still
// running or after it failed, since no model exists in either case.
func (a *mqlAwsBedrockModelCustomizationJob) customModel() (*mqlAwsBedrockCustomModel, error) {
	if a.cacheCustomModelArn == "" {
		a.CustomModel.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.bedrock.customModel",
		map[string]*llx.RawData{"modelArn": llx.StringData(a.cacheCustomModelArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBedrockCustomModel), nil
}

func (a *mqlAwsBedrockModelCustomizationJob) iamRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || convert.ToValue(detail.RoleArn) == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.RoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBedrockModelCustomizationJob) trainingDataS3Uri() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil || detail.TrainingDataConfig == nil {
		return "", err
	}
	return convert.ToValue(detail.TrainingDataConfig.S3Uri), nil
}

func (a *mqlAwsBedrockModelCustomizationJob) trainingDataBucket() (*mqlAwsS3Bucket, error) {
	uri, err := a.trainingDataS3Uri()
	if err != nil {
		return nil, err
	}
	return s3BucketRefFromUri(a.MqlRuntime, uri, &a.TrainingDataBucket)
}

// invocationLogsConfig reports whether the job trained on captured production
// invocation logs instead of, or alongside, a curated dataset.
func (a *mqlAwsBedrockModelCustomizationJob) invocationLogsConfig() (any, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil || detail.TrainingDataConfig == nil ||
		detail.TrainingDataConfig.InvocationLogsConfig == nil {
		return nil, err
	}
	result, _ := convert.JsonToDict(detail.TrainingDataConfig.InvocationLogsConfig)
	return result, nil
}

func (a *mqlAwsBedrockModelCustomizationJob) validationDataS3Uris() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if detail == nil || detail.ValidationDataConfig == nil {
		return res, nil
	}
	for _, v := range detail.ValidationDataConfig.Validators {
		if uri := convert.ToValue(v.S3Uri); uri != "" {
			res = append(res, uri)
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockModelCustomizationJob) outputDataS3Uri() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil || detail.OutputDataConfig == nil {
		return "", err
	}
	return convert.ToValue(detail.OutputDataConfig.S3Uri), nil
}

func (a *mqlAwsBedrockModelCustomizationJob) outputDataBucket() (*mqlAwsS3Bucket, error) {
	uri, err := a.outputDataS3Uri()
	if err != nil {
		return nil, err
	}
	return s3BucketRefFromUri(a.MqlRuntime, uri, &a.OutputDataBucket)
}

func (a *mqlAwsBedrockModelCustomizationJob) outputModelKmsKey() (*mqlAwsKmsKey, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || convert.ToValue(detail.OutputModelKmsKeyArn) == "" {
		a.OutputModelKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.OutputModelKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

// customizationJobSubnetIds returns the subnets the training container attached
// to, or nil when the job ran outside a VPC.
func (a *mqlAwsBedrockModelCustomizationJob) customizationJobSubnetIds() ([]string, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil || detail.VpcConfig == nil {
		return nil, err
	}
	return detail.VpcConfig.SubnetIds, nil
}

func (a *mqlAwsBedrockModelCustomizationJob) vpc() (*mqlAwsVpc, error) {
	subnetIds, err := a.customizationJobSubnetIds()
	if err != nil {
		return nil, err
	}
	return awsResolveVpcFromSubnets(a.MqlRuntime, a.cacheRegion, subnetIds, &a.Vpc)
}

func (a *mqlAwsBedrockModelCustomizationJob) subnets() ([]any, error) {
	subnetIds, err := a.customizationJobSubnetIds()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, subnetId := range subnetIds {
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{"id": llx.StringData(subnetId)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsBedrockModelCustomizationJob) securityGroups() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.VpcConfig == nil {
		return []any{}, nil
	}
	sgs, err := awsSecurityGroupRefs(a.MqlRuntime, a.cacheRegion, detail.VpcConfig.SecurityGroupIds)
	if err != nil {
		return nil, err
	}
	if sgs == nil {
		return []any{}, nil
	}
	return sgs, nil
}

func (a *mqlAwsBedrockModelCustomizationJob) hyperParameters() (map[string]any, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(detail.HyperParameters), nil
}

func (a *mqlAwsBedrockModelCustomizationJob) failureMessage() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil {
		return "", err
	}
	return convert.ToValue(detail.FailureMessage), nil
}

// --- Model copy jobs ---

func (a *mqlAwsBedrock) modelCopyJobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return bedrockCollectRegionJobs(jobpool.CreatePool(bedrockRegionJobs(conn, a.collectModelCopyJobs), 5))
}

func (a *mqlAwsBedrock) collectModelCopyJobs(svc *bedrock.Client, region string) ([]any, error) {
	ctx := context.Background()
	res := []any{}
	paginator := bedrock.NewListModelCopyJobsPaginator(svc, &bedrock.ListModelCopyJobsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, j := range page.ModelCopyJobSummaries {
			tags := make(map[string]any, len(j.TargetModelTags))
			for _, t := range j.TargetModelTags {
				tags[convert.ToValue(t.Key)] = convert.ToValue(t.Value)
			}
			mqlJob, err := CreateResource(a.MqlRuntime, "aws.bedrock.modelCopyJob",
				map[string]*llx.RawData{
					"__id":            llx.StringDataPtr(j.JobArn),
					"jobArn":          llx.StringDataPtr(j.JobArn),
					"region":          llx.StringData(region),
					"status":          llx.StringData(string(j.Status)),
					"sourceAccountId": llx.StringDataPtr(j.SourceAccountId),
					"sourceModelArn":  llx.StringDataPtr(j.SourceModelArn),
					"sourceModelName": llx.StringDataPtr(j.SourceModelName),
					"targetModelArn":  llx.StringDataPtr(j.TargetModelArn),
					"targetModelName": llx.StringDataPtr(j.TargetModelName),
					"targetModelTags": llx.MapData(tags, types.String),
					"failureMessage":  llx.StringDataPtr(j.FailureMessage),
					"createdAt":       llx.TimeDataPtr(j.CreationTime),
				})
			if err != nil {
				return nil, err
			}
			mqlJobRes := mqlJob.(*mqlAwsBedrockModelCopyJob)
			mqlJobRes.cacheTargetModelKmsKeyArn = convert.ToValue(j.TargetModelKmsKeyArn)
			res = append(res, mqlJobRes)
		}
	}
	return res, nil
}

type mqlAwsBedrockModelCopyJobInternal struct {
	cacheTargetModelKmsKeyArn string
}

func (a *mqlAwsBedrockModelCopyJob) id() (string, error) {
	return a.JobArn.Data, nil
}

func (a *mqlAwsBedrockModelCopyJob) targetModelKmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheTargetModelKmsKeyArn == "" {
		a.TargetModelKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheTargetModelKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

// --- Marketplace model endpoints ---

func (a *mqlAwsBedrock) marketplaceModelEndpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return bedrockCollectRegionJobs(jobpool.CreatePool(bedrockRegionJobs(conn, a.collectMarketplaceModelEndpoints), 5))
}

func (a *mqlAwsBedrock) collectMarketplaceModelEndpoints(svc *bedrock.Client, region string) ([]any, error) {
	ctx := context.Background()
	res := []any{}
	paginator := bedrock.NewListMarketplaceModelEndpointsPaginator(svc, &bedrock.ListMarketplaceModelEndpointsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, e := range page.MarketplaceModelEndpoints {
			mqlEP, err := CreateResource(a.MqlRuntime, "aws.bedrock.marketplaceModelEndpoint",
				map[string]*llx.RawData{
					"__id":                  llx.StringDataPtr(e.EndpointArn),
					"endpointArn":           llx.StringDataPtr(e.EndpointArn),
					"region":                llx.StringData(region),
					"modelSourceIdentifier": llx.StringDataPtr(e.ModelSourceIdentifier),
					"status":                llx.StringData(string(e.Status)),
					"statusMessage":         llx.StringDataPtr(e.StatusMessage),
					"createdAt":             llx.TimeDataPtr(e.CreatedAt),
					"updatedAt":             llx.TimeDataPtr(e.UpdatedAt),
				})
			if err != nil {
				return nil, err
			}
			mqlEPRes := mqlEP.(*mqlAwsBedrockMarketplaceModelEndpoint)
			mqlEPRes.cacheRegion = region
			res = append(res, mqlEPRes)
		}
	}
	return res, nil
}

type mqlAwsBedrockMarketplaceModelEndpointInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     bool
	detail      *bedrocktypes.MarketplaceModelEndpoint
	detailErr   error
}

func (a *mqlAwsBedrockMarketplaceModelEndpoint) id() (string, error) {
	return a.EndpointArn.Data, nil
}

func (a *mqlAwsBedrockMarketplaceModelEndpoint) fetchDetail() (*bedrocktypes.MarketplaceModelEndpoint, error) {
	if a.fetched {
		return a.detail, a.detailErr
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, a.detailErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Bedrock(a.cacheRegion)
	endpointArn := a.EndpointArn.Data
	resp, err := svc.GetMarketplaceModelEndpoint(context.Background(), &bedrock.GetMarketplaceModelEndpointInput{
		EndpointArn: &endpointArn,
	})
	if err != nil {
		a.fetched = true
		a.detailErr = classifyAwsError(err, "bedrock:GetMarketplaceModelEndpoint")
		return nil, a.detailErr
	}
	if resp != nil {
		a.detail = resp.MarketplaceModelEndpoint
	}
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsBedrockMarketplaceModelEndpoint) endpointStatus() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil {
		return "", err
	}
	return convert.ToValue(detail.EndpointStatus), nil
}

func (a *mqlAwsBedrockMarketplaceModelEndpoint) endpointStatusMessage() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil {
		return "", err
	}
	return convert.ToValue(detail.EndpointStatusMessage), nil
}

// endpointConfig flattens the endpoint-config union into the SageMaker hosting
// configuration behind the model.
func (a *mqlAwsBedrockMarketplaceModelEndpoint) endpointConfig() (any, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil || detail.EndpointConfig == nil {
		return nil, err
	}
	sageMaker, ok := detail.EndpointConfig.(*bedrocktypes.EndpointConfigMemberSageMaker)
	if !ok {
		return nil, nil
	}
	result, _ := convert.JsonToDict(sageMaker.Value)
	return result, nil
}
