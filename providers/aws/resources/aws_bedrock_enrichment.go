// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// --- Inference profiles ---

func (a *mqlAwsBedrock) inferenceProfiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return bedrockCollectRegionJobs(jobpool.CreatePool(a.getInferenceProfiles(conn), 5))
}

func (a *mqlAwsBedrock) getInferenceProfiles(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			svc := conn.Bedrock(region)
			ctx := context.Background()
			res := []any{}
			paginator := bedrock.NewListInferenceProfilesPaginator(svc, &bedrock.ListInferenceProfilesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("bedrock is not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, ip := range page.InferenceProfileSummaries {
					modelArns := make([]any, 0, len(ip.Models))
					for _, m := range ip.Models {
						if m.ModelArn != nil {
							modelArns = append(modelArns, *m.ModelArn)
						}
					}
					mqlIP, err := CreateResource(a.MqlRuntime, "aws.bedrock.inferenceProfile", map[string]*llx.RawData{
						"__id":        llx.StringDataPtr(ip.InferenceProfileArn),
						"arn":         llx.StringDataPtr(ip.InferenceProfileArn),
						"id":          llx.StringDataPtr(ip.InferenceProfileId),
						"name":        llx.StringDataPtr(ip.InferenceProfileName),
						"region":      llx.StringData(region),
						"status":      llx.StringData(string(ip.Status)),
						"type":        llx.StringData(string(ip.Type)),
						"description": llx.StringDataPtr(ip.Description),
						"modelArns":   llx.ArrayData(modelArns, types.String),
						"createdAt":   llx.TimeDataPtr(ip.CreatedAt),
						"updatedAt":   llx.TimeDataPtr(ip.UpdatedAt),
					})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlIP)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsBedrockInferenceProfile) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsBedrockInferenceProfile) models() ([]any, error) {
	if a.ModelArns.Error != nil {
		return nil, a.ModelArns.Error
	}
	res := make([]any, 0, len(a.ModelArns.Data))
	for _, raw := range a.ModelArns.Data {
		arn, ok := raw.(string)
		if !ok || arn == "" {
			continue
		}
		model, err := NewResource(a.MqlRuntime, "aws.bedrock.foundationModel",
			map[string]*llx.RawData{"modelArn": llx.StringData(arn)})
		if err != nil {
			return nil, err
		}
		res = append(res, model)
	}
	return res, nil
}

// --- Imported models ---

func (a *mqlAwsBedrock) importedModels() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return bedrockCollectRegionJobs(jobpool.CreatePool(a.getImportedModels(conn), 5))
}

func (a *mqlAwsBedrock) getImportedModels(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			svc := conn.Bedrock(region)
			ctx := context.Background()
			res := []any{}
			paginator := bedrock.NewListImportedModelsPaginator(svc, &bedrock.ListImportedModelsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("bedrock is not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, im := range page.ModelSummaries {
					mqlIM, err := CreateResource(a.MqlRuntime, "aws.bedrock.importedModel", map[string]*llx.RawData{
						"__id":              llx.StringDataPtr(im.ModelArn),
						"arn":               llx.StringDataPtr(im.ModelArn),
						"name":              llx.StringDataPtr(im.ModelName),
						"region":            llx.StringData(region),
						"modelArchitecture": llx.StringDataPtr(im.ModelArchitecture),
						"instructSupported": llx.BoolDataPtr(im.InstructSupported),
						"createdAt":         llx.TimeDataPtr(im.CreationTime),
					})
					if err != nil {
						return nil, err
					}
					mqlIMRes := mqlIM.(*mqlAwsBedrockImportedModel)
					mqlIMRes.cacheRegion = region
					res = append(res, mqlIMRes)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsBedrockImportedModelInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     bool
	detail      *bedrock.GetImportedModelOutput
}

func (a *mqlAwsBedrockImportedModel) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsBedrockImportedModel) fetchDetail() (*bedrock.GetImportedModelOutput, error) {
	if a.fetched {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Bedrock(a.cacheRegion)
	ctx := context.Background()
	modelArn := a.Arn.Data
	detail, err := svc.GetImportedModel(ctx, &bedrock.GetImportedModelInput{ModelIdentifier: &modelArn})
	if err != nil {
		return nil, err
	}
	a.detail = detail
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsBedrockImportedModel) kmsKey() (*mqlAwsKmsKey, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.ModelKmsKeyArn == nil || *detail.ModelKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.ModelKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

// --- Prompts ---

func (a *mqlAwsBedrock) prompts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return bedrockCollectRegionJobs(jobpool.CreatePool(a.getPrompts(conn), 5))
}

func (a *mqlAwsBedrock) getPrompts(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			svc := conn.BedrockAgent(region)
			ctx := context.Background()
			res := []any{}
			paginator := bedrockagent.NewListPromptsPaginator(svc, &bedrockagent.ListPromptsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("bedrock is not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, p := range page.PromptSummaries {
					mqlPrompt, err := CreateResource(a.MqlRuntime, "aws.bedrock.prompt", map[string]*llx.RawData{
						"__id":        llx.StringDataPtr(p.Arn),
						"arn":         llx.StringDataPtr(p.Arn),
						"id":          llx.StringDataPtr(p.Id),
						"name":        llx.StringDataPtr(p.Name),
						"region":      llx.StringData(region),
						"version":     llx.StringDataPtr(p.Version),
						"description": llx.StringDataPtr(p.Description),
						"createdAt":   llx.TimeDataPtr(p.CreatedAt),
						"updatedAt":   llx.TimeDataPtr(p.UpdatedAt),
					})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPrompt)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsBedrockPrompt) id() (string, error) {
	return a.Arn.Data, nil
}

// --- Agent aliases ---

func (a *mqlAwsBedrockAgent) aliases() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgent(a.cacheRegion)
	ctx := context.Background()
	agentId := a.Id.Data
	region := a.Region.Data
	res := []any{}
	paginator := bedrockagent.NewListAgentAliasesPaginator(svc, &bedrockagent.ListAgentAliasesInput{AgentId: &agentId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "bedrock:ListAgentAliases")
		}
		for _, al := range page.AgentAliasSummaries {
			aliasId := convert.ToValue(al.AgentAliasId)
			routing, err := convert.JsonToDictSlice(al.RoutingConfiguration)
			if err != nil {
				return nil, err
			}
			mqlAlias, err := CreateResource(a.MqlRuntime, "aws.bedrock.agent.alias", map[string]*llx.RawData{
				"__id":                 llx.StringData(region + "/" + agentId + "/alias/" + aliasId),
				"id":                   llx.StringDataPtr(al.AgentAliasId),
				"agentId":              llx.StringData(agentId),
				"name":                 llx.StringDataPtr(al.AgentAliasName),
				"region":               llx.StringData(region),
				"status":               llx.StringData(string(al.AgentAliasStatus)),
				"description":          llx.StringDataPtr(al.Description),
				"invocationState":      llx.StringData(string(al.AliasInvocationState)),
				"routingConfiguration": llx.ArrayData(routing, types.Dict),
				"createdAt":            llx.TimeDataPtr(al.CreatedAt),
				"updatedAt":            llx.TimeDataPtr(al.UpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAlias)
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockAgentAlias) id() (string, error) {
	return a.Region.Data + "/" + a.AgentId.Data + "/alias/" + a.Id.Data, nil
}

// bedrockCollectRegionJobs runs a region-fanned job pool and flattens the
// []any results, mirroring the aggregation used elsewhere in this package.
func bedrockCollectRegionJobs(poolOfJobs *jobpool.Pool) ([]any, error) {
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	res := []any{}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}
