// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	cptypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsCodepipeline) id() (string, error) {
	return "aws.codepipeline", nil
}

// ===== pipelines =====

func (a *mqlAwsCodepipeline) pipelines() ([]any, error) {
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

func (a *mqlAwsCodepipeline) getPipelines(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Codepipeline(region)
			ctx := context.Background()

			res := []any{}
			paginator := codepipeline.NewListPipelinesPaginator(svc, &codepipeline.ListPipelinesInput{})
			var names []string
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for i := range page.Pipelines {
					summary := page.Pipelines[i]
					if summary.Name != nil {
						names = append(names, *summary.Name)
					}
				}
			}

			pipelines := make([]plugin.Resource, len(names))
			g, _ := errgroup.WithContext(ctx)
			g.SetLimit(10)
			for i, name := range names {
				g.Go(func() error {
					mqlPipeline, err := newMqlAwsCodepipelinePipeline(a.MqlRuntime, region, name)
					if err != nil {
						if Is400AccessDeniedError(err) {
							log.Warn().Str("region", region).Str("pipeline", name).Msg("error accessing pipeline for AWS API")
							return nil
						}
						return err
					}
					pipelines[i] = mqlPipeline
					return nil
				})
			}
			if err := g.Wait(); err != nil {
				return nil, err
			}
			for _, p := range pipelines {
				if p == nil {
					continue
				}
				res = append(res, p)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// newMqlAwsCodepipelinePipeline builds a fully populated aws.codepipeline.pipeline
// from a name + region, calling GetPipeline for the full PipelineDeclaration and
// ListTagsForResource for tags. Returns nil when the pipeline cannot be fetched
// (e.g. it was deleted between list and get).
func newMqlAwsCodepipelinePipeline(runtime *plugin.Runtime, region, name string) (plugin.Resource, error) {
	ctx := context.Background()
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Codepipeline(region)

	gp, err := svc.GetPipeline(ctx, &codepipeline.GetPipelineInput{Name: &name})
	if err != nil {
		return nil, err
	}
	if gp.Pipeline == nil {
		return nil, nil
	}

	pipeline := gp.Pipeline
	meta := gp.Metadata

	var arn string
	var createdAt, updatedAt *time.Time
	if meta != nil {
		if meta.PipelineArn != nil {
			arn = *meta.PipelineArn
		}
		createdAt = meta.Created
		updatedAt = meta.Updated
	}

	artifactStoreDict, err := convert.JsonToDict(pipeline.ArtifactStore)
	if err != nil {
		return nil, err
	}
	artifactStoresMap, err := convert.JsonToDict(pipeline.ArtifactStores)
	if err != nil {
		return nil, err
	}

	stages, err := cpStagesToDicts(pipeline.Stages)
	if err != nil {
		return nil, err
	}
	triggers, err := cpTriggersToDicts(pipeline.Triggers)
	if err != nil {
		return nil, err
	}
	variables := cpVariablesToDicts(pipeline.Variables)

	tags := map[string]any{}
	if arn != "" {
		var nextToken *string
		for {
			tagOut, err := svc.ListTagsForResource(ctx, &codepipeline.ListTagsForResourceInput{
				ResourceArn: &arn,
				NextToken:   nextToken,
			})
			if err != nil {
				if Is400AccessDeniedError(err) {
					break
				}
				return nil, err
			}
			for _, t := range tagOut.Tags {
				tags[convert.ToValue(t.Key)] = convert.ToValue(t.Value)
			}
			if tagOut.NextToken == nil {
				break
			}
			nextToken = tagOut.NextToken
		}
	}

	version := int64(0)
	if pipeline.Version != nil {
		version = int64(*pipeline.Version)
	}

	args := map[string]*llx.RawData{
		"__id":           llx.StringData(arn),
		"arn":            llx.StringData(arn),
		"name":           llx.StringDataPtr(pipeline.Name),
		"version":        llx.IntData(version),
		"region":         llx.StringData(region),
		"createdAt":      llx.TimeDataPtr(createdAt),
		"updatedAt":      llx.TimeDataPtr(updatedAt),
		"pipelineType":   llx.StringData(string(pipeline.PipelineType)),
		"executionMode":  llx.StringData(string(pipeline.ExecutionMode)),
		"artifactStore":  llx.MapData(artifactStoreDict, types.String),
		"artifactStores": llx.MapData(artifactStoresMap, types.String),
		"stages":         llx.ArrayData(stages, types.Dict),
		"triggers":       llx.ArrayData(triggers, types.Dict),
		"variables":      llx.ArrayData(variables, types.Dict),
		"tags":           llx.MapData(tags, types.String),
	}

	obj, err := CreateResource(runtime, "aws.codepipeline.pipeline", args)
	if err != nil {
		return nil, err
	}
	mqlPipeline := obj.(*mqlAwsCodepipelinePipeline)
	mqlPipeline.cacheRoleArn = pipeline.RoleArn
	return mqlPipeline, nil
}

func (a *mqlAwsCodepipelinePipeline) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsCodepipelinePipelineInternal struct {
	cacheRoleArn *string
}

func (a *mqlAwsCodepipelinePipeline) role() (*mqlAwsIamRole, error) {
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

// ===== webhooks =====

func (a *mqlAwsCodepipeline) webhooks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getWebhooks(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCodepipeline) getWebhooks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Codepipeline(region)
			ctx := context.Background()

			res := []any{}
			var nextToken *string
			for {
				out, err := svc.ListWebhooks(ctx, &codepipeline.ListWebhooksInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for i := range out.Webhooks {
					wh := out.Webhooks[i]
					mqlWebhook, err := newMqlAwsCodepipelineWebhook(a.MqlRuntime, region, wh)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlWebhook)
				}
				if out.NextToken == nil {
					break
				}
				nextToken = out.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsCodepipelineWebhook(runtime *plugin.Runtime, region string, wh cptypes.ListWebhookItem) (plugin.Resource, error) {
	var arn, name, targetAction, targetPipeline, url, authentication, errorCode, errorMessage string
	var secretTokenPresent bool
	var authConfigDict map[string]any
	filters := []any{}

	if wh.Arn != nil {
		arn = *wh.Arn
	}
	if wh.Url != nil {
		url = *wh.Url
	}
	if wh.ErrorCode != nil {
		errorCode = *wh.ErrorCode
	}
	if wh.ErrorMessage != nil {
		errorMessage = *wh.ErrorMessage
	}

	if def := wh.Definition; def != nil {
		if def.Name != nil {
			name = *def.Name
		}
		if def.TargetAction != nil {
			targetAction = *def.TargetAction
		}
		if def.TargetPipeline != nil {
			targetPipeline = *def.TargetPipeline
		}
		authentication = string(def.Authentication)
		if ac := def.AuthenticationConfiguration; ac != nil {
			// SecretToken is intentionally projected as a boolean to avoid
			// leaking GitHub HMAC secrets into query output. Only the
			// non-sensitive AllowedIPRange is surfaced in the dict.
			secretTokenPresent = ac.SecretToken != nil && *ac.SecretToken != ""
			if ac.AllowedIPRange != nil && *ac.AllowedIPRange != "" {
				authConfigDict = map[string]any{
					"allowedIPRange": *ac.AllowedIPRange,
				}
			}
		}
		for _, f := range def.Filters {
			filters = append(filters, map[string]any{
				"jsonPath":    convert.ToValue(f.JsonPath),
				"matchEquals": convert.ToValue(f.MatchEquals),
			})
		}
	}

	tagsMap := cpTagsToMap(wh.Tags)

	id := arn
	if id == "" {
		// Fallback when ARN is missing: synthesise a stable ID per region/name.
		id = fmt.Sprintf("aws.codepipeline.webhook/%s/%s", region, name)
	}

	args := map[string]*llx.RawData{
		"__id":                        llx.StringData(id),
		"arn":                         llx.StringData(arn),
		"name":                        llx.StringData(name),
		"region":                      llx.StringData(region),
		"targetPipelineName":          llx.StringData(targetPipeline),
		"targetAction":                llx.StringData(targetAction),
		"filters":                     llx.ArrayData(filters, types.Dict),
		"authentication":              llx.StringData(authentication),
		"authenticationConfiguration": llx.MapData(authConfigDict, types.String),
		"secretTokenPresent":          llx.BoolData(secretTokenPresent),
		"url":                         llx.StringData(url),
		"lastTriggered":               llx.TimeDataPtr(wh.LastTriggered),
		"errorCode":                   llx.StringData(errorCode),
		"errorMessage":                llx.StringData(errorMessage),
		"tags":                        llx.MapData(tagsMap, types.String),
	}

	obj, err := CreateResource(runtime, "aws.codepipeline.webhook", args)
	if err != nil {
		return nil, err
	}
	mqlWebhook := obj.(*mqlAwsCodepipelineWebhook)
	mqlWebhook.cacheTargetPipeline = targetPipeline
	mqlWebhook.cacheRegion = region
	return mqlWebhook, nil
}

func (a *mqlAwsCodepipelineWebhook) id() (string, error) {
	if a.Arn.Data != "" {
		return a.Arn.Data, nil
	}
	return fmt.Sprintf("aws.codepipeline.webhook/%s/%s", a.Region.Data, a.Name.Data), nil
}

type mqlAwsCodepipelineWebhookInternal struct {
	cacheTargetPipeline string
	cacheRegion         string
}

func (a *mqlAwsCodepipelineWebhook) targetPipeline() (*mqlAwsCodepipelinePipeline, error) {
	if a.cacheTargetPipeline == "" || a.cacheRegion == "" {
		a.TargetPipeline.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlPipeline, err := newMqlAwsCodepipelinePipeline(a.MqlRuntime, a.cacheRegion, a.cacheTargetPipeline)
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.TargetPipeline.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if mqlPipeline == nil {
		a.TargetPipeline.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlPipeline.(*mqlAwsCodepipelinePipeline), nil
}

// ===== helpers =====

func cpTagsToMap(tags []cptypes.Tag) map[string]any {
	return tagsToMap(tags, func(t cptypes.Tag) *string { return t.Key }, func(t cptypes.Tag) *string { return t.Value })
}

func cpStagesToDicts(stages []cptypes.StageDeclaration) ([]any, error) {
	res := make([]any, 0, len(stages))
	for i := range stages {
		stage := stages[i]
		actions := make([]any, 0, len(stage.Actions))
		for j := range stage.Actions {
			action := stage.Actions[j]
			actionDict := map[string]any{
				"name":          convert.ToValue(action.Name),
				"configuration": stringMapToAnyMap(action.Configuration),
				"namespace":     convert.ToValue(action.Namespace),
				"region":        convert.ToValue(action.Region),
				"roleArn":       convert.ToValue(action.RoleArn),
			}
			if action.ActionTypeId != nil {
				actionDict["actionTypeId"] = map[string]any{
					"category": string(action.ActionTypeId.Category),
					"owner":    string(action.ActionTypeId.Owner),
					"provider": convert.ToValue(action.ActionTypeId.Provider),
					"version":  convert.ToValue(action.ActionTypeId.Version),
				}
			}
			if action.RunOrder != nil {
				actionDict["runOrder"] = int64(*action.RunOrder)
			}
			if action.TimeoutInMinutes != nil {
				actionDict["timeoutInMinutes"] = int64(*action.TimeoutInMinutes)
			}
			inputs := make([]any, 0, len(action.InputArtifacts))
			for k := range action.InputArtifacts {
				inputs = append(inputs, map[string]any{"name": convert.ToValue(action.InputArtifacts[k].Name)})
			}
			actionDict["inputArtifacts"] = inputs
			outputs := make([]any, 0, len(action.OutputArtifacts))
			for k := range action.OutputArtifacts {
				outputs = append(outputs, map[string]any{"name": convert.ToValue(action.OutputArtifacts[k].Name)})
			}
			actionDict["outputArtifacts"] = outputs
			envVars := make([]any, 0, len(action.EnvironmentVariables))
			for k := range action.EnvironmentVariables {
				envVars = append(envVars, map[string]any{
					"name":  convert.ToValue(action.EnvironmentVariables[k].Name),
					"value": convert.ToValue(action.EnvironmentVariables[k].Value),
					"type":  string(action.EnvironmentVariables[k].Type),
				})
			}
			actionDict["environmentVariables"] = envVars
			actions = append(actions, actionDict)
		}
		stageDict := map[string]any{
			"name":    convert.ToValue(stage.Name),
			"actions": actions,
		}
		res = append(res, stageDict)
	}
	return res, nil
}

func cpTriggersToDicts(triggers []cptypes.PipelineTriggerDeclaration) ([]any, error) {
	res := make([]any, 0, len(triggers))
	for i := range triggers {
		trigger := triggers[i]
		triggerDict := map[string]any{
			"providerType": string(trigger.ProviderType),
		}
		if trigger.GitConfiguration != nil {
			gitDict, err := convert.JsonToDict(trigger.GitConfiguration)
			if err != nil {
				return nil, err
			}
			triggerDict["gitConfiguration"] = gitDict
		}
		res = append(res, triggerDict)
	}
	return res, nil
}

func cpVariablesToDicts(vars []cptypes.PipelineVariableDeclaration) []any {
	res := make([]any, 0, len(vars))
	for i := range vars {
		v := vars[i]
		res = append(res, map[string]any{
			"name":         convert.ToValue(v.Name),
			"defaultValue": convert.ToValue(v.DefaultValue),
			"description":  convert.ToValue(v.Description),
		})
	}
	return res
}

func stringMapToAnyMap(m map[string]string) map[string]any {
	if m == nil {
		return nil
	}
	res := make(map[string]any, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}
