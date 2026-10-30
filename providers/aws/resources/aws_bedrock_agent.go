// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

// agentDraftVersion is the working version an agent's action groups, knowledge
// bases, and collaborators are read from. Aliases point at numbered prepared
// versions, but DRAFT is what the console edits and what the next prepare
// publishes, so it is the configuration to audit.
const agentDraftVersion = "DRAFT"

// --- Guardrail and orchestration posture ---

// guardrail resolves the guardrail applied to the agent's model invocations.
// GuardrailIdentifier accepts either a bare guardrail id or a full ARN, so both
// forms are handled here.
func (a *mqlAwsBedrockAgent) guardrail() (*mqlAwsBedrockGuardrail, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.Agent == nil || detail.Agent.GuardrailConfiguration == nil {
		a.Guardrail.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	identifier := convert.ToValue(detail.Agent.GuardrailConfiguration.GuardrailIdentifier)
	if identifier == "" {
		a.Guardrail.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	args := map[string]*llx.RawData{}
	if strings.HasPrefix(identifier, "arn:") {
		args["arn"] = llx.StringData(identifier)
	} else {
		args["id"] = llx.StringData(identifier)
		args["region"] = llx.StringData(a.Region.Data)
	}
	res, err := NewResource(a.MqlRuntime, "aws.bedrock.guardrail", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBedrockGuardrail), nil
}

func (a *mqlAwsBedrockAgent) guardrailVersion() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.Agent == nil || detail.Agent.GuardrailConfiguration == nil {
		return "", nil
	}
	return convert.ToValue(detail.Agent.GuardrailConfiguration.GuardrailVersion), nil
}

func (a *mqlAwsBedrockAgent) agentCollaboration() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.Agent == nil {
		return "", nil
	}
	return string(detail.Agent.AgentCollaboration), nil
}

func (a *mqlAwsBedrockAgent) orchestrationType() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.Agent == nil {
		return "", nil
	}
	return string(detail.Agent.OrchestrationType), nil
}

// customOrchestrationLambda resolves the function that replaces Bedrock's
// built-in orchestration loop. Null on agents using DEFAULT orchestration.
func (a *mqlAwsBedrockAgent) customOrchestrationLambda() (*mqlAwsLambdaFunction, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.Agent == nil || detail.Agent.CustomOrchestration == nil {
		a.CustomOrchestrationLambda.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	lambdaArn := ""
	if executor, ok := detail.Agent.CustomOrchestration.Executor.(*bedrockagenttypes.OrchestrationExecutorMemberLambda); ok {
		lambdaArn = executor.Value
	}
	return bedrockLambdaRef(a.MqlRuntime, lambdaArn, &a.CustomOrchestrationLambda)
}

// --- Session memory ---

func (a *mqlAwsBedrockAgent) enabledMemoryTypes() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.Agent == nil || detail.Agent.MemoryConfiguration == nil {
		return []any{}, nil
	}
	return enumSliceToAny(detail.Agent.MemoryConfiguration.EnabledMemoryTypes), nil
}

func (a *mqlAwsBedrockAgent) memoryStorageDays() (int64, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail == nil || detail.Agent == nil || detail.Agent.MemoryConfiguration == nil ||
		detail.Agent.MemoryConfiguration.StorageDays == nil {
		return 0, nil
	}
	return int64(*detail.Agent.MemoryConfiguration.StorageDays), nil
}

func (a *mqlAwsBedrockAgent) memoryMaxRecentSessions() (int64, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail == nil || detail.Agent == nil || detail.Agent.MemoryConfiguration == nil ||
		detail.Agent.MemoryConfiguration.SessionSummaryConfiguration == nil ||
		detail.Agent.MemoryConfiguration.SessionSummaryConfiguration.MaxRecentSessions == nil {
		return 0, nil
	}
	return int64(*detail.Agent.MemoryConfiguration.SessionSummaryConfiguration.MaxRecentSessions), nil
}

// --- Prompt overrides ---

// overriddenPromptTypes lists the prompt stages whose Bedrock-supplied template
// has been replaced. PromptCreationMode is what records the replacement:
// DEFAULT means Bedrock's template is in use, OVERRIDDEN means a custom one is.
func (a *mqlAwsBedrockAgent) overriddenPromptTypes() ([]any, error) {
	return a.promptTypesWhere(func(p bedrockagenttypes.PromptConfiguration) bool {
		return p.PromptCreationMode == bedrockagenttypes.CreationModeOverridden
	})
}

// disabledPromptTypes lists the prompt stages the agent skips entirely.
func (a *mqlAwsBedrockAgent) disabledPromptTypes() ([]any, error) {
	return a.promptTypesWhere(func(p bedrockagenttypes.PromptConfiguration) bool {
		return p.PromptState == bedrockagenttypes.PromptStateDisabled
	})
}

func (a *mqlAwsBedrockAgent) promptTypesWhere(match func(bedrockagenttypes.PromptConfiguration) bool) ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if detail == nil || detail.Agent == nil || detail.Agent.PromptOverrideConfiguration == nil {
		return res, nil
	}
	for _, p := range detail.Agent.PromptOverrideConfiguration.PromptConfigurations {
		if match(p) {
			res = append(res, string(p.PromptType))
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockAgent) promptOverrideLambda() (*mqlAwsLambdaFunction, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	lambdaArn := ""
	if detail != nil && detail.Agent != nil && detail.Agent.PromptOverrideConfiguration != nil {
		lambdaArn = convert.ToValue(detail.Agent.PromptOverrideConfiguration.OverrideLambda)
	}
	return bedrockLambdaRef(a.MqlRuntime, lambdaArn, &a.PromptOverrideLambda)
}

// bedrockLambdaRef resolves a Lambda ARN to a typed function, marking the field
// null when no ARN is configured.
func bedrockLambdaRef(runtime *plugin.Runtime, lambdaArn string, field *plugin.TValue[*mqlAwsLambdaFunction]) (*mqlAwsLambdaFunction, error) {
	if lambdaArn == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.lambda.function",
		map[string]*llx.RawData{"arn": llx.StringData(lambdaArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaFunction), nil
}

// --- Attached knowledge bases ---

// attachedKnowledgeBases resolves the knowledge bases associated with the
// agent's DRAFT version. The association carries only the knowledge-base id, so
// each one is resolved through the knowledge-base init.
func (a *mqlAwsBedrockAgent) attachedKnowledgeBases() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgent(a.cacheRegion)
	ctx := context.Background()
	agentId := a.Id.Data
	draft := agentDraftVersion
	region := a.Region.Data
	res := []any{}

	paginator := bedrockagent.NewListAgentKnowledgeBasesPaginator(svc, &bedrockagent.ListAgentKnowledgeBasesInput{
		AgentId:      &agentId,
		AgentVersion: &draft,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, kb := range page.AgentKnowledgeBaseSummaries {
			kbId := convert.ToValue(kb.KnowledgeBaseId)
			if kbId == "" {
				continue
			}
			mqlKB, err := NewResource(a.MqlRuntime, "aws.bedrock.knowledgeBase",
				map[string]*llx.RawData{
					"id":     llx.StringData(kbId),
					"region": llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlKB)
		}
	}
	return res, nil
}

// --- Action groups ---

func (a *mqlAwsBedrockAgent) actionGroupDetails() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgent(a.cacheRegion)
	ctx := context.Background()
	agentId := a.Id.Data
	draft := agentDraftVersion
	region := a.Region.Data
	res := []any{}

	paginator := bedrockagent.NewListAgentActionGroupsPaginator(svc, &bedrockagent.ListAgentActionGroupsInput{
		AgentId:      &agentId,
		AgentVersion: &draft,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, ag := range page.ActionGroupSummaries {
			actionGroupId := convert.ToValue(ag.ActionGroupId)
			mqlAG, err := CreateResource(a.MqlRuntime, "aws.bedrock.agent.actionGroup",
				map[string]*llx.RawData{
					"__id":        llx.StringData(region + "/" + agentId + "/actionGroup/" + actionGroupId),
					"id":          llx.StringData(actionGroupId),
					"agentId":     llx.StringData(agentId),
					"region":      llx.StringData(region),
					"name":        llx.StringDataPtr(ag.ActionGroupName),
					"state":       llx.StringData(string(ag.ActionGroupState)),
					"description": llx.StringDataPtr(ag.Description),
					"updatedAt":   llx.TimeDataPtr(ag.UpdatedAt),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAG)
		}
	}
	return res, nil
}

type mqlAwsBedrockAgentActionGroupInternal struct {
	fetchLock sync.Mutex
	fetched   bool
	detail    *bedrockagent.GetAgentActionGroupOutput
}

func (a *mqlAwsBedrockAgentActionGroup) id() (string, error) {
	return a.Region.Data + "/" + a.AgentId.Data + "/actionGroup/" + a.Id.Data, nil
}

// fetchDetail loads the executor and schema, which the list operation does not
// return. Only the fields that need them trigger the call.
func (a *mqlAwsBedrockAgentActionGroup) fetchDetail() (*bedrockagent.GetAgentActionGroupOutput, error) {
	if a.fetched {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgent(a.Region.Data)
	agentId := a.AgentId.Data
	actionGroupId := a.Id.Data
	draft := agentDraftVersion
	detail, err := svc.GetAgentActionGroup(context.Background(), &bedrockagent.GetAgentActionGroupInput{
		AgentId:       &agentId,
		AgentVersion:  &draft,
		ActionGroupId: &actionGroupId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.fetched = true
			return nil, nil
		}
		return nil, err
	}
	a.detail = detail
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsBedrockAgentActionGroup) executorLambda() (*mqlAwsLambdaFunction, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	lambdaArn := ""
	if detail != nil && detail.AgentActionGroup != nil {
		if executor, ok := detail.AgentActionGroup.ActionGroupExecutor.(*bedrockagenttypes.ActionGroupExecutorMemberLambda); ok {
			lambdaArn = executor.Value
		}
	}
	return bedrockLambdaRef(a.MqlRuntime, lambdaArn, &a.ExecutorLambda)
}

// returnsControl reports whether the action group hands the invocation back to
// the calling application instead of running a function itself.
func (a *mqlAwsBedrockAgentActionGroup) returnsControl() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if detail == nil || detail.AgentActionGroup == nil {
		return false, nil
	}
	_, ok := detail.AgentActionGroup.ActionGroupExecutor.(*bedrockagenttypes.ActionGroupExecutorMemberCustomControl)
	return ok, nil
}

func (a *mqlAwsBedrockAgentActionGroup) parentActionSignature() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.AgentActionGroup == nil {
		return "", nil
	}
	return string(detail.AgentActionGroup.ParentActionSignature), nil
}

func (a *mqlAwsBedrockAgentActionGroup) parentActionGroupSignatureParams() (map[string]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.AgentActionGroup == nil {
		return map[string]any{}, nil
	}
	return convert.MapToInterfaceMap(detail.AgentActionGroup.ParentActionGroupSignatureParams), nil
}

// apiSchema flattens the schema union into the payload it carries inline or the
// S3 object it is read from.
func (a *mqlAwsBedrockAgentActionGroup) apiSchema() (any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.AgentActionGroup == nil || detail.AgentActionGroup.ApiSchema == nil {
		return nil, nil
	}
	switch schema := detail.AgentActionGroup.ApiSchema.(type) {
	case *bedrockagenttypes.APISchemaMemberPayload:
		return map[string]any{"payload": schema.Value}, nil
	case *bedrockagenttypes.APISchemaMemberS3:
		return map[string]any{
			"s3": map[string]any{
				"s3BucketName": convert.ToValue(schema.Value.S3BucketName),
				"s3ObjectKey":  convert.ToValue(schema.Value.S3ObjectKey),
			},
		}, nil
	}
	return nil, nil
}

func (a *mqlAwsBedrockAgentActionGroup) functionSchema() (any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.AgentActionGroup == nil || detail.AgentActionGroup.FunctionSchema == nil {
		return nil, nil
	}
	result, _ := convert.JsonToDict(detail.AgentActionGroup.FunctionSchema)
	return result, nil
}

func (a *mqlAwsBedrockAgentActionGroup) createdAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.AgentActionGroup == nil {
		return nil, nil
	}
	return detail.AgentActionGroup.CreatedAt, nil
}

// --- Collaborators ---

func (a *mqlAwsBedrockAgent) collaborators() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgent(a.cacheRegion)
	ctx := context.Background()
	agentId := a.Id.Data
	draft := agentDraftVersion
	region := a.Region.Data
	res := []any{}

	paginator := bedrockagent.NewListAgentCollaboratorsPaginator(svc, &bedrockagent.ListAgentCollaboratorsInput{
		AgentId:      &agentId,
		AgentVersion: &draft,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, c := range page.AgentCollaboratorSummaries {
			collaboratorId := convert.ToValue(c.CollaboratorId)
			aliasArn := ""
			if c.AgentDescriptor != nil {
				aliasArn = convert.ToValue(c.AgentDescriptor.AliasArn)
			}
			mqlC, err := CreateResource(a.MqlRuntime, "aws.bedrock.agent.collaborator",
				map[string]*llx.RawData{
					"__id":                     llx.StringData(region + "/" + agentId + "/collaborator/" + collaboratorId),
					"id":                       llx.StringData(collaboratorId),
					"agentId":                  llx.StringData(agentId),
					"region":                   llx.StringData(region),
					"name":                     llx.StringDataPtr(c.CollaboratorName),
					"agentVersion":             llx.StringDataPtr(c.AgentVersion),
					"agentAliasArn":            llx.StringData(aliasArn),
					"collaborationInstruction": llx.StringDataPtr(c.CollaborationInstruction),
					"relayConversationHistory": llx.StringData(string(c.RelayConversationHistory)),
					"createdAt":                llx.TimeDataPtr(c.CreatedAt),
					"updatedAt":                llx.TimeDataPtr(c.LastUpdatedAt),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlC)
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockAgentCollaborator) id() (string, error) {
	return a.Region.Data + "/" + a.AgentId.Data + "/collaborator/" + a.Id.Data, nil
}
