// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	bacctypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// --- Policy engines ---

type mqlAwsBedrockAgentCorePolicyEngineInternal struct {
	cacheRegion    string
	cacheKmsKeyArn string
}

func (a *mqlAwsBedrockAgentCore) policyEngines() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListPolicyEnginesPaginator(svc, &bedrockagentcorecontrol.ListPolicyEnginesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, pe := range page.PolicyEngines {
				mqlPe, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockAgentCorePolicyEngine, map[string]*llx.RawData{
					"__id":          llx.StringDataPtr(pe.PolicyEngineArn),
					"arn":           llx.StringDataPtr(pe.PolicyEngineArn),
					"id":            llx.StringDataPtr(pe.PolicyEngineId),
					"name":          llx.StringDataPtr(pe.Name),
					"region":        llx.StringData(region),
					"status":        llx.StringData(string(pe.Status)),
					"statusReasons": llx.ArrayData(stringsToArrayData(pe.StatusReasons), types.String),
					"description":   llx.StringDataPtr(pe.Description),
					"createdAt":     llx.TimeDataPtr(pe.CreatedAt),
					"updatedAt":     llx.TimeDataPtr(pe.UpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				cast := mqlPe.(*mqlAwsBedrockAgentCorePolicyEngine)
				cast.cacheRegion = region
				cast.cacheKmsKeyArn = convert.ToValue(pe.EncryptionKeyArn)
				res = append(res, cast)
			}
		}
		return res, nil
	}))
}

func (a *mqlAwsBedrockAgentCorePolicyEngine) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey, map[string]*llx.RawData{"arn": llx.StringData(a.cacheKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

// policyDefinitionOf reports which form a policy definition takes and the
// statement it carries. A generated-policy reference carries no statement.
func policyDefinitionOf(def bacctypes.PolicyDefinition) (kind string, statement *string) {
	switch v := def.(type) {
	case *bacctypes.PolicyDefinitionMemberCedar:
		return "cedar", v.Value.Statement
	case *bacctypes.PolicyDefinitionMemberPolicy:
		return "policy", v.Value.Statement
	case *bacctypes.PolicyDefinitionMemberPolicyGeneration:
		return "policyGeneration", nil
	}
	return "", nil
}

func (a *mqlAwsBedrockAgentCorePolicyEngine) policies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	engineId := a.Id.Data
	res := []any{}
	paginator := bedrockagentcorecontrol.NewListPoliciesPaginator(svc, &bedrockagentcorecontrol.ListPoliciesInput{
		PolicyEngineId: &engineId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if Is400AccessDeniedError(err) {
				if !plugin.StructuredErrors() {
					return res, nil
				}
				return nil, llx.Forbidden(err, llx.WithPermissions("bedrock-agentcore:ListPolicies"))
			}
			return nil, err
		}
		for _, p := range page.Policies {
			kind, statement := policyDefinitionOf(p.Definition)
			args := map[string]*llx.RawData{
				"__id":            llx.StringDataPtr(p.PolicyArn),
				"arn":             llx.StringDataPtr(p.PolicyArn),
				"id":              llx.StringDataPtr(p.PolicyId),
				"name":            llx.StringDataPtr(p.Name),
				"policyEngineId":  llx.StringDataPtr(p.PolicyEngineId),
				"status":          llx.StringData(string(p.Status)),
				"statusReasons":   llx.ArrayData(stringsToArrayData(p.StatusReasons), types.String),
				"description":     llx.StringDataPtr(p.Description),
				"enforcementMode": llx.StringData(string(p.EnforcementMode)),
				"definitionType":  llx.StringData(kind),
				"statement":       llx.StringDataPtr(statement),
				"createdAt":       llx.TimeDataPtr(p.CreatedAt),
				"updatedAt":       llx.TimeDataPtr(p.UpdatedAt),
			}
			mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockAgentCorePolicy, args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockAgentCoreGateway) policyEngine() (*mqlAwsBedrockAgentCorePolicyEngine, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.PolicyEngineConfiguration == nil || convert.ToValue(detail.PolicyEngineConfiguration.Arn) == "" {
		a.PolicyEngine.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	wantArn := *detail.PolicyEngineConfiguration.Arn

	agentCore, err := agentCoreRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	engines := agentCore.GetPolicyEngines()
	if engines.Error != nil {
		return nil, engines.Error
	}
	for _, raw := range engines.Data {
		if engine, ok := raw.(*mqlAwsBedrockAgentCorePolicyEngine); ok && engine.Arn.Data == wantArn {
			return engine, nil
		}
	}
	a.PolicyEngine.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// agentCoreRoot returns the cached aws.bedrock.agentCore resource, whose lists
// are used to resolve references between AgentCore resources.
func agentCoreRoot(runtime *plugin.Runtime) (*mqlAwsBedrockAgentCore, error) {
	obj, err := CreateResource(runtime, ResourceAwsBedrockAgentCore, map[string]*llx.RawData{
		"__id": llx.StringData("aws.bedrock.agentCore"),
	})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlAwsBedrockAgentCore), nil
}

// --- Token vaults ---

// defaultTokenVaultId is the only token vault AgentCore Identity creates in a
// region.
const defaultTokenVaultId = "default"

type mqlAwsBedrockAgentCoreTokenVaultInternal struct {
	cacheKmsKeyArn string
}

func (a *mqlAwsBedrockAgentCore) tokenVaults() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		vaultId := defaultTokenVaultId
		out, err := svc.GetTokenVault(ctx, &bedrockagentcorecontrol.GetTokenVaultInput{TokenVaultId: &vaultId})
		if err != nil {
			if isResourceNotFoundError(err) {
				log.Debug().Str("region", region).Msg("no agentcore token vault in region")
				return []any{}, nil
			}
			return nil, err
		}
		keyType, kmsKeyArn := tokenVaultKey(out.KmsConfiguration)
		id := convert.ToValue(out.TokenVaultId)
		if id == "" {
			id = vaultId
		}
		mqlVault, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockAgentCoreTokenVault, map[string]*llx.RawData{
			"__id":           llx.StringData(region + "/tokenVault/" + id),
			"id":             llx.StringData(id),
			"region":         llx.StringData(region),
			"keyType":        llx.StringDataPtr(keyType),
			"lastModifiedAt": llx.TimeDataPtr(out.LastModifiedDate),
		})
		if err != nil {
			return nil, err
		}
		cast := mqlVault.(*mqlAwsBedrockAgentCoreTokenVault)
		cast.cacheKmsKeyArn = kmsKeyArn
		return []any{cast}, nil
	}))
}

// tokenVaultKey returns the vault's key type and, for a customer-managed key,
// the key ARN. The key type is nil when the response carries no KMS
// configuration, so it reads as null rather than as an assumed default.
func tokenVaultKey(cfg *bacctypes.KmsConfiguration) (keyType *string, kmsKeyArn string) {
	if cfg == nil || cfg.KeyType == "" {
		return nil, ""
	}
	kt := string(cfg.KeyType)
	if cfg.KeyType == bacctypes.KeyTypeCustomerManagedKey {
		return &kt, convert.ToValue(cfg.KmsKeyArn)
	}
	return &kt, ""
}

func (a *mqlAwsBedrockAgentCoreTokenVault) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey, map[string]*llx.RawData{"arn": llx.StringData(a.cacheKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

// --- Registries ---

type mqlAwsBedrockAgentCoreRegistryInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     atomic.Bool
	detail      *bedrockagentcorecontrol.GetRegistryOutput
}

func (a *mqlAwsBedrockAgentCore) registries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListRegistriesPaginator(svc, &bedrockagentcorecontrol.ListRegistriesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, r := range page.Registries {
				mqlReg, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockAgentCoreRegistry, map[string]*llx.RawData{
					"__id":           llx.StringDataPtr(r.RegistryArn),
					"arn":            llx.StringDataPtr(r.RegistryArn),
					"id":             llx.StringDataPtr(r.RegistryId),
					"name":           llx.StringDataPtr(r.Name),
					"region":         llx.StringData(region),
					"status":         llx.StringData(string(r.Status)),
					"statusReason":   llx.StringDataPtr(r.StatusReason),
					"description":    llx.StringDataPtr(r.Description),
					"authorizerType": llx.StringData(string(r.AuthorizerType)),
					"createdAt":      llx.TimeDataPtr(r.CreatedAt),
					"updatedAt":      llx.TimeDataPtr(r.UpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				cast := mqlReg.(*mqlAwsBedrockAgentCoreRegistry)
				cast.cacheRegion = region
				res = append(res, cast)
			}
		}
		return res, nil
	}))
}

func (a *mqlAwsBedrockAgentCoreRegistry) fetchDetail() (*bedrockagentcorecontrol.GetRegistryOutput, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	registryId := a.Id.Data
	detail, err := svc.GetRegistry(context.Background(), &bedrockagentcorecontrol.GetRegistryInput{RegistryId: &registryId})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("bedrock-agentcore:GetRegistry"))
		}
		return nil, err
	}
	a.detail = detail
	a.fetched.Store(true)
	return a.detail, nil
}

func (a *mqlAwsBedrockAgentCoreRegistry) autoApproval() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if detail == nil || detail.ApprovalConfiguration == nil {
		a.AutoApproval.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return detail.ApprovalConfiguration.AutoApproval, nil
}

func (a *mqlAwsBedrockAgentCoreRegistry) jwtAuthorizer() (*bacctypes.CustomJWTAuthorizerConfiguration, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil {
		return nil, err
	}
	return agentCoreJWTAuthorizer(detail.AuthorizerConfiguration), nil
}

func (a *mqlAwsBedrockAgentCoreRegistry) authorizerDiscoveryUrl() (string, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return "", err
	}
	return jwtDiscoveryUrl(jwt, &a.AuthorizerDiscoveryUrl)
}

func (a *mqlAwsBedrockAgentCoreRegistry) allowedClients() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(j *bacctypes.CustomJWTAuthorizerConfiguration) []string { return j.AllowedClients }, &a.AllowedClients)
}

func (a *mqlAwsBedrockAgentCoreRegistry) allowedAudiences() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(j *bacctypes.CustomJWTAuthorizerConfiguration) []string { return j.AllowedAudience }, &a.AllowedAudiences)
}

func (a *mqlAwsBedrockAgentCoreRegistry) allowedScopes() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(j *bacctypes.CustomJWTAuthorizerConfiguration) []string { return j.AllowedScopes }, &a.AllowedScopes)
}

func (a *mqlAwsBedrockAgentCoreRegistry) records() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	registryId := a.Id.Data
	res := []any{}
	paginator := bedrockagentcorecontrol.NewListRegistryRecordsPaginator(svc, &bedrockagentcorecontrol.ListRegistryRecordsInput{
		RegistryId: &registryId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if Is400AccessDeniedError(err) {
				if !plugin.StructuredErrors() {
					return res, nil
				}
				return nil, llx.Forbidden(err, llx.WithPermissions("bedrock-agentcore:ListRegistryRecords"))
			}
			return nil, err
		}
		for _, r := range page.RegistryRecords {
			mqlRec, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockAgentCoreRegistryRecord, map[string]*llx.RawData{
				"__id":           llx.StringDataPtr(r.RecordArn),
				"arn":            llx.StringDataPtr(r.RecordArn),
				"id":             llx.StringDataPtr(r.RecordId),
				"name":           llx.StringDataPtr(r.Name),
				"descriptorType": llx.StringData(string(r.DescriptorType)),
				"status":         llx.StringData(string(r.Status)),
				"recordVersion":  llx.StringDataPtr(r.RecordVersion),
				"description":    llx.StringDataPtr(r.Description),
				"createdAt":      llx.TimeDataPtr(r.CreatedAt),
				"updatedAt":      llx.TimeDataPtr(r.UpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRec)
		}
	}
	return res, nil
}
