// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// --- Foundation model availability ---

type mqlAwsBedrockFoundationModelInternal struct {
	availabilityLock    sync.Mutex
	availabilityFetched atomic.Bool
	availability        *bedrock.GetFoundationModelAvailabilityOutput
	availabilityErr     error
}

// foundationModelRegion returns the region a foundation model ARN names,
// arn:aws:bedrock:<region>::foundation-model/<id>.
func foundationModelRegion(modelArn string) string {
	parsed, err := arn.Parse(modelArn)
	if err != nil {
		return ""
	}
	return parsed.Region
}

func (a *mqlAwsBedrockFoundationModel) fetchAvailability() (*bedrock.GetFoundationModelAvailabilityOutput, error) {
	if a.availabilityFetched.Load() {
		return a.availability, a.availabilityErr
	}
	a.availabilityLock.Lock()
	defer a.availabilityLock.Unlock()
	if a.availabilityFetched.Load() {
		return a.availability, a.availabilityErr
	}
	defer a.availabilityFetched.Store(true)

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	modelId := a.ModelId.Data
	out, err := conn.Bedrock(foundationModelRegion(a.ModelArn.Data)).GetFoundationModelAvailability(context.Background(),
		&bedrock.GetFoundationModelAvailabilityInput{ModelId: &modelId})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				return nil, nil
			}
			a.availabilityErr = llx.Forbidden(err, llx.WithPermissions("bedrock:GetFoundationModelAvailability"))
			return nil, a.availabilityErr
		}
		a.availabilityErr = err
		return nil, err
	}
	a.availability = out
	return out, nil
}

// availabilityBool maps a two-state availability enum onto a boolean. An empty
// value reports ok=false so the field reads as null.
func availabilityBool[T ~string](v T, yes T) (value bool, ok bool) {
	if v == "" {
		return false, false
	}
	return v == yes, true
}

func (a *mqlAwsBedrockFoundationModel) accessAuthorized() (bool, error) {
	out, err := a.fetchAvailability()
	if err != nil {
		return false, err
	}
	if out != nil {
		if v, ok := availabilityBool(out.AuthorizationStatus, bedrocktypes.AuthorizationStatusAuthorized); ok {
			return v, nil
		}
	}
	a.AccessAuthorized.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

func (a *mqlAwsBedrockFoundationModel) entitlementAvailable() (bool, error) {
	out, err := a.fetchAvailability()
	if err != nil {
		return false, err
	}
	if out != nil {
		if v, ok := availabilityBool(out.EntitlementAvailability, bedrocktypes.EntitlementAvailabilityAvailable); ok {
			return v, nil
		}
	}
	a.EntitlementAvailable.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

func (a *mqlAwsBedrockFoundationModel) availableInRegion() (bool, error) {
	out, err := a.fetchAvailability()
	if err != nil {
		return false, err
	}
	if out != nil {
		if v, ok := availabilityBool(out.RegionAvailability, bedrocktypes.RegionAvailabilityAvailable); ok {
			return v, nil
		}
	}
	a.AvailableInRegion.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

func (a *mqlAwsBedrockFoundationModel) agreementStatus() (string, error) {
	out, err := a.fetchAvailability()
	if err != nil {
		return "", err
	}
	if out == nil || out.AgreementAvailability == nil || out.AgreementAvailability.Status == "" {
		a.AgreementStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(out.AgreementAvailability.Status), nil
}

// --- Prompt routers ---

func (a *mqlAwsBedrock) promptRouters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return bedrockCollectRegionJobs(jobpool.CreatePool(bedrockRegionJobs(conn, a.collectPromptRouters), 5))
}

func promptRouterModelArns(models []bedrocktypes.PromptRouterTargetModel) []any {
	res := []any{}
	for _, m := range models {
		if v := convert.ToValue(m.ModelArn); v != "" {
			res = append(res, v)
		}
	}
	return res
}

func (a *mqlAwsBedrock) collectPromptRouters(svc *bedrock.Client, region string) ([]any, error) {
	ctx := context.Background()
	res := []any{}
	paginator := bedrock.NewListPromptRoutersPaginator(svc, &bedrock.ListPromptRoutersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range page.PromptRouterSummaries {
			var fallback *string
			if r.FallbackModel != nil {
				fallback = r.FallbackModel.ModelArn
			}
			var qualityDiff *float64
			if r.RoutingCriteria != nil {
				qualityDiff = r.RoutingCriteria.ResponseQualityDifference
			}
			mqlR, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockPromptRouter, map[string]*llx.RawData{
				"__id":                      llx.StringDataPtr(r.PromptRouterArn),
				"arn":                       llx.StringDataPtr(r.PromptRouterArn),
				"name":                      llx.StringDataPtr(r.PromptRouterName),
				"region":                    llx.StringData(region),
				"type":                      llx.StringData(string(r.Type)),
				"status":                    llx.StringData(string(r.Status)),
				"description":               llx.StringDataPtr(r.Description),
				"modelArns":                 llx.ArrayData(promptRouterModelArns(r.Models), types.String),
				"fallbackModelArn":          llx.StringDataPtr(fallback),
				"responseQualityDifference": llx.FloatDataPtr(qualityDiff),
				"createdAt":                 llx.TimeDataPtr(r.CreatedAt),
				"updatedAt":                 llx.TimeDataPtr(r.UpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlR)
		}
	}
	return res, nil
}

// --- Automated Reasoning policies ---

type mqlAwsBedrockAutomatedReasoningPolicyInternal struct {
	fetchLock sync.Mutex
	fetched   atomic.Bool
	detail    *bedrock.GetAutomatedReasoningPolicyOutput
	detailErr error
}

func (a *mqlAwsBedrock) automatedReasoningPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return bedrockCollectRegionJobs(jobpool.CreatePool(bedrockRegionJobs(conn, a.collectAutomatedReasoningPolicies), 5))
}

func (a *mqlAwsBedrock) collectAutomatedReasoningPolicies(svc *bedrock.Client, region string) ([]any, error) {
	ctx := context.Background()
	res := []any{}
	paginator := bedrock.NewListAutomatedReasoningPoliciesPaginator(svc, &bedrock.ListAutomatedReasoningPoliciesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range page.AutomatedReasoningPolicySummaries {
			mqlP, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockAutomatedReasoningPolicy, map[string]*llx.RawData{
				"__id":        llx.StringDataPtr(p.PolicyArn),
				"arn":         llx.StringDataPtr(p.PolicyArn),
				"id":          llx.StringDataPtr(p.PolicyId),
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
			res = append(res, mqlP)
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockAutomatedReasoningPolicy) fetchDetail() (*bedrock.GetAutomatedReasoningPolicyOutput, error) {
	if a.fetched.Load() {
		return a.detail, a.detailErr
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, a.detailErr
	}
	defer a.fetched.Store(true)
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	policyArn := a.Arn.Data
	out, err := conn.Bedrock(a.Region.Data).GetAutomatedReasoningPolicy(context.Background(), &bedrock.GetAutomatedReasoningPolicyInput{
		PolicyArn: &policyArn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				return nil, nil
			}
			a.detailErr = llx.Forbidden(err, llx.WithPermissions("bedrock:GetAutomatedReasoningPolicy"))
			return nil, a.detailErr
		}
		a.detailErr = err
		return nil, err
	}
	a.detail = out
	return a.detail, nil
}

func (a *mqlAwsBedrockAutomatedReasoningPolicy) definitionHash() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || convert.ToValue(detail.DefinitionHash) == "" {
		a.DefinitionHash.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *detail.DefinitionHash, nil
}

func (a *mqlAwsBedrockAutomatedReasoningPolicy) kmsKey() (*mqlAwsKmsKey, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || convert.ToValue(detail.KmsKeyArn) == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey, map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.KmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

// --- Custom model deployments ---

type mqlAwsBedrockCustomModelDeploymentInternal struct {
	cacheModelArn string
	fetchLock     sync.Mutex
	fetched       atomic.Bool
	detail        *bedrock.GetCustomModelDeploymentOutput
	detailErr     error
}

func (a *mqlAwsBedrock) customModelDeployments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return bedrockCollectRegionJobs(jobpool.CreatePool(bedrockRegionJobs(conn, a.collectCustomModelDeployments), 5))
}

func (a *mqlAwsBedrock) collectCustomModelDeployments(svc *bedrock.Client, region string) ([]any, error) {
	ctx := context.Background()
	res := []any{}
	paginator := bedrock.NewListCustomModelDeploymentsPaginator(svc, &bedrock.ListCustomModelDeploymentsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, d := range page.ModelDeploymentSummaries {
			mqlD, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockCustomModelDeployment, map[string]*llx.RawData{
				"__id":           llx.StringDataPtr(d.CustomModelDeploymentArn),
				"arn":            llx.StringDataPtr(d.CustomModelDeploymentArn),
				"name":           llx.StringDataPtr(d.CustomModelDeploymentName),
				"region":         llx.StringData(region),
				"status":         llx.StringData(string(d.Status)),
				"failureMessage": llx.StringDataPtr(d.FailureMessage),
				"createdAt":      llx.TimeDataPtr(d.CreatedAt),
				"updatedAt":      llx.TimeDataPtr(d.LastUpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			cast := mqlD.(*mqlAwsBedrockCustomModelDeployment)
			cast.cacheModelArn = convert.ToValue(d.ModelArn)
			res = append(res, cast)
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockCustomModelDeployment) fetchDetail() (*bedrock.GetCustomModelDeploymentOutput, error) {
	if a.fetched.Load() {
		return a.detail, a.detailErr
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, a.detailErr
	}
	defer a.fetched.Store(true)
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	deploymentArn := a.Arn.Data
	out, err := conn.Bedrock(a.Region.Data).GetCustomModelDeployment(context.Background(), &bedrock.GetCustomModelDeploymentInput{
		CustomModelDeploymentIdentifier: &deploymentArn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				return nil, nil
			}
			a.detailErr = llx.Forbidden(err, llx.WithPermissions("bedrock:GetCustomModelDeployment"))
			return nil, a.detailErr
		}
		a.detailErr = err
		return nil, err
	}
	a.detail = out
	return a.detail, nil
}

func (a *mqlAwsBedrockCustomModelDeployment) description() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.Description == nil {
		a.Description.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *detail.Description, nil
}

func (a *mqlAwsBedrockCustomModelDeployment) customModel() (*mqlAwsBedrockCustomModel, error) {
	if a.cacheModelArn == "" {
		a.CustomModel.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsBedrockCustomModel, map[string]*llx.RawData{"modelArn": llx.StringData(a.cacheModelArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBedrockCustomModel), nil
}
