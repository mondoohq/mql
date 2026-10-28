// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/configservice"
	cstypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// orgScopeTally counts how the regions of a fan-out answered an API that only
// an organization's management account or delegated administrator can call.
//
// A region that answers, even with nothing, makes the combined list a real
// answer. When no region answered and at least one said the account is not
// positioned to call the API at all, the list is not applicable rather than
// empty.
type orgScopeTally struct {
	mu            sync.Mutex
	answered      int
	notApplicable error
}

func (t *orgScopeTally) answer() {
	t.mu.Lock()
	t.answered++
	t.mu.Unlock()
}

func (t *orgScopeTally) refuse(err error) {
	t.mu.Lock()
	if t.notApplicable == nil {
		t.notApplicable = err
	}
	t.mu.Unlock()
}

// result is the field's answer once every region has reported. structured is
// plugin.StructuredErrors(): without it the refusal keeps reading as an empty
// list.
func (t *orgScopeTally) result(items []any, structured bool) ([]any, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.answered > 0 || t.notApplicable == nil || !structured {
		return items, nil
	}
	return nil, llx.NotApplicable(t.notApplicable)
}

// isConfigOrganizationNotApplicable reports whether Config refused an
// organization API because of the account's place in the organization rather
// than its IAM permissions: the account is neither the management account nor
// a Config delegated administrator, or the organization lacks all features.
// No IAM grant changes either answer, so they are not Forbidden.
//
// It is checked before Is400AccessDeniedError, which matches any error text
// containing "AccessDenied" and so also matches
// OrganizationAccessDeniedException.
func isConfigOrganizationNotApplicable(err error) bool {
	if err == nil {
		return false
	}
	var orgDenied *cstypes.OrganizationAccessDeniedException
	var allFeatures *cstypes.OrganizationAllFeaturesNotEnabledException
	return errors.As(err, &orgDenied) || errors.As(err, &allFeatures)
}

// isConfigNoOrganization reports Config's answer for an account that belongs to
// no organization. Such an account has no organization rules or packs, so an
// empty list is the truthful answer.
func isConfigNoOrganization(err error) bool {
	if err == nil {
		return false
	}
	var noOrg *cstypes.NoAvailableOrganizationException
	return errors.As(err, &noOrg)
}

// configOrganizationRegion lists one region's organization rules or packs and
// sorts its error into the tally. A nil error with nil items means the region
// contributed nothing and the error, if any, was accounted for.
func configOrganizationRegion(tally *orgScopeTally, region string, list func() ([]any, error)) ([]any, error) {
	items, err := list()
	if err == nil {
		tally.answer()
		return items, nil
	}
	switch {
	case isConfigNoOrganization(err):
		tally.answer()
		return []any{}, nil
	case isConfigOrganizationNotApplicable(err):
		log.Debug().Str("region", region).Err(err).Msg("config organization APIs do not apply to this account")
		tally.refuse(err)
		return []any{}, nil
	}
	return nil, err
}

// configOrgStatus is the organization-wide deployment status of one
// organization rule or conformance pack.
type configOrgStatus struct {
	status       string
	errorCode    string
	errorMessage string
}

// configOrgStatusCache fetches every status of a region once, on the first
// request, and serves every rule or pack of that region from the result.
type configOrgStatusCache struct {
	fetch func() (map[string]configOrgStatus, error)

	mu      sync.Mutex
	fetched bool
	byName  map[string]configOrgStatus
	err     error
}

func (c *configOrgStatusCache) get(name string) (configOrgStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fetched {
		c.byName, c.err = c.fetch()
		c.fetched = true
	}
	if c.err != nil {
		return configOrgStatus{}, c.err
	}
	return c.byName[name], nil
}

// configOrgStatusError classifies an error from a status call. Without
// structured errors a refusal reads as an absent status, as the other Config
// fields do.
func configOrgStatusError(err error, permission string) (map[string]configOrgStatus, error) {
	if isConfigOrganizationNotApplicable(err) {
		if !plugin.StructuredErrors() {
			return map[string]configOrgStatus{}, nil
		}
		return nil, llx.NotApplicable(err)
	}
	if Is400AccessDeniedError(err) {
		if !plugin.StructuredErrors() {
			return map[string]configOrgStatus{}, nil
		}
		return nil, llx.Forbidden(err, llx.WithPermissions(permission))
	}
	return nil, err
}

// organizationRuleDetails is the part of an organization Config rule that
// depends on its kind. Exactly one of the three metadata blocks is set on a
// rule AWS returns.
type organizationRuleDetails struct {
	ruleType                  string
	sourceIdentifier          string
	lambdaFunctionArn         string
	policyRuntime             string
	description               string
	inputParameters           string
	maximumExecutionFrequency string
	triggerTypes              []any
	resourceTypesScope        []any
	resourceIdScope           string
	tagKeyScope               string
	tagValueScope             string
}

func organizationRuleDetailsOf(r cstypes.OrganizationConfigRule) organizationRuleDetails {
	d := organizationRuleDetails{triggerTypes: []any{}, resourceTypesScope: []any{}}
	switch {
	case r.OrganizationManagedRuleMetadata != nil:
		m := r.OrganizationManagedRuleMetadata
		d.ruleType = string(cstypes.OwnerAws)
		d.sourceIdentifier = convert.ToValue(m.RuleIdentifier)
		d.description = convert.ToValue(m.Description)
		d.inputParameters = convert.ToValue(m.InputParameters)
		d.maximumExecutionFrequency = string(m.MaximumExecutionFrequency)
		d.resourceTypesScope = toAnySlice(m.ResourceTypesScope)
		d.resourceIdScope = convert.ToValue(m.ResourceIdScope)
		d.tagKeyScope = convert.ToValue(m.TagKeyScope)
		d.tagValueScope = convert.ToValue(m.TagValueScope)
	case r.OrganizationCustomRuleMetadata != nil:
		m := r.OrganizationCustomRuleMetadata
		d.ruleType = string(cstypes.OwnerCustomLambda)
		d.lambdaFunctionArn = convert.ToValue(m.LambdaFunctionArn)
		d.description = convert.ToValue(m.Description)
		d.inputParameters = convert.ToValue(m.InputParameters)
		d.maximumExecutionFrequency = string(m.MaximumExecutionFrequency)
		d.triggerTypes = toAnySlice(m.OrganizationConfigRuleTriggerTypes)
		d.resourceTypesScope = toAnySlice(m.ResourceTypesScope)
		d.resourceIdScope = convert.ToValue(m.ResourceIdScope)
		d.tagKeyScope = convert.ToValue(m.TagKeyScope)
		d.tagValueScope = convert.ToValue(m.TagValueScope)
	case r.OrganizationCustomPolicyRuleMetadata != nil:
		m := r.OrganizationCustomPolicyRuleMetadata
		d.ruleType = string(cstypes.OwnerCustomPolicy)
		d.policyRuntime = convert.ToValue(m.PolicyRuntime)
		d.description = convert.ToValue(m.Description)
		d.inputParameters = convert.ToValue(m.InputParameters)
		d.maximumExecutionFrequency = string(m.MaximumExecutionFrequency)
		d.triggerTypes = toAnySlice(m.OrganizationConfigRuleTriggerTypes)
		d.resourceTypesScope = toAnySlice(m.ResourceTypesScope)
		d.resourceIdScope = convert.ToValue(m.ResourceIdScope)
		d.tagKeyScope = convert.ToValue(m.TagKeyScope)
		d.tagValueScope = convert.ToValue(m.TagValueScope)
	}
	return d
}

// parseConfigInputParameters decodes a Config rule's input parameters, which
// the API hands over as a JSON object in a string. No parameters is null.
func parseConfigInputParameters(raw string) (map[string]any, error) {
	if raw == "" {
		return nil, nil
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		return nil, fmt.Errorf("cannot parse config rule input parameters: %w", err)
	}
	return res, nil
}

// conformancePackParametersMap turns conformance pack input parameters into a
// name to value map. A parameter without a name cannot be addressed and is
// dropped.
func conformancePackParametersMap(params []cstypes.ConformancePackInputParameter) map[string]any {
	res := make(map[string]any, len(params))
	for _, p := range params {
		if p.ParameterName == nil {
			continue
		}
		res[*p.ParameterName] = convert.ToValue(p.ParameterValue)
	}
	return res
}

// awsAccountsByID resolves account IDs to aws.account resources.
func awsAccountsByID(runtime *plugin.Runtime, ids []string) ([]any, error) {
	res := make([]any, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		acc, err := NewResource(runtime, ResourceAwsAccount, map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, acc)
	}
	return res, nil
}

func (a *mqlAwsConfig) organizationRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	tally := &orgScopeTally{}
	items, err := perRegion(conn, "config", func(ctx context.Context, region string) ([]any, error) {
		return configOrganizationRegion(tally, region, func() ([]any, error) {
			return a.listOrganizationRules(ctx, conn, region)
		})
	})
	if err != nil {
		return nil, err
	}
	return tally.result(items, plugin.StructuredErrors())
}

func (a *mqlAwsConfig) listOrganizationRules(ctx context.Context, conn *connection.AwsConnection, region string) ([]any, error) {
	svc := conn.ConfigService(region)
	statuses := &configOrgStatusCache{fetch: func() (map[string]configOrgStatus, error) {
		res := map[string]configOrgStatus{}
		paginator := configservice.NewDescribeOrganizationConfigRuleStatusesPaginator(svc, &configservice.DescribeOrganizationConfigRuleStatusesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return configOrgStatusError(err, "config:DescribeOrganizationConfigRuleStatuses")
			}
			for _, s := range page.OrganizationConfigRuleStatuses {
				res[convert.ToValue(s.OrganizationConfigRuleName)] = configOrgStatus{
					status:       string(s.OrganizationRuleStatus),
					errorCode:    convert.ToValue(s.ErrorCode),
					errorMessage: convert.ToValue(s.ErrorMessage),
				}
			}
		}
		return res, nil
	}}

	res := []any{}
	paginator := configservice.NewDescribeOrganizationConfigRulesPaginator(svc, &configservice.DescribeOrganizationConfigRulesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range page.OrganizationConfigRules {
			d := organizationRuleDetailsOf(r)
			mqlRule, err := CreateResource(a.MqlRuntime, ResourceAwsConfigOrganizationRule,
				map[string]*llx.RawData{
					"arn":                       llx.StringDataPtr(r.OrganizationConfigRuleArn),
					"name":                      llx.StringDataPtr(r.OrganizationConfigRuleName),
					"region":                    llx.StringData(region),
					"ruleType":                  llx.StringData(d.ruleType),
					"sourceIdentifier":          llx.StringData(d.sourceIdentifier),
					"policyRuntime":             llx.StringData(d.policyRuntime),
					"description":               llx.StringData(d.description),
					"maximumExecutionFrequency": llx.StringData(d.maximumExecutionFrequency),
					"triggerTypes":              llx.ArrayData(d.triggerTypes, types.String),
					"resourceTypesScope":        llx.ArrayData(d.resourceTypesScope, types.String),
					"resourceIdScope":           llx.StringData(d.resourceIdScope),
					"tagKeyScope":               llx.StringData(d.tagKeyScope),
					"tagValueScope":             llx.StringData(d.tagValueScope),
					"lastUpdateTime":            llx.TimeDataPtr(r.LastUpdateTime),
				})
			if err != nil {
				return nil, err
			}
			rule := mqlRule.(*mqlAwsConfigOrganizationRule)
			rule.cacheLambdaFunctionArn = d.lambdaFunctionArn
			rule.cacheInputParameters = d.inputParameters
			rule.cacheExcludedAccounts = r.ExcludedAccounts
			rule.statuses = statuses
			res = append(res, rule)
		}
	}
	return res, nil
}

type mqlAwsConfigOrganizationRuleInternal struct {
	cacheLambdaFunctionArn string
	cacheInputParameters   string
	cacheExcludedAccounts  []string
	statuses               *configOrgStatusCache
}

func (a *mqlAwsConfigOrganizationRule) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsConfigOrganizationRule) lambdaFunction() (*mqlAwsLambdaFunction, error) {
	if a.cacheLambdaFunctionArn == "" {
		a.LambdaFunction.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsLambdaFunction, map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheLambdaFunctionArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaFunction), nil
}

func (a *mqlAwsConfigOrganizationRule) inputParameters() (any, error) {
	params, err := parseConfigInputParameters(a.cacheInputParameters)
	if err != nil {
		return nil, llx.MalformedData(err)
	}
	if params == nil {
		return nil, nil
	}
	return params, nil
}

func (a *mqlAwsConfigOrganizationRule) excludedAccounts() ([]any, error) {
	return awsAccountsByID(a.MqlRuntime, a.cacheExcludedAccounts)
}

func (a *mqlAwsConfigOrganizationRule) status() (string, error) {
	s, err := a.statuses.get(a.Name.Data)
	return s.status, err
}

func (a *mqlAwsConfigOrganizationRule) statusErrorCode() (string, error) {
	s, err := a.statuses.get(a.Name.Data)
	return s.errorCode, err
}

func (a *mqlAwsConfigOrganizationRule) statusErrorMessage() (string, error) {
	s, err := a.statuses.get(a.Name.Data)
	return s.errorMessage, err
}

func (a *mqlAwsConfig) organizationConformancePacks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	tally := &orgScopeTally{}
	items, err := perRegion(conn, "config", func(ctx context.Context, region string) ([]any, error) {
		return configOrganizationRegion(tally, region, func() ([]any, error) {
			return a.listOrganizationConformancePacks(ctx, conn, region)
		})
	})
	if err != nil {
		return nil, err
	}
	return tally.result(items, plugin.StructuredErrors())
}

func (a *mqlAwsConfig) listOrganizationConformancePacks(ctx context.Context, conn *connection.AwsConnection, region string) ([]any, error) {
	svc := conn.ConfigService(region)
	statuses := &configOrgStatusCache{fetch: func() (map[string]configOrgStatus, error) {
		res := map[string]configOrgStatus{}
		paginator := configservice.NewDescribeOrganizationConformancePackStatusesPaginator(svc, &configservice.DescribeOrganizationConformancePackStatusesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return configOrgStatusError(err, "config:DescribeOrganizationConformancePackStatuses")
			}
			for _, s := range page.OrganizationConformancePackStatuses {
				res[convert.ToValue(s.OrganizationConformancePackName)] = configOrgStatus{
					status:       string(s.Status),
					errorCode:    convert.ToValue(s.ErrorCode),
					errorMessage: convert.ToValue(s.ErrorMessage),
				}
			}
		}
		return res, nil
	}}

	res := []any{}
	paginator := configservice.NewDescribeOrganizationConformancePacksPaginator(svc, &configservice.DescribeOrganizationConformancePacksInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range page.OrganizationConformancePacks {
			mqlPack, err := CreateResource(a.MqlRuntime, ResourceAwsConfigOrganizationConformancePack,
				map[string]*llx.RawData{
					"arn":                 llx.StringDataPtr(p.OrganizationConformancePackArn),
					"name":                llx.StringDataPtr(p.OrganizationConformancePackName),
					"region":              llx.StringData(region),
					"deliveryS3KeyPrefix": llx.StringDataPtr(p.DeliveryS3KeyPrefix),
					"inputParameters":     llx.MapData(conformancePackParametersMap(p.ConformancePackInputParameters), types.String),
					"lastUpdateTime":      llx.TimeDataPtr(p.LastUpdateTime),
				})
			if err != nil {
				return nil, err
			}
			pack := mqlPack.(*mqlAwsConfigOrganizationConformancePack)
			pack.cacheDeliveryS3Bucket = convert.ToValue(p.DeliveryS3Bucket)
			pack.cacheExcludedAccounts = p.ExcludedAccounts
			pack.statuses = statuses
			res = append(res, pack)
		}
	}
	return res, nil
}

type mqlAwsConfigOrganizationConformancePackInternal struct {
	cacheDeliveryS3Bucket string
	cacheExcludedAccounts []string
	statuses              *configOrgStatusCache
}

func (a *mqlAwsConfigOrganizationConformancePack) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsConfigOrganizationConformancePack) deliveryS3Bucket() (*mqlAwsS3Bucket, error) {
	if a.cacheDeliveryS3Bucket == "" {
		a.DeliveryS3Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsS3Bucket, map[string]*llx.RawData{
		"name": llx.StringData(a.cacheDeliveryS3Bucket),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsConfigOrganizationConformancePack) excludedAccounts() ([]any, error) {
	return awsAccountsByID(a.MqlRuntime, a.cacheExcludedAccounts)
}

func (a *mqlAwsConfigOrganizationConformancePack) status() (string, error) {
	s, err := a.statuses.get(a.Name.Data)
	return s.status, err
}

func (a *mqlAwsConfigOrganizationConformancePack) statusErrorCode() (string, error) {
	s, err := a.statuses.get(a.Name.Data)
	return s.errorCode, err
}

func (a *mqlAwsConfigOrganizationConformancePack) statusErrorMessage() (string, error) {
	s, err := a.statuses.get(a.Name.Data)
	return s.errorMessage, err
}
