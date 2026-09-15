// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	mqlTypes "go.mondoo.com/mql/v13/types"
)

func (a *mqlAwsSecurityhub) id() (string, error) {
	return "aws.securityhub", nil
}

func (a *mqlAwsSecurityhub) hubs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getHubs(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsSecurityhub) getHubs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Securityhub(region)
			ctx := context.Background()
			res := []any{}
			secHub, err := svc.DescribeHub(ctx, &securityhub.DescribeHubInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				var notFoundErr *types.InvalidAccessException
				if errors.As(err, &notFoundErr) {
					return nil, nil
				}
				return nil, err
			}
			mqlHub, err := CreateResource(a.MqlRuntime, "aws.securityhub.hub",
				map[string]*llx.RawData{
					"arn":                     llx.StringDataPtr(secHub.HubArn),
					"subscribedAt":            llx.StringDataPtr(secHub.SubscribedAt),
					"region":                  llx.StringData(region),
					"autoEnableControls":      llx.BoolData(convert.ToValue(secHub.AutoEnableControls)),
					"controlFindingGenerator": llx.StringData(string(secHub.ControlFindingGenerator)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlHub)
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsSecurityhubHub) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsSecurityhubHubInternal struct {
	lazyTags
	standardsFetched bool
	standardsLock    sync.Mutex
	standards        []types.StandardsSubscription
}

func (a *mqlAwsSecurityhubHub) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		hubArn := a.Arn.Data

		svc := conn.Securityhub(a.Region.Data)
		resp, err := svc.ListTagsForResource(context.Background(), &securityhub.ListTagsForResourceInput{
			ResourceArn: &hubArn,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		tags := make(map[string]any, len(resp.Tags))
		for k, v := range resp.Tags {
			tags[k] = v
		}
		return tags, nil
	})
}

func (a *mqlAwsSecurityhubHub) getEnabledStandards() ([]types.StandardsSubscription, error) {
	if a.standardsFetched {
		return a.standards, nil
	}
	a.standardsLock.Lock()
	defer a.standardsLock.Unlock()
	if a.standardsFetched {
		return a.standards, nil
	}

	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Securityhub(region)
	ctx := context.Background()

	var all []types.StandardsSubscription
	paginator := securityhub.NewGetEnabledStandardsPaginator(svc, &securityhub.GetEnabledStandardsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				a.standardsFetched = true
				return nil, nil
			}
			return nil, err
		}
		all = append(all, page.StandardsSubscriptions...)
	}
	a.standards = all
	a.standardsFetched = true
	return all, nil
}

func (a *mqlAwsSecurityhubHub) enabledStandards() ([]any, error) {
	standards, err := a.getEnabledStandards()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(standards))
	for _, std := range standards {
		d, err := convert.JsonToDict(std)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

func (a *mqlAwsSecurityhubHub) standardSubscriptions() ([]any, error) {
	standards, err := a.getEnabledStandards()
	if err != nil {
		return nil, err
	}
	region := a.Region.Data
	res := make([]any, 0, len(standards))
	for _, std := range standards {
		name := standardNameFromArn(convert.ToValue(std.StandardsArn))

		mqlStd, err := CreateResource(a.MqlRuntime, "aws.securityhub.standardSubscription",
			map[string]*llx.RawData{
				"arn":         llx.StringDataPtr(std.StandardsSubscriptionArn),
				"standardArn": llx.StringDataPtr(std.StandardsArn),
				"name":        llx.StringData(name),
				"region":      llx.StringData(region),
				"status":      llx.StringData(string(std.StandardsStatus)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlStd)
	}
	return res, nil
}

func (a *mqlAwsSecurityhubStandardSubscription) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSecurityhubStandardSubscription) controls() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Securityhub(region)
	ctx := context.Background()

	standardArn := a.StandardArn.Data

	// Step 1: List all control definitions for this standard
	var controlDefs []types.SecurityControlDefinition
	paginator := securityhub.NewListSecurityControlDefinitionsPaginator(svc, &securityhub.ListSecurityControlDefinitionsInput{
		StandardsArn: &standardArn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}
		controlDefs = append(controlDefs, page.SecurityControlDefinitions...)
	}

	if len(controlDefs) == 0 {
		return []any{}, nil
	}

	// Step 2: Batch-fetch per-standard association details (status, relatedRequirements, disabledReason)
	assocMap := make(map[string]types.StandardsControlAssociationDetail, len(controlDefs))
	const batchSize = 100
	for i := 0; i < len(controlDefs); i += batchSize {
		end := i + batchSize
		if end > len(controlDefs) {
			end = len(controlDefs)
		}
		ids := make([]types.StandardsControlAssociationId, 0, end-i)
		for _, def := range controlDefs[i:end] {
			ids = append(ids, types.StandardsControlAssociationId{
				SecurityControlId: def.SecurityControlId,
				StandardsArn:      &standardArn,
			})
		}
		resp, err := svc.BatchGetStandardsControlAssociations(ctx, &securityhub.BatchGetStandardsControlAssociationsInput{
			StandardsControlAssociationIds: ids,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, detail := range resp.StandardsControlAssociationDetails {
			assocMap[convert.ToValue(detail.SecurityControlId)] = detail
		}
	}

	// Step 3: Combine definitions + associations into resources
	res := make([]any, 0, len(controlDefs))
	for _, def := range controlDefs {
		controlId := convert.ToValue(def.SecurityControlId)
		assoc := assocMap[controlId]

		var controlStatus, disabledReason string
		controlStatus = string(assoc.AssociationStatus)
		disabledReason = convert.ToValue(assoc.UpdatedReason)

		relatedReqs := make([]any, len(assoc.RelatedRequirements))
		for j, r := range assoc.RelatedRequirements {
			relatedReqs[j] = r
		}

		mqlCtrl, err := CreateResource(a.MqlRuntime, "aws.securityhub.standardControl",
			map[string]*llx.RawData{
				"arn":                 llx.StringDataPtr(assoc.SecurityControlArn),
				"controlId":           llx.StringDataPtr(def.SecurityControlId),
				"title":               llx.StringDataPtr(def.Title),
				"description":         llx.StringDataPtr(def.Description),
				"controlStatus":       llx.StringData(controlStatus),
				"severity":            llx.StringData(string(def.SeverityRating)),
				"disabledReason":      llx.StringData(disabledReason),
				"relatedRequirements": llx.ArrayData(relatedReqs, mqlTypes.String),
				"remediationUrl":      llx.StringDataPtr(def.RemediationUrl),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCtrl)
	}
	return res, nil
}

func (a *mqlAwsSecurityhubStandardControl) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSecurityhubHub) findings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Securityhub(region)
	ctx := context.Background()

	res := []any{}
	// Only fetch active, non-suppressed findings
	paginator := securityhub.NewGetFindingsPaginator(svc, &securityhub.GetFindingsInput{
		Filters: &types.AwsSecurityFindingFilters{
			RecordState: []types.StringFilter{
				{
					Comparison: types.StringFilterComparisonEquals,
					Value:      aws.String("ACTIVE"),
				},
			},
			WorkflowStatus: []types.StringFilter{
				{
					Comparison: types.StringFilterComparisonNotEquals,
					Value:      aws.String("SUPPRESSED"),
				},
			},
		},
		MaxResults: aws.Int32(100),
	})

	// Limit to 1000 findings to avoid unbounded API calls
	maxFindings := 1000
	for paginator.HasMorePages() && len(res) < maxFindings {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for i := range page.Findings {
			if len(res) >= maxFindings {
				break
			}
			mqlFinding, err := newMqlSecurityHubFinding(a.MqlRuntime, &page.Findings[i], region)
			if err != nil {
				return nil, err
			}
			mqlFinding.cacheRegion = region
			res = append(res, mqlFinding)
		}
	}
	return res, nil
}

func newMqlSecurityHubFinding(runtime *plugin.Runtime, finding *types.AwsSecurityFinding, region string) (*mqlAwsSecurityhubFinding, error) {
	var severity string
	var severityNormalized int64
	if finding.Severity != nil {
		severity = string(finding.Severity.Label)
		if finding.Severity.Normalized != nil {
			severityNormalized = int64(*finding.Severity.Normalized)
		}
	}

	var complianceStatus string
	if finding.Compliance != nil {
		complianceStatus = string(finding.Compliance.Status)
	}

	var workflowStatus string
	if finding.Workflow != nil {
		workflowStatus = string(finding.Workflow.Status)
	}

	// A finding can reference multiple resources, but we expose only the first
	// (primary) one. Most findings have exactly one resource.
	var resourceType, resourceId, resourceRegion string
	if len(finding.Resources) > 0 {
		resourceType = convert.ToValue(finding.Resources[0].Type)
		resourceId = convert.ToValue(finding.Resources[0].Id)
		resourceRegion = convert.ToValue(finding.Resources[0].Region)
	}

	var remediationUrl, remediationText string
	if finding.Remediation != nil && finding.Remediation.Recommendation != nil {
		remediationUrl = convert.ToValue(finding.Remediation.Recommendation.Url)
		remediationText = convert.ToValue(finding.Remediation.Recommendation.Text)
	}

	findingTypes := make([]any, len(finding.Types))
	for i, t := range finding.Types {
		findingTypes[i] = t
	}

	res, err := CreateResource(runtime, "aws.securityhub.finding",
		map[string]*llx.RawData{
			"__id":               llx.StringData(fmt.Sprintf("securityhub/finding/%s/%s", region, convert.ToValue(finding.Id))),
			"id":                 llx.StringDataPtr(finding.Id),
			"title":              llx.StringDataPtr(finding.Title),
			"description":        llx.StringDataPtr(finding.Description),
			"severity":           llx.StringData(severity),
			"severityNormalized": llx.IntData(severityNormalized),
			"recordState":        llx.StringData(string(finding.RecordState)),
			"complianceStatus":   llx.StringData(complianceStatus),
			"workflowStatus":     llx.StringData(workflowStatus),
			"types":              llx.ArrayData(findingTypes, mqlTypes.String),
			"productArn":         llx.StringDataPtr(finding.ProductArn),
			"productName":        llx.StringDataPtr(finding.ProductName),
			"generatorId":        llx.StringDataPtr(finding.GeneratorId),
			"resourceType":       llx.StringData(resourceType),
			"resourceId":         llx.StringData(resourceId),
			"resourceRegion":     llx.StringData(resourceRegion),
			"createdAt":          llx.TimeDataPtr(parseAwsTimestampPtr(finding.CreatedAt)),
			"updatedAt":          llx.TimeDataPtr(parseAwsTimestampPtr(finding.UpdatedAt)),
			"firstObservedAt":    llx.TimeDataPtr(parseAwsTimestampPtr(finding.FirstObservedAt)),
			"lastObservedAt":     llx.TimeDataPtr(parseAwsTimestampPtr(finding.LastObservedAt)),
			"remediationUrl":     llx.StringData(remediationUrl),
			"remediationText":    llx.StringData(remediationText),
			"accountId":          llx.StringDataPtr(finding.AwsAccountId),
			"region":             llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecurityhubFinding), nil
}

func (a *mqlAwsSecurityhubFinding) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsSecurityhubHub) automationRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Securityhub(region)
	ctx := context.Background()

	res := []any{}
	var nextToken *string
	for {
		resp, err := svc.ListAutomationRules(ctx, &securityhub.ListAutomationRulesInput{
			NextToken: nextToken,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}

		for _, rule := range resp.AutomationRulesMetadata {
			mqlRule, err := CreateResource(a.MqlRuntime, "aws.securityhub.automationRule",
				map[string]*llx.RawData{
					"arn":         llx.StringDataPtr(rule.RuleArn),
					"ruleName":    llx.StringDataPtr(rule.RuleName),
					"ruleOrder":   llx.IntDataDefault(rule.RuleOrder, 0),
					"ruleStatus":  llx.StringData(string(rule.RuleStatus)),
					"description": llx.StringDataPtr(rule.Description),
					"isTerminal":  llx.BoolDataPtr(rule.IsTerminal),
					"createdAt":   llx.TimeDataPtr(rule.CreatedAt),
					"updatedAt":   llx.TimeDataPtr(rule.UpdatedAt),
					"createdBy":   llx.StringDataPtr(rule.CreatedBy),
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

func (a *mqlAwsSecurityhubAutomationRule) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSecurityhubHub) insights() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Securityhub(region)
	ctx := context.Background()

	res := []any{}
	paginator := securityhub.NewGetInsightsPaginator(svc, &securityhub.GetInsightsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, insight := range page.Insights {
			filters, err := convert.JsonToDict(insight.Filters)
			if err != nil {
				return nil, err
			}

			mqlInsight, err := CreateResource(a.MqlRuntime, "aws.securityhub.insight",
				map[string]*llx.RawData{
					"arn":              llx.StringDataPtr(insight.InsightArn),
					"name":             llx.StringDataPtr(insight.Name),
					"groupByAttribute": llx.StringDataPtr(insight.GroupByAttribute),
					"filters":          llx.DictData(filters),
				})
			if err != nil {
				return nil, err
			}
			mqlInsightRes := mqlInsight.(*mqlAwsSecurityhubInsight)
			mqlInsightRes.cacheRegion = region
			res = append(res, mqlInsightRes)
		}
	}
	return res, nil
}

type mqlAwsSecurityhubInsightInternal struct {
	cacheRegion string
}

func (a *mqlAwsSecurityhubInsight) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSecurityhubInsight) results() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Securityhub(a.cacheRegion)
	ctx := context.Background()

	insightArn := a.Arn.Data
	resp, err := svc.GetInsightResults(ctx, &securityhub.GetInsightResultsInput{
		InsightArn: &insightArn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := []any{}
	if resp.InsightResults != nil {
		for _, rv := range resp.InsightResults.ResultValues {
			var count int64
			if rv.Count != nil {
				count = int64(*rv.Count)
			}
			mqlResult, err := CreateResource(a.MqlRuntime, "aws.securityhub.insightResult",
				map[string]*llx.RawData{
					"__id":                  llx.StringData(fmt.Sprintf("%s/result/%s", insightArn, convert.ToValue(rv.GroupByAttributeValue))),
					"groupByAttributeValue": llx.StringDataPtr(rv.GroupByAttributeValue),
					"count":                 llx.IntData(count),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResult)
		}
	}
	return res, nil
}

func (a *mqlAwsSecurityhubInsightResult) id() (string, error) {
	return a.__id, nil
}

// organizationConfiguration returns the organization-wide Security Hub
// settings the delegated administrator applies to member accounts. The call
// only succeeds for a Security Hub administrator account, so a standalone or
// member account resolves the field to null rather than failing the scan.
func (a *mqlAwsSecurityhubHub) organizationConfiguration() (*mqlAwsSecurityhubOrganizationConfiguration, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Securityhub(region)
	ctx := context.Background()

	resp, err := svc.DescribeOrganizationConfiguration(ctx, &securityhub.DescribeOrganizationConfigurationInput{})
	if err != nil {
		var invalidAccess *types.InvalidAccessException
		if Is400AccessDeniedError(err) || errors.As(err, &invalidAccess) {
			a.OrganizationConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var configurationType, status, statusMessage string
	if oc := resp.OrganizationConfiguration; oc != nil {
		configurationType = string(oc.ConfigurationType)
		status = string(oc.Status)
		statusMessage = convert.ToValue(oc.StatusMessage)
	}

	res, err := CreateResource(a.MqlRuntime, "aws.securityhub.organizationConfiguration",
		map[string]*llx.RawData{
			"__id":                      llx.StringData(a.Arn.Data + "/organizationConfiguration"),
			"region":                    llx.StringData(region),
			"autoEnable":                llx.BoolData(convert.ToValue(resp.AutoEnable)),
			"autoEnableStandards":       llx.StringData(string(resp.AutoEnableStandards)),
			"configurationType":         llx.StringData(configurationType),
			"status":                    llx.StringData(status),
			"statusMessage":             llx.StringData(statusMessage),
			"memberAccountLimitReached": llx.BoolData(convert.ToValue(resp.MemberAccountLimitReached)),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecurityhubOrganizationConfiguration), nil
}

// findingAggregator returns the cross-region finding aggregator configured for
// this hub. ListFindingAggregators returns at most one aggregator, and only in
// the aggregation home region, so every other region resolves to null.
func (a *mqlAwsSecurityhubHub) findingAggregator() (*mqlAwsSecurityhubFindingAggregator, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Securityhub(region)
	ctx := context.Background()

	var aggregatorArn *string
	paginator := securityhub.NewListFindingAggregatorsPaginator(svc, &securityhub.ListFindingAggregatorsInput{})
	for paginator.HasMorePages() && aggregatorArn == nil {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			var invalidAccess *types.InvalidAccessException
			if Is400AccessDeniedError(err) || errors.As(err, &invalidAccess) {
				a.FindingAggregator.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}
		for i := range page.FindingAggregators {
			if arn := page.FindingAggregators[i].FindingAggregatorArn; arn != nil && *arn != "" {
				aggregatorArn = arn
				break
			}
		}
	}
	if aggregatorArn == nil {
		a.FindingAggregator.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	detail, err := svc.GetFindingAggregator(ctx, &securityhub.GetFindingAggregatorInput{
		FindingAggregatorArn: aggregatorArn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.FindingAggregator.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	regions := make([]any, 0, len(detail.Regions))
	for _, r := range detail.Regions {
		regions = append(regions, r)
	}

	res, err := CreateResource(a.MqlRuntime, "aws.securityhub.findingAggregator",
		map[string]*llx.RawData{
			"arn":                      llx.StringDataPtr(aggregatorArn),
			"findingAggregationRegion": llx.StringDataPtr(detail.FindingAggregationRegion),
			"regionLinkingMode":        llx.StringDataPtr(detail.RegionLinkingMode),
			"regions":                  llx.ArrayData(regions, mqlTypes.String),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecurityhubFindingAggregator), nil
}

func (a *mqlAwsSecurityhubOrganizationConfiguration) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsSecurityhubFindingAggregator) id() (string, error) {
	return a.Arn.Data, nil
}

// standardNameFromArn extracts a human-readable name from a Security Hub standard ARN.
// Handles both "standards/" and "ruleset/" prefixes:
//
//	"arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"
//	 → "aws-foundational-security-best-practices"
//	"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
//	 → "cis-aws-foundations-benchmark"
func standardNameFromArn(arn string) string {
	for _, prefix := range []string{"standards/", "ruleset/"} {
		idx := strings.Index(arn, prefix)
		if idx == -1 {
			continue
		}
		name := arn[idx+len(prefix):]
		if slash := strings.Index(name, "/"); slash != -1 {
			name = name[:slash]
		}
		return name
	}
	return arn
}

// Security Hub members
func (a *mqlAwsSecurityhubHub) members() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Securityhub(region)
	ctx := context.Background()

	res := []any{}
	paginator := securityhub.NewListMembersPaginator(svc, &securityhub.ListMembersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, member := range page.Members {
			mqlMember, err := CreateResource(a.MqlRuntime, "aws.securityhub.member",
				map[string]*llx.RawData{
					"__id":            llx.StringData(fmt.Sprintf("securityhub/member/%s/%s", region, convert.ToValue(member.AccountId))),
					"accountId":       llx.StringDataPtr(member.AccountId),
					"email":           llx.StringDataPtr(member.Email),
					"memberStatus":    llx.StringDataPtr(member.MemberStatus),
					"invitedAt":       llx.TimeDataPtr(member.InvitedAt),
					"updatedAt":       llx.TimeDataPtr(member.UpdatedAt),
					"administratorId": llx.StringDataPtr(member.AdministratorId),
					"region":          llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlMember)
		}
	}
	return res, nil
}

func (a *mqlAwsSecurityhubMember) id() (string, error) {
	return a.__id, nil
}

// Security Hub enabled products
func (a *mqlAwsSecurityhubHub) enabledProducts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Securityhub(region)
	ctx := context.Background()

	res := []any{}
	paginator := securityhub.NewListEnabledProductsForImportPaginator(svc, &securityhub.ListEnabledProductsForImportInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, productSubArn := range page.ProductSubscriptions {
			// Extract product ARN from the subscription ARN
			// Subscription ARN: arn:aws:securityhub:region:account:product-subscription/product-arn
			productArn := productSubArn
			if idx := strings.Index(productSubArn, ":product-subscription/"); idx != -1 {
				// Reconstruct the product ARN
				productArn = productSubArn[:idx] + ":product/" + productSubArn[idx+len(":product-subscription/"):]
			}

			mqlProduct, err := CreateResource(a.MqlRuntime, "aws.securityhub.enabledProduct",
				map[string]*llx.RawData{
					"__id":                   llx.StringData(fmt.Sprintf("securityhub/product/%s/%s", region, productSubArn)),
					"productSubscriptionArn": llx.StringData(productSubArn),
					"productArn":             llx.StringData(productArn),
					"region":                 llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlProduct)
		}
	}
	return res, nil
}

func (a *mqlAwsSecurityhubEnabledProduct) id() (string, error) {
	return a.__id, nil
}

// Finding history
type mqlAwsSecurityhubFindingInternal struct {
	cacheRegion string
}

func (a *mqlAwsSecurityhubFinding) history() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.cacheRegion
	if region == "" {
		region = a.Region.Data
	}
	svc := conn.Securityhub(region)
	ctx := context.Background()

	findingId := a.Id.Data
	productArn := a.ProductArn.Data

	res := []any{}
	paginator := securityhub.NewGetFindingHistoryPaginator(svc, &securityhub.GetFindingHistoryInput{
		FindingIdentifier: &types.AwsSecurityFindingIdentifier{
			Id:         &findingId,
			ProductArn: &productArn,
		},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, record := range page.Records {
			d, err := convert.JsonToDict(record)
			if err != nil {
				return nil, err
			}
			res = append(res, d)
		}
	}
	return res, nil
}
