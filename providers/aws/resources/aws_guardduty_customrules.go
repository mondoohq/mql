// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// customDetectionRuleCacheID builds the cache key for a rule organization
// rollout. A rollout is identified by the rule it applies and the mode it
// applies it in, and the same rule can carry one rollout per mode, so both
// dimensions have to be in the key. The region is the third: the rules API is
// regional, so the same rule id appears independently in every region it is
// defined in.
func guarddutyOrgConfigCacheID(region, ruleID, mode string) string {
	return fmt.Sprintf("%s/customDetectionRuleOrgConfiguration/%s/%s", region, ruleID, mode)
}

// findCustomDetectionRule resolves a rule out of an already-fetched rule list.
//
// Resolving through the cached list rather than NewResource matters here:
// NewResource runs a resource's init before the runtime cache is consulted, so
// a per-rollout lookup would re-read a rule the account list already holds.
// Rules are regional, so a match needs both the region and the rule id; keying
// on the id alone would return a same-named rule from whichever region was
// listed first.
func findCustomDetectionRule(rules []any, region, ruleID string) *mqlAwsGuarddutyCustomDetectionRule {
	if ruleID == "" {
		return nil
	}
	for _, raw := range rules {
		rule, ok := raw.(*mqlAwsGuarddutyCustomDetectionRule)
		if !ok {
			continue
		}
		if rule.RuleId.Data == ruleID && rule.Region.Data == region {
			return rule
		}
	}
	return nil
}

// --- Custom detection rules ---

func (a *mqlAwsGuardduty) customDetectionRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCustomDetectionRules(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsGuardduty) getCustomDetectionRules(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("guardduty>getCustomDetectionRules>calling aws with region %s", region)

			svc := conn.Guardduty(region)
			ctx := context.Background()
			res := []any{}

			paginator := guardduty.NewListCustomDetectionRulesPaginator(svc, &guardduty.ListCustomDetectionRulesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("guardduty custom detection rules are not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, rule := range page.Rules {
					mqlRule, err := newMqlGuarddutyCustomDetectionRule(a.MqlRuntime, region, rule)
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

func newMqlGuarddutyCustomDetectionRule(runtime *plugin.Runtime, region string, rule types.RuleSummary) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "aws.guardduty.customDetectionRule", map[string]*llx.RawData{
		"__id":          llx.StringDataPtr(rule.Arn),
		"arn":           llx.StringDataPtr(rule.Arn),
		"ruleId":        llx.StringDataPtr(rule.RuleId),
		"name":          llx.StringDataPtr(rule.Name),
		"description":   llx.StringDataPtr(rule.Description),
		"region":        llx.StringData(region),
		"service":       llx.StringDataPtr(rule.Service),
		"severity":      llx.StringData(string(rule.Severity)),
		"tactic":        llx.StringDataPtr(rule.Tactic),
		"technique":     llx.StringDataPtr(rule.Technique),
		"dataSource":    llx.StringData(string(rule.DataSource)),
		"language":      llx.StringData(string(rule.Language)),
		"schemaVersion": llx.StringData(string(rule.Schema)),
		"createdAt":     llx.TimeDataPtr(rule.CreatedAt),
		"updatedAt":     llx.TimeDataPtr(rule.UpdatedAt),
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (a *mqlAwsGuarddutyCustomDetectionRule) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsGuarddutyCustomDetectionRuleInternal struct {
	detailOnce sync.Once
	detail     *types.RuleDetail
	detailErr  error
}

// fetchDetail reads the rule body, which the list API does not carry.
//
// A failure to read leaves detail nil rather than erroring, so the expression
// resolves to null. Reporting an empty expression instead would say the rule
// matches nothing, which is the opposite of unknown.
func (a *mqlAwsGuarddutyCustomDetectionRule) fetchDetail() (*types.RuleDetail, error) {
	a.detailOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Guardduty(a.Region.Data)
		ruleID := a.RuleId.Data

		out, err := svc.GetCustomDetectionRule(context.Background(), &guardduty.GetCustomDetectionRuleInput{
			RuleId: &ruleID,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("rule", ruleID).Msg("access denied getting guardduty custom detection rule")
				return
			}
			a.detailErr = err
			return
		}
		a.detail = out.Rule
	})
	return a.detail, a.detailErr
}

func (a *mqlAwsGuarddutyCustomDetectionRule) expression() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.Definition == nil || detail.Definition.Expression == nil {
		a.Expression = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *detail.Definition.Expression, nil
}

// --- Rule associations ---

func (a *mqlAwsGuarddutyCustomDetectionRule) associations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	ruleID := a.RuleId.Data
	svc := conn.Guardduty(region)
	ctx := context.Background()

	res := []any{}
	paginator := guardduty.NewListCustomDetectionRuleAssociationsPaginator(svc, &guardduty.ListCustomDetectionRuleAssociationsInput{
		RuleId: &ruleID,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			if IsServiceNotAvailableInRegionError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, assoc := range page.RuleAssociations {
			mqlAssoc, err := CreateResource(a.MqlRuntime, "aws.guardduty.customDetectionRule.association", map[string]*llx.RawData{
				"__id":          llx.StringDataPtr(assoc.Arn),
				"arn":           llx.StringDataPtr(assoc.Arn),
				"associationId": llx.StringDataPtr(assoc.AssociationId),
				"region":        llx.StringData(region),
				"mode":          llx.StringData(string(assoc.Mode)),
				"rule":          llx.ResourceData(a, a.MqlName()),
				"createdAt":     llx.TimeDataPtr(assoc.CreatedAt),
				"updatedAt":     llx.TimeDataPtr(assoc.UpdatedAt),
				"expiresAt":     llx.TimeDataPtr(assoc.ExpiresAt),
			})
			if err != nil {
				return nil, err
			}
			cast := mqlAssoc.(*mqlAwsGuarddutyCustomDetectionRuleAssociation)
			cast.cacheRuleID = ruleID
			res = append(res, mqlAssoc)
		}
	}
	return res, nil
}

func (a *mqlAwsGuarddutyCustomDetectionRuleAssociation) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsGuarddutyCustomDetectionRuleAssociationInternal struct {
	cacheRuleID string
	detailOnce  sync.Once
	detail      *types.AssociationDetail
	detailErr   error
}

// fetchDetail reads the account the association binds the rule to, which the
// list API does not carry. There is no batch form, so this costs one call per
// association and stays behind the accountId accessor.
func (a *mqlAwsGuarddutyCustomDetectionRuleAssociation) fetchDetail() (*types.AssociationDetail, error) {
	a.detailOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Guardduty(a.Region.Data)
		associationID := a.AssociationId.Data
		ruleID := a.cacheRuleID

		out, err := svc.GetCustomDetectionRuleAssociation(context.Background(), &guardduty.GetCustomDetectionRuleAssociationInput{
			AssociationId: &associationID,
			RuleId:        &ruleID,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("association", associationID).Msg("access denied getting guardduty custom detection rule association")
				return
			}
			a.detailErr = err
			return
		}
		a.detail = out.RuleAssociation
	})
	return a.detail, a.detailErr
}

func (a *mqlAwsGuarddutyCustomDetectionRuleAssociation) accountId() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.AccountId == nil {
		a.AccountId = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *detail.AccountId, nil
}

// --- Organization rollouts ---

func (a *mqlAwsGuardduty) customDetectionRuleOrgConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCustomDetectionRuleOrgConfigurations(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsGuardduty) getCustomDetectionRuleOrgConfigurations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("guardduty>getCustomDetectionRuleOrgConfigurations>calling aws with region %s", region)

			svc := conn.Guardduty(region)
			ctx := context.Background()
			res := []any{}

			paginator := guardduty.NewListCustomDetectionRuleOrgConfigurationsPaginator(svc, &guardduty.ListCustomDetectionRuleOrgConfigurationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("guardduty custom detection rules are not available in region")
						return res, nil
					}
					if isOrganizationsNotInUseError(err) {
						return res, nil
					}
					return nil, err
				}
				for _, cfg := range page.Configurations {
					ruleID := convert.ToValue(cfg.RuleId)
					mode := string(cfg.Mode)

					mqlCfg, err := CreateResource(a.MqlRuntime, "aws.guardduty.customDetectionRule.organizationConfiguration", map[string]*llx.RawData{
						"__id":         llx.StringData(guarddutyOrgConfigCacheID(region, ruleID, mode)),
						"region":       llx.StringData(region),
						"mode":         llx.StringData(mode),
						"status":       llx.StringData(string(cfg.Status)),
						"statusReason": llx.StringDataPtr(cfg.StatusReason),
						"createdAt":    llx.TimeDataPtr(cfg.CreatedAt),
						"updatedAt":    llx.TimeDataPtr(cfg.UpdatedAt),
						"expiresAt":    llx.TimeDataPtr(cfg.ExpiresAt),
					})
					if err != nil {
						return nil, err
					}
					cast := mqlCfg.(*mqlAwsGuarddutyCustomDetectionRuleOrganizationConfiguration)
					cast.cacheRuleID = ruleID
					res = append(res, mqlCfg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsGuarddutyCustomDetectionRuleOrganizationConfiguration) id() (string, error) {
	return a.__id, nil
}

type mqlAwsGuarddutyCustomDetectionRuleOrganizationConfigurationInternal struct {
	cacheRuleID string
	detailOnce  sync.Once
	detail      *types.DetectionRuleOrgConfiguration
	detailErr   error
}

// fetchDetail reads the account scoping of the rollout, which the list API
// does not carry.
func (a *mqlAwsGuarddutyCustomDetectionRuleOrganizationConfiguration) fetchDetail() (*types.DetectionRuleOrgConfiguration, error) {
	a.detailOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Guardduty(a.Region.Data)
		ruleID := a.cacheRuleID

		out, err := svc.GetCustomDetectionRuleOrgConfiguration(context.Background(), &guardduty.GetCustomDetectionRuleOrgConfigurationInput{
			RuleId: &ruleID,
			Mode:   types.AssociationMode(a.Mode.Data),
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("rule", ruleID).Msg("access denied getting guardduty custom detection rule org configuration")
				return
			}
			a.detailErr = err
			return
		}
		a.detail = out.Configuration
	})
	return a.detail, a.detailErr
}

func (a *mqlAwsGuarddutyCustomDetectionRuleOrganizationConfiguration) includeAccountIds() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		a.IncludeAccountIds = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return toInterfaceArr(detail.IncludeAccountIds), nil
}

func (a *mqlAwsGuarddutyCustomDetectionRuleOrganizationConfiguration) excludeAccountIds() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		a.ExcludeAccountIds = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return toInterfaceArr(detail.ExcludeAccountIds), nil
}

func (a *mqlAwsGuarddutyCustomDetectionRuleOrganizationConfiguration) rule() (*mqlAwsGuarddutyCustomDetectionRule, error) {
	obj, err := CreateResource(a.MqlRuntime, "aws.guardduty", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	guardduty := obj.(*mqlAwsGuardduty)
	rules := guardduty.GetCustomDetectionRules()
	if rules.Error != nil {
		return nil, rules.Error
	}

	if rule := findCustomDetectionRule(rules.Data, a.Region.Data, a.cacheRuleID); rule != nil {
		return rule, nil
	}
	a.Rule.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
