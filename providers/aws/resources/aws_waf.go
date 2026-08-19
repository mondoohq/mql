// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/types"
)

// wafRegionForScope returns the region to use for WAF API calls.
// CLOUDFRONT-scoped resources must use us-east-1; REGIONAL uses the default.
func wafRegionForScope(scope string) string {
	if scope == "CLOUDFRONT" {
		return "us-east-1"
	}
	return ""
}

// id includes the scope: aws.waf is parameterized on it, so a constant key made
// aws.waf(scope: "REGIONAL") return the cached CLOUDFRONT instance (or vice
// versa) whenever both were queried in one scan.
func (a *mqlAwsWaf) id() (string, error) {
	return "aws.waf/" + a.Scope.Data, nil
}

// wafTagsForArn lists the tags on a WAF resource, resolving the WAF endpoint
// from the resource's scope. A missing wafv2:ListTagsForResource permission is
// reported as errTagsUnreadable, which each caller turns into a null tags
// field rather than an empty one.
func wafTagsForArn(runtime *plugin.Runtime, scope, arn string) (map[string]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Wafv2(wafRegionForScope(scope))
	ctx := context.Background()

	tags := map[string]any{}
	var nextMarker *string
	for {
		resp, err := svc.ListTagsForResource(ctx, &wafv2.ListTagsForResourceInput{
			ResourceARN: &arn,
			NextMarker:  nextMarker,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		if resp.TagInfoForResource != nil {
			for _, t := range resp.TagInfoForResource.TagList {
				if t.Key != nil {
					tags[*t.Key] = convert.ToValue(t.Value)
				}
			}
		}
		// WAFv2 signals the end of pagination with an empty-but-non-nil
		// NextMarker. Passing that empty string back to ListTagsForResource
		// fails validation ("Member must have length greater than or equal to
		// 1"), so treat empty the same as nil.
		if resp.NextMarker == nil || *resp.NextMarker == "" {
			break
		}
		nextMarker = resp.NextMarker
	}
	return tags, nil
}

func (a *mqlAwsWafAcl) tags() (map[string]any, error) {
	tags, err := wafTagsForArn(a.MqlRuntime, a.Scope.Data, a.Arn.Data)
	return tagsOrUnreadable(&a.Tags, tags, err)
}

func (a *mqlAwsWafRulegroup) tags() (map[string]any, error) {
	tags, err := wafTagsForArn(a.MqlRuntime, a.Scope.Data, a.Arn.Data)
	return tagsOrUnreadable(&a.Tags, tags, err)
}

func (a *mqlAwsWafIpset) tags() (map[string]any, error) {
	tags, err := wafTagsForArn(a.MqlRuntime, a.Scope.Data, a.Arn.Data)
	return tagsOrUnreadable(&a.Tags, tags, err)
}

func (a *mqlAwsWafRegexPatternSet) tags() (map[string]any, error) {
	tags, err := wafTagsForArn(a.MqlRuntime, a.Scope.Data, a.Arn.Data)
	return tagsOrUnreadable(&a.Tags, tags, err)
}

func (a *mqlAwsWafAcl) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsWafAclInternal struct {
	fetched                  bool
	cachedManagedByFwManager bool
	cachedRules              []waftypes.Rule
	cachedACL                *waftypes.WebACL
	lock                     sync.Mutex
}

func (a *mqlAwsWafAcl) fetchACLDetails() error {
	if a.fetched {
		return nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Wafv2(wafRegionForScope(a.Scope.Data))
	ctx := context.Background()

	resp, err := svc.GetWebACL(ctx, &wafv2.GetWebACLInput{
		Id:    &a.Id.Data,
		Name:  &a.Name.Data,
		Scope: waftypes.Scope(a.Scope.Data),
	})
	if err != nil {
		return err
	}
	if resp.WebACL == nil {
		return errors.New("GetWebACL returned no web acl for " + a.Name.Data)
	}
	a.cachedManagedByFwManager = resp.WebACL.ManagedByFirewallManager
	a.cachedRules = resp.WebACL.Rules
	a.cachedACL = resp.WebACL
	a.fetched = true
	return nil
}

func (a *mqlAwsWafAcl) managedByFirewallManager() (bool, error) {
	if err := a.fetchACLDetails(); err != nil {
		return false, err
	}
	return a.cachedManagedByFwManager, nil
}

func (a *mqlAwsWafAcl) defaultAction() (string, error) {
	if err := a.fetchACLDetails(); err != nil {
		return "", err
	}
	action := ""
	if a.cachedACL != nil && a.cachedACL.DefaultAction != nil {
		if a.cachedACL.DefaultAction.Allow != nil {
			action = "allow"
		} else if a.cachedACL.DefaultAction.Block != nil {
			action = "block"
		}
	}
	return action, nil
}

func (a *mqlAwsWafAcl) visibilityConfig() (any, error) {
	if err := a.fetchACLDetails(); err != nil {
		return nil, err
	}
	if a.cachedACL == nil {
		return nil, nil
	}
	return wafVisibilityConfigToDict(a.cachedACL.VisibilityConfig), nil
}

func (a *mqlAwsWafAcl) capacity() (int64, error) {
	if err := a.fetchACLDetails(); err != nil {
		return 0, err
	}
	if a.cachedACL == nil {
		return 0, nil
	}
	return a.cachedACL.Capacity, nil
}

func (a *mqlAwsWafAcl) tokenDomains() ([]any, error) {
	if err := a.fetchACLDetails(); err != nil {
		return nil, err
	}
	if a.cachedACL == nil {
		return nil, nil
	}
	return convert.SliceAnyToInterface(a.cachedACL.TokenDomains), nil
}

func (a *mqlAwsWafAcl) labelNamespace() (string, error) {
	if err := a.fetchACLDetails(); err != nil {
		return "", err
	}
	if a.cachedACL == nil {
		return "", nil
	}
	return convert.ToValue(a.cachedACL.LabelNamespace), nil
}

func wafVisibilityConfigToDict(vc *waftypes.VisibilityConfig) map[string]any {
	if vc == nil {
		return nil
	}
	return map[string]any{
		"cloudWatchMetricsEnabled": vc.CloudWatchMetricsEnabled,
		"sampledRequestsEnabled":   vc.SampledRequestsEnabled,
		"metricName":               convert.ToValue(vc.MetricName),
	}
}

func wafLoggingFilterToDict(lf *waftypes.LoggingFilter) map[string]any {
	if lf == nil {
		return nil
	}
	filters := []any{}
	for _, f := range lf.Filters {
		conditions := []any{}
		for _, c := range f.Conditions {
			cond := map[string]any{}
			if c.ActionCondition != nil {
				cond["actionCondition"] = string(c.ActionCondition.Action)
			}
			if c.LabelNameCondition != nil {
				cond["labelNameCondition"] = convert.ToValue(c.LabelNameCondition.LabelName)
			}
			conditions = append(conditions, cond)
		}
		filters = append(filters, map[string]any{
			"behavior":    string(f.Behavior),
			"requirement": string(f.Requirement),
			"conditions":  conditions,
		})
	}
	return map[string]any{
		"defaultBehavior": string(lf.DefaultBehavior),
		"filters":         filters,
	}
}

func wafRuleLabelsToInterface(labels []waftypes.Label) []any {
	res := []any{}
	for _, l := range labels {
		res = append(res, convert.ToValue(l.Name))
	}
	return res
}

func wafOverrideActionString(oa *waftypes.OverrideAction) string {
	if oa == nil {
		return ""
	}
	if oa.Count != nil {
		return "count"
	}
	if oa.None != nil {
		return "none"
	}
	return ""
}

func (a *mqlAwsWafRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsWafRuleStatement) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsWafRulegroup) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsWafIpset) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsWafIpsetInternal struct {
	fetched         bool
	cachedAddrType  string
	cachedAddresses []any
	lock            sync.Mutex
}

func (a *mqlAwsWafIpset) fetchIPSet() error {
	if a.fetched {
		return nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Wafv2(wafRegionForScope(a.Scope.Data))
	ctx := context.Background()

	resp, err := svc.GetIPSet(ctx, &wafv2.GetIPSetInput{
		Id:    &a.Id.Data,
		Name:  &a.Name.Data,
		Scope: waftypes.Scope(a.Scope.Data),
	})
	if err != nil {
		return err
	}
	if resp.IPSet == nil {
		return errors.New("GetIPSet returned no ip set for " + a.Name.Data)
	}
	a.cachedAddrType = string(resp.IPSet.IPAddressVersion)
	a.cachedAddresses = convert.SliceAnyToInterface(resp.IPSet.Addresses)
	a.fetched = true
	return nil
}

func (a *mqlAwsWafIpset) addressType() (string, error) {
	if err := a.fetchIPSet(); err != nil {
		return "", err
	}
	return a.cachedAddrType, nil
}

func (a *mqlAwsWafIpset) addresses() (any, error) {
	if err := a.fetchIPSet(); err != nil {
		return nil, err
	}
	return a.cachedAddresses, nil
}

func initAwsWaf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	scope := ""
	if x, ok := args["scope"]; ok {
		scope = x.Value.(string)
	} else {
		scope = "CLOUDFRONT"
	}
	args["scope"] = llx.StringData(scope)

	log.Debug().Msgf("AWS WAF using scope: %s", scope)

	return args, nil, nil
}

func (a *mqlAwsWaf) acls() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	scopeString := a.Scope.Data
	svc := conn.Wafv2(wafRegionForScope(scopeString))
	ctx := context.Background()
	acls := []any{}
	nextMarker := aws.String("No-Marker-to-begin-with")
	scope := waftypes.Scope(scopeString)
	params := &wafv2.ListWebACLsInput{Scope: scope}
	for nextMarker != nil {
		aclsRes, err := svc.ListWebACLs(ctx, params)
		if err != nil {
			return nil, err
		}
		nextMarker = aclsRes.NextMarker
		if aclsRes.NextMarker != nil {
			params.NextMarker = nextMarker
		}

		for _, acl := range aclsRes.WebACLs {
			mqlAcl, err := CreateResource(a.MqlRuntime, "aws.waf.acl",
				map[string]*llx.RawData{
					"__id":        llx.StringDataPtr(acl.ARN),
					"id":          llx.StringDataPtr(acl.Id),
					"scope":       llx.StringData(scopeString),
					"arn":         llx.StringDataPtr(acl.ARN),
					"name":        llx.StringDataPtr(acl.Name),
					"description": llx.StringDataPtr(acl.Description),
				},
			)
			if err != nil {
				return nil, err
			}
			acls = append(acls, mqlAcl)
		}
	}
	return acls, nil
}

func (a *mqlAwsWafRuleStatementSqlimatchstatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementBytematchstatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementXssmatchstatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementRegexmatchstatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementGeomatchstatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementIpsetreferencestatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementLabelmatchstatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementManagedrulegroupstatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementNotstatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementOrstatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementAndstatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementRatebasedstatement) id() (string, error) {
	return "not implemented", nil
}

func (a *mqlAwsWafRuleStatementRegexpatternsetreferencestatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementRulegroupreferencestatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleStatementSizeconstraintstatement) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleFieldtomatch) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleFieldtomatchBody) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleFieldtomatchJsonbody) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleFieldtomatchCookie) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleFieldtomatchHeaders) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleFieldtomatchHeaderorder) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleFieldtomatchSingleheader) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleFieldtomatchSinglequeryargument) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleFieldtomatchHeadersMatchpattern) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleFieldtomatchJsonbodyMatchpattern) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRuleFieldtomatchJa3fingerprint) id() (string, error) {
	return a.StatementID.Data, nil
}

func (a *mqlAwsWafRulegroup) rules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	scopeString := a.Scope.Data
	scope := waftypes.Scope(scopeString)
	ctx := context.Background()
	svc := conn.Wafv2(wafRegionForScope(scopeString))
	rules := []any{}
	params := &wafv2.GetRuleGroupInput{
		Id:    &a.Id.Data,
		Name:  &a.Name.Data,
		Scope: scope,
	}
	ruleGroupDetails, err := svc.GetRuleGroup(ctx, params)
	if err != nil {
		return nil, err
	}
	if ruleGroupDetails.RuleGroup == nil {
		return nil, errors.New("GetRuleGroup returned no rule group for " + a.Name.Data)
	}
	for _, rule := range ruleGroupDetails.RuleGroup.Rules {
		if rule.Name == nil {
			log.Debug().Str("rulegroup", a.Arn.Data).Msg("skipping a rule group rule with no name")
			continue
		}
		ruleID := a.Arn.Data + "/" + *rule.Name
		mqlStatement, err := createStatementResource(a.MqlRuntime, rule.Statement, rule.Name, ruleID)
		if err != nil {
			return nil, err
		}
		ruleAction, err := createActionResource(a.MqlRuntime, rule.Action, rule.Name, ruleID)
		if err != nil {
			return nil, err
		}
		mqlRule, err := CreateResource(a.MqlRuntime, "aws.waf.rule",
			map[string]*llx.RawData{
				"id":               llx.StringData(ruleID),
				"name":             llx.StringDataPtr(rule.Name),
				"priority":         llx.IntData(int64(rule.Priority)),
				"action":           llx.ResourceData(ruleAction, "aws.waf.rule.action"),
				"overrideAction":   llx.StringData(wafOverrideActionString(rule.OverrideAction)),
				"visibilityConfig": llx.DictData(wafVisibilityConfigToDict(rule.VisibilityConfig)),
				"ruleLabels":       llx.ArrayData(wafRuleLabelsToInterface(rule.RuleLabels), types.String),
				"statement":        llx.ResourceData(mqlStatement, "aws.waf.rule.statement"),
				"belongsTo":        llx.StringData(a.Arn.Data),
			},
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, mqlRule)
	}
	return rules, nil
}

func (a *mqlAwsWaf) ruleGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	scopeString := a.Scope.Data
	svc := conn.Wafv2(wafRegionForScope(scopeString))
	ctx := context.Background()
	acls := []any{}
	nextMarker := aws.String("No-Marker-to-begin-with")
	scope := waftypes.Scope(scopeString)
	params := &wafv2.ListRuleGroupsInput{Scope: scope}
	for nextMarker != nil {
		aclsRes, err := svc.ListRuleGroups(ctx, params)
		if err != nil {
			return nil, err
		}
		nextMarker = aclsRes.NextMarker
		if aclsRes.NextMarker != nil {
			params.NextMarker = nextMarker
		}

		for _, ruleGroup := range aclsRes.RuleGroups {
			mqlRuleGroup, err := CreateResource(a.MqlRuntime, "aws.waf.rulegroup",
				map[string]*llx.RawData{
					"__id":        llx.StringDataPtr(ruleGroup.ARN),
					"id":          llx.StringDataPtr(ruleGroup.Id),
					"arn":         llx.StringDataPtr(ruleGroup.ARN),
					"name":        llx.StringDataPtr(ruleGroup.Name),
					"description": llx.StringDataPtr(ruleGroup.Description),
					"scope":       llx.StringData(scopeString),
				},
			)
			if err != nil {
				return nil, err
			}
			acls = append(acls, mqlRuleGroup)
		}
	}
	return acls, nil
}

func (a *mqlAwsWaf) ipSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	scopeString := a.Scope.Data
	svc := conn.Wafv2(wafRegionForScope(scopeString))
	ctx := context.Background()
	acls := []any{}
	nextMarker := aws.String("No-Marker-to-begin-with")
	scope := waftypes.Scope(scopeString)
	params := &wafv2.ListIPSetsInput{Scope: scope}
	for nextMarker != nil {
		aclsRes, err := svc.ListIPSets(ctx, params)
		if err != nil {
			return nil, err
		}
		nextMarker = aclsRes.NextMarker
		if aclsRes.NextMarker != nil {
			params.NextMarker = nextMarker
		}

		for _, ipset := range aclsRes.IPSets {
			mqlIPSet, err := CreateResource(a.MqlRuntime, "aws.waf.ipset",
				map[string]*llx.RawData{
					"__id":        llx.StringDataPtr(ipset.ARN),
					"id":          llx.StringDataPtr(ipset.Id),
					"arn":         llx.StringDataPtr(ipset.ARN),
					"name":        llx.StringDataPtr(ipset.Name),
					"description": llx.StringDataPtr(ipset.Description),
					"scope":       llx.StringData(scopeString),
				},
			)
			if err != nil {
				return nil, err
			}
			acls = append(acls, mqlIPSet)
		}
	}
	return acls, nil
}

func (a *mqlAwsWafAcl) rules() ([]any, error) {
	if err := a.fetchACLDetails(); err != nil {
		return nil, err
	}
	rules := []any{}
	for _, rule := range a.cachedRules {
		ruleID := a.Arn.Data + "/" + *rule.Name
		mqlStatement, err := createStatementResource(a.MqlRuntime, rule.Statement, rule.Name, ruleID)
		if err != nil {
			return nil, err
		}
		ruleAction, err := createActionResource(a.MqlRuntime, rule.Action, rule.Name, ruleID)
		if err != nil {
			return nil, err
		}
		mqlRule, err := CreateResource(a.MqlRuntime, "aws.waf.rule",
			map[string]*llx.RawData{
				"id":               llx.StringData(ruleID),
				"name":             llx.StringDataPtr(rule.Name),
				"priority":         llx.IntData(int64(rule.Priority)),
				"action":           llx.ResourceData(ruleAction, "aws.waf.rule.action"),
				"overrideAction":   llx.StringData(wafOverrideActionString(rule.OverrideAction)),
				"visibilityConfig": llx.DictData(wafVisibilityConfigToDict(rule.VisibilityConfig)),
				"ruleLabels":       llx.ArrayData(wafRuleLabelsToInterface(rule.RuleLabels), types.String),
				"statement":        llx.ResourceData(mqlStatement, "aws.waf.rule.statement"),
				"belongsTo":        llx.StringData(a.Arn.Data),
			},
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, mqlRule)
	}
	return rules, nil
}

func createActionResource(runtime *plugin.Runtime, ruleAction *waftypes.RuleAction, ruleName *string, ruleID string) (plugin.Resource, error) {
	var mqlAction plugin.Resource
	var err error

	var action string
	responseCode := ""
	if ruleAction != nil {
		if ruleAction.Allow != nil {
			action = "allow"
		}

		if ruleAction.Block != nil {
			action = "block"
			if ruleAction.Block.CustomResponse != nil && ruleAction.Block.CustomResponse.ResponseCode != nil {
				responseCode = strconv.Itoa(int(*ruleAction.Block.CustomResponse.ResponseCode))
			} else {
				responseCode = "403" // Default for Block
			}
		}

		if ruleAction.Count != nil {
			action = "count"
		}
		if ruleAction.Captcha != nil {
			action = "captcha"
		}
		if ruleAction.Challenge != nil {
			action = "challenge"
		}
	}
	mqlAction, err = CreateResource(runtime, "aws.waf.rule.action", map[string]*llx.RawData{
		"__id":         llx.StringData(ruleID + "/action"),
		"ruleName":     llx.StringDataPtr(ruleName),
		"action":       llx.StringData(action),
		"responseCode": llx.StringData(responseCode),
	})
	return mqlAction, err
}

func createStatementResource(runtime *plugin.Runtime, statement *waftypes.Statement, ruleName *string, ruleID string) (plugin.Resource, error) {
	var err error
	var sqlimatchstatement plugin.Resource
	var xssmatchstatement plugin.Resource
	var bytematchstatement plugin.Resource
	var regexmatchstatement plugin.Resource
	var geomatchstatement plugin.Resource
	var ipsetreferencestatement plugin.Resource
	var labelmatchstatement plugin.Resource
	var managedrulegroupstatement plugin.Resource
	var andStatement plugin.Resource
	var notstatement plugin.Resource
	var orstatement plugin.Resource
	var ratebasedstatement plugin.Resource
	var regexpatternsetreferencestatement plugin.Resource
	var rulegroupreferencestatement plugin.Resource
	var sizeconstraintstatement plugin.Resource
	var statementJson map[string]any
	mqlStatementID := ruleID + "/" + uuid.New().String()
	var kind string
	if statement != nil {
		statementJson, err = convert.JsonToDict(statement)
		if err != nil {
			return nil, err
		}
		if statement.RegexMatchStatement != nil {
			kind = "RegexMatchStatement"
			var fieldToMatch plugin.Resource
			fieldToMatch, err = createFieldToMatchResource(runtime, statement.RegexMatchStatement.FieldToMatch, ruleName, mqlStatementID)
			if err != nil {
				return nil, err
			}
			regexmatchstatement, err = CreateResource(runtime, "aws.waf.rule.statement.regexmatchstatement", map[string]*llx.RawData{
				"statementID":  llx.StringData(mqlStatementID),
				"ruleName":     llx.StringDataPtr(ruleName),
				"fieldToMatch": llx.ResourceData(fieldToMatch, "aws.waf.rule.statement.regexmatchstatement.fieldtomatch"),
				"regexString":  llx.StringDataPtr(statement.RegexMatchStatement.RegexString),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.ByteMatchStatement != nil {
			kind = "ByteMatchStatement"
			var fieldToMatch plugin.Resource
			fieldToMatch, err = createFieldToMatchResource(runtime, statement.ByteMatchStatement.FieldToMatch, ruleName, mqlStatementID)
			if err != nil {
				return nil, err
			}
			bytematchstatement, err = CreateResource(runtime, "aws.waf.rule.statement.bytematchstatement", map[string]*llx.RawData{
				"statementID":  llx.StringData(mqlStatementID),
				"ruleName":     llx.StringDataPtr(ruleName),
				"fieldToMatch": llx.ResourceData(fieldToMatch, "aws.waf.rule.fieldtomatch"),
				"searchString": llx.StringData(string(statement.ByteMatchStatement.SearchString)),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.XssMatchStatement != nil {
			kind = "XssMatchStatement"
			var fieldToMatch plugin.Resource
			fieldToMatch, err = createFieldToMatchResource(runtime, statement.XssMatchStatement.FieldToMatch, ruleName, mqlStatementID)
			if err != nil {
				return nil, err
			}
			xssmatchstatement, err = CreateResource(runtime, "aws.waf.rule.statement.xssmatchstatement", map[string]*llx.RawData{
				"statementID":  llx.StringData(mqlStatementID),
				"ruleName":     llx.StringDataPtr(ruleName),
				"fieldToMatch": llx.ResourceData(fieldToMatch, "aws.waf.rule.fieldtomatch"),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.SqliMatchStatement != nil {
			kind = "SqliMatchStatement"
			var fieldToMatch plugin.Resource
			fieldToMatch, err := createFieldToMatchResource(runtime, statement.SqliMatchStatement.FieldToMatch, ruleName, mqlStatementID)
			if err != nil {
				return nil, err
			}
			sqlimatchstatement, err = CreateResource(runtime, "aws.waf.rule.statement.sqlimatchstatement", map[string]*llx.RawData{
				"statementID":      llx.StringData(mqlStatementID),
				"ruleName":         llx.StringDataPtr(ruleName),
				"fieldToMatch":     llx.ResourceData(fieldToMatch, "aws.waf.rule.fieldtomatch"),
				"sensitivityLevel": llx.StringData(string(statement.SqliMatchStatement.SensitivityLevel)),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.GeoMatchStatement != nil {
			kind = "GeoMatchStatement"
			var countryCodes []string
			for _, countryCode := range statement.GeoMatchStatement.CountryCodes {
				countryCodes = append(countryCodes, string(countryCode))
			}
			countryCodesArray := convert.SliceAnyToInterface(countryCodes)
			geomatchstatement, err = CreateResource(runtime, "aws.waf.rule.statement.geomatchstatement", map[string]*llx.RawData{
				"statementID":  llx.StringData(mqlStatementID),
				"ruleName":     llx.StringDataPtr(ruleName),
				"countryCodes": llx.ArrayData(countryCodesArray, types.String),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.IPSetReferenceStatement != nil {
			kind = "IPSetReferenceStatement"
			var IPSetForwardedIPConfig plugin.Resource
			if statement.IPSetReferenceStatement.IPSetForwardedIPConfig != nil {
				IPSetForwardedIPConfig, err = CreateResource(runtime, "aws.waf.rule.statement.ipsetreferencestatement.ipsetforwardedipconfig", map[string]*llx.RawData{
					"__id":             llx.StringData(mqlStatementID + "/ipsetforwardedipconfig"),
					"statementID":      llx.StringData(mqlStatementID),
					"ruleName":         llx.StringDataPtr(ruleName),
					"headerName":       llx.StringDataPtr(statement.IPSetReferenceStatement.IPSetForwardedIPConfig.HeaderName),
					"position":         llx.StringData(string(statement.IPSetReferenceStatement.IPSetForwardedIPConfig.Position)),
					"fallbackBehavior": llx.StringData(string(statement.IPSetReferenceStatement.IPSetForwardedIPConfig.FallbackBehavior)),
				})
				if err != nil {
					return nil, err
				}
			}
			ipsetreferencestatement, err = CreateResource(runtime, "aws.waf.rule.statement.ipsetreferencestatement", map[string]*llx.RawData{
				"statementID":            llx.StringData(mqlStatementID),
				"ruleName":               llx.StringDataPtr(ruleName),
				"arn":                    llx.StringDataPtr(statement.IPSetReferenceStatement.ARN),
				"ipSetForwardedIPConfig": llx.ResourceData(IPSetForwardedIPConfig, "aws.waf.rule.statement.ipsetreferencestatement.ipsetforwardedipconfig"),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.LabelMatchStatement != nil {
			kind = "LabelMatchStatement"
			labelmatchstatement, err = CreateResource(runtime, "aws.waf.rule.statement.labelmatchstatement", map[string]*llx.RawData{
				"statementID": llx.StringData(mqlStatementID),
				"ruleName":    llx.StringDataPtr(ruleName),
				"key":         llx.StringDataPtr(statement.LabelMatchStatement.Key),
				"scope":       llx.StringData(string(statement.LabelMatchStatement.Scope)),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.ManagedRuleGroupStatement != nil {
			kind = "ManagedRuleGroupStatement"
			managedrulegroupstatement, err = CreateResource(runtime, "aws.waf.rule.statement.managedrulegroupstatement", map[string]*llx.RawData{
				"statementID": llx.StringData(mqlStatementID),
				"ruleName":    llx.StringDataPtr(ruleName),
				"name":        llx.StringDataPtr(statement.ManagedRuleGroupStatement.Name),
				"vendorName":  llx.StringDataPtr(statement.ManagedRuleGroupStatement.VendorName),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.AndStatement != nil {
			kind = "AndStatement"
			var statements []any
			for _, statement := range statement.AndStatement.Statements {
				andStatementMqlStatement, err := createStatementResource(runtime, &statement, ruleName, ruleID)
				if err != nil {
					return nil, err
				}
				statements = append(statements, andStatementMqlStatement)
			}
			andStatement, err = CreateResource(runtime, "aws.waf.rule.statement.andstatement", map[string]*llx.RawData{
				"statementID": llx.StringData(mqlStatementID),
				"statements":  llx.ArrayData(statements, types.ResourceLike),
				"ruleName":    llx.StringDataPtr(ruleName),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.NotStatement != nil {
			kind = "NotStatement"
			var notStatementMqlStatement plugin.Resource
			notStatementMqlStatement, err = createStatementResource(runtime, statement.NotStatement.Statement, ruleName, ruleID)
			if err != nil {
				return nil, err
			}
			notstatement, err = CreateResource(runtime, "aws.waf.rule.statement.notstatement", map[string]*llx.RawData{
				"statementID": llx.StringData(mqlStatementID),
				"statement":   llx.ResourceData(notStatementMqlStatement, "aws.waf.rule.statement.notstatement"),
				"ruleName":    llx.StringDataPtr(ruleName),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.OrStatement != nil {
			kind = "OrStatement"
			var statements []any
			for _, statement := range statement.OrStatement.Statements {
				orStatementMqlStatement, err := createStatementResource(runtime, &statement, ruleName, ruleID)
				if err != nil {
					return nil, err
				}
				statements = append(statements, orStatementMqlStatement)
			}
			orstatement, err = CreateResource(runtime, "aws.waf.rule.statement.orstatement", map[string]*llx.RawData{
				"statementID": llx.StringData(mqlStatementID),
				"statements":  llx.ArrayData(statements, types.ResourceLike),
				"ruleName":    llx.StringDataPtr(ruleName),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.RateBasedStatement != nil {
			kind = "RateBasedStatement"
			ratebasedstatement, err = CreateResource(runtime, "aws.waf.rule.statement.ratebasedstatement", map[string]*llx.RawData{})
			if err != nil {
				return nil, err
			}
		}
		if statement.RegexPatternSetReferenceStatement != nil {
			kind = "RegexPatternSetReferenceStatement"
			var fieldToMatch plugin.Resource
			fieldToMatch, err = createFieldToMatchResource(runtime, statement.RegexPatternSetReferenceStatement.FieldToMatch, ruleName, mqlStatementID)
			if err != nil {
				return nil, err
			}
			regexpatternsetreferencestatement, err = CreateResource(runtime, "aws.waf.rule.statement.regexpatternsetreferencestatement", map[string]*llx.RawData{
				"statementID":  llx.StringData(mqlStatementID),
				"ruleName":     llx.StringDataPtr(ruleName),
				"arn":          llx.StringDataPtr(statement.RegexPatternSetReferenceStatement.ARN),
				"fieldToMatch": llx.ResourceData(fieldToMatch, "aws.waf.rule.fieldtomatch"),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.RuleGroupReferenceStatement != nil {
			kind = "RuleGroupReferenceStatement"
			excludeRules := convert.SliceAnyToInterface(statement.RuleGroupReferenceStatement.ExcludedRules)
			rulegroupreferencestatement, err = CreateResource(runtime, "aws.waf.rule.statement.rulegroupreferencestatement", map[string]*llx.RawData{
				"statementID":  llx.StringData(mqlStatementID),
				"ruleName":     llx.StringDataPtr(ruleName),
				"arn":          llx.StringDataPtr(statement.RuleGroupReferenceStatement.ARN),
				"excludeRules": llx.ArrayData(excludeRules, types.String),
			})
			if err != nil {
				return nil, err
			}
		}
		if statement.SizeConstraintStatement != nil {
			kind = "SizeConstraintStatement"
			var fieldToMatch plugin.Resource
			fieldToMatch, err = createFieldToMatchResource(runtime, statement.SizeConstraintStatement.FieldToMatch, ruleName, mqlStatementID)
			if err != nil {
				return nil, err
			}
			sizeconstraintstatement, err = CreateResource(runtime, "aws.waf.rule.statement.sizeconstraintstatement", map[string]*llx.RawData{
				"statementID":        llx.StringData(mqlStatementID),
				"ruleName":           llx.StringDataPtr(ruleName),
				"size":               llx.IntData(statement.SizeConstraintStatement.Size),
				"comparisonOperator": llx.StringData(string(statement.SizeConstraintStatement.ComparisonOperator)),
				"fieldToMatch":       llx.ResourceData(fieldToMatch, "aws.waf.rule.fieldtomatch"),
			})
			if err != nil {
				return nil, err
			}
		}
	}
	var mqlStatement plugin.Resource
	mqlStatement, err = CreateResource(runtime, "aws.waf.rule.statement",
		map[string]*llx.RawData{
			"id":                                llx.StringData(mqlStatementID),
			"kind":                              llx.StringData(kind),
			"json":                              llx.DictData(statementJson),
			"regexMatchStatement":               llx.ResourceData(regexmatchstatement, "aws.waf.rule.statement.regexmatchstatement"),
			"byteMatchStatement":                llx.ResourceData(bytematchstatement, "aws.waf.rule.statement.bytematchstatement"),
			"xssMatchStatement":                 llx.ResourceData(xssmatchstatement, "aws.waf.rule.statement.xssmatchstatement"),
			"sqliMatchStatement":                llx.ResourceData(sqlimatchstatement, "aws.waf.rule.statement.sqlimatchstatement"),
			"geoMatchStatement":                 llx.ResourceData(geomatchstatement, "aws.waf.rule.statement.geomatchstatement"),
			"ipSetReferenceStatement":           llx.ResourceData(ipsetreferencestatement, "aws.waf.rule.statement.ipsetreferencestatement"),
			"labelMatchStatement":               llx.ResourceData(labelmatchstatement, "aws.waf.rule.statement.labelmatchstatement"),
			"managedRuleGroupStatement":         llx.ResourceData(managedrulegroupstatement, "aws.waf.rule.statement.managedrulegroupstatement"),
			"notStatement":                      llx.ResourceData(notstatement, "aws.waf.rule.statement.notstatement"),
			"orStatement":                       llx.ResourceData(orstatement, "aws.waf.rule.statement.orstatement"),
			"andStatement":                      llx.ResourceData(andStatement, "aws.waf.rule.statement.andStatement"),
			"rateBasedStatement":                llx.ResourceData(ratebasedstatement, "aws.waf.rule.statement.ratebasedstatement"),
			"regexPatternSetReferenceStatement": llx.ResourceData(regexpatternsetreferencestatement, "aws.waf.rule.statement.regexpatternsetreferencestatement"),
			"ruleGroupReferenceStatement":       llx.ResourceData(rulegroupreferencestatement, "aws.waf.rule.statement.rulegroupreferencestatement"),
			"sizeConstraintStatement":           llx.ResourceData(sizeconstraintstatement, "aws.waf.rule.statement.sizeconstraintstatement"),
		},
	)

	return mqlStatement, nil
}

func createFieldToMatchResource(runtime *plugin.Runtime, fieldToMatch *waftypes.FieldToMatch, ruleName *string, mqlStatementID string) (plugin.Resource, error) {
	var err error
	var singleHeader plugin.Resource
	var singleQueryArgument plugin.Resource
	var body plugin.Resource
	var cookie plugin.Resource
	var headerOrder plugin.Resource
	var headers plugin.Resource
	var ja3Fingerprint plugin.Resource
	var jsonBody plugin.Resource
	var target string
	if fieldToMatch.SingleHeader != nil {
		target = "SingleHeader"
		singleHeader, err = CreateResource(runtime, "aws.waf.rule.fieldtomatch.singleheader", map[string]*llx.RawData{
			"statementID": llx.StringData(mqlStatementID),
			"ruleName":    llx.StringDataPtr(ruleName),
			"name":        llx.StringDataPtr(fieldToMatch.SingleHeader.Name),
		})
		if err != nil {
			return nil, err
		}
	}
	if fieldToMatch.SingleQueryArgument != nil {
		target = "SingleQueryArgument"
		singleQueryArgument, err = CreateResource(runtime, "aws.waf.rule.fieldtomatch.singlequeryargument", map[string]*llx.RawData{
			"statementID": llx.StringData(mqlStatementID),
			"ruleName":    llx.StringDataPtr(ruleName),
			"name":        llx.StringDataPtr(fieldToMatch.SingleQueryArgument.Name),
		})
		if err != nil {
			return nil, err
		}
	}
	if fieldToMatch.Body != nil {
		target = "Body"
		body, err = CreateResource(runtime, "aws.waf.rule.fieldtomatch.body", map[string]*llx.RawData{
			"statementID":      llx.StringData(mqlStatementID),
			"ruleName":         llx.StringDataPtr(ruleName),
			"overSizeHandling": llx.StringData(string(fieldToMatch.Body.OversizeHandling)),
		})
		if err != nil {
			return nil, err
		}
	}
	if fieldToMatch.Cookies != nil {
		target = "Cookies"
		cookie, err = CreateResource(runtime, "aws.waf.rule.fieldtomatch.cookie", map[string]*llx.RawData{
			"statementID":      llx.StringData(mqlStatementID),
			"ruleName":         llx.StringDataPtr(ruleName),
			"overSizeHandling": llx.StringData(string(fieldToMatch.Cookies.OversizeHandling)),
		})
		if err != nil {
			return nil, err
		}
	}
	if fieldToMatch.HeaderOrder != nil {
		target = "HeaderOrder"
		headerOrder, err = CreateResource(runtime, ResourceAwsWafRuleFieldtomatchHeaderorder, map[string]*llx.RawData{
			"__id":             llx.StringData(mqlStatementID + "/headerOrder"),
			"statementID":      llx.StringData(mqlStatementID),
			"ruleName":         llx.StringDataPtr(ruleName),
			"overSizeHandling": llx.StringData(string(fieldToMatch.HeaderOrder.OversizeHandling)),
		})
		if err != nil {
			return nil, err
		}
	}
	if fieldToMatch.JA3Fingerprint != nil {
		target = "JA3Fingerprint"
		ja3Fingerprint, err = CreateResource(runtime, "aws.waf.rule.fieldtomatch.ja3fingerprint", map[string]*llx.RawData{
			"statementID":      llx.StringData(mqlStatementID),
			"ruleName":         llx.StringDataPtr(ruleName),
			"fallbackBehavior": llx.StringData(string(fieldToMatch.JA3Fingerprint.FallbackBehavior)),
		})
		if err != nil {
			return nil, err
		}
	}

	if fieldToMatch.Headers != nil {
		target = "Headers"
		var matchPattern plugin.Resource
		if fieldToMatch.Headers.MatchPattern != nil {
			includeHeaders := convert.SliceAnyToInterface(fieldToMatch.Headers.MatchPattern.IncludedHeaders)
			excludeHeaders := convert.SliceAnyToInterface(fieldToMatch.Headers.MatchPattern.ExcludedHeaders)
			matchPattern, err = CreateResource(runtime, ResourceAwsWafRuleFieldtomatchHeadersMatchpattern, map[string]*llx.RawData{
				"__id":           llx.StringData(mqlStatementID + "/headers/matchPattern"),
				"statementID":    llx.StringData(mqlStatementID),
				"ruleName":       llx.StringDataPtr(ruleName),
				"all":            llx.BoolData(fieldToMatch.Headers.MatchPattern.All != nil),
				"includeHeaders": llx.ArrayData(includeHeaders, types.String),
				"excludeHeaders": llx.ArrayData(excludeHeaders, types.String),
			})
			if err != nil {
				return nil, err
			}
		}
		headers, err = CreateResource(runtime, ResourceAwsWafRuleFieldtomatchHeaders, map[string]*llx.RawData{
			"__id":             llx.StringData(mqlStatementID + "/headers"),
			"statementID":      llx.StringData(mqlStatementID),
			"ruleName":         llx.StringDataPtr(ruleName),
			"matchPattern":     llx.ResourceData(matchPattern, ResourceAwsWafRuleFieldtomatchHeadersMatchpattern),
			"overSizeHandling": llx.StringData(string(fieldToMatch.Headers.OversizeHandling)),
			"matchScope":       llx.StringData(string(fieldToMatch.Headers.MatchScope)),
		})
		if err != nil {
			return nil, err
		}
	}
	if fieldToMatch.JsonBody != nil {
		target = "JsonBody"
		var matchPattern plugin.Resource
		if fieldToMatch.JsonBody.MatchPattern != nil {
			includePathsArray := convert.SliceAnyToInterface(fieldToMatch.JsonBody.MatchPattern.IncludedPaths)
			matchPattern, err = CreateResource(runtime, "aws.waf.rule.fieldtomatch.jsonbody.matchpattern", map[string]*llx.RawData{
				"statementID":  llx.StringData(mqlStatementID),
				"ruleName":     llx.StringDataPtr(ruleName),
				"all":          llx.BoolData(fieldToMatch.JsonBody.MatchPattern.All != nil),
				"includePaths": llx.ArrayData(includePathsArray, types.String),
			})
			if err != nil {
				return nil, err
			}
		}
		jsonBody, err = CreateResource(runtime, "aws.waf.rule.fieldtomatch.jsonbody", map[string]*llx.RawData{
			"statementID":             llx.StringData(mqlStatementID),
			"ruleName":                llx.StringDataPtr(ruleName),
			"overSizeHandling":        llx.StringData(string(fieldToMatch.JsonBody.OversizeHandling)),
			"invalidFallbackBehavior": llx.StringData(string(fieldToMatch.JsonBody.InvalidFallbackBehavior)),
			"matchScope":              llx.StringData(string(fieldToMatch.JsonBody.MatchScope)),
			"matchPattern":            llx.ResourceData(matchPattern, "aws.waf.rule.fieldtomatch.jsonbody.matchpattern"),
		})
		if err != nil {
			return nil, err
		}
	}
	if fieldToMatch.QueryString != nil {
		target = "QueryString"
	}
	if fieldToMatch.Method != nil {
		target = "Method"
	}
	if fieldToMatch.UriPath != nil {
		target = "UriPath"
	}
	if fieldToMatch.AllQueryArguments != nil {
		target = "allQueryArguments"
	}
	mqlFieldToMatch, err := CreateResource(runtime, "aws.waf.rule.fieldtomatch", map[string]*llx.RawData{
		"statementID":         llx.StringData(mqlStatementID),
		"target":              llx.StringData(target),
		"ruleName":            llx.StringDataPtr(ruleName),
		"queryString":         llx.BoolData(fieldToMatch.QueryString != nil),
		"method":              llx.BoolData(fieldToMatch.Method != nil),
		"uriPath":             llx.BoolData(fieldToMatch.UriPath != nil),
		"allQueryArguments":   llx.BoolData(fieldToMatch.AllQueryArguments != nil),
		"singleHeader":        llx.ResourceData(singleHeader, "aws.waf.rule.fieldtomatch.singleheader"),
		"singleQueryArgument": llx.ResourceData(singleQueryArgument, "aws.waf.rule.fieldtomatch.singlequeryargument"),
		"body":                llx.ResourceData(body, "aws.waf.rule.fieldtomatch.body"),
		"cookie":              llx.ResourceData(cookie, "aws.waf.rule.fieldtomatch.cookie"),
		"headerOrder":         llx.ResourceData(headerOrder, "aws.waf.rule.fieldToMatch.headerorder"),
		"headers":             llx.ResourceData(headers, "aws.waf.rule.fieldToMatch.headers"),
		"ja3Fingerprint":      llx.ResourceData(ja3Fingerprint, "aws.waf.rule.fieldToMatch.ja3fingerprint"),
		"jsonBody":            llx.ResourceData(jsonBody, "aws.waf.rule.fieldToMatch.jsonbody"),
	})
	if err != nil {
		return nil, err
	}

	return mqlFieldToMatch, nil
}

func (a *mqlAwsWafRegexPatternSet) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsWaf) regexPatternSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	scopeString := a.Scope.Data
	svc := conn.Wafv2(wafRegionForScope(scopeString))
	ctx := context.Background()
	res := []any{}
	nextMarker := aws.String("No-Marker-to-begin-with")
	scope := waftypes.Scope(scopeString)
	params := &wafv2.ListRegexPatternSetsInput{Scope: scope}
	for nextMarker != nil {
		setsRes, err := svc.ListRegexPatternSets(ctx, params)
		if err != nil {
			return nil, err
		}
		nextMarker = setsRes.NextMarker
		if setsRes.NextMarker != nil {
			params.NextMarker = nextMarker
		}

		for _, summary := range setsRes.RegexPatternSets {
			getParams := &wafv2.GetRegexPatternSetInput{
				Id:    summary.Id,
				Name:  summary.Name,
				Scope: scope,
			}
			details, err := svc.GetRegexPatternSet(ctx, getParams)
			if err != nil {
				return nil, err
			}
			regexes := []any{}
			if details.RegexPatternSet != nil {
				for _, r := range details.RegexPatternSet.RegularExpressionList {
					if r.RegexString != nil {
						regexes = append(regexes, *r.RegexString)
					}
				}
			}
			mqlSet, err := CreateResource(a.MqlRuntime, "aws.waf.regexPatternSet",
				map[string]*llx.RawData{
					"__id":               llx.StringDataPtr(summary.ARN),
					"id":                 llx.StringDataPtr(summary.Id),
					"arn":                llx.StringDataPtr(summary.ARN),
					"name":               llx.StringDataPtr(summary.Name),
					"description":        llx.StringDataPtr(summary.Description),
					"scope":              llx.StringData(scopeString),
					"regularExpressions": llx.ArrayData(regexes, types.String),
				},
			)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSet)
		}
	}
	return res, nil
}

func (a *mqlAwsWafAclLoggingConfiguration) id() (string, error) {
	return a.Arn.Data, nil
}

// newEmptyWafLoggingConfiguration reports a web ACL that logs nowhere. Reading
// that as a resource with no destinations rather than as a null keeps the
// negative answer assertable: a null logDestinationConfigs would make a check
// for "this ACL logs somewhere" pass without having established anything.
func newEmptyWafLoggingConfiguration(runtime *plugin.Runtime, aclArn string) (*mqlAwsWafAclLoggingConfiguration, error) {
	res, err := CreateResource(runtime, "aws.waf.acl.loggingConfiguration",
		map[string]*llx.RawData{
			"__id":                     llx.StringData(aclArn),
			"arn":                      llx.StringData(aclArn),
			"logDestinationConfigs":    llx.ArrayData([]any{}, types.String),
			"managedByFirewallManager": llx.BoolData(false),
			"redactedFields":           llx.ArrayData([]any{}, types.String),
			"loggingFilter":            llx.DictData(nil),
			"logScope":                 llx.StringData(""),
			"logType":                  llx.StringData(""),
		},
	)
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsWafAclLoggingConfiguration), nil
}

func (a *mqlAwsWafAcl) loggingConfiguration() (*mqlAwsWafAclLoggingConfiguration, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Wafv2(wafRegionForScope(a.Scope.Data))
	ctx := context.Background()

	arnVal := a.Arn.Data
	resp, err := svc.GetLoggingConfiguration(ctx, &wafv2.GetLoggingConfigurationInput{
		ResourceArn: &arnVal,
	})
	if err != nil {
		var notFound *waftypes.WAFNonexistentItemException
		if !errors.As(err, &notFound) {
			return nil, err
		}
		log.Debug().Str("acl", arnVal).Msg("no logging configuration found for web ACL")
		return newEmptyWafLoggingConfiguration(a.MqlRuntime, arnVal)
	}

	if resp.LoggingConfiguration == nil {
		// A 200 with no configuration in it means the same thing as the
		// exception above, and WAF is not consistent about which one it sends.
		log.Debug().Str("acl", arnVal).Msg("empty logging configuration returned for web ACL")
		return newEmptyWafLoggingConfiguration(a.MqlRuntime, arnVal)
	}
	logConfig := resp.LoggingConfiguration
	destinations := convert.SliceAnyToInterface(logConfig.LogDestinationConfigs)

	redactedFields := []any{}
	for _, field := range logConfig.RedactedFields {
		if field.SingleHeader != nil {
			redactedFields = append(redactedFields, "SingleHeader:"+convert.ToValue(field.SingleHeader.Name))
		} else if field.UriPath != nil {
			redactedFields = append(redactedFields, "UriPath")
		} else if field.QueryString != nil {
			redactedFields = append(redactedFields, "QueryString")
		} else if field.Method != nil {
			redactedFields = append(redactedFields, "Method")
		}
	}

	res, err := CreateResource(a.MqlRuntime, "aws.waf.acl.loggingConfiguration",
		map[string]*llx.RawData{
			"__id":                     llx.StringData(arnVal),
			"arn":                      llx.StringData(arnVal),
			"logDestinationConfigs":    llx.ArrayData(destinations, types.String),
			"managedByFirewallManager": llx.BoolData(logConfig.ManagedByFirewallManager),
			"redactedFields":           llx.ArrayData(redactedFields, types.String),
			"loggingFilter":            llx.DictData(wafLoggingFilterToDict(logConfig.LoggingFilter)),
			"logScope":                 llx.StringData(string(logConfig.LogScope)),
			"logType":                  llx.StringData(string(logConfig.LogType)),
		},
	)
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsWafAclLoggingConfiguration), nil
}

func (a *mqlAwsWafAcl) associatedResources() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	scopeString := a.Scope.Data

	// ListResourcesForWebACL only supports REGIONAL scope ACLs.
	// CLOUDFRONT ACLs are associated via CloudFront distributions, not this API.
	if scopeString == "CLOUDFRONT" {
		return []any{}, nil
	}

	svc := conn.Wafv2(wafRegionForScope(scopeString))
	ctx := context.Background()

	arnVal := a.Arn.Data

	// ListResourcesForWebACL without a ResourceType only returns ALBs for regional ACLs.
	// Iterate over all resource types to get the full set of associated resources.
	var allArns []any
	for _, rt := range waftypes.ResourceType("").Values() {
		resp, err := svc.ListResourcesForWebACL(ctx, &wafv2.ListResourcesForWebACLInput{
			WebACLArn:    &arnVal,
			ResourceType: rt,
		})
		if err != nil {
			log.Warn().Str("acl", arnVal).Str("resourceType", string(rt)).Err(err).Msg("could not list resources for web ACL")
			continue
		}
		allArns = append(allArns, convert.SliceAnyToInterface(resp.ResourceArns)...)
	}

	return allArns, nil
}

// associatedLoadBalancers resolves the Application Load Balancers this regional
// web ACL protects to typed resources. CloudFront-scoped ACLs attach through
// distributions rather than this API and so return an empty list.
func (a *mqlAwsWafAcl) associatedLoadBalancers() ([]any, error) {
	if a.Scope.Data == "CLOUDFRONT" {
		return []any{}, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Wafv2(wafRegionForScope(a.Scope.Data))
	arnVal := a.Arn.Data

	resp, err := svc.ListResourcesForWebACL(context.Background(), &wafv2.ListResourcesForWebACLInput{
		WebACLArn:    &arnVal,
		ResourceType: waftypes.ResourceTypeApplicationLoadBalancer,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := []any{}
	for _, lbArn := range resp.ResourceArns {
		mqlLb, err := NewResource(a.MqlRuntime, ResourceAwsElbLoadbalancer,
			map[string]*llx.RawData{"arn": llx.StringData(lbArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlLb)
	}
	return res, nil
}

// webAcl resolves the WAFv2 web ACL protecting an Application Load Balancer.
// Only Application Load Balancers can carry a WAFv2 web ACL, so other load
// balancer types short-circuit to null.
func (a *mqlAwsElbLoadbalancer) webAcl() (*mqlAwsWafAcl, error) {
	elbType := a.GetElbType()
	if elbType.Error != nil {
		return nil, elbType.Error
	}
	if elbType.Data != "application" {
		a.WebAcl.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	arnVal := a.Arn.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Wafv2(a.Region.Data)
	resp, err := svc.GetWebACLForResource(context.Background(), &wafv2.GetWebACLForResourceInput{
		ResourceArn: &arnVal,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.WebAcl.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	if resp.WebACL == nil || resp.WebACL.ARN == nil {
		a.WebAcl.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	// Build the typed web ACL directly from the association response. An ALB's
	// associated web ACL is always REGIONAL scope; setting scope here (rather
	// than resolving through the account-wide aws.waf listing) both avoids a
	// scopeless ListWebACLs call that fails validation and gives the returned
	// ACL the scope its own accessors (associatedLoadBalancers, rules) need.
	acl := resp.WebACL
	mqlAcl, err := CreateResource(a.MqlRuntime, "aws.waf.acl", map[string]*llx.RawData{
		"__id":        llx.StringDataPtr(acl.ARN),
		"id":          llx.StringDataPtr(acl.Id),
		"scope":       llx.StringData(string(waftypes.ScopeRegional)),
		"arn":         llx.StringDataPtr(acl.ARN),
		"name":        llx.StringDataPtr(acl.Name),
		"description": llx.StringDataPtr(acl.Description),
	})
	if err != nil {
		return nil, err
	}
	return mqlAcl.(*mqlAwsWafAcl), nil
}
