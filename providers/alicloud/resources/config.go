// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	configclient "github.com/alibabacloud-go/config-20200907/v4/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// configEpochMillis converts an epoch-milliseconds timestamp into a *time.Time,
// returning nil when the value is nil or zero.
func configEpochMillis(v *int64) *time.Time {
	if v == nil || *v == 0 {
		return nil
	}
	t := time.UnixMilli(*v).UTC()
	return &t
}

// mqlAlicloudConfigInternal memoizes the configuration-recorder detail shared by
// the recorderEnabled, recorderStatus, and recordedResourceTypes accessors.
type mqlAlicloudConfigInternal struct {
	recorderLock    sync.Mutex
	recorderFetched atomic.Bool
	recorder        *configclient.GetConfigurationRecorderResponseBodyConfigurationRecorder
}

func (r *mqlAlicloudConfig) id() (string, error) {
	return "alicloud.config", nil
}

func (r *mqlAlicloudConfig) rules() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ConfigClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	pageSize := int32(100)
	for {
		resp, err := client.ListConfigRules(&configclient.ListConfigRulesRequest{
			PageNumber: new(pageNumber),
			PageSize:   new(pageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.ConfigRules == nil {
			break
		}

		items := resp.Body.ConfigRules.ConfigRuleList
		for _, rule := range items {
			if rule == nil || rule.ConfigRuleId == nil {
				continue
			}
			mqlRule, err := newConfigRule(r.MqlRuntime, rule)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRule)
		}

		total := tea.Int64Value(resp.Body.ConfigRules.TotalCount)
		if len(items) < int(pageSize) || (total > 0 && int64(pageNumber)*int64(pageSize) >= total) {
			break
		}
		pageNumber++
	}
	return res, nil
}

// newConfigRule builds a fully populated alicloud.config.rule from a
// ListConfigRules item.
func newConfigRule(runtime *plugin.Runtime, rule *configclient.ListConfigRulesResponseBodyConfigRulesConfigRuleList) (*mqlAlicloudConfigRule, error) {
	resourceTypes := []any{}
	if rule.ResourceTypesScope != nil {
		for t := range strings.SplitSeq(*rule.ResourceTypesScope, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				resourceTypes = append(resourceTypes, t)
			}
		}
	}

	complianceType := ""
	complianceCount := int64(0)
	if rule.Compliance != nil {
		complianceType = tea.StringValue(rule.Compliance.ComplianceType)
		complianceCount = int64(tea.Int32Value(rule.Compliance.Count))
	}

	compliancePackId := ""
	if rule.CreateBy != nil {
		compliancePackId = tea.StringValue(rule.CreateBy.CompliancePackId)
	}

	tags := map[string]any{}
	for _, t := range rule.Tags {
		if t == nil || t.Key == nil {
			continue
		}
		tags[*t.Key] = tea.StringValue(t.Value)
	}

	resource, err := CreateResource(runtime, "alicloud.config.rule", map[string]*llx.RawData{
		"__id":               llx.StringDataPtr(rule.ConfigRuleId),
		"configRuleId":       llx.StringDataPtr(rule.ConfigRuleId),
		"configRuleName":     llx.StringDataPtr(rule.ConfigRuleName),
		"configRuleArn":      llx.StringDataPtr(rule.ConfigRuleArn),
		"configRuleState":    llx.StringDataPtr(rule.ConfigRuleState),
		"description":        llx.StringDataPtr(rule.Description),
		"riskLevel":          llx.IntData(int64(tea.Int32Value(rule.RiskLevel))),
		"sourceOwner":        llx.StringDataPtr(rule.SourceOwner),
		"sourceIdentifier":   llx.StringDataPtr(rule.SourceIdentifier),
		"automationType":     llx.StringDataPtr(rule.AutomationType),
		"resourceTypesScope": llx.ArrayData(resourceTypes, types.String),
		"complianceType":     llx.StringData(complianceType),
		"complianceCount":    llx.IntData(complianceCount),
		"compliancePackId":   llx.StringData(compliancePackId),
		"tags":               llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAlicloudConfigRule), nil
}

// recorderDetail lazily fetches and caches the configuration recorder. A
// transient error is not cached and is returned, so recorderEnabled cannot
// permanently report a recording account as disabled after one failed call.
func (r *mqlAlicloudConfig) recorderDetail() (*configclient.GetConfigurationRecorderResponseBodyConfigurationRecorder, error) {
	if r.recorderFetched.Load() {
		return r.recorder, nil
	}
	r.recorderLock.Lock()
	defer r.recorderLock.Unlock()
	if r.recorderFetched.Load() {
		return r.recorder, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ConfigClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetConfigurationRecorder()
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Body != nil {
		r.recorder = resp.Body.ConfigurationRecorder
	}
	r.recorderFetched.Store(true)
	return r.recorder, nil
}

func (r *mqlAlicloudConfig) recorderStatus() (string, error) {
	rec, err := r.recorderDetail()
	if err != nil || rec == nil {
		return "", err
	}
	return tea.StringValue(rec.ConfigurationRecorderStatus), nil
}

func (r *mqlAlicloudConfig) recorderEnabled() (bool, error) {
	rec, err := r.recorderDetail()
	if err != nil || rec == nil {
		return false, err
	}
	return tea.StringValue(rec.ConfigurationRecorderStatus) == "REGISTERED", nil
}

func (r *mqlAlicloudConfig) recordedResourceTypes() ([]any, error) {
	rec, err := r.recorderDetail()
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, t := range rec.ResourceTypes {
		if t == nil {
			continue
		}
		res = append(res, tea.StringValue(t))
	}
	return res, nil
}

func (r *mqlAlicloudConfig) complianceSummary() (any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ConfigClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetComplianceSummary()
	if err != nil || resp == nil || resp.Body == nil || resp.Body.ComplianceSummary == nil {
		return nil, nil
	}
	summary := resp.Body.ComplianceSummary

	res := map[string]any{}
	if byRule := summary.ComplianceSummaryByConfigRule; byRule != nil {
		res["compliantRuleCount"] = int64(tea.Int32Value(byRule.CompliantCount))
		res["nonCompliantRuleCount"] = int64(tea.Int32Value(byRule.NonCompliantCount))
		res["totalRuleCount"] = tea.Int64Value(byRule.TotalCount)
	}
	if byResource := summary.ComplianceSummaryByResource; byResource != nil {
		res["compliantResourceCount"] = int64(tea.Int32Value(byResource.CompliantCount))
		res["nonCompliantResourceCount"] = int64(tea.Int32Value(byResource.NonCompliantCount))
		res["totalResourceCount"] = tea.Int64Value(byResource.TotalCount)
		res["highRiskNonCompliantResourceCount"] = int64(tea.Int32Value(byResource.HighRiskRuleNonCompliantResourceCount))
		res["mediumRiskNonCompliantResourceCount"] = int64(tea.Int32Value(byResource.MediumRiskRuleNonCompliantResourceCount))
		res["lowRiskNonCompliantResourceCount"] = int64(tea.Int32Value(byResource.LowRiskRuleNonCompliantResourceCount))
	}
	return res, nil
}

// mqlAlicloudConfigRuleInternal memoizes the GetConfigRule detail shared by the
// timestamp and execution-frequency accessors.
type mqlAlicloudConfigRuleInternal struct {
	detailLock    sync.Mutex
	detailFetched atomic.Bool
	detail        *configclient.GetConfigRuleResponseBodyConfigRule
}

func (r *mqlAlicloudConfigRule) id() (string, error) {
	return r.ConfigRuleId.Data, nil
}

// detailFor lazily fetches and caches the GetConfigRule detail. A transient
// error is not cached and is returned rather than swallowed.
func (r *mqlAlicloudConfigRule) detailFor() (*configclient.GetConfigRuleResponseBodyConfigRule, error) {
	if r.detailFetched.Load() {
		return r.detail, nil
	}
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailFetched.Load() {
		return r.detail, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ConfigClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetConfigRule(&configclient.GetConfigRuleRequest{
		ConfigRuleId: new(r.ConfigRuleId.Data),
	})
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Body != nil {
		r.detail = resp.Body.ConfigRule
	}
	r.detailFetched.Store(true)
	return r.detail, nil
}

func (r *mqlAlicloudConfigRule) maximumExecutionFrequency() (string, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.MaximumExecutionFrequency), nil
}

func (r *mqlAlicloudConfigRule) createTime() (*time.Time, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return nil, err
	}
	return configEpochMillis(d.CreateTimestamp), nil
}

func (r *mqlAlicloudConfigRule) modifiedTime() (*time.Time, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return nil, err
	}
	return configEpochMillis(d.ModifiedTimestamp), nil
}

// configService returns the alicloud.config singleton. CreateResource returns
// the already-cached instance once the __id exists, so every lookup that walks
// the account-wide rule or compliance-pack list shares one fetch of each
// instead of paying for its own.
func configService(runtime *plugin.Runtime) (*mqlAlicloudConfig, error) {
	res, err := CreateResource(runtime, "alicloud.config", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudConfig), nil
}

// configRuleByID finds a Config rule in the account-wide rule list. Resolving
// through the list rather than a per-rule init matters because an init runs
// before the resource cache is consulted, which would turn one list into one
// API call per evaluation result.
func configRuleByID(runtime *plugin.Runtime, ruleID string) (*mqlAlicloudConfigRule, error) {
	if ruleID == "" {
		return nil, nil
	}
	svc, err := configService(runtime)
	if err != nil {
		return nil, err
	}
	rules := svc.GetRules()
	if rules.Error != nil {
		return nil, rules.Error
	}
	for _, entry := range rules.Data {
		rule, ok := entry.(*mqlAlicloudConfigRule)
		if !ok {
			continue
		}
		if rule.ConfigRuleId.Data == ruleID {
			return rule, nil
		}
	}
	return nil, nil
}

// compliancePackByID finds a compliance pack in the account-wide pack list, for
// the same reason configRuleByID walks the rule list.
func compliancePackByID(runtime *plugin.Runtime, packID string) (*mqlAlicloudConfigCompliancePack, error) {
	if packID == "" {
		return nil, nil
	}
	svc, err := configService(runtime)
	if err != nil {
		return nil, err
	}
	packs := svc.GetCompliancePacks()
	if packs.Error != nil {
		return nil, packs.Error
	}
	for _, entry := range packs.Data {
		pack, ok := entry.(*mqlAlicloudConfigCompliancePack)
		if !ok {
			continue
		}
		if pack.CompliancePackId.Data == packID {
			return pack, nil
		}
	}
	return nil, nil
}

// configNextToken decides whether a token-paginated walk continues. It stops on
// an empty token and on a token identical to the one just sent, so an endpoint
// that echoes the cursor back cannot spin the walk forever.
func configNextToken(current, next string) (string, bool) {
	if next == "" || next == current {
		return "", false
	}
	return next, true
}

// parseOssBucketArn extracts the bucket name from an OSS delivery target ARN of
// the form acs:oss:<region>:<account>:<bucket>[/<prefix>], returning "" for any
// other shape.
func parseOssBucketArn(arn string) string {
	parts := strings.SplitN(arn, ":", 5)
	if len(parts) < 5 || parts[1] != "oss" {
		return ""
	}
	bucket, _, _ := strings.Cut(parts[4], "/")
	return bucket
}

// parseSlsLogstoreArn extracts the region, project and logstore from a Log
// Service delivery target ARN of the form
// acs:log:<region>:<account>:project/<project>/logstore/<logstore>. Returns
// empty strings for any other shape.
func parseSlsLogstoreArn(arn string) (region, project, logstore string) {
	parts := strings.SplitN(arn, ":", 5)
	if len(parts) < 5 || parts[1] != "log" {
		return "", "", ""
	}
	rest, ok := strings.CutPrefix(parts[4], "project/")
	if !ok {
		return "", "", ""
	}
	p, l, ok := strings.Cut(rest, "/logstore/")
	if !ok || p == "" || l == "" {
		return "", "", ""
	}
	return parts[2], p, l
}

func (r *mqlAlicloudConfig) deliveryChannels() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ConfigClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.ListConfigDeliveryChannels(&configclient.ListConfigDeliveryChannelsRequest{})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, ch := range resp.Body.DeliveryChannels {
		if ch == nil || ch.DeliveryChannelId == nil {
			continue
		}
		resource, err := CreateResource(r.MqlRuntime, "alicloud.config.deliveryChannel", map[string]*llx.RawData{
			"__id":         llx.StringDataPtr(ch.DeliveryChannelId),
			"channelId":    llx.StringDataPtr(ch.DeliveryChannelId),
			"name":         llx.StringDataPtr(ch.DeliveryChannelName),
			"type":         llx.StringDataPtr(ch.DeliveryChannelType),
			"targetArn":    llx.StringDataPtr(ch.DeliveryChannelTargetArn),
			"enabled":      llx.BoolData(tea.Int32Value(ch.Status) == 1),
			"description":  llx.StringDataPtr(ch.Description),
			"condition":    llx.StringDataPtr(ch.DeliveryChannelCondition),
			"snapshotTime": llx.StringDataPtr(ch.DeliverySnapshotTime),
			// the four toggles are read through tea.BoolValue rather than as
			// pointers: an absent toggle means the payload is not delivered, and
			// a null would pass a `{ a && b }` assertion that a false fails
			"configurationItemChangeNotification": llx.BoolData(tea.BoolValue(ch.ConfigurationItemChangeNotification)),
			"configurationSnapshot":               llx.BoolData(tea.BoolValue(ch.ConfigurationSnapshot)),
			"compliantSnapshot":                   llx.BoolData(tea.BoolValue(ch.CompliantSnapshot)),
			"nonCompliantNotification":            llx.BoolData(tea.BoolValue(ch.NonCompliantNotification)),
			"oversizedDataOssTargetArn":           llx.StringDataPtr(ch.OversizedDataOSSTargetArn),
		})
		if err != nil {
			return nil, err
		}
		mqlChannel := resource.(*mqlAlicloudConfigDeliveryChannel)
		mqlChannel.cacheAssumeRoleArn = tea.StringValue(ch.DeliveryChannelAssumeRoleArn)
		res = append(res, mqlChannel)
	}
	return res, nil
}

// mqlAlicloudConfigDeliveryChannelInternal caches the assume-role ARN, which the
// channel exposes only through the RAM role it names.
type mqlAlicloudConfigDeliveryChannelInternal struct {
	cacheAssumeRoleArn string
}

func (r *mqlAlicloudConfigDeliveryChannel) id() (string, error) {
	return r.ChannelId.Data, nil
}

// ossBucket resolves the bucket a channel delivers to. A delivery target can
// name a bucket in another account or one that has since been deleted, so a
// failed lookup resolves to null rather than failing the channel list.
func (r *mqlAlicloudConfigDeliveryChannel) ossBucket() (*mqlAlicloudOssBucket, error) {
	name := parseOssBucketArn(r.TargetArn.Data)
	if name == "" {
		r.OssBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	bucket, err := resolveOssBucket(r.MqlRuntime, name)
	if err != nil || bucket == nil {
		if err != nil {
			log.Warn().Err(err).Str("bucket", name).
				Msg("alicloud> unable to resolve the config delivery bucket")
		}
		r.OssBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return bucket, nil
}

// logstore resolves the logstore a channel delivers to, null for a channel that
// targets a bucket or a message topic, or whose logstore no longer exists.
func (r *mqlAlicloudConfigDeliveryChannel) logstore() (*mqlAlicloudLogLogstore, error) {
	region, project, name := parseSlsLogstoreArn(r.TargetArn.Data)
	if name == "" {
		r.Logstore.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	store, err := resolveLogStore(r.MqlRuntime, region, project, name)
	if err != nil || store == nil {
		if err != nil {
			log.Warn().Err(err).Str("logstore", name).Str("project", project).
				Msg("alicloud> unable to resolve the config delivery logstore")
		}
		r.Logstore.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return store, nil
}

// assumeRole resolves the RAM role Cloud Config writes through. The role is a
// service-linked role in the common case, but a channel can outlive a role that
// was deleted by hand, so a failed lookup resolves to null.
func (r *mqlAlicloudConfigDeliveryChannel) assumeRole() (*mqlAlicloudRamRole, error) {
	roleName := ramRoleNameFromArn(r.cacheAssumeRoleArn)
	if roleName == "" {
		r.AssumeRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	role, err := resolveRamRole(r.MqlRuntime, roleName)
	if err != nil || role == nil {
		if err != nil {
			log.Warn().Err(err).Str("role", roleName).
				Msg("alicloud> unable to resolve the config delivery assume role")
		}
		r.AssumeRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return role, nil
}

func (r *mqlAlicloudConfig) compliancePacks() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ConfigClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	pageSize := int32(100)
	for {
		resp, err := client.ListCompliancePacks(&configclient.ListCompliancePacksRequest{
			PageNumber: new(pageNumber),
			PageSize:   new(pageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.CompliancePacksResult == nil {
			break
		}

		items := resp.Body.CompliancePacksResult.CompliancePacks
		for _, pack := range items {
			if pack == nil || pack.CompliancePackId == nil {
				continue
			}
			tags := map[string]any{}
			for _, t := range pack.Tags {
				if t == nil || tea.StringValue(t.TagKey) == "" {
					continue
				}
				tags[tea.StringValue(t.TagKey)] = tea.StringValue(t.TagValue)
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.config.compliancePack", map[string]*llx.RawData{
				"__id":                     llx.StringDataPtr(pack.CompliancePackId),
				"compliancePackId":         llx.StringDataPtr(pack.CompliancePackId),
				"compliancePackName":       llx.StringDataPtr(pack.CompliancePackName),
				"compliancePackTemplateId": llx.StringDataPtr(pack.CompliancePackTemplateId),
				"description":              llx.StringDataPtr(pack.Description),
				"riskLevel":                llx.IntData(int64(tea.Int32Value(pack.RiskLevel))),
				"status":                   llx.StringDataPtr(pack.Status),
				"createTime":               llx.TimeDataPtr(configEpochMillis(pack.CreateTimestamp)),
				"tags":                     llx.MapData(tags, types.String),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}

		total := tea.Int64Value(resp.Body.CompliancePacksResult.TotalCount)
		if len(items) < int(pageSize) || (total > 0 && int64(pageNumber)*int64(pageSize) >= total) {
			break
		}
		pageNumber++
	}
	return res, nil
}

func (r *mqlAlicloudConfigCompliancePack) id() (string, error) {
	return r.CompliancePackId.Data, nil
}

// rules lists the Config rules the pack evaluates. The pack detail names them by
// id only, so each is resolved against the account-wide rule list rather than
// rebuilt here, which would otherwise seed the cache with a partial rule under
// the same key as the full one.
func (r *mqlAlicloudConfigCompliancePack) rules() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ConfigClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetCompliancePack(&configclient.GetCompliancePackRequest{
		CompliancePackId: new(r.CompliancePackId.Data),
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.CompliancePack == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, cr := range resp.Body.CompliancePack.ConfigRules {
		if cr == nil {
			continue
		}
		ruleID := tea.StringValue(cr.ConfigRuleId)
		rule, err := configRuleByID(r.MqlRuntime, ruleID)
		if err != nil {
			return nil, err
		}
		if rule == nil {
			log.Debug().Str("configRuleId", ruleID).Str("compliancePackId", r.CompliancePackId.Data).
				Msg("alicloud> compliance pack names a rule that is not in the account rule list")
			continue
		}
		res = append(res, rule)
	}
	return res, nil
}

func (r *mqlAlicloudConfig) aggregators() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ConfigClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	token := ""
	for {
		req := &configclient.ListAggregatorsRequest{MaxResults: tea.Int32(100)}
		if token != "" {
			req.NextToken = new(token)
		}
		resp, err := client.ListAggregators(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.AggregatorsResult == nil {
			break
		}

		for _, agg := range resp.Body.AggregatorsResult.Aggregators {
			if agg == nil || agg.AggregatorId == nil {
				continue
			}
			tags := map[string]any{}
			for _, t := range agg.Tags {
				if t == nil || tea.StringValue(t.TagKey) == "" {
					continue
				}
				tags[tea.StringValue(t.TagKey)] = tea.StringValue(t.TagValue)
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.config.aggregator", map[string]*llx.RawData{
				"__id":           llx.StringDataPtr(agg.AggregatorId),
				"aggregatorId":   llx.StringDataPtr(agg.AggregatorId),
				"aggregatorName": llx.StringDataPtr(agg.AggregatorName),
				"aggregatorType": llx.StringDataPtr(agg.AggregatorType),
				"description":    llx.StringDataPtr(agg.Description),
				"status":         llx.IntData(int64(tea.Int32Value(agg.AggregatorStatus))),
				"accountCount":   llx.IntData(tea.Int64Value(agg.AggregatorAccountCount)),
				"createTime":     llx.TimeDataPtr(configEpochMillis(agg.AggregatorCreateTimestamp)),
				"tags":           llx.MapData(tags, types.String),
			})
			if err != nil {
				return nil, err
			}
			mqlAgg := resource.(*mqlAlicloudConfigAggregator)
			mqlAgg.cacheFolderID = tea.StringValue(agg.FolderId)
			res = append(res, mqlAgg)
		}

		next, more := configNextToken(token, tea.StringValue(resp.Body.AggregatorsResult.NextToken))
		if !more {
			break
		}
		token = next
	}
	return res, nil
}

// mqlAlicloudConfigAggregatorInternal caches the resource directory folder id,
// which the aggregator exposes only through the folder it covers.
type mqlAlicloudConfigAggregatorInternal struct {
	cacheFolderID string
}

func (r *mqlAlicloudConfigAggregator) id() (string, error) {
	return r.AggregatorId.Data, nil
}

// folder resolves the resource directory folder an RD aggregator covers. A
// CUSTOM aggregator names accounts instead and has no folder, and an account
// without Resource Directory permissions cannot read one, so both resolve to
// null rather than failing the aggregator list.
func (r *mqlAlicloudConfigAggregator) folder() (*mqlAlicloudResourceManagerFolder, error) {
	if r.cacheFolderID == "" {
		r.Folder.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.resourceManager.folder", map[string]*llx.RawData{
		"folderId": llx.StringData(r.cacheFolderID),
	})
	if err != nil {
		log.Warn().Err(err).Str("folderId", r.cacheFolderID).
			Msg("alicloud> unable to resolve the aggregator folder")
		r.Folder.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAlicloudResourceManagerFolder), nil
}

func (r *mqlAlicloudConfig) nonCompliantResults() ([]any, error) {
	return listConfigEvaluationResults(r.MqlRuntime, "", "NON_COMPLIANT")
}

func (r *mqlAlicloudConfigRule) evaluationResults() ([]any, error) {
	return listConfigEvaluationResults(r.MqlRuntime, r.ConfigRuleId.Data, "")
}

// listConfigEvaluationResults walks ListConfigRuleEvaluationResults. An empty
// ruleID lists across every rule in the account, and an empty complianceType
// lists every verdict.
func listConfigEvaluationResults(runtime *plugin.Runtime, ruleID, complianceType string) ([]any, error) {
	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ConfigClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	token := ""
	for {
		req := &configclient.ListConfigRuleEvaluationResultsRequest{MaxResults: tea.Int32(100)}
		if ruleID != "" {
			req.ConfigRuleId = new(ruleID)
		}
		if complianceType != "" {
			req.ComplianceType = new(complianceType)
		}
		if token != "" {
			req.NextToken = new(token)
		}
		resp, err := client.ListConfigRuleEvaluationResults(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.EvaluationResults == nil {
			break
		}

		for _, result := range resp.Body.EvaluationResults.EvaluationResultList {
			mqlResult, err := newConfigEvaluationResult(runtime, result)
			if err != nil {
				return nil, err
			}
			if mqlResult == nil {
				continue
			}
			res = append(res, mqlResult)
		}

		next, more := configNextToken(token, tea.StringValue(resp.Body.EvaluationResults.NextToken))
		if !more {
			break
		}
		token = next
	}
	return res, nil
}

// newConfigEvaluationResult builds one evaluation result, returning (nil, nil)
// for an entry with no qualifier, which carries neither the rule nor the
// resource the result is about.
func newConfigEvaluationResult(runtime *plugin.Runtime, result *configclient.ListConfigRuleEvaluationResultsResponseBodyEvaluationResultsEvaluationResultList) (*mqlAlicloudConfigEvaluationResult, error) {
	if result == nil || result.EvaluationResultIdentifier == nil ||
		result.EvaluationResultIdentifier.EvaluationResultQualifier == nil {
		return nil, nil
	}
	q := result.EvaluationResultIdentifier.EvaluationResultQualifier

	ruleID := tea.StringValue(q.ConfigRuleId)
	resourceID := tea.StringValue(q.ResourceId)
	resourceType := tea.StringValue(q.ResourceType)
	regionID := tea.StringValue(q.RegionId)

	// one rule evaluates a resource once, so the rule plus the fully qualified
	// resource is unique; the id stays internal because none of its parts is
	// something a user would select a result by
	id := strings.Join([]string{ruleID, resourceType, regionID, resourceID}, "/")

	resource, err := CreateResource(runtime, "alicloud.config.evaluationResult", map[string]*llx.RawData{
		"__id":               llx.StringData(id),
		"complianceType":     llx.StringDataPtr(result.ComplianceType),
		"annotation":         llx.StringDataPtr(result.Annotation),
		"riskLevel":          llx.IntData(int64(tea.Int32Value(result.RiskLevel))),
		"remediationEnabled": llx.BoolData(tea.BoolValue(result.RemediationEnabled)),
		"resourceId":         llx.StringData(resourceID),
		"resourceName":       llx.StringDataPtr(q.ResourceName),
		"resourceType":       llx.StringData(resourceType),
		"regionId":           llx.StringData(regionID),
		"ignoreDate":         llx.StringDataPtr(q.IgnoreDate),
		"invokedTime":        llx.TimeDataPtr(configEpochMillis(result.ConfigRuleInvokedTimestamp)),
		"resultRecordedTime": llx.TimeDataPtr(configEpochMillis(result.ResultRecordedTimestamp)),
		// both timestamps stay null when the resource has never been in that
		// state, rather than becoming the zero time
		"lastNonCompliantTime":   llx.TimeDataPtr(configEpochMillis(result.LastNonCompliantRecordTimestamp)),
		"lastCompliantFixedTime": llx.TimeDataPtr(configEpochMillis(result.LastCompliantFixedTimestamp)),
	})
	if err != nil {
		return nil, err
	}
	mqlResult := resource.(*mqlAlicloudConfigEvaluationResult)
	mqlResult.cacheConfigRuleID = ruleID
	mqlResult.cacheCompliancePackID = tea.StringValue(q.CompliancePackId)
	mqlResult.cacheResourceGroupID = tea.StringValue(q.ResourceGroupId)
	return mqlResult, nil
}

// mqlAlicloudConfigEvaluationResultInternal caches the ids the result exposes
// only through the rule, pack, and resource group it points at.
type mqlAlicloudConfigEvaluationResultInternal struct {
	cacheConfigRuleID     string
	cacheCompliancePackID string
	cacheResourceGroupID  string
}

func (r *mqlAlicloudConfigEvaluationResult) id() (string, error) {
	return strings.Join([]string{
		r.cacheConfigRuleID,
		r.ResourceType.Data,
		r.RegionId.Data,
		r.ResourceId.Data,
	}, "/"), nil
}

// configRule resolves the rule that produced the result. The rule can be
// deleted after its verdict was recorded, which leaves the result behind with
// nothing to point at, so a rule that is not in the account list resolves to
// null. A failure to read the rule list at all is still an error.
func (r *mqlAlicloudConfigEvaluationResult) configRule() (*mqlAlicloudConfigRule, error) {
	rule, err := configRuleByID(r.MqlRuntime, r.cacheConfigRuleID)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		r.ConfigRule.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return rule, nil
}

// compliancePack resolves the pack the rule was evaluated under, null for a
// rule that belongs to no pack.
func (r *mqlAlicloudConfigEvaluationResult) compliancePack() (*mqlAlicloudConfigCompliancePack, error) {
	if r.cacheCompliancePackID == "" {
		r.CompliancePack.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pack, err := compliancePackByID(r.MqlRuntime, r.cacheCompliancePackID)
	if err != nil || pack == nil {
		if err != nil {
			log.Warn().Err(err).Str("compliancePackId", r.cacheCompliancePackID).
				Msg("alicloud> unable to resolve the evaluation result compliance pack")
		}
		r.CompliancePack.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return pack, nil
}

func (r *mqlAlicloudConfigEvaluationResult) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}
