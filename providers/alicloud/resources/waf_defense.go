// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	tea "github.com/alibabacloud-go/tea/tea"
	wafclient "github.com/alibabacloud-go/waf-openapi-20211001/v7/client"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// wafDefenseTemplate is the shape shared by the two WAF endpoints that return
// protection templates: DescribeDefenseTemplates lists every template on the
// instance, DescribeDefenseResourceTemplates lists the ones bound to a single
// protected object. Their response types are distinct Go structs with identical
// members, so both are normalized here and mapped by one constructor.
type wafDefenseTemplate struct {
	TemplateID      *int64
	TemplateName    *string
	TemplateType    *string
	TemplateOrigin  *string
	TemplateStatus  *int32
	DefenseScene    *string
	DefenseSubScene *string
	Description     *string
	GmtModified     *int64
}

// wafTemplateEnabled reports whether a template status means the template
// inspects traffic. WAF documents 1 as enabled and 0 as disabled; an absent
// status is treated as disabled, because reporting an unread switch as on would
// claim protection nobody confirmed.
func wafTemplateEnabled(status *int32) bool {
	return tea.Int32Value(status) == 1
}

// wafRuleEnabled reports whether a rule status means the rule is enforced. Same
// 0/1 encoding as a template status, and the same reading of an absent value.
func wafRuleEnabled(status *int32) bool {
	return tea.Int32Value(status) == 1
}

// parseWafRuleConfig decodes a rule's Config member, which the API returns as a
// JSON document embedded in a string. A blank or unparseable config yields nil,
// which surfaces as a null dict rather than as an empty object that would read
// as "the rule has no conditions".
func parseWafRuleConfig(raw *string) any {
	s := strings.TrimSpace(tea.StringValue(raw))
	if s == "" {
		return nil
	}
	var out any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

// wafEnabledDefenseScenes returns the protection scenes covered by an enabled
// template, sorted and deduplicated. A scene whose template is bound but
// switched off is left out: a disabled template inspects nothing, so listing
// its scene would report protection that is not in force.
func wafEnabledDefenseScenes(templates []any) []any {
	seen := map[string]struct{}{}
	for _, entry := range templates {
		tmpl, ok := entry.(*mqlAlicloudWafDefenseTemplate)
		if !ok || !tmpl.Enabled.Data {
			continue
		}
		scene := tmpl.DefenseScene.Data
		if scene == "" {
			continue
		}
		seen[scene] = struct{}{}
	}
	scenes := make([]string, 0, len(seen))
	for scene := range seen {
		scenes = append(scenes, scene)
	}
	sort.Strings(scenes)

	res := make([]any, 0, len(scenes))
	for _, scene := range scenes {
		res = append(res, scene)
	}
	return res
}

// mqlAlicloudWafDefenseTemplateInternal caches the keys the template's rule
// lookup needs. A template is reached from two different parents, so the region
// and instance travel with the resource rather than being re-derived.
type mqlAlicloudWafDefenseTemplateInternal struct {
	region     string
	instanceId string
}

func (r *mqlAlicloudWafDefenseTemplate) id() (string, error) {
	return fmt.Sprintf("%s/%s/%d", r.RegionId.Data, r.InstanceId.Data, r.TemplateId.Data), nil
}

func (r *mqlAlicloudWafDefenseRule) id() (string, error) {
	return fmt.Sprintf("%s/%s/%d", r.RegionId.Data, r.InstanceId.Data, r.RuleId.Data), nil
}

// newWafDefenseTemplate maps one normalized template into a resource. The cache
// key carries the region and instance as well as the template id, because
// template ids are only unique within one WAF instance.
func newWafDefenseTemplate(runtime *plugin.Runtime, region, instanceID string, t wafDefenseTemplate) (*mqlAlicloudWafDefenseTemplate, error) {
	templateID := tea.Int64Value(t.TemplateID)
	resource, err := CreateResource(runtime, "alicloud.waf.defenseTemplate", map[string]*llx.RawData{
		"__id":            llx.StringData(fmt.Sprintf("%s/%s/%d", region, instanceID, templateID)),
		"regionId":        llx.StringData(region),
		"instanceId":      llx.StringData(instanceID),
		"templateId":      llx.IntData(templateID),
		"templateName":    llx.StringDataPtr(t.TemplateName),
		"templateType":    llx.StringDataPtr(t.TemplateType),
		"templateOrigin":  llx.StringDataPtr(t.TemplateOrigin),
		"defenseScene":    llx.StringDataPtr(t.DefenseScene),
		"defenseSubScene": llx.StringDataPtr(t.DefenseSubScene),
		"description":     llx.StringDataPtr(t.Description),
		"status":          llx.IntData(int64(tea.Int32Value(t.TemplateStatus))),
		"enabled":         llx.BoolData(wafTemplateEnabled(t.TemplateStatus)),
		"updateTime":      llx.TimeDataPtr(configEpochMillis(t.GmtModified)),
	})
	if err != nil {
		return nil, err
	}
	mqlTemplate := resource.(*mqlAlicloudWafDefenseTemplate)
	mqlTemplate.region = region
	mqlTemplate.instanceId = instanceID
	return mqlTemplate, nil
}

// wafDefenseTemplatePageSize is the page size used when enumerating protection
// templates. The API defaults to 20; asking for more keeps a busy instance to a
// handful of calls.
const wafDefenseTemplatePageSize = 100

// defenseTemplates enumerates every protection template on the instance. WAF
// pages this endpoint and reports a total, so the walk terminates on the count
// collected rather than on a short page, which is robust to the server capping
// the page size below what was asked for.
func (r *mqlAlicloudWafInstance) defenseTemplates() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.WafClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	collected := int64(0)
	for {
		resp, err := client.DescribeDefenseTemplates(&wafclient.DescribeDefenseTemplatesRequest{
			InstanceId: new(r.instanceId),
			RegionId:   new(r.region),
			PageNumber: new(pageNumber),
			PageSize:   tea.Int32(wafDefenseTemplatePageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		items := resp.Body.Templates
		for _, t := range items {
			if t == nil || t.TemplateId == nil {
				continue
			}
			mqlTemplate, err := newWafDefenseTemplate(r.MqlRuntime, r.region, r.instanceId, wafDefenseTemplate{
				TemplateID:      t.TemplateId,
				TemplateName:    t.TemplateName,
				TemplateType:    t.TemplateType,
				TemplateOrigin:  t.TemplateOrigin,
				TemplateStatus:  t.TemplateStatus,
				DefenseScene:    t.DefenseScene,
				DefenseSubScene: t.DefenseSubScene,
				Description:     t.Description,
				GmtModified:     t.GmtModified,
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTemplate)
		}
		collected += int64(len(items))
		if len(items) == 0 || collected >= tea.Int64Value(resp.Body.TotalCount) {
			break
		}
		pageNumber++
	}
	return res, nil
}

// templates lists the protection templates bound to this protected object. The
// endpoint is keyed on the object name, so unlike the instance-wide list it
// answers "what actually defends this asset".
func (r *mqlAlicloudWafDefenseResource) templates() ([]any, error) {
	region := r.RegionId.Data
	instanceID := r.InstanceId.Data
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.WafClient(region)
	if err != nil {
		return nil, err
	}

	resp, err := client.DescribeDefenseResourceTemplates(&wafclient.DescribeDefenseResourceTemplatesRequest{
		InstanceId: new(instanceID),
		RegionId:   new(region),
		Resource:   new(r.Resource.Data),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	if resp == nil || resp.Body == nil {
		return res, nil
	}
	for _, t := range resp.Body.Templates {
		if t == nil || t.TemplateId == nil {
			continue
		}
		mqlTemplate, err := newWafDefenseTemplate(r.MqlRuntime, region, instanceID, wafDefenseTemplate{
			TemplateID:      t.TemplateId,
			TemplateName:    t.TemplateName,
			TemplateType:    t.TemplateType,
			TemplateOrigin:  t.TemplateOrigin,
			TemplateStatus:  t.TemplateStatus,
			DefenseScene:    t.DefenseScene,
			DefenseSubScene: t.DefenseSubScene,
			Description:     t.Description,
			GmtModified:     t.GmtModified,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTemplate)
	}
	return res, nil
}

func (r *mqlAlicloudWafDefenseResource) enabledDefenseScenes() ([]any, error) {
	templates := r.GetTemplates()
	if templates.Error != nil {
		return nil, templates.Error
	}
	return wafEnabledDefenseScenes(templates.Data), nil
}

func (r *mqlAlicloudWafDefenseResource) protectionEnabled() (bool, error) {
	scenes, err := r.enabledDefenseScenes()
	if err != nil {
		return false, err
	}
	return len(scenes) > 0, nil
}

// wafDefenseRulePageSize is the page size used when enumerating the rules of a
// protection template. The API defaults to 10.
const wafDefenseRulePageSize = 100

// wafTemplateRuleQuery builds the Query filter that scopes DescribeDefenseRules
// to one template. The endpoint has no TemplateId parameter; the filter is a
// JSON document passed as a string, so it is built with the JSON encoder rather
// than by concatenation.
func wafTemplateRuleQuery(templateID int64) (string, error) {
	raw, err := json.Marshal(map[string]any{"templateId": templateID})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// rules enumerates the protection rules held by the template.
func (r *mqlAlicloudWafDefenseTemplate) rules() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.WafClient(r.region)
	if err != nil {
		return nil, err
	}
	query, err := wafTemplateRuleQuery(r.TemplateId.Data)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	collected := int64(0)
	for {
		resp, err := client.DescribeDefenseRules(&wafclient.DescribeDefenseRulesRequest{
			InstanceId: new(r.instanceId),
			RegionId:   new(r.region),
			Query:      new(query),
			PageNumber: new(pageNumber),
			PageSize:   tea.Int32(wafDefenseRulePageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		items := resp.Body.Rules
		for _, rule := range items {
			if rule == nil || rule.RuleId == nil {
				continue
			}
			ruleID := tea.Int64Value(rule.RuleId)
			resource, err := CreateResource(r.MqlRuntime, "alicloud.waf.defenseRule", map[string]*llx.RawData{
				"__id":          llx.StringData(fmt.Sprintf("%s/%s/%d", r.region, r.instanceId, ruleID)),
				"regionId":      llx.StringData(r.region),
				"instanceId":    llx.StringData(r.instanceId),
				"templateId":    llx.IntDataPtr(rule.TemplateId),
				"ruleId":        llx.IntData(ruleID),
				"ruleName":      llx.StringDataPtr(rule.RuleName),
				"ruleType":      llx.StringDataPtr(rule.RuleType),
				"defenseType":   llx.StringDataPtr(rule.DefenseType),
				"defenseScene":  llx.StringDataPtr(rule.DefenseScene),
				"defenseOrigin": llx.StringDataPtr(rule.DefenseOrigin),
				"action":        llx.StringDataPtr(rule.ActionExternal),
				"config":        llx.DictData(parseWafRuleConfig(rule.Config)),
				"description":   llx.StringDataPtr(rule.Description),
				"resource":      llx.StringDataPtr(rule.Resource),
				"status":        llx.IntData(int64(tea.Int32Value(rule.Status))),
				"enabled":       llx.BoolData(wafRuleEnabled(rule.Status)),
				"createTime":    llx.TimeDataPtr(configEpochMillis(rule.GmtCreate)),
				"updateTime":    llx.TimeDataPtr(configEpochMillis(rule.GmtModified)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
		collected += int64(len(items))
		if len(items) == 0 || collected >= tea.Int64Value(resp.Body.TotalCount) {
			break
		}
		pageNumber++
	}
	return res, nil
}
