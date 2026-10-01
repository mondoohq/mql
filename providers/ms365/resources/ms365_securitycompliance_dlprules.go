// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// parentPolicy resolves the DLP policy this rule belongs to by matching its
// name against the policies in the same Security & Compliance report.
func (r *mqlMs365ExchangeonlineDlpComplianceRule) parentPolicy() (*mqlMs365ExchangeonlineDlpCompliancePolicy, error) {
	name := r.ParentPolicyName.Data
	if name == "" {
		r.ParentPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	sc, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.securityAndCompliance", nil)
	if err != nil {
		return nil, err
	}
	policies := sc.(*mqlMs365ExchangeonlineSecurityAndCompliance).GetDlpPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}
	for _, p := range policies.Data {
		if pol, ok := p.(*mqlMs365ExchangeonlineDlpCompliancePolicy); ok && pol.Name.Data == name {
			return pol, nil
		}
	}

	r.ParentPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// dlpRules returns the Data Loss Prevention compliance rules as typed
// resources. Like dlpPolicies, fields are extracted defensively from the
// Security & Compliance PowerShell report.
func (r *mqlMs365ExchangeonlineSecurityAndCompliance) dlpRules() ([]any, error) {
	report, err := r.getSecurityAndComplianceReport()
	if err != nil {
		return nil, err
	}
	return convertDlpComplianceRules(r.MqlRuntime, report.DlpComplianceRule)
}

func convertDlpComplianceRules(runtime *plugin.Runtime, raw []any) ([]any, error) {
	result := []any{}
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}

		guid := dlpString(m, "Guid")
		id := guid
		if id == "" {
			id = dlpString(m, "Name")
		}

		mql, err := CreateResource(runtime, "ms365.exchangeonline.dlpComplianceRule",
			map[string]*llx.RawData{
				"__id":                      llx.StringData("dlpComplianceRule-" + id),
				"name":                      llx.StringData(dlpString(m, "Name")),
				"guid":                      llx.StringData(guid),
				"parentPolicyName":          llx.StringData(dlpString(m, "ParentPolicyName")),
				"disabled":                  llx.BoolData(dlpBool(m, "Disabled")),
				"mode":                      llx.StringData(dlpString(m, "Mode")),
				"priority":                  llx.IntData(dlpInt(m, "Priority")),
				"sensitiveInformationTypes": llx.ArrayData(dlpRuleSensitiveInfoTypes(m), types.String),
				"blockAccess":               llx.BoolData(dlpBool(m, "BlockAccess")),
				"blockAccessScope":          llx.StringData(dlpString(m, "BlockAccessScope")),
				"notifyUser":                llx.ArrayData(dlpStringSlice(m, "NotifyUser"), types.String),
				"notifyUserType":            llx.StringData(dlpString(m, "NotifyUserType")),
				"generateIncidentReport":    llx.ArrayData(dlpStringSlice(m, "GenerateIncidentReport"), types.String),
				"reportSeverityLevel":       llx.StringData(dlpString(m, "ReportSeverityLevel")),
				"accessScope":               llx.StringData(dlpString(m, "AccessScope")),
				"isAdvancedRule":            llx.BoolData(dlpBool(m, "IsAdvancedRule")),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// dlpStringSlice extracts a list of strings from a map value that may be a
// JSON array of strings or a single string.
func dlpStringSlice(m map[string]any, key string) []any {
	res := []any{}
	switch v := m[key].(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				res = append(res, s)
			}
		}
	case string:
		if v != "" {
			res = append(res, v)
		}
	}
	return res
}

// dlpConditionSensitiveInfo is the condition that lists the sensitive
// information types a rule detects.
const dlpConditionSensitiveInfo = "ContentContainsSensitiveInformation"

// dlpRuleSensitiveInfoTypes returns the distinct, sorted names of the
// sensitive information types a DLP rule detects.
//
// A simple rule carries them in its ContentContainsSensitiveInformation
// property. An advanced rule leaves that property empty and carries its
// conditions as a JSON document in AdvancedRule, where the
// ContentContainsSensitiveInformation condition can sit at any depth of the
// SubConditions tree. Both are read.
func dlpRuleSensitiveInfoTypes(rule map[string]any) []any {
	c := &dlpSensitiveInfoCollector{seen: map[string]struct{}{}}
	c.addCondition(rule[dlpConditionSensitiveInfo])
	if advanced, ok := rule["AdvancedRule"].(string); ok && advanced != "" {
		var doc any
		if err := json.Unmarshal([]byte(advanced), &doc); err != nil {
			log.Debug().Err(err).Str("rule", dlpString(rule, "Name")).Msg("cannot parse DLP advanced rule")
		} else {
			c.addAdvancedRule(doc)
		}
	}

	// sort for deterministic output across runs
	sort.Strings(c.names)
	res := make([]any, 0, len(c.names))
	for _, n := range c.names {
		res = append(res, n)
	}
	return res
}

type dlpSensitiveInfoCollector struct {
	names []string
	seen  map[string]struct{}
}

// addAdvancedRule walks an AdvancedRule document
// ({"Condition": {"Operator": ..., "SubConditions": [...]}}) and reads every
// ContentContainsSensitiveInformation condition in it.
func (c *dlpSensitiveInfoCollector) addAdvancedRule(node any) {
	switch t := node.(type) {
	case map[string]any:
		if name, _ := dlpCaseInsensitive(t, "ConditionName").(string); strings.EqualFold(name, dlpConditionSensitiveInfo) {
			c.addCondition(dlpCaseInsensitive(t, "Value"))
			return
		}
		c.addAdvancedRule(dlpCaseInsensitive(t, "Condition"))
		c.addAdvancedRule(dlpCaseInsensitive(t, "SubConditions"))
	case []any:
		for _, item := range t {
			c.addAdvancedRule(item)
		}
	}
}

// addCondition reads the value of a ContentContainsSensitiveInformation
// condition, which comes in two shapes. The simple shape is a list of
// sensitive information type entries:
//
//	[{"name": "Credit Card Number", "mincount": "1", ...}]
//
// The grouped shape is a list holding an operator and groups. Each group has a
// name of its own and lists sensitive information types under sensitivetypes
// and sensitivity labels under labels:
//
//	[{"operator": "And", "groups": [{"operator": "Or", "name": "Default",
//	  "sensitivetypes": [{"name": "Credit Card Number"}],
//	  "labels": [{"name": "Confidential"}]}]}]
//
// Only sensitive information type entries are collected. Group names and
// label names are not sensitive information types.
func (c *dlpSensitiveInfoCollector) addCondition(v any) {
	for _, entry := range dlpList(v) {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if groups := dlpCaseInsensitive(m, "groups"); groups != nil {
			c.addGroups(groups)
			continue
		}
		c.addEntry(m)
	}
}

func (c *dlpSensitiveInfoCollector) addGroups(groups any) {
	for _, g := range dlpList(groups) {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		for _, st := range dlpList(dlpCaseInsensitive(gm, "sensitivetypes")) {
			c.addEntry(st)
		}
		if nested := dlpCaseInsensitive(gm, "groups"); nested != nil {
			c.addGroups(nested)
		}
	}
}

// addEntry records the name of one sensitive information type entry. Trainable
// classifiers (classifier type MLModel) share the list but are not sensitive
// information types, and are named only by their GUID, so they are skipped.
func (c *dlpSensitiveInfoCollector) addEntry(entry any) {
	m, ok := entry.(map[string]any)
	if !ok {
		return
	}
	if ct, _ := dlpCaseInsensitive(m, "classifiertype").(string); strings.EqualFold(ct, "MLModel") {
		return
	}
	s, ok := dlpCaseInsensitive(m, "name").(string)
	if !ok || s == "" {
		return
	}
	if _, dup := c.seen[s]; dup {
		return
	}
	c.seen[s] = struct{}{}
	c.names = append(c.names, s)
}

// dlpList returns v as a list. PowerShell serializes a one-element collection
// either as a list or as the bare element, so a single map is wrapped.
func dlpList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case map[string]any:
		return []any{t}
	}
	return nil
}

// dlpCaseInsensitive looks up key in m ignoring case. PowerShell hashtables
// are case-insensitive, so the serialized key casing follows whatever the
// rule author typed.
func dlpCaseInsensitive(m map[string]any, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}
