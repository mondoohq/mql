// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/compute/v1"
)

// newMqlSecurityPolicyAdaptiveProtection promotes a policy's Adaptive
// Protection configuration.
//
// SecurityPolicyAdaptiveProtectionConfig carries exactly one member, the layer
// 7 defense, so the resource has one field. Returns llx.NilData for a policy
// with no adaptive protection configured, which is every policy that is not a
// global CLOUD_ARMOR policy.
func newMqlSecurityPolicyAdaptiveProtection(runtime *plugin.Runtime, policyID string, cfg *compute.SecurityPolicyAdaptiveProtectionConfig) (*llx.RawData, error) {
	if cfg == nil {
		return llx.NilData, nil
	}

	layer7 := llx.NilData
	if l7 := cfg.Layer7DdosDefenseConfig; l7 != nil {
		thresholds, err := convert.JsonToDictSlice(l7.ThresholdConfigs)
		if err != nil {
			return nil, err
		}

		res, err := CreateResource(runtime, "gcp.project.computeService.securityPolicy.layer7DdosDefense", map[string]*llx.RawData{
			"__id":             llx.StringData(policyID + "/layer7DdosDefense"),
			"enable":           llx.BoolData(l7.Enable),
			"ruleVisibility":   llx.StringData(l7.RuleVisibility),
			"thresholdConfigs": llx.ArrayData(thresholds, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		layer7 = llx.ResourceData(res, "gcp.project.computeService.securityPolicy.layer7DdosDefense")
	}

	res, err := CreateResource(runtime, "gcp.project.computeService.securityPolicy.adaptiveProtection", map[string]*llx.RawData{
		"__id":              llx.StringData(policyID + "/adaptiveProtection"),
		"layer7DdosDefense": layer7,
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "gcp.project.computeService.securityPolicy.adaptiveProtection"), nil
}

// newMqlSecurityPolicyAdvancedOptions promotes the advanced options of a
// policy. Returns llx.NilData when the policy leaves every advanced option at
// its default, which is a different claim from a policy that explicitly
// disables JSON parsing.
func newMqlSecurityPolicyAdvancedOptions(runtime *plugin.Runtime, policyID string, cfg *compute.SecurityPolicyAdvancedOptionsConfig) (*llx.RawData, error) {
	if cfg == nil {
		return llx.NilData, nil
	}

	var contentTypes []string
	if cfg.JsonCustomConfig != nil {
		contentTypes = cfg.JsonCustomConfig.ContentTypes
	}

	res, err := CreateResource(runtime, "gcp.project.computeService.securityPolicy.advancedOptions", map[string]*llx.RawData{
		"__id":                      llx.StringData(policyID + "/advancedOptions"),
		"jsonParsing":               llx.StringData(cfg.JsonParsing),
		"logLevel":                  llx.StringData(cfg.LogLevel),
		"requestBodyInspectionSize": llx.StringData(cfg.RequestBodyInspectionSize),
		"jsonCustomContentTypes":    llx.ArrayData(convert.SliceAnyToInterface(contentTypes), types.String),
		"userIpRequestHeaders":      llx.ArrayData(convert.SliceAnyToInterface(cfg.UserIpRequestHeaders), types.String),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "gcp.project.computeService.securityPolicy.advancedOptions"), nil
}

// newMqlSecurityPolicyDdosProtection promotes the network DDoS protection of a
// policy. Returns llx.NilData for a policy that carries none, which is every
// policy that is not a CLOUD_ARMOR_NETWORK policy.
func newMqlSecurityPolicyDdosProtection(runtime *plugin.Runtime, policyID string, cfg *compute.SecurityPolicyDdosProtectionConfig) (*llx.RawData, error) {
	if cfg == nil {
		return llx.NilData, nil
	}

	res, err := CreateResource(runtime, "gcp.project.computeService.securityPolicy.networkDdosProtection", map[string]*llx.RawData{
		"__id":                          llx.StringData(policyID + "/ddosProtection"),
		"ddosProtection":                llx.StringData(cfg.DdosProtection),
		"ddosAdaptiveProtection":        llx.StringData(cfg.DdosAdaptiveProtection),
		"ddosImpactedBaselineThreshold": llx.FloatData(cfg.DdosImpactedBaselineThreshold),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "gcp.project.computeService.securityPolicy.networkDdosProtection"), nil
}

// securityPolicyRuleMatcherArgs maps a rule's match condition onto resource
// arguments.
//
// A rule matches either on a source IP list or on an expression, and the two
// arrive in different members of the message. Reading only one of them makes an
// allow rule that matches every client look like a rule with no condition at
// all.
func securityPolicyRuleMatcherArgs(ruleID string, m *compute.SecurityPolicyRuleMatcher) map[string]*llx.RawData {
	srcIpRanges := []any{}
	if m.Config != nil {
		for _, r := range m.Config.SrcIpRanges {
			srcIpRanges = append(srcIpRanges, r)
		}
	}

	var expression, title, description, location string
	if m.Expr != nil {
		expression = m.Expr.Expression
		title = m.Expr.Title
		description = m.Expr.Description
		location = m.Expr.Location
	}

	return map[string]*llx.RawData{
		"__id":                  llx.StringData(ruleID + "/matcher"),
		"versionedExpr":         llx.StringData(m.VersionedExpr),
		"srcIpRanges":           llx.ArrayData(srcIpRanges, types.String),
		"expression":            llx.StringData(expression),
		"expressionTitle":       llx.StringData(title),
		"expressionDescription": llx.StringData(description),
		"expressionLocation":    llx.StringData(location),
	}
}

// newMqlSecurityPolicyRuleMatcher promotes a rule's match condition. Returns
// llx.NilData for a rule that carries none.
func newMqlSecurityPolicyRuleMatcher(runtime *plugin.Runtime, ruleID string, m *compute.SecurityPolicyRuleMatcher) (*llx.RawData, error) {
	if m == nil {
		return llx.NilData, nil
	}

	args := securityPolicyRuleMatcherArgs(ruleID, m)
	exprOptions, err := convert.JsonToDict(m.ExprOptions)
	if err != nil {
		return nil, err
	}
	args["exprOptions"] = llx.DictData(exprOptions)

	res, err := CreateResource(runtime, "gcp.project.computeService.securityPolicy.rule.matcher", args)
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "gcp.project.computeService.securityPolicy.rule.matcher"), nil
}
