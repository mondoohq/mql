// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/waf"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// The listing returns a policy summary with no body, so every field below
// reads the full policy from GetWebAppFirewallPolicy. One fetch serves all of
// them.
func (o *mqlOciWafPolicy) getDetail() (*waf.WebAppFirewallPolicy, error) {
	return o.detail.get(func() (*waf.WebAppFirewallPolicy, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		client, err := conn.WafClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}
		response, err := client.GetWebAppFirewallPolicy(context.Background(), waf.GetWebAppFirewallPolicyRequest{
			WebAppFirewallPolicyId: common.String(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &response.WebAppFirewallPolicy, nil
	})
}

// ociWafActionFields reports an action's type, and for a RETURN_HTTP_RESPONSE
// action the status code and headers it answers with.
//
// The SDK decodes the polymorphic action list into concrete values, but the
// pointer forms are accepted too so a change in how the SDK hands them over
// cannot silently turn every action into an unknown one.
func ociWafActionFields(a waf.Action) (actionType string, code *int, headers map[string]any) {
	headers = map[string]any{}
	var ret *waf.ReturnHttpResponseAction
	switch v := a.(type) {
	case waf.CheckAction, *waf.CheckAction:
		return string(waf.ActionTypeCheck), nil, headers
	case waf.AllowAction, *waf.AllowAction:
		return string(waf.ActionTypeAllow), nil, headers
	case waf.ReturnHttpResponseAction:
		ret = &v
	case *waf.ReturnHttpResponseAction:
		ret = v
	default:
		return "", nil, headers
	}
	if ret == nil {
		return string(waf.ActionTypeReturnHttpResponse), nil, headers
	}
	for _, h := range ret.Headers {
		if h.Name == nil {
			continue
		}
		headers[*h.Name] = stringValue(h.Value)
	}
	return string(waf.ActionTypeReturnHttpResponse), ret.Code, headers
}

func (o *mqlOciWafPolicy) actions() ([]any, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(detail.Actions))
	for _, a := range detail.Actions {
		if a == nil || a.GetName() == nil {
			continue
		}
		name := *a.GetName()
		actionType, code, headers := ociWafActionFields(a)
		mqlAction, err := CreateResource(o.MqlRuntime, "oci.waf.policy.action", map[string]*llx.RawData{
			"__id":            llx.StringData(o.Id.Data + "/action/" + name),
			"name":            llx.StringData(name),
			"type":            llx.StringData(actionType),
			"responseCode":    llx.IntDataPtr(intPtrToInt64(code)),
			"responseHeaders": llx.MapData(headers, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAction)
	}
	return res, nil
}

// actionByName resolves an action a rule or setting refers to by name.
//
// Null when no name is given, and also when the name matches no action the
// policy defines: the policy is then referring to something that does not
// exist, and a null keeps that visible rather than inventing an action.
func (o *mqlOciWafPolicy) actionByName(name string, field *plugin.TValue[*mqlOciWafPolicyAction]) (*mqlOciWafPolicyAction, error) {
	if name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	actions := o.GetActions()
	if actions.Error != nil {
		return nil, actions.Error
	}
	for _, raw := range actions.Data {
		if a, ok := raw.(*mqlOciWafPolicyAction); ok && a.Name.Data == name {
			return a, nil
		}
	}
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (o *mqlOciWafPolicy) requestAccessControlDefaultAction() (*mqlOciWafPolicyAction, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	var name string
	if detail.RequestAccessControl != nil {
		name = stringValue(detail.RequestAccessControl.DefaultActionName)
	}
	return o.actionByName(name, &o.RequestAccessControlDefaultAction)
}

func (o *mqlOciWafPolicy) requestProtectionBodyInspectionSizeLimitInBytes() (int64, error) {
	detail, err := o.getDetail()
	if err != nil {
		return 0, err
	}
	if detail.RequestProtection == nil || detail.RequestProtection.BodyInspectionSizeLimitInBytes == nil {
		o.RequestProtectionBodyInspectionSizeLimitInBytes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*detail.RequestProtection.BodyInspectionSizeLimitInBytes), nil
}

func (o *mqlOciWafPolicy) requestProtectionBodyInspectionSizeLimitExceededAction() (*mqlOciWafPolicyAction, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	var name string
	if detail.RequestProtection != nil {
		name = stringValue(detail.RequestProtection.BodyInspectionSizeLimitExceededActionName)
	}
	return o.actionByName(name, &o.RequestProtectionBodyInspectionSizeLimitExceededAction)
}

// ociWafRule is one rule of a WAF policy, flattened out of whichever module
// holds it. The modules each have their own rule type in the SDK; this is the
// union of what they carry.
type ociWafRule struct {
	module            string
	ruleType          string
	name              string
	actionName        string
	condition         string
	conditionLanguage string

	capabilities       []waf.ProtectionCapability
	settings           *waf.ProtectionCapabilitySettings
	bodyInspection     *bool
	rateLimits         []waf.RequestRateLimitingConfiguration
	isProtectionRule   bool
	isRateLimitingRule bool
}

// Module names as they appear in the policy document, which is how the
// console and the API documentation refer to them.
const (
	ociWafModuleRequestAccessControl  = "requestAccessControl"
	ociWafModuleRequestRateLimiting   = "requestRateLimiting"
	ociWafModuleRequestProtection     = "requestProtection"
	ociWafModuleResponseAccessControl = "responseAccessControl"
	ociWafModuleResponseProtection    = "responseProtection"
)

// ociWafPolicyRules flattens a policy's modules into one rule list, keeping
// the modules in the order the firewall evaluates them and the rules in their
// order within each module.
func ociWafPolicyRules(p *waf.WebAppFirewallPolicy) []ociWafRule {
	if p == nil {
		return nil
	}
	var rules []ociWafRule

	accessControl := func(module string, list []waf.AccessControlRule) {
		for _, r := range list {
			rules = append(rules, ociWafRule{
				module:            module,
				ruleType:          string(waf.WebAppFirewallPolicyRuleTypeAccessControl),
				name:              stringValue(r.Name),
				actionName:        stringValue(r.ActionName),
				condition:         stringValue(r.Condition),
				conditionLanguage: string(r.ConditionLanguage),
			})
		}
	}
	protection := func(module string, list []waf.ProtectionRule) {
		for _, r := range list {
			rules = append(rules, ociWafRule{
				module:            module,
				ruleType:          string(waf.WebAppFirewallPolicyRuleTypeProtection),
				name:              stringValue(r.Name),
				actionName:        stringValue(r.ActionName),
				condition:         stringValue(r.Condition),
				conditionLanguage: string(r.ConditionLanguage),
				capabilities:      r.ProtectionCapabilities,
				settings:          r.ProtectionCapabilitySettings,
				bodyInspection:    r.IsBodyInspectionEnabled,
				isProtectionRule:  true,
			})
		}
	}

	if p.RequestAccessControl != nil {
		accessControl(ociWafModuleRequestAccessControl, p.RequestAccessControl.Rules)
	}
	if p.RequestRateLimiting != nil {
		for _, r := range p.RequestRateLimiting.Rules {
			rules = append(rules, ociWafRule{
				module:             ociWafModuleRequestRateLimiting,
				ruleType:           string(waf.WebAppFirewallPolicyRuleTypeRequestRateLimiting),
				name:               stringValue(r.Name),
				actionName:         stringValue(r.ActionName),
				condition:          stringValue(r.Condition),
				conditionLanguage:  string(r.ConditionLanguage),
				rateLimits:         r.Configurations,
				isRateLimitingRule: true,
			})
		}
	}
	if p.RequestProtection != nil {
		protection(ociWafModuleRequestProtection, p.RequestProtection.Rules)
	}
	if p.ResponseAccessControl != nil {
		accessControl(ociWafModuleResponseAccessControl, p.ResponseAccessControl.Rules)
	}
	if p.ResponseProtection != nil {
		protection(ociWafModuleResponseProtection, p.ResponseProtection.Rules)
	}
	return rules
}

// ociWafRateLimits maps a rate-limiting rule's configurations to dicts, with
// an unset action duration left null rather than read as zero seconds.
func ociWafRateLimits(configs []waf.RequestRateLimitingConfiguration) []any {
	res := make([]any, 0, len(configs))
	for _, c := range configs {
		entry := map[string]any{
			"periodInSeconds":         nil,
			"requestsLimit":           nil,
			"actionDurationInSeconds": nil,
		}
		if c.PeriodInSeconds != nil {
			entry["periodInSeconds"] = int64(*c.PeriodInSeconds)
		}
		if c.RequestsLimit != nil {
			entry["requestsLimit"] = int64(*c.RequestsLimit)
		}
		if c.ActionDurationInSeconds != nil {
			entry["actionDurationInSeconds"] = int64(*c.ActionDurationInSeconds)
		}
		res = append(res, entry)
	}
	return res
}

func (o *mqlOciWafPolicy) rules() ([]any, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}

	flat := ociWafPolicyRules(detail)
	res := make([]any, 0, len(flat))
	for i, r := range flat {
		var (
			maxArgs, maxSingleArg, maxTotalArg, maxHeaders, maxHeaderLen *int
			allowedMethods                                               = []any{}
		)
		if r.settings != nil {
			maxArgs = r.settings.MaxNumberOfArguments
			maxSingleArg = r.settings.MaxSingleArgumentLength
			maxTotalArg = r.settings.MaxTotalArgumentLength
			maxHeaders = r.settings.MaxHttpRequestHeaders
			maxHeaderLen = r.settings.MaxHttpRequestHeaderLength
			allowedMethods = stringsToAny(r.settings.AllowedHttpMethods)
		}

		bodyInspection := llx.NilData
		if r.isProtectionRule {
			// An unset flag on a protection rule means the body is not
			// inspected, which is the answer an audit needs; on any other rule
			// the question does not apply.
			bodyInspection = llx.BoolData(boolValue(r.bodyInspection))
		}

		// The position is part of the id because the API does not promise
		// rule names are unique within a module, and two rules sharing an id
		// would report the first one's settings twice.
		ruleID := o.Id.Data + "/rule/" + r.module + "/" + strconv.Itoa(i) + "/" + r.name
		mqlRule, err := CreateResource(o.MqlRuntime, "oci.waf.policy.rule", map[string]*llx.RawData{
			"__id":                       llx.StringData(ruleID),
			"module":                     llx.StringData(r.module),
			"name":                       llx.StringData(r.name),
			"type":                       llx.StringData(r.ruleType),
			"condition":                  llx.StringData(r.condition),
			"conditionLanguage":          llx.StringData(r.conditionLanguage),
			"isBodyInspectionEnabled":    bodyInspection,
			"maxNumberOfArguments":       llx.IntDataPtr(intPtrToInt64(maxArgs)),
			"maxSingleArgumentLength":    llx.IntDataPtr(intPtrToInt64(maxSingleArg)),
			"maxTotalArgumentLength":     llx.IntDataPtr(intPtrToInt64(maxTotalArg)),
			"maxHttpRequestHeaders":      llx.IntDataPtr(intPtrToInt64(maxHeaders)),
			"maxHttpRequestHeaderLength": llx.IntDataPtr(intPtrToInt64(maxHeaderLen)),
			"allowedHttpMethods":         llx.ArrayData(allowedMethods, types.String),
			"rateLimits":                 llx.ArrayData(ociWafRateLimits(r.rateLimits), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		rule := mqlRule.(*mqlOciWafPolicyRule)
		rule.policy = o
		rule.cacheActionName = r.actionName
		rule.cacheCapabilities = r.capabilities
		res = append(res, rule)
	}
	return res, nil
}

type mqlOciWafPolicyRuleInternal struct {
	policy            *mqlOciWafPolicy
	cacheActionName   string
	cacheCapabilities []waf.ProtectionCapability
}

func (o *mqlOciWafPolicyRule) action() (*mqlOciWafPolicyAction, error) {
	if o.policy == nil {
		o.Action.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return o.policy.actionByName(o.cacheActionName, &o.Action)
}

func (o *mqlOciWafPolicyRule) protectionCapabilities() ([]any, error) {
	res := make([]any, 0, len(o.cacheCapabilities))
	for i, c := range o.cacheCapabilities {
		var excludedArgs, excludedCookies []string
		if c.Exclusions != nil {
			excludedArgs = c.Exclusions.Args
			excludedCookies = c.Exclusions.RequestCookies
		}
		key := stringValue(c.Key)
		mqlCap, err := CreateResource(o.MqlRuntime, "oci.waf.policy.protectionCapability", map[string]*llx.RawData{
			"__id":                         llx.StringData(o.MqlID() + "/capability/" + strconv.Itoa(i) + "/" + key),
			"key":                          llx.StringData(key),
			"version":                      llx.IntDataPtr(intPtrToInt64(c.Version)),
			"collaborativeActionThreshold": llx.IntDataPtr(intPtrToInt64(c.CollaborativeActionThreshold)),
			"excludedArgs":                 llx.ArrayData(stringsToAny(excludedArgs), types.String),
			"excludedRequestCookies":       llx.ArrayData(stringsToAny(excludedCookies), types.String),
		})
		if err != nil {
			return nil, err
		}
		capability := mqlCap.(*mqlOciWafPolicyProtectionCapability)
		capability.policy = o.policy
		capability.cacheActionName = stringValue(c.ActionName)
		res = append(res, capability)
	}
	return res, nil
}

type mqlOciWafPolicyProtectionCapabilityInternal struct {
	policy          *mqlOciWafPolicy
	cacheActionName string
}

func (o *mqlOciWafPolicyProtectionCapability) action() (*mqlOciWafPolicyAction, error) {
	if o.policy == nil {
		o.Action.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return o.policy.actionByName(o.cacheActionName, &o.Action)
}
