// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"

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
	// a cmdlet that failed leaves its section null; reporting that as an
	// empty list would claim the tenant has none
	if report == nil || report.DlpComplianceRule == nil {
		r.DlpRules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
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
				"sensitiveInformationTypes": llx.ArrayData(dlpSensitiveInfoTypes(m["ContentContainsSensitiveInformation"]), types.String),
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

// dlpSensitiveInfoTypes walks the ContentContainsSensitiveInformation condition
// — whose shape differs between simple and advanced rules — and collects the
// distinct sensitive information type names.
func dlpSensitiveInfoTypes(v any) []any {
	names := []string{}
	seen := map[string]struct{}{}
	var walk func(any)
	walk = func(node any) {
		switch t := node.(type) {
		case map[string]any:
			for k, val := range t {
				if k == "Name" || k == "name" {
					if s, ok := val.(string); ok && s != "" {
						if _, dup := seen[s]; !dup {
							seen[s] = struct{}{}
							names = append(names, s)
						}
						continue
					}
				}
				walk(val)
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(v)

	// sort for deterministic output across runs
	sort.Strings(names)
	res := make([]any, 0, len(names))
	for _, n := range names {
		res = append(res, n)
	}
	return res
}
