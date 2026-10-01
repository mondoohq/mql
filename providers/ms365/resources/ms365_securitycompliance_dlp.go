// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// dlpPolicies returns the Data Loss Prevention compliance policies as typed
// resources. The underlying data comes from the Security & Compliance
// PowerShell report, whose JSON shape varies by module version, so each field
// is extracted defensively rather than struct-decoded.
func (r *mqlMs365ExchangeonlineSecurityAndCompliance) dlpPolicies() ([]any, error) {
	report, err := r.getSecurityAndComplianceReport()
	if err != nil {
		return nil, err
	}
	// a cmdlet that failed leaves its section null; reporting that as an
	// empty list would claim the tenant has none
	if report == nil || report.DlpCompliancePolicy == nil {
		r.DlpPolicies.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convertDlpCompliancePolicies(r.MqlRuntime, report.DlpCompliancePolicy)
}

func convertDlpCompliancePolicies(runtime *plugin.Runtime, raw []any) ([]any, error) {
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

		copilot, err := convert.JsonToDict(m["Copilot"])
		if err != nil {
			return nil, err
		}

		mql, err := CreateResource(runtime, "ms365.exchangeonline.dlpCompliancePolicy",
			map[string]*llx.RawData{
				"__id":               llx.StringData("dlpCompliancePolicy-" + id),
				"name":               llx.StringData(dlpString(m, "Name")),
				"guid":               llx.StringData(guid),
				"mode":               llx.StringData(dlpString(m, "Mode")),
				"enabled":            llx.BoolData(dlpBool(m, "Enabled")),
				"workload":           llx.StringData(dlpWorkload(m)),
				"priority":           llx.IntData(dlpInt(m, "Priority")),
				"comment":            llx.StringData(dlpString(m, "Comment")),
				"createdBy":          llx.StringData(dlpString(m, "CreatedBy")),
				"isValid":            llx.BoolData(dlpBool(m, "IsValid")),
				"distributionStatus": llx.StringData(dlpString(m, "DistributionStatus")),
				"whenCreated":        llx.TimeDataPtr(dlpTime(m, "WhenCreated")),
				"whenChanged":        llx.TimeDataPtr(dlpTime(m, "WhenChanged")),
				"enforcementPlanes":  llx.ArrayData(dlpStringSlice(m, "EnforcementPlanes"), types.String),
				"copilot":            llx.DictData(copilot),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

func dlpString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// dlpBoolPtr is dlpBool for a field where an absent value has to stay null.
// dlpBool cannot distinguish "the policy reports false" from "the property was
// not in the response", and for a field an audit reads as a decision the
// tenant made, inventing false is worse than reporting nothing.
func dlpBoolPtr(m map[string]any, key string) *bool {
	switch v := m[key].(type) {
	case bool:
		return &v
	case string:
		// some PowerShell JSON serializers emit booleans as "True"/"False"
		b := strings.EqualFold(v, "true")
		if !b && !strings.EqualFold(v, "false") {
			return nil
		}
		return &b
	}
	return nil
}

func dlpBool(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		// some PowerShell JSON serializers emit booleans as "True"/"False"
		return strings.EqualFold(v, "true")
	}
	return false
}

func dlpInt(m map[string]any, key string) int64 {
	switch v := m[key].(type) {
	case float64:
		return int64(v)
	case string:
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
	}
	return 0
}

// dlpWorkload coerces the Workload property, which may serialize as a single
// string, a list of workload names, or (for a numeric enum) be unreadable.
func dlpWorkload(m map[string]any) string {
	switch v := m["Workload"].(type) {
	case string:
		return v
	case []any:
		parts := []string{}
		for _, p := range v {
			if s, ok := p.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

// dlpTime parses a timestamp that PowerShell may emit either as an ISO 8601
// string or as the legacy "/Date(milliseconds)/" form.
func dlpTime(m map[string]any, key string) *time.Time {
	s, ok := m[key].(string)
	if !ok || s == "" {
		return nil
	}

	if strings.HasPrefix(s, "/Date(") && strings.HasSuffix(s, ")/") {
		inner := strings.TrimSuffix(strings.TrimPrefix(s, "/Date("), ")/")
		if idx := strings.IndexAny(inner, "+-"); idx > 0 {
			inner = inner[:idx]
		}
		if ms, err := strconv.ParseInt(inner, 10, 64); err == nil {
			t := time.UnixMilli(ms).UTC()
			return &t
		}
		return nil
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}
