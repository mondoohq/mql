// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	betadm "github.com/microsoftgraph/msgraph-beta-sdk-go/devicemanagement"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// configurationPolicies lists the settings catalog (unified configuration)
// policies. Uses the beta Graph SDK because v1 does not expose
// /deviceManagement/configurationPolicies. Per-policy settings are loaded
// lazily through the settings() accessor.
// requires DeviceManagementConfiguration.Read.All permission
func (a *mqlMicrosoftDevicemanagement) configurationPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	// Expand assignments so isAssigned can be derived reliably: the list
	// endpoint omits the computed isAssigned property (returns a nil *bool)
	// unless assignments are expanded.
	reqConfig := &betadm.ConfigurationPoliciesRequestBuilderGetRequestConfiguration{
		QueryParameters: &betadm.ConfigurationPoliciesRequestBuilderGetQueryParameters{
			Expand: []string{"assignments"},
		},
	}
	resp, err := graphClient.DeviceManagement().ConfigurationPolicies().Get(ctx, reqConfig)
	if err != nil {
		return nil, transformError(err)
	}
	policies, err := iterate[betamodels.DeviceManagementConfigurationPolicyable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateDeviceManagementConfigurationPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, p := range policies {
		// skip policies without an id; their cache key would collide
		if p.GetId() == nil {
			continue
		}
		var templateId, templateDisplayName, templateFamily *string
		if tr := p.GetTemplateReference(); tr != nil {
			templateId = tr.GetTemplateId()
			templateDisplayName = tr.GetTemplateDisplayName()
			templateFamily = enumPtrString(tr.GetTemplateFamily())
		}

		mqlPolicy, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.configurationPolicy",
			map[string]*llx.RawData{
				"__id":                 llx.StringDataPtr(p.GetId()),
				"id":                   llx.StringDataPtr(p.GetId()),
				"name":                 llx.StringDataPtr(p.GetName()),
				"description":          llx.StringDataPtr(p.GetDescription()),
				"platforms":            llx.StringDataPtr(enumPtrString(p.GetPlatforms())),
				"technologies":         llx.StringDataPtr(enumPtrString(p.GetTechnologies())),
				"isAssigned":           llx.BoolData(len(p.GetAssignments()) > 0),
				"settingCount":         llx.IntDataPtr(p.GetSettingCount()),
				"roleScopeTagIds":      llx.ArrayData(llx.TArr2Raw(p.GetRoleScopeTagIds()), types.String),
				"templateId":           llx.StringDataPtr(templateId),
				"templateDisplayName":  llx.StringDataPtr(templateDisplayName),
				"templateFamily":       llx.StringDataPtr(templateFamily),
				"createdDateTime":      llx.TimeDataPtr(p.GetCreatedDateTime()),
				"lastModifiedDateTime": llx.TimeDataPtr(p.GetLastModifiedDateTime()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

// settings loads the individual configured settings of a configuration policy,
// flattening each polymorphic setting instance into a dictionary.
func (p *mqlMicrosoftDevicemanagementConfigurationPolicy) settings() ([]any, error) {
	if p.Id.Data == "" {
		return []any{}, nil
	}
	conn := p.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().ConfigurationPolicies().
		ByDeviceManagementConfigurationPolicyId(p.Id.Data).
		Settings().
		Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	settings, err := iterate[betamodels.DeviceManagementConfigurationSettingable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateDeviceManagementConfigurationSettingCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, s := range settings {
		res = append(res, flattenConfigurationSetting(s.GetSettingInstance()))
	}
	return res, nil
}

// flattenConfigurationSetting reduces a polymorphic setting instance to a
// dictionary with its settingDefinitionId, settingType, a best-effort value,
// and the nested settings under it as children, in the same shape.
//
// Most real configuration sits below the top level: a choice setting such as
// "enable BitLocker" carries the dependent options as children of the selected
// value, and a group setting holds its members as children. A group collection
// (for example a list of firewall rules) has one groupInstance child per
// configured instance, whose children are that instance's settings.
func flattenConfigurationSetting(inst betamodels.DeviceManagementConfigurationSettingInstanceable) map[string]any {
	d := map[string]any{}
	if inst == nil {
		return d
	}
	d["settingDefinitionId"] = convert.ToValue(inst.GetSettingDefinitionId())
	// always present so consumers can rely on the keys across all setting types
	d["value"] = nil
	children := []any{}

	switch v := inst.(type) {
	case betamodels.DeviceManagementConfigurationChoiceSettingInstanceable:
		d["settingType"] = "choice"
		if cv := v.GetChoiceSettingValue(); cv != nil {
			d["value"] = convert.ToValue(cv.GetValue())
			children = appendConfigurationSettings(children, cv.GetChildren())
		}
	case betamodels.DeviceManagementConfigurationSimpleSettingInstanceable:
		d["settingType"] = "simple"
		d["value"] = simpleConfigurationSettingValue(v.GetSimpleSettingValue())
	case betamodels.DeviceManagementConfigurationChoiceSettingCollectionInstanceable:
		d["settingType"] = "choiceCollection"
		vals := []any{}
		for _, cv := range v.GetChoiceSettingCollectionValue() {
			if cv == nil {
				continue
			}
			vals = append(vals, convert.ToValue(cv.GetValue()))
			children = appendConfigurationSettings(children, cv.GetChildren())
		}
		d["value"] = vals
	case betamodels.DeviceManagementConfigurationSimpleSettingCollectionInstanceable:
		d["settingType"] = "simpleCollection"
		vals := []any{}
		for _, sv := range v.GetSimpleSettingCollectionValue() {
			vals = append(vals, simpleConfigurationSettingValue(sv))
		}
		d["value"] = vals
	case betamodels.DeviceManagementConfigurationGroupSettingInstanceable:
		d["settingType"] = "group"
		if gv := v.GetGroupSettingValue(); gv != nil {
			children = appendConfigurationSettings(children, gv.GetChildren())
		}
	case betamodels.DeviceManagementConfigurationGroupSettingCollectionInstanceable:
		d["settingType"] = "groupCollection"
		for _, gv := range v.GetGroupSettingCollectionValue() {
			if gv == nil {
				continue
			}
			children = append(children, map[string]any{
				"settingDefinitionId": d["settingDefinitionId"],
				"settingType":         "groupInstance",
				"value":               nil,
				"children":            appendConfigurationSettings([]any{}, gv.GetChildren()),
			})
		}
	default:
		d["settingType"] = "unknown"
	}
	d["children"] = children
	return d
}

// appendConfigurationSettings flattens each nested setting instance onto dst.
func appendConfigurationSettings(dst []any, insts []betamodels.DeviceManagementConfigurationSettingInstanceable) []any {
	for _, child := range insts {
		if child == nil {
			continue
		}
		dst = append(dst, flattenConfigurationSetting(child))
	}
	return dst
}

func simpleConfigurationSettingValue(sv betamodels.DeviceManagementConfigurationSimpleSettingValueable) any {
	// The Secret case must come before the String case: the concrete secret
	// type also satisfies the StringSettingValueable interface, and a Go type
	// switch matches interface cases in source order — so with String first,
	// secret values fell through to it and were returned in cleartext instead
	// of being masked.
	switch v := sv.(type) {
	case betamodels.DeviceManagementConfigurationSecretSettingValueable:
		return "***"
	case betamodels.DeviceManagementConfigurationStringSettingValueable:
		return convert.ToValue(v.GetValue())
	case betamodels.DeviceManagementConfigurationIntegerSettingValueable:
		if v.GetValue() != nil {
			return int64(*v.GetValue())
		}
	}
	return nil
}
