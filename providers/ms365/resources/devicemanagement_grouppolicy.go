// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	betadevicemanagement "github.com/microsoftgraph/msgraph-beta-sdk-go/devicemanagement"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// groupPolicyConfigurations lists the administrative-templates (ADMX) policy
// configurations. Uses the beta Graph SDK because v1 does not expose them.
// Per-configuration settings are loaded lazily through definitionValues().
// requires DeviceManagementConfiguration.Read.All permission
func (a *mqlMicrosoftDevicemanagement) groupPolicyConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().GroupPolicyConfigurations().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	configs, err := iterate[betamodels.GroupPolicyConfigurationable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateGroupPolicyConfigurationCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, c := range configs {
		mqlConfig, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.groupPolicyConfiguration",
			map[string]*llx.RawData{
				"__id":                             llx.StringDataPtr(c.GetId()),
				"id":                               llx.StringDataPtr(c.GetId()),
				"displayName":                      llx.StringDataPtr(c.GetDisplayName()),
				"description":                      llx.StringDataPtr(c.GetDescription()),
				"policyConfigurationIngestionType": llx.StringDataPtr(enumPtrString(c.GetPolicyConfigurationIngestionType())),
				"roleScopeTagIds":                  llx.ArrayData(llx.TArr2Raw(c.GetRoleScopeTagIds()), types.String),
				"createdDateTime":                  graphTimeData(c.GetCreatedDateTime()),
				"lastModifiedDateTime":             graphTimeData(c.GetLastModifiedDateTime()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConfig)
	}
	return res, nil
}

// definitionValues loads the administrative-template settings configured by a
// group policy configuration, expanding each value's definition so the policy
// name, class, and category are available.
func (g *mqlMicrosoftDevicemanagementGroupPolicyConfiguration) definitionValues() ([]any, error) {
	if g.Id.Data == "" {
		return []any{}, nil
	}
	conn := g.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().GroupPolicyConfigurations().
		ByGroupPolicyConfigurationId(g.Id.Data).
		DefinitionValues().
		Get(ctx, &betadevicemanagement.GroupPolicyConfigurationsItemDefinitionValuesRequestBuilderGetRequestConfiguration{
			QueryParameters: &betadevicemanagement.GroupPolicyConfigurationsItemDefinitionValuesRequestBuilderGetQueryParameters{
				Expand: []string{"definition"},
			},
		})
	if err != nil {
		return nil, transformError(err)
	}
	values, err := iterate[betamodels.GroupPolicyDefinitionValueable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateGroupPolicyDefinitionValueCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, v := range values {
		var definitionName, definitionClassType, definitionCategoryPath *string
		if d := v.GetDefinition(); d != nil {
			definitionName = d.GetDisplayName()
			definitionClassType = enumPtrString(d.GetClassType())
			definitionCategoryPath = d.GetCategoryPath()
		}

		mqlValue, err := CreateResource(g.MqlRuntime, "microsoft.devicemanagement.groupPolicyDefinitionValue",
			map[string]*llx.RawData{
				"__id":                   llx.StringDataPtr(v.GetId()),
				"id":                     llx.StringDataPtr(v.GetId()),
				"enabled":                llx.BoolDataPtr(v.GetEnabled()),
				"configurationType":      llx.StringDataPtr(enumPtrString(v.GetConfigurationType())),
				"definitionName":         llx.StringDataPtr(definitionName),
				"definitionClassType":    llx.StringDataPtr(definitionClassType),
				"definitionCategoryPath": llx.StringDataPtr(definitionCategoryPath),
				"createdDateTime":        graphTimeData(v.GetCreatedDateTime()),
				"lastModifiedDateTime":   graphTimeData(v.GetLastModifiedDateTime()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlValue)
	}
	return res, nil
}
