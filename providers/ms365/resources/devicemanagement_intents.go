// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

func (m *mqlMicrosoftDevicemanagementIntent) id() (string, error) {
	return m.Id.Data, nil
}

func (m *mqlMicrosoftDevicemanagementIntentSetting) id() (string, error) {
	return m.Id.Data, nil
}

// intents returns all endpoint security intents in the tenant. Each intent
// is created from a template (antivirus, disk encryption, etc.); we fetch
// templates once and resolve template display names inline so callers get
// human-readable names without an extra query.
func (a *mqlMicrosoftDevicemanagement) intents() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	templatesResp, err := graphClient.DeviceManagement().Templates().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	templates, err := iterate[betamodels.DeviceManagementTemplateable](ctx, templatesResp, graphClient.GetAdapter(), betamodels.CreateDeviceManagementTemplateCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}
	templateNames := map[string]string{}
	for _, t := range templates {
		if t.GetId() == nil {
			continue
		}
		if name := t.GetDisplayName(); name != nil {
			templateNames[*t.GetId()] = *name
		}
	}

	intentsResp, err := graphClient.DeviceManagement().Intents().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	intents, err := iterate[betamodels.DeviceManagementIntentable](ctx, intentsResp, graphClient.GetAdapter(), betamodels.CreateDeviceManagementIntentCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, intent := range intents {
		r, err := newIntentResource(a.MqlRuntime, intent, templateNames)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func newIntentResource(runtime *plugin.Runtime, intent betamodels.DeviceManagementIntentable, templateNames map[string]string) (any, error) {
	templateId := ""
	if v := intent.GetTemplateId(); v != nil {
		templateId = *v
	}
	return CreateResource(runtime, "microsoft.devicemanagement.intent",
		map[string]*llx.RawData{
			"__id":                 llx.StringDataPtr(intent.GetId()),
			"id":                   llx.StringDataPtr(intent.GetId()),
			"displayName":          llx.StringDataPtr(intent.GetDisplayName()),
			"description":          llx.StringDataPtr(intent.GetDescription()),
			"templateId":           llx.StringData(templateId),
			"templateDisplayName":  llx.StringData(templateNames[templateId]),
			"isAssigned":           llx.BoolDataPtr(intent.GetIsAssigned()),
			"lastModifiedDateTime": graphTimeData(intent.GetLastModifiedDateTime()),
		})
}

func (a *mqlMicrosoftDevicemanagementIntent) settings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().Intents().ByDeviceManagementIntentId(a.Id.Data).Settings().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	settings, err := iterate[betamodels.DeviceManagementSettingInstanceable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateDeviceManagementSettingInstanceCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, s := range settings {
		id := ""
		if v := s.GetId(); v != nil {
			id = *v
		}
		definitionId := ""
		if v := s.GetDefinitionId(); v != nil {
			definitionId = *v
		}
		valueJson := ""
		if v := s.GetValueJson(); v != nil {
			valueJson = *v
		}
		valueType := ""
		if v := s.GetOdataType(); v != nil {
			valueType = trimOdataType(*v)
		}
		r, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.intent.setting",
			map[string]*llx.RawData{
				"__id":         llx.StringData(a.Id.Data + "/" + id),
				"id":           llx.StringData(id),
				"definitionId": llx.StringData(definitionId),
				"valueJson":    llx.StringData(valueJson),
				"valueType":    llx.StringData(valueType),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (a *mqlMicrosoftDevicemanagementIntent) assignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().Intents().ByDeviceManagementIntentId(a.Id.Data).Assignments().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	assignments, err := iterate[betamodels.DeviceManagementIntentAssignmentable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateDeviceManagementIntentAssignmentCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, assignment := range assignments {
		id := ""
		if v := assignment.GetId(); v != nil {
			id = *v
		}
		r, err := newBetaPolicyAssignmentResource(a.MqlRuntime, a.Id.Data+"/"+id, assignment.GetTarget())
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}
