// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

type mqlMicrosoftDevicemanagementPolicyAssignmentInternal struct {
	cacheGroupID  string
	cacheFilterID string
}

type mqlMicrosoftDevicemanagementManageddeviceInternal struct {
	cacheUserID string
}

func (m *mqlMicrosoftDevicemanagementPolicyAssignment) id() (string, error) {
	return m.Id.Data, nil
}

// group resolves the Entra ID group a policy assignment targets, when the
// assignment targets a group.
func (m *mqlMicrosoftDevicemanagementPolicyAssignment) group() (*mqlMicrosoftGroup, error) {
	id := m.cacheGroupID
	if id == "" {
		m.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, "microsoft.group", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftGroup), nil
}

// user resolves the Entra ID user associated with the managed device.
func (m *mqlMicrosoftDevicemanagementManageddevice) user() (*mqlMicrosoftUser, error) {
	id := m.cacheUserID
	if id == "" {
		m.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, "microsoft.user", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftUser), nil
}

func (m *mqlMicrosoftDevicemanagementManageddevicePolicyState) id() (string, error) {
	return m.Id.Data, nil
}

func (a *mqlMicrosoftDevicemanagementManageddevice) compliancePolicyStates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().ManagedDevices().ByManagedDeviceId(a.Id.Data).DeviceCompliancePolicyStates().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	states, err := iterate[models.DeviceCompliancePolicyStateable](ctx, resp, graphClient.GetAdapter(), models.CreateDeviceCompliancePolicyStateCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, state := range states {
		r, err := newCompliancePolicyState(a.MqlRuntime, a.Id.Data, state)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (a *mqlMicrosoftDevicemanagementManageddevice) configurationStates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().ManagedDevices().ByManagedDeviceId(a.Id.Data).DeviceConfigurationStates().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	states, err := iterate[models.DeviceConfigurationStateable](ctx, resp, graphClient.GetAdapter(), models.CreateDeviceConfigurationStateCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, state := range states {
		r, err := newConfigurationState(a.MqlRuntime, a.Id.Data, state)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func newCompliancePolicyState(runtime *plugin.Runtime, deviceId string, state models.DeviceCompliancePolicyStateable) (any, error) {
	id := deviceId + "/compliance/"
	if v := state.GetId(); v != nil {
		id += *v
	}
	displayName := ""
	if v := state.GetDisplayName(); v != nil {
		displayName = *v
	}
	stateStr := ""
	if v := state.GetState(); v != nil {
		stateStr = v.String()
	}
	platform := ""
	if v := state.GetPlatformType(); v != nil {
		platform = v.String()
	}
	settingStates, err := complianceSettingStatesToDicts(state.GetSettingStates())
	if err != nil {
		return nil, err
	}
	settingCount := int64(0)
	if v := state.GetSettingCount(); v != nil {
		settingCount = int64(*v)
	}
	version := int64(0)
	if v := state.GetVersion(); v != nil {
		version = int64(*v)
	}
	return CreateResource(runtime, "microsoft.devicemanagement.manageddevice.policyState",
		map[string]*llx.RawData{
			"__id":          llx.StringData(id),
			"id":            llx.StringData(id),
			"displayName":   llx.StringData(displayName),
			"state":         llx.StringData(stateStr),
			"settingStates": llx.ArrayData(settingStates, types.Any),
			"sourceType":    llx.StringData("deviceCompliancePolicyState"),
			"platformType":  llx.StringData(platform),
			"settingCount":  llx.IntData(settingCount),
			"version":       llx.IntData(version),
		})
}

func newConfigurationState(runtime *plugin.Runtime, deviceId string, state models.DeviceConfigurationStateable) (any, error) {
	id := deviceId + "/configuration/"
	if v := state.GetId(); v != nil {
		id += *v
	}
	displayName := ""
	if v := state.GetDisplayName(); v != nil {
		displayName = *v
	}
	stateStr := ""
	if v := state.GetState(); v != nil {
		stateStr = v.String()
	}
	platform := ""
	if v := state.GetPlatformType(); v != nil {
		platform = v.String()
	}
	settingStates, err := configurationSettingStatesToDicts(state.GetSettingStates())
	if err != nil {
		return nil, err
	}
	settingCount := int64(0)
	if v := state.GetSettingCount(); v != nil {
		settingCount = int64(*v)
	}
	version := int64(0)
	if v := state.GetVersion(); v != nil {
		version = int64(*v)
	}
	return CreateResource(runtime, "microsoft.devicemanagement.manageddevice.policyState",
		map[string]*llx.RawData{
			"__id":          llx.StringData(id),
			"id":            llx.StringData(id),
			"displayName":   llx.StringData(displayName),
			"state":         llx.StringData(stateStr),
			"settingStates": llx.ArrayData(settingStates, types.Any),
			"sourceType":    llx.StringData("deviceConfigurationState"),
			"platformType":  llx.StringData(platform),
			"settingCount":  llx.IntData(settingCount),
			"version":       llx.IntData(version),
		})
}

func complianceSettingStatesToDicts(states []models.DeviceCompliancePolicySettingStateable) ([]any, error) {
	res := []any{}
	for _, s := range states {
		entry := map[string]any{}
		if v := s.GetSetting(); v != nil {
			entry["setting"] = *v
		}
		if v := s.GetSettingName(); v != nil {
			entry["settingName"] = *v
		}
		if v := s.GetState(); v != nil {
			entry["state"] = v.String()
		}
		if v := s.GetCurrentValue(); v != nil {
			entry["currentValue"] = *v
		}
		if v := s.GetUserName(); v != nil {
			entry["userName"] = *v
		}
		if v := s.GetUserId(); v != nil {
			entry["userId"] = *v
		}
		res = append(res, entry)
	}
	return res, nil
}

func configurationSettingStatesToDicts(states []models.DeviceConfigurationSettingStateable) ([]any, error) {
	res := []any{}
	for _, s := range states {
		entry := map[string]any{}
		if v := s.GetSetting(); v != nil {
			entry["setting"] = *v
		}
		if v := s.GetSettingName(); v != nil {
			entry["settingName"] = *v
		}
		if v := s.GetState(); v != nil {
			entry["state"] = v.String()
		}
		if v := s.GetCurrentValue(); v != nil {
			entry["currentValue"] = *v
		}
		if v := s.GetUserName(); v != nil {
			entry["userName"] = *v
		}
		if v := s.GetUserId(); v != nil {
			entry["userId"] = *v
		}
		res = append(res, entry)
	}
	return res, nil
}
