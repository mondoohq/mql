// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
)

func TestComplianceSettingStatesToDicts_Empty(t *testing.T) {
	got, err := complianceSettingStatesToDicts(nil)
	assert.NoError(t, err)
	assert.Equal(t, []any{}, got)
}

func TestComplianceSettingStatesToDicts_FieldMapping(t *testing.T) {
	s := models.NewDeviceCompliancePolicySettingState()
	s.SetSetting(new("setting.key"))
	s.SetSettingName(new("Setting Name"))
	state := models.COMPLIANT_COMPLIANCESTATUS
	s.SetState(&state)
	s.SetCurrentValue(new("on"))
	s.SetUserName(new("alice"))
	s.SetUserId(new("uid-1"))

	got, err := complianceSettingStatesToDicts([]models.DeviceCompliancePolicySettingStateable{s})
	assert.NoError(t, err)
	assert.Len(t, got, 1)
	entry := got[0].(map[string]any)
	assert.Equal(t, "setting.key", entry["setting"])
	assert.Equal(t, "Setting Name", entry["settingName"])
	assert.Equal(t, "compliant", entry["state"])
	assert.Equal(t, "on", entry["currentValue"])
	assert.Equal(t, "alice", entry["userName"])
	assert.Equal(t, "uid-1", entry["userId"])
}

func TestComplianceSettingStatesToDicts_OmitsNilFields(t *testing.T) {
	s := models.NewDeviceCompliancePolicySettingState()
	s.SetSetting(new("only.set"))

	got, err := complianceSettingStatesToDicts([]models.DeviceCompliancePolicySettingStateable{s})
	assert.NoError(t, err)
	entry := got[0].(map[string]any)
	assert.Equal(t, map[string]any{"setting": "only.set"}, entry)
}

func TestConfigurationSettingStatesToDicts_FieldMapping(t *testing.T) {
	s := models.NewDeviceConfigurationSettingState()
	s.SetSetting(new("config.key"))
	s.SetSettingName(new("Config Name"))
	state := models.NONCOMPLIANT_COMPLIANCESTATUS
	s.SetState(&state)
	s.SetCurrentValue(new("off"))
	s.SetUserName(new("bob"))
	s.SetUserId(new("uid-2"))

	got, err := configurationSettingStatesToDicts([]models.DeviceConfigurationSettingStateable{s})
	assert.NoError(t, err)
	assert.Len(t, got, 1)
	entry := got[0].(map[string]any)
	assert.Equal(t, "config.key", entry["setting"])
	assert.Equal(t, "Config Name", entry["settingName"])
	assert.Equal(t, "nonCompliant", entry["state"])
	assert.Equal(t, "off", entry["currentValue"])
	assert.Equal(t, "bob", entry["userName"])
	assert.Equal(t, "uid-2", entry["userId"])
}

func TestConfigurationSettingStatesToDicts_Empty(t *testing.T) {
	got, err := configurationSettingStatesToDicts(nil)
	assert.NoError(t, err)
	assert.Equal(t, []any{}, got)
}
