// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// TestSimpleConfigurationSettingValue_SecretRedaction locks in the type-switch
// ordering: the concrete secret type also satisfies the string-setting-value
// interface, so if the String case is matched first a secret value is returned
// in cleartext instead of the "***" mask. The Secret case must win.
func TestSimpleConfigurationSettingValue_SecretRedaction(t *testing.T) {
	secret := betamodels.NewDeviceManagementConfigurationSecretSettingValue()
	secret.SetValue(ptr("super-secret-value"))
	assert.Equal(t, "***", simpleConfigurationSettingValue(secret),
		"secret setting values must be masked, never returned in cleartext")

	str := betamodels.NewDeviceManagementConfigurationStringSettingValue()
	str.SetValue(ptr("plain-value"))
	assert.Equal(t, "plain-value", simpleConfigurationSettingValue(str))

	integer := betamodels.NewDeviceManagementConfigurationIntegerSettingValue()
	integer.SetValue(ptr(int32(42)))
	assert.Equal(t, int64(42), simpleConfigurationSettingValue(integer))

	assert.Nil(t, simpleConfigurationSettingValue(nil))
}

// settingsCatalogJSON is the shape GET
// /deviceManagement/configurationPolicies/{id}/settings returns: a BitLocker
// switch whose dependent options are children of the selected choice, a
// firewall rule list (a group collection with one value per rule), and a
// plain group setting holding a secret.
const settingsCatalogJSON = `{
  "value": [
    {
      "id": "0",
      "settingInstance": {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        "settingDefinitionId": "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication",
        "settingInstanceTemplateReference": null,
        "choiceSettingValue": {
          "settingValueTemplateReference": null,
          "value": "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_1",
          "children": [
            {
              "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
              "settingDefinitionId": "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmstartupkeyusagedropdown_name",
              "choiceSettingValue": {
                "value": "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmstartupkeyusagedropdown_name_0",
                "children": []
              }
            },
            {
              "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
              "settingDefinitionId": "device_vendor_msft_bitlocker_systemdrivesminimumpinlength_minpinlength",
              "simpleSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                "value": 6
              }
            }
          ]
        }
      }
    },
    {
      "id": "1",
      "settingInstance": {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}",
        "groupSettingCollectionValue": [
          {
            "children": [
              {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_name",
                "simpleSettingValue": {
                  "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                  "value": "Allow SSH"
                }
              },
              {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_direction",
                "choiceSettingValue": {
                  "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_direction_in",
                  "children": []
                }
              }
            ]
          },
          {
            "children": [
              {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_name",
                "simpleSettingValue": {
                  "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                  "value": "Block Telnet"
                }
              }
            ]
          }
        ]
      }
    },
    {
      "id": "2",
      "settingInstance": {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingInstance",
        "settingDefinitionId": "device_vendor_msft_policy_config_example_group",
        "groupSettingValue": {
          "children": [
            {
              "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
              "settingDefinitionId": "device_vendor_msft_policy_config_example_group_secret",
              "simpleSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSecretSettingValue",
                "value": "hunter2",
                "valueState": "notEncrypted"
              }
            }
          ]
        }
      }
    }
  ]
}`

func decodeSettingsCatalog(t *testing.T) []any {
	node, err := kjson.NewJsonParseNode([]byte(settingsCatalogJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(betamodels.CreateDeviceManagementConfigurationSettingCollectionResponseFromDiscriminatorValue)
	require.NoError(t, err)
	res := []any{}
	for _, s := range parsed.(betamodels.DeviceManagementConfigurationSettingCollectionResponseable).GetValue() {
		res = append(res, flattenConfigurationSetting(s.GetSettingInstance()))
	}
	return res
}

func settingChildren(t *testing.T, d any) []any {
	m, ok := d.(map[string]any)
	require.True(t, ok)
	children, ok := m["children"].([]any)
	require.True(t, ok, "every setting dict carries a children list")
	return children
}

// The options a choice unlocks are children of the selected value; the old
// flattening reported only the top-level choice and dropped them.
func TestFlattenConfigurationSetting_ChoiceChildren(t *testing.T) {
	settings := decodeSettingsCatalog(t)
	require.Len(t, settings, 3)

	bitlocker := settings[0].(map[string]any)
	assert.Equal(t, "choice", bitlocker["settingType"])
	assert.Equal(t, "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_1", bitlocker["value"])

	children := settingChildren(t, bitlocker)
	require.Len(t, children, 2)
	tpm := children[0].(map[string]any)
	assert.Equal(t, "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmstartupkeyusagedropdown_name", tpm["settingDefinitionId"])
	assert.Equal(t, "choice", tpm["settingType"])
	assert.Equal(t, "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmstartupkeyusagedropdown_name_0", tpm["value"])
	assert.Empty(t, settingChildren(t, tpm))

	pin := children[1].(map[string]any)
	assert.Equal(t, "simple", pin["settingType"])
	assert.Equal(t, int64(6), pin["value"])
}

// A group collection holds one groupInstance per configured group (one per
// firewall rule here), each carrying that instance's settings. It used to be
// reported with a null value and nothing beneath it.
func TestFlattenConfigurationSetting_GroupCollection(t *testing.T) {
	settings := decodeSettingsCatalog(t)
	rules := settings[1].(map[string]any)
	assert.Equal(t, "groupCollection", rules["settingType"])
	assert.Nil(t, rules["value"])

	instances := settingChildren(t, rules)
	require.Len(t, instances, 2)

	first := instances[0].(map[string]any)
	assert.Equal(t, "groupInstance", first["settingType"])
	assert.Equal(t, "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}", first["settingDefinitionId"])
	firstSettings := settingChildren(t, first)
	require.Len(t, firstSettings, 2)
	assert.Equal(t, "Allow SSH", firstSettings[0].(map[string]any)["value"])
	assert.Equal(t, "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_direction_in", firstSettings[1].(map[string]any)["value"])

	second := settingChildren(t, instances[1])
	require.Len(t, second, 1)
	assert.Equal(t, "Block Telnet", second[0].(map[string]any)["value"])
}

// A non-collection group setting used to fall through to "unknown". Its
// members are children, and a nested secret is still masked.
func TestFlattenConfigurationSetting_Group(t *testing.T) {
	settings := decodeSettingsCatalog(t)
	group := settings[2].(map[string]any)
	assert.Equal(t, "group", group["settingType"])

	children := settingChildren(t, group)
	require.Len(t, children, 1)
	assert.Equal(t, "***", children[0].(map[string]any)["value"])
}

// settings is a []dict field, so the nested output must convert to an llx
// primitive without "unsupported child type".
func TestFlattenConfigurationSetting_IsJSONNative(t *testing.T) {
	result := llx.ArrayData(decodeSettingsCatalog(t), types.Dict).Result()
	require.NotNil(t, result)
	assert.Empty(t, result.Error)
}
