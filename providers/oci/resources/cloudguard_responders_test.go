// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/cloudguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// A responder rule identifier is a name, not an OCID, so the same one appears
// in the Oracle-managed recipe and in every customer clone of it. Keying a rule
// on that alone makes the clones collide, and CreateResource answers a repeated
// id with the cached first instance - so a clone with the responder switched
// off would report the original's enabled state.
func TestOciCloudGuardResponderRuleIDSeparatesRecipes(t *testing.T) {
	oracle := ociCloudGuardResponderRuleID("ocid1.responderrecipe.oc1..oracle", "SIMPLE_QUARANTINE")
	clone := ociCloudGuardResponderRuleID("ocid1.responderrecipe.oc1..clone", "SIMPLE_QUARANTINE")

	assert.NotEqual(t, oracle, clone)
	assert.Equal(t, "ocid1.responderrecipe.oc1..oracle/SIMPLE_QUARANTINE", oracle)
}

func TestOciCloudGuardResponderRuleIDSeparatesRulesInOneRecipe(t *testing.T) {
	recipe := "ocid1.responderrecipe.oc1..a"

	assert.NotEqual(t,
		ociCloudGuardResponderRuleID(recipe, "SIMPLE_QUARANTINE"),
		ociCloudGuardResponderRuleID(recipe, "DISABLE_USER"),
	)
}

// The same setting key (a notification topic, a retry count) is exposed by
// several rules, so the key has to carry the rule and the recipe as well.
func TestOciCloudGuardResponderSettingIDSeparatesRules(t *testing.T) {
	recipe := "ocid1.responderrecipe.oc1..a"

	assert.NotEqual(t,
		ociCloudGuardResponderSettingID(recipe, "SIMPLE_QUARANTINE", "topicId"),
		ociCloudGuardResponderSettingID(recipe, "DISABLE_USER", "topicId"),
	)
	assert.NotEqual(t,
		ociCloudGuardResponderSettingID(recipe, "SIMPLE_QUARANTINE", "topicId"),
		ociCloudGuardResponderSettingID("ocid1.responderrecipe.oc1..b", "SIMPLE_QUARANTINE", "topicId"),
	)
}

func TestOciCloudGuardResponderActivityIDSeparatesProblems(t *testing.T) {
	assert.NotEqual(t,
		ociCloudGuardResponderActivityID("ocid1.cloudguardproblem.oc1..a", "activity-1"),
		ociCloudGuardResponderActivityID("ocid1.cloudguardproblem.oc1..b", "activity-1"),
	)
}

// The detail block is optional on the rule summary, and it is where every
// field that decides whether the responder acts lives. An absent block has to
// read as "not enabled" rather than as null: a null would leave an assertion
// over the rule with nothing to fail on, so a rule nobody could read would
// pass a check asking whether remediation is configured.
func TestOciCloudGuardResponderRuleExecution(t *testing.T) {
	enabled := true
	disabled := false

	tests := []struct {
		name          string
		details       *cloudguard.ResponderRuleDetails
		wantEnabled   bool
		wantExecution string
	}{
		{
			name:          "absent detail block",
			details:       nil,
			wantEnabled:   false,
			wantExecution: "",
		},
		{
			name: "auto-executing responder",
			details: &cloudguard.ResponderRuleDetails{
				IsEnabled: &enabled,
				Mode:      cloudguard.ResponderModeTypesAutoaction,
			},
			wantEnabled:   true,
			wantExecution: "AUTOACTION",
		},
		{
			// The distinction the resource exists for: enabled, but it never
			// acts until an operator confirms.
			name: "enabled but waiting on an operator",
			details: &cloudguard.ResponderRuleDetails{
				IsEnabled: &enabled,
				Mode:      cloudguard.ResponderModeTypesUseraction,
			},
			wantEnabled:   true,
			wantExecution: "USERACTION",
		},
		{
			name: "switched off",
			details: &cloudguard.ResponderRuleDetails{
				IsEnabled: &disabled,
				Mode:      cloudguard.ResponderModeTypesAutoaction,
			},
			wantEnabled:   false,
			wantExecution: "AUTOACTION",
		},
		{
			// isEnabled is mandatory on the wire but arrives as a pointer, so
			// a payload omitting it must not read as enabled.
			name:          "detail block with no enabled flag",
			details:       &cloudguard.ResponderRuleDetails{Mode: cloudguard.ResponderModeTypesAutoaction},
			wantEnabled:   false,
			wantExecution: "AUTOACTION",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEnabled, gotMode := ociCloudGuardResponderRuleExecution(tt.details)
			assert.Equal(t, tt.wantEnabled, gotEnabled)
			assert.Equal(t, tt.wantExecution, gotMode)
		})
	}
}

// The responder rule payload decodes through a hand-written UnmarshalJSON in
// the SDK, because `condition` is polymorphic: the concrete type is chosen from
// the `kind` discriminator and the result is an interface, not a struct. If
// that decode yields nothing the rule still resolves and every execution field
// reads as though the rule were unconfigured, with no error anywhere.
//
// Payload shaped after the ListResponderRecipeResponderRules response.
func TestOciCloudGuardResponderRuleSummaryDecode(t *testing.T) {
	payload := []byte(`{
		"id": "SIMPLE_QUARANTINE",
		"compartmentId": "ocid1.compartment.oc1..aaaa",
		"displayName": "Quarantine the instance",
		"description": "Isolates a compute instance from the network",
		"type": "REMEDIATION",
		"policies": ["Allow service cloudguard to use instances in tenancy"],
		"supportedModes": ["AUTOACTION", "USERACTION"],
		"lifecycleState": "ACTIVE",
		"details": {
			"isEnabled": true,
			"mode": "USERACTION",
			"configurations": [
				{"configKey": "topicId", "name": "Notification topic", "value": "ocid1.onstopic.oc1..bbbb"}
			],
			"condition": {
				"kind": "COMPOSITE",
				"compositeOperator": "AND",
				"leftOperand": {"kind": "SIMPLE", "parameter": "region", "operator": "EQUALS", "value": "us-ashburn-1", "valueType": "MANAGED"},
				"rightOperand": {"kind": "SIMPLE", "parameter": "resourceType", "operator": "EQUALS", "value": "Instance", "valueType": "MANAGED"}
			}
		}
	}`)

	var rule cloudguard.ResponderRecipeResponderRuleSummary
	require.NoError(t, json.Unmarshal(payload, &rule))

	require.NotNil(t, rule.Details)
	isEnabled, mode := ociCloudGuardResponderRuleExecution(rule.Details)
	assert.True(t, isEnabled)
	assert.Equal(t, "USERACTION", mode)
	assert.Equal(t, cloudguard.ResponderTypeRemediation, rule.Type)
	assert.Equal(t, []string{"Allow service cloudguard to use instances in tenancy"}, rule.Policies)
	require.Len(t, rule.SupportedModes, 2)
	require.Len(t, rule.Details.Configurations, 1)
	assert.Equal(t, "ocid1.onstopic.oc1..bbbb", stringValue(rule.Details.Configurations[0].Value))

	// The polymorphic arm: the condition has to survive into the dict the
	// schema exposes, rather than flattening to an empty value.
	require.NotNil(t, rule.Details.Condition)
	condition, err := convert.JsonToDict(rule.Details.Condition)
	require.NoError(t, err)
	require.NotEmpty(t, condition, "the polymorphic condition flattened to nothing")
	assert.Equal(t, "AND", condition["compositeOperator"])
	assert.NotNil(t, condition["leftOperand"])
	assert.NotNil(t, condition["rightOperand"])
}

// A rule the service reports without a detail block. The whole record still has
// to decode: an error here would take the recipe's entire rule list down.
func TestOciCloudGuardResponderRuleSummaryDecodeWithoutDetails(t *testing.T) {
	var rule cloudguard.ResponderRecipeResponderRuleSummary
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "SIMPLE_QUARANTINE",
		"compartmentId": "ocid1.compartment.oc1..aaaa",
		"lifecycleState": "ACTIVE"
	}`), &rule))

	assert.Nil(t, rule.Details)
	isEnabled, mode := ociCloudGuardResponderRuleExecution(rule.Details)
	assert.False(t, isEnabled)
	assert.Empty(t, mode)
}
