// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The rule shapes below follow what Get-DlpComplianceRule returns through
// ConvertTo-Json: a simple rule lists its sensitive information types in
// ContentContainsSensitiveInformation, an advanced rule leaves that property
// null and carries its conditions as a JSON string in AdvancedRule.
func TestDlpRuleSensitiveInfoTypes(t *testing.T) {
	tests := []struct {
		name string
		rule string
		want []any
	}{
		{
			name: "simple rule",
			rule: `{
				"Name": "Items containing credit card numbers shared externally",
				"IsAdvancedRule": false,
				"ContentContainsSensitiveInformation": [
					{"maxconfidence": "100", "mincount": "1", "confidencelevel": "High",
					 "id": "50842eb7-edc8-4019-85dd-5a5c1f2bb085", "name": "Credit Card Number",
					 "maxcount": "9", "minconfidence": "85", "classifiertype": "Content"},
					{"mincount": "1", "id": "a44669fe-0d48-453d-a9b1-2cc83f2cba77",
					 "name": "U.S. Social Security Number (SSN)", "classifiertype": "Content"}
				]
			}`,
			want: []any{"Credit Card Number", "U.S. Social Security Number (SSN)"},
		},
		{
			name: "grouped condition does not report group or label names",
			rule: `{
				"Name": "grouped",
				"ContentContainsSensitiveInformation": [
					{"operator": "And", "groups": [
						{"operator": "Or", "name": "Default",
						 "sensitivetypes": [{"name": "Credit Card Number", "mincount": 1}],
						 "labels": [{"name": "Confidential", "type": "Sensitivity"}]},
						{"operator": "Or", "name": "Banking",
						 "sensitivetypes": [{"name": "ABA Routing Number"}]}
					]}
				]
			}`,
			want: []any{"ABA Routing Number", "Credit Card Number"},
		},
		{
			name: "advanced rule reads the AdvancedRule document",
			rule: `{
				"Name": "Content matches U.S HIPAA Enhanced Default Rule",
				"IsAdvancedRule": true,
				"ContentContainsSensitiveInformation": null,
				"AdvancedRule": "{\r\n  \"Version\": \"1.0\",\r\n  \"Condition\": {\"Operator\": \"And\", \"SubConditions\": [{\"ConditionName\": \"ContentContainsSensitiveInformation\", \"Value\": [{\"Groups\": [{\"Name\": \"PII Identifiers\", \"Operator\": \"Or\", \"Sensitivetypes\": [{\"Name\": \"U.S. Social Security Number (SSN)\", \"Id\": \"a44669fe-0d48-453d-a9b1-2cc83f2cba77\", \"Mincount\": 1, \"Maxcount\": -1, \"Confidencelevel\": \"Medium\"}, {\"Name\": \"Drug Enforcement Agency (DEA) Number\", \"Id\": \"9a5445ad-406e-43eb-8bd7-cac17ab6d0e4\"}]}, {\"Name\": \"Trainable Classifiers\", \"Operator\": \"Or\", \"Sensitivetypes\": [{\"Name\": \"dcbada08-65bf-4561-b140-25d8fee4d143\", \"Id\": \"dcbada08-65bf-4561-b140-25d8fee4d143\", \"Classifiertype\": \"MLModel\"}]}], \"Operator\": \"And\"}]}]}\r\n}"
			}`,
			want: []any{"Drug Enforcement Agency (DEA) Number", "U.S. Social Security Number (SSN)"},
		},
		{
			name: "advanced rule with the condition nested under another operator",
			rule: `{
				"Name": "nested",
				"IsAdvancedRule": true,
				"AdvancedRule": "{\"Version\": \"1.0\", \"Condition\": {\"Operator\": \"And\", \"SubConditions\": [{\"ConditionName\": \"AccessScope\", \"Value\": \"NotInOrganization\"}, {\"Operator\": \"Or\", \"SubConditions\": [{\"ConditionName\": \"ContentContainsSensitiveInformation\", \"Value\": [{\"id\": \"50842eb7-edc8-4019-85dd-5a5c1f2bb085\", \"name\": \"Credit Card Number\"}]}]}]}}"
			}`,
			want: []any{"Credit Card Number"},
		},
		{
			name: "advanced rule with only trainable classifiers",
			rule: `{
				"Name": "Content Contains Intellectual Property",
				"IsAdvancedRule": true,
				"AdvancedRule": "{\"Version\": \"1.0\", \"Condition\": {\"Operator\": \"And\", \"SubConditions\": [{\"ConditionName\": \"ContentContainsSensitiveInformation\", \"Value\": [{\"Groups\": [{\"Name\": \"Default\", \"Operator\": \"Or\", \"Sensitivetypes\": [{\"Name\": \"495fad07-d6e4-4da4-9c64-5b9b109a5f59\", \"Id\": \"495fad07-d6e4-4da4-9c64-5b9b109a5f59\", \"Classifiertype\": \"MLModel\"}]}], \"Operator\": \"And\"}]}]}}"
			}`,
			want: []any{},
		},
		{
			name: "same type in both sources is reported once",
			rule: `{
				"Name": "both",
				"ContentContainsSensitiveInformation": [{"name": "Credit Card Number"}],
				"AdvancedRule": "{\"Condition\": {\"SubConditions\": [{\"ConditionName\": \"ContentContainsSensitiveInformation\", \"Value\": [{\"name\": \"Credit Card Number\"}]}]}}"
			}`,
			want: []any{"Credit Card Number"},
		},
		{
			name: "single entry serialized without a list",
			rule: `{"Name": "single", "ContentContainsSensitiveInformation": {"name": "Credit Card Number"}}`,
			want: []any{"Credit Card Number"},
		},
		{
			name: "unparseable advanced rule leaves the simple condition",
			rule: `{"Name": "broken", "ContentContainsSensitiveInformation": [{"name": "Credit Card Number"}], "AdvancedRule": "{not json"}`,
			want: []any{"Credit Card Number"},
		},
		{
			name: "rule without a sensitive information condition",
			rule: `{"Name": "none", "ContentContainsSensitiveInformation": null, "AdvancedRule": "{\"Condition\": {\"SubConditions\": [{\"ConditionName\": \"AccessScope\", \"Value\": \"NotInOrganization\"}]}}"}`,
			want: []any{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var rule map[string]any
			require.NoError(t, json.Unmarshal([]byte(tc.rule), &rule))
			assert.Equal(t, tc.want, dlpRuleSensitiveInfoTypes(rule))
		})
	}
}
