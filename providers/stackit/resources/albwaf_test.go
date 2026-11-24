// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	albwaf "github.com/stackitcloud/stackit-sdk-go/services/albwaf/v1api"
)

// TestCustomRuleBehavior pins the custom rule mapping after the move from the
// v1beta to the v1 WAF API, which renamed the rule's "behaviour" block to
// "behavior". The action, log flag, log message and severity must read the
// same values the v1beta mapping produced, and an unset log message reads "".
func TestCustomRuleBehavior(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    customRuleFields
	}{
		{
			// Synthetic: a deny rule with every behavior field set; no live account was checked.
			name: "all fields",
			payload: `{"id": 7, "description": "block admin", "conditions": [],
				"behavior": {"action": "ACTION_DENY", "log": true, "logMsg": "admin probe", "severity": "SEVERITY_CRITICAL"}}`,
			want: customRuleFields{action: "ACTION_DENY", log: true, logMsg: "admin probe", severity: "SEVERITY_CRITICAL"},
		},
		{
			// Synthetic: an allow rule without a log message; no live account was checked.
			name: "no log message",
			payload: `{"id": 8, "conditions": [],
				"behavior": {"action": "ACTION_ALLOW", "log": false, "severity": "SEVERITY_INFO"}}`,
			want: customRuleFields{action: "ACTION_ALLOW", log: false, logMsg: "", severity: "SEVERITY_INFO"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rule albwaf.GetCustomRule
			if err := json.Unmarshal([]byte(tt.payload), &rule); err != nil {
				t.Fatalf("decoding rule: %v", err)
			}
			if got := customRuleBehavior(&rule); got != tt.want {
				t.Fatalf("behavior = %+v, want %+v", got, tt.want)
			}
		})
	}
}
