// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfigComplianceDetailID(t *testing.T) {
	recorded := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name               string
		ruleArn            string
		resourceType       string
		resourceID         string
		resultRecordedTime *time.Time
		expected           string
	}{
		{
			name:               "recorded time present",
			ruleArn:            "arn:aws:config:us-east-1:000000000000:config-rule/config-rule-abcdef",
			resourceType:       "AWS::EC2::Instance",
			resourceID:         "i-0123456789abcdef0",
			resultRecordedTime: &recorded,
			expected:           "arn:aws:config:us-east-1:000000000000:config-rule/config-rule-abcdef/complianceDetail/AWS::EC2::Instance/i-0123456789abcdef0/1787140800000000000",
		},
		{
			// GetComplianceDetailsByConfigRule leaves ResultRecordedTime unset for
			// an evaluation that has not been recorded yet. Reading it must not
			// panic, and the key must stay stable across calls.
			name:               "recorded time absent",
			ruleArn:            "arn:aws:config:us-east-1:000000000000:config-rule/config-rule-abcdef",
			resourceType:       "AWS::EC2::Instance",
			resourceID:         "i-0123456789abcdef0",
			resultRecordedTime: nil,
			expected:           "arn:aws:config:us-east-1:000000000000:config-rule/config-rule-abcdef/complianceDetail/AWS::EC2::Instance/i-0123456789abcdef0/0",
		},
		{
			// The evaluation result identifier is optional too, so both the type
			// and the id can reach the key empty.
			name:               "resource type and id absent",
			ruleArn:            "arn:aws:config:us-east-1:000000000000:config-rule/config-rule-abcdef",
			resourceType:       "",
			resourceID:         "",
			resultRecordedTime: nil,
			expected:           "arn:aws:config:us-east-1:000000000000:config-rule/config-rule-abcdef/complianceDetail///0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected,
				configComplianceDetailID(test.ruleArn, test.resourceType, test.resourceID, test.resultRecordedTime))
		})
	}
}

func TestConfigComplianceDetailIDIsDistinctPerResource(t *testing.T) {
	// Two resources evaluated by the same rule with no recorded time must still
	// land on different cache keys, or one would overwrite the other.
	arn := "arn:aws:config:us-east-1:000000000000:config-rule/config-rule-abcdef"
	first := configComplianceDetailID(arn, "AWS::EC2::Instance", "i-aaaaaaaaaaaaaaaaa", nil)
	second := configComplianceDetailID(arn, "AWS::EC2::Instance", "i-bbbbbbbbbbbbbbbbb", nil)
	assert.NotEqual(t, first, second)
}
