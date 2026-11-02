// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func logAccountPolicy(policyType, region, name string) *mqlAwsCloudwatchLogAccountPolicy {
	return &mqlAwsCloudwatchLogAccountPolicy{
		PolicyType: plugin.TValue[string]{Data: policyType, State: plugin.StateIsSet},
		Region:     plugin.TValue[string]{Data: region, State: plugin.StateIsSet},
		PolicyName: plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
	}
}

// Synthetic: account policies of several types and regions sharing one name; no
// account in this test had a retention policy.
func TestIsRetentionPolicyFor(t *testing.T) {
	assert.True(t, isRetentionPolicyFor(logAccountPolicy("RETENTION_POLICY", "us-east-1", "org"), "us-east-1", "org"))

	// Account policies are regional, so the same name in another region is a
	// different policy.
	assert.False(t, isRetentionPolicyFor(logAccountPolicy("RETENTION_POLICY", "eu-west-1", "org"), "us-east-1", "org"))
	// Policy names are only unique within a type.
	assert.False(t, isRetentionPolicyFor(logAccountPolicy("DATA_PROTECTION_POLICY", "us-east-1", "org"), "us-east-1", "org"))
	assert.False(t, isRetentionPolicyFor(logAccountPolicy("RETENTION_POLICY", "us-east-1", "other"), "us-east-1", "org"))
}
