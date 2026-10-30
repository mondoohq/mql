// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVpcFlowLogCacheKey(t *testing.T) {
	t.Run("two flow logs on one vpc get distinct keys", func(t *testing.T) {
		// The bug this guards: both creators omitted "__id", so every flow log
		// keyed on "" and a VPC logging ALL and a VPC logging REJECT reported
		// identical rows.
		all := vpcFlowLogCacheKey("us-west-2", "fl-05570b926e84de4a6")
		reject := vpcFlowLogCacheKey("us-west-2", "fl-0ff770bdab6b32b86")
		assert.NotEqual(t, all, reject)
		assert.NotEmpty(t, all)
		assert.NotEmpty(t, reject)
	})

	t.Run("same flow log from vpc and subnet paths agrees", func(t *testing.T) {
		// vpc.flowLogs() and subnet.flowLogs() must produce the same key so the
		// runtime cache dedupes rather than building two instances.
		assert.Equal(t,
			vpcFlowLogCacheKey("eu-west-1", "fl-abc123"),
			vpcFlowLogCacheKey("eu-west-1", "fl-abc123"),
		)
	})

	t.Run("region qualifies the key", func(t *testing.T) {
		assert.NotEqual(t,
			vpcFlowLogCacheKey("us-west-2", "fl-abc123"),
			vpcFlowLogCacheKey("us-east-1", "fl-abc123"),
		)
	})

	t.Run("an empty flow log id still yields a region-scoped key", func(t *testing.T) {
		assert.Equal(t, "us-west-2/", vpcFlowLogCacheKey("us-west-2", ""))
	})
}

func TestRdsParameterGroupMatches(t *testing.T) {
	const (
		arn  = "arn:aws:rds:us-west-2:123456789012:pg:default.mysql8.0"
		name = "default.mysql8.0"
	)

	for _, tc := range []struct {
		title             string
		gotArn, gotName   string
		wantArn, wantName string
		expected          bool
	}{
		{"arn matches", arn, name, arn, "", true},
		{"arn mismatch", arn, name, "arn:aws:rds:us-west-2:123456789012:pg:other", "", false},
		{"name matches", arn, name, "", name, true},
		{"name mismatch", arn, name, "", "default.postgres16", false},
		// The live bug: asking for default.postgres16 returned default.mysql8.0.
		// A name-only lookup must never be satisfied by a different group.
		{"name-only lookup ignores a matching arn field", arn, name, "", "default.postgres16", false},
		// An arn was supplied, so the name is not consulted -- otherwise a stale
		// arn would silently fall back to a name match.
		{"arn takes precedence over name", arn, name, "arn:aws:rds:us-west-2:123456789012:pg:other", name, false},
		{"empty wanted values never match", arn, name, "", "", false},
		{"empty wanted values never match an empty group", "", "", "", "", false},
	} {
		t.Run(tc.title, func(t *testing.T) {
			assert.Equal(t, tc.expected,
				rdsParameterGroupMatches(tc.gotArn, tc.gotName, tc.wantArn, tc.wantName))
		})
	}
}

func TestRdsParameterGroupWanted(t *testing.T) {
	assert.Equal(t, `arn "arn:aws:rds:us-west-2:1:pg:x"`, rdsParameterGroupWanted("arn:aws:rds:us-west-2:1:pg:x", "x"))
	assert.Equal(t, `name "default.mysql8.0"`, rdsParameterGroupWanted("", "default.mysql8.0"))
}
