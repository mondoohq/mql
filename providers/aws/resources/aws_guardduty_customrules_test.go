// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func testCustomDetectionRule(ruleID, region, name string) *mqlAwsGuarddutyCustomDetectionRule {
	rule := &mqlAwsGuarddutyCustomDetectionRule{}
	rule.RuleId = plugin.TValue[string]{Data: ruleID, State: plugin.StateIsSet}
	rule.Region = plugin.TValue[string]{Data: region, State: plugin.StateIsSet}
	rule.Name = plugin.TValue[string]{Data: name, State: plugin.StateIsSet}
	return rule
}

// The rules API is regional, so the same rule id is a different rule in a
// different region. Matching on the id alone would attach a rollout to
// whichever region happened to be listed first, misreporting which rule an
// organization rollout applies.
func TestFindCustomDetectionRule_RegionScoped(t *testing.T) {
	rules := []any{
		testCustomDetectionRule("rule-1", "us-east-1", "east rule"),
		testCustomDetectionRule("rule-1", "eu-west-1", "west rule"),
		testCustomDetectionRule("rule-2", "us-east-1", "other east rule"),
	}

	east := findCustomDetectionRule(rules, "us-east-1", "rule-1")
	require.NotNil(t, east)
	assert.Equal(t, "east rule", east.Name.Data)

	west := findCustomDetectionRule(rules, "eu-west-1", "rule-1")
	require.NotNil(t, west)
	assert.Equal(t, "west rule", west.Name.Data)
}

// A rollout naming a rule that is no longer in the region must resolve to
// nothing, so the accessor marks the field null. Falling back to any rule
// would report a rollout as applying a rule it does not apply.
func TestFindCustomDetectionRule_NoMatch(t *testing.T) {
	rules := []any{
		testCustomDetectionRule("rule-1", "us-east-1", "east rule"),
	}

	assert.Nil(t, findCustomDetectionRule(rules, "ap-south-1", "rule-1"), "wrong region must not match")
	assert.Nil(t, findCustomDetectionRule(rules, "us-east-1", "rule-9"), "unknown rule id must not match")
	assert.Nil(t, findCustomDetectionRule(rules, "us-east-1", ""), "empty rule id must not match")
	assert.Nil(t, findCustomDetectionRule(nil, "us-east-1", "rule-1"), "empty rule list must not match")
}

// A rule that has both a LIVE and a DRY_RUN rollout in the same region is two
// rollouts, and DRY_RUN raises no findings while LIVE does. A key that drops
// the mode collapses them, so CreateResource returns the cached first one and
// the account's real detection coverage is reported as whichever arrived
// first.
func TestGuarddutyOrgConfigCacheID_ModeAndRegionDistinct(t *testing.T) {
	live := guarddutyOrgConfigCacheID("us-east-1", "rule-1", "LIVE")
	dryRun := guarddutyOrgConfigCacheID("us-east-1", "rule-1", "DRY_RUN")
	assert.NotEqual(t, live, dryRun)

	otherRegion := guarddutyOrgConfigCacheID("eu-west-1", "rule-1", "LIVE")
	assert.NotEqual(t, live, otherRegion)

	otherRule := guarddutyOrgConfigCacheID("us-east-1", "rule-2", "LIVE")
	assert.NotEqual(t, live, otherRule)
}
