// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/identitydomains"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----- rule ordering -----
//
// A sign-on policy stops at the first rule whose condition matches, so the
// order the rules are reported in is not presentation: it decides which rule
// wins. The API returns the references unordered with the position in
// `sequence`.

func TestOciPolicyRuleIDsInOrder(t *testing.T) {
	t.Run("references are ordered by sequence, not by arrival", func(t *testing.T) {
		got := ociPolicyRuleIDsInOrder([]identitydomains.PolicyRules{
			{Value: new("rule-c"), Sequence: new(3)},
			{Value: new("rule-a"), Sequence: new(1)},
			{Value: new("rule-b"), Sequence: new(2)},
		})
		assert.Equal(t, []string{"rule-a", "rule-b", "rule-c"}, got)
	})

	t.Run("a shared sequence keeps the order the API sent", func(t *testing.T) {
		// Unstable sorting here would make the reported evaluation order flip
		// between scans of an unchanged policy.
		got := ociPolicyRuleIDsInOrder([]identitydomains.PolicyRules{
			{Value: new("first"), Sequence: new(1)},
			{Value: new("second"), Sequence: new(1)},
		})
		assert.Equal(t, []string{"first", "second"}, got)
	})

	t.Run("an absent sequence sorts first rather than panicking", func(t *testing.T) {
		got := ociPolicyRuleIDsInOrder([]identitydomains.PolicyRules{
			{Value: new("sequenced"), Sequence: new(5)},
			{Value: new("unsequenced")},
		})
		assert.Equal(t, []string{"unsequenced", "sequenced"}, got)
	})

	t.Run("references with no id are dropped", func(t *testing.T) {
		got := ociPolicyRuleIDsInOrder([]identitydomains.PolicyRules{
			{Sequence: new(1)},
			{Value: new("real"), Sequence: new(2)},
		})
		assert.Equal(t, []string{"real"}, got)
	})

	t.Run("no references is an empty list", func(t *testing.T) {
		assert.Empty(t, ociPolicyRuleIDsInOrder(nil))
	})

	t.Run("the caller's slice is not reordered", func(t *testing.T) {
		// The references come off the SDK response the lister is still reading
		// from; sorting in place would reorder it underneath the caller.
		refs := []identitydomains.PolicyRules{
			{Value: new("b"), Sequence: new(2)},
			{Value: new("a"), Sequence: new(1)},
		}
		ociPolicyRuleIDsInOrder(refs)
		assert.Equal(t, "b", *refs[0].Value)
	})
}

// ----- rule outcomes -----

func TestOciRuleReturns(t *testing.T) {
	t.Run("name and value pairs become a map", func(t *testing.T) {
		got := ociRuleReturns([]identitydomains.RuleReturn{
			{Name: new("effect"), Value: new("ALLOW")},
			{Name: new("authenticationFactor"), Value: new("PUSH")},
		})
		assert.Equal(t, map[string]any{
			"effect":               "ALLOW",
			"authenticationFactor": "PUSH",
		}, got)
	})

	t.Run("a deny is carried through as a deny", func(t *testing.T) {
		got := ociRuleReturns([]identitydomains.RuleReturn{
			{Name: new("effect"), Value: new("DENY")},
		})
		assert.Equal(t, "DENY", got["effect"])
	})

	t.Run("an entry with no name is skipped", func(t *testing.T) {
		// An empty key would be indistinguishable from a lookup miss, so a
		// query reading returns[""] would get a value that means nothing.
		got := ociRuleReturns([]identitydomains.RuleReturn{
			{Value: new("orphan")},
			{Name: new("effect"), Value: new("ALLOW")},
		})
		assert.Len(t, got, 1)
		assert.Equal(t, "ALLOW", got["effect"])
	})

	t.Run("no returns is an empty map, not null", func(t *testing.T) {
		assert.Equal(t, map[string]any{}, ociRuleReturns(nil))
	})
}

// ----- what a rule matches on -----

func TestOciRuleConditionGroup(t *testing.T) {
	t.Run("a single condition is resolvable", func(t *testing.T) {
		groupType, name, id := ociRuleConditionGroup(&identitydomains.RuleConditionGroup{
			Type:  identitydomains.RuleConditionGroupTypeCondition,
			Value: new("cond-1"),
			Name:  new("From corporate network"),
		})
		assert.Equal(t, "Condition", groupType)
		assert.Equal(t, "From corporate network", name)
		assert.Equal(t, "cond-1", id)
	})

	t.Run("a condition group is named but not resolved", func(t *testing.T) {
		// There is no list API for condition groups, so resolving a group id
		// against the condition collection would find nothing and render as a
		// rule that matches on nothing at all.
		groupType, name, id := ociRuleConditionGroup(&identitydomains.RuleConditionGroup{
			Type:  identitydomains.RuleConditionGroupTypeConditiongroup,
			Value: new("group-1"),
			Name:  new("Off-network or unmanaged"),
		})
		assert.Equal(t, "ConditionGroup", groupType)
		assert.Equal(t, "Off-network or unmanaged", name)
		assert.Empty(t, id, "a condition group id must not be resolved as a condition")
	})

	t.Run("no condition group at all", func(t *testing.T) {
		groupType, name, id := ociRuleConditionGroup(nil)
		assert.Empty(t, groupType)
		assert.Empty(t, name)
		assert.Empty(t, id)
	})
}

func TestOciRuleConditionGroupTypeCoverage(t *testing.T) {
	// ociRuleConditionGroup resolves only the Condition member and reports
	// every other one by name alone. A third member added by an SDK upgrade
	// would silently fall into the unresolved branch, so it is pinned here.
	handled := map[string]bool{
		"Condition":      true,
		"ConditionGroup": true,
	}

	values := identitydomains.GetRuleConditionGroupTypeEnumStringValues()
	require.NotEmpty(t, values, "the SDK enum helper returned nothing; the drift check would pass vacuously")

	for _, value := range values {
		assert.Truef(t, handled[value],
			"identitydomains.RuleConditionGroupType %q is not accounted for by ociRuleConditionGroup", value)
	}
}
