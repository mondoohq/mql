// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/orgpolicy/apiv2/orgpolicypb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	expr "google.golang.org/genproto/googleapis/type/expr"
)

func TestExtractConstraintName(t *testing.T) {
	t.Run("organization policy path", func(t *testing.T) {
		result := extractConstraintName("organizations/123456/policies/compute.disableSerialPortAccess")
		assert.Equal(t, "compute.disableSerialPortAccess", result)
	})

	t.Run("project policy path", func(t *testing.T) {
		result := extractConstraintName("projects/my-project/policies/iam.allowedPolicyMemberDomains")
		assert.Equal(t, "iam.allowedPolicyMemberDomains", result)
	})

	t.Run("folder policy path", func(t *testing.T) {
		result := extractConstraintName("folders/987654/policies/storage.uniformBucketLevelAccess")
		assert.Equal(t, "storage.uniformBucketLevelAccess", result)
	})

	t.Run("no policies segment returns full name", func(t *testing.T) {
		result := extractConstraintName("compute.disableSerialPortAccess")
		assert.Equal(t, "compute.disableSerialPortAccess", result)
	})

	t.Run("empty string", func(t *testing.T) {
		result := extractConstraintName("")
		assert.Equal(t, "", result)
	})

	t.Run("path ending with /policies/ returns empty constraint", func(t *testing.T) {
		result := extractConstraintName("organizations/123/policies/")
		assert.Equal(t, "", result)
	})

	t.Run("uses last occurrence of /policies/", func(t *testing.T) {
		result := extractConstraintName("organizations/123/policies/nested/policies/actual.constraint")
		assert.Equal(t, "actual.constraint", result)
	})
}

// TestInterpretPolicySpecConditionalRules pins the behavior that used to be the
// bug: a rule carrying a CEL condition was dropped on the floor, so a
// constraint enforced only for tagged resources produced the same all-false
// summary as a constraint with no policy at all.
func TestInterpretPolicySpecConditionalRules(t *testing.T) {
	conditionalEnforce := &orgpolicypb.PolicySpec_PolicyRule{
		Kind: &orgpolicypb.PolicySpec_PolicyRule_Enforce{Enforce: true},
		Condition: &expr.Expr{
			Expression:  "resource.matchTag('123456789/env', 'prod')",
			Title:       "prod only",
			Description: "enforced for production resources",
		},
	}
	unconditionalEnforce := &orgpolicypb.PolicySpec_PolicyRule{
		Kind: &orgpolicypb.PolicySpec_PolicyRule_Enforce{Enforce: true},
	}

	t.Run("nil spec is the empty summary", func(t *testing.T) {
		summary := interpretPolicySpec(nil)
		assert.False(t, summary.enforced)
		assert.False(t, summary.hasConditionalRules)
		assert.Empty(t, summary.conditionalRules)
		assert.NotNil(t, summary.conditionalRules)
		assert.NotNil(t, summary.allowedValues)
		assert.NotNil(t, summary.deniedValues)
	})

	t.Run("no rules at all", func(t *testing.T) {
		summary := interpretPolicySpec(&orgpolicypb.PolicySpec{})
		assert.False(t, summary.enforced)
		assert.False(t, summary.hasConditionalRules)
		assert.Empty(t, summary.conditionalRules)
	})

	t.Run("all-conditional policy is distinguishable from no policy", func(t *testing.T) {
		summary := interpretPolicySpec(&orgpolicypb.PolicySpec{
			Rules: []*orgpolicypb.PolicySpec_PolicyRule{conditionalEnforce},
		})
		// The scalar summary is unchanged: a conditional rule still does not
		// count as unconditional enforcement.
		assert.False(t, summary.enforced)
		assert.False(t, summary.allowAll)
		assert.False(t, summary.denyAll)
		// ... but the rule is now visible, which is the whole point.
		assert.True(t, summary.hasConditionalRules)
		require.Len(t, summary.conditionalRules, 1)

		rule, ok := summary.conditionalRules[0].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "resource.matchTag('123456789/env', 'prod')", rule["condition"])
		assert.Equal(t, "prod only", rule["conditionTitle"])
		assert.Equal(t, "enforced for production resources", rule["conditionDescription"])
		assert.Equal(t, true, rule["enforce"])
		assert.Equal(t, false, rule["allowAll"])
		assert.Equal(t, false, rule["denyAll"])
		assert.Equal(t, []any{}, rule["allowedValues"])
		assert.Equal(t, []any{}, rule["deniedValues"])
	})

	t.Run("unconditional rules keep their shipped meaning", func(t *testing.T) {
		summary := interpretPolicySpec(&orgpolicypb.PolicySpec{
			Rules: []*orgpolicypb.PolicySpec_PolicyRule{unconditionalEnforce},
		})
		assert.True(t, summary.enforced)
		assert.False(t, summary.hasConditionalRules)
		assert.Empty(t, summary.conditionalRules)
	})

	t.Run("mixed spec reports both", func(t *testing.T) {
		summary := interpretPolicySpec(&orgpolicypb.PolicySpec{
			InheritFromParent: true,
			Rules: []*orgpolicypb.PolicySpec_PolicyRule{
				unconditionalEnforce,
				conditionalEnforce,
			},
		})
		assert.True(t, summary.enforced)
		assert.True(t, summary.inheritFromParent)
		assert.True(t, summary.hasConditionalRules)
		assert.Len(t, summary.conditionalRules, 1)
	})

	t.Run("conditional list rule carries its values", func(t *testing.T) {
		summary := interpretPolicySpec(&orgpolicypb.PolicySpec{
			Rules: []*orgpolicypb.PolicySpec_PolicyRule{
				{
					Kind: &orgpolicypb.PolicySpec_PolicyRule_Values{
						Values: &orgpolicypb.PolicySpec_PolicyRule_StringValues{
							AllowedValues: []string{"projects/allowed"},
							DeniedValues:  []string{"projects/denied"},
						},
					},
					Condition: &expr.Expr{Expression: "resource.matchTagId('tagKeys/1', 'tagValues/2')"},
				},
			},
		})
		// The conditional values must NOT leak into the unconditional lists.
		assert.Empty(t, summary.allowedValues)
		assert.Empty(t, summary.deniedValues)
		require.Len(t, summary.conditionalRules, 1)
		rule := summary.conditionalRules[0].(map[string]any)
		assert.Equal(t, []any{"projects/allowed"}, rule["allowedValues"])
		assert.Equal(t, []any{"projects/denied"}, rule["deniedValues"])
		assert.Equal(t, "", rule["conditionTitle"])
	})

	t.Run("conditional allowAll and denyAll", func(t *testing.T) {
		summary := interpretPolicySpec(&orgpolicypb.PolicySpec{
			Rules: []*orgpolicypb.PolicySpec_PolicyRule{
				{
					Kind:      &orgpolicypb.PolicySpec_PolicyRule_AllowAll{AllowAll: true},
					Condition: &expr.Expr{Expression: "resource.matchTag('1/a', 'b')"},
				},
				{
					Kind:      &orgpolicypb.PolicySpec_PolicyRule_DenyAll{DenyAll: true},
					Condition: &expr.Expr{Expression: "resource.matchTag('1/c', 'd')"},
				},
			},
		})
		assert.False(t, summary.allowAll)
		assert.False(t, summary.denyAll)
		assert.True(t, summary.hasConditionalRules)
		require.Len(t, summary.conditionalRules, 2)
		assert.Equal(t, true, summary.conditionalRules[0].(map[string]any)["allowAll"])
		assert.Equal(t, true, summary.conditionalRules[1].(map[string]any)["denyAll"])
	})
}
