// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/compute/v1"
)

// A rule matches either on a source IP list or on an expression, and the two
// arrive in different members of the message. Reading only one of them makes an
// allow rule that matches every client look like a rule with no condition.
func TestSecurityPolicyRuleMatcherArgsSrcIpRanges(t *testing.T) {
	args := securityPolicyRuleMatcherArgs("rule/1000", &compute.SecurityPolicyRuleMatcher{
		VersionedExpr: "SRC_IPS_V1",
		Config: &compute.SecurityPolicyRuleMatcherConfig{
			SrcIpRanges: []string{"0.0.0.0/0", "::/0"},
		},
	})

	assert.Equal(t, "SRC_IPS_V1", args["versionedExpr"].Value)
	assert.Equal(t, []any{"0.0.0.0/0", "::/0"}, args["srcIpRanges"].Value)
	assert.Equal(t, "", args["expression"].Value)
}

func TestSecurityPolicyRuleMatcherArgsExpression(t *testing.T) {
	args := securityPolicyRuleMatcherArgs("rule/1000", &compute.SecurityPolicyRuleMatcher{
		Expr: &compute.Expr{
			Expression:  "evaluatePreconfiguredExpr('sqli-v33-stable')",
			Title:       "block sqli",
			Description: "OWASP CRS SQL injection",
			Location:    "policy.rules[0]",
		},
	})

	assert.Equal(t, "evaluatePreconfiguredExpr('sqli-v33-stable')", args["expression"].Value)
	assert.Equal(t, "block sqli", args["expressionTitle"].Value)
	assert.Equal(t, "OWASP CRS SQL injection", args["expressionDescription"].Value)
	assert.Equal(t, "policy.rules[0]", args["expressionLocation"].Value)
	assert.Equal(t, "", args["versionedExpr"].Value)
	// An expression rule has no source IP list. Empty, not null: the rule was
	// read and it names no ranges.
	assert.Equal(t, []any{}, args["srcIpRanges"].Value)
}

// A matcher with neither member set must not panic and must not invent a range.
func TestSecurityPolicyRuleMatcherArgsEmpty(t *testing.T) {
	args := securityPolicyRuleMatcherArgs("rule/1000", &compute.SecurityPolicyRuleMatcher{})

	assert.Equal(t, "", args["versionedExpr"].Value)
	assert.Equal(t, "", args["expression"].Value)
	assert.Equal(t, []any{}, args["srcIpRanges"].Value)
}

// Every rule of a policy builds its own matcher, so the cache key has to carry
// the rule. Sharing one key would make every rule report the first rule's
// condition.
func TestSecurityPolicyRuleMatcherArgsScopesTheCacheKeyToTheRule(t *testing.T) {
	a := securityPolicyRuleMatcherArgs("rule/1000", &compute.SecurityPolicyRuleMatcher{})
	b := securityPolicyRuleMatcherArgs("rule/2000", &compute.SecurityPolicyRuleMatcher{})

	assert.NotEqual(t, a["__id"].Value, b["__id"].Value)
}
