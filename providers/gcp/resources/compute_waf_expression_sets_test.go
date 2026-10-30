// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	compute "google.golang.org/api/compute/v1"
)

// Sensitivity is the ModSecurity paranoia level and is the reason this resource
// is worth reading: a policy running a set at level 1 catches far less than the
// same set at level 3. Dropping it would leave the expressions
// indistinguishable from a bare ID list.
func TestWafExpressionSetExpressionArgs(t *testing.T) {
	args := wafExpressionSetExpressionArgs("proj-1/wafExpressionSet/sqli-v33-stable",
		&compute.WafExpressionSetExpression{Id: "owasp-crs-v030301-id942100-sqli", Sensitivity: 3})

	assert.Equal(t, "owasp-crs-v030301-id942100-sqli", args["id"].Value)
	assert.EqualValues(t, 3, args["sensitivity"].Value)
}

// A sensitivity of 0 marks an expression applied only when a rule opts into it
// by name. It is a real level, not an absent one, so it has to reach MQL as 0
// rather than being dropped as a zero value.
func TestWafExpressionSetExpressionArgsKeepsZeroSensitivity(t *testing.T) {
	args := wafExpressionSetExpressionArgs("proj-1/wafExpressionSet/sqli-v33-stable",
		&compute.WafExpressionSetExpression{Id: "owasp-crs-v030301-id942100-sqli", Sensitivity: 0})

	assert.EqualValues(t, 0, args["sensitivity"].Value)
}

// Two expressions in one set, and the same expression across two projects, all
// need distinct cache keys. The sets are Google-maintained and identical across
// projects, so scanning two projects in one run would otherwise make the second
// project's expressions resolve to the first project's.
func TestWafExpressionSetExpressionArgsIdsAreDistinct(t *testing.T) {
	a := wafExpressionSetExpressionArgs("proj-1/wafExpressionSet/sqli-v33-stable",
		&compute.WafExpressionSetExpression{Id: "owasp-crs-v030301-id942100-sqli"})
	b := wafExpressionSetExpressionArgs("proj-1/wafExpressionSet/sqli-v33-stable",
		&compute.WafExpressionSetExpression{Id: "owasp-crs-v030301-id942110-sqli"})
	c := wafExpressionSetExpressionArgs("proj-2/wafExpressionSet/sqli-v33-stable",
		&compute.WafExpressionSetExpression{Id: "owasp-crs-v030301-id942100-sqli"})

	assert.NotEqual(t, a["__id"].Value, b["__id"].Value)
	assert.NotEqual(t, a["__id"].Value, c["__id"].Value)
}

// Every level of the response is optional in the API. A nil anywhere in the
// chain must read as "no sets", not panic the provider and take the scan with
// it.
func TestWafExpressionSetsFromResponseToleratesNils(t *testing.T) {
	assert.Nil(t, wafExpressionSetsFromResponse(nil))
	assert.Nil(t, wafExpressionSetsFromResponse(&compute.SecurityPoliciesListPreconfiguredExpressionSetsResponse{}))
	assert.Nil(t, wafExpressionSetsFromResponse(&compute.SecurityPoliciesListPreconfiguredExpressionSetsResponse{
		PreconfiguredExpressionSets: &compute.SecurityPoliciesWafConfig{},
	}))

	sets := wafExpressionSetsFromResponse(&compute.SecurityPoliciesListPreconfiguredExpressionSetsResponse{
		PreconfiguredExpressionSets: &compute.SecurityPoliciesWafConfig{
			WafRules: &compute.PreconfiguredWafSet{
				ExpressionSets: []*compute.WafExpressionSet{{Id: "sqli-v33-stable"}},
			},
		},
	})
	require.Len(t, sets, 1)
	assert.Equal(t, "sqli-v33-stable", sets[0].Id)
}
