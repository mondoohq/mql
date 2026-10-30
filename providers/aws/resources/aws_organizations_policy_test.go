// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPolicyTypeUnavailable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"policy type not enabled", &orgtypes.PolicyTypeNotEnabledException{}, true},
		{"policy type not available", &orgtypes.PolicyTypeNotAvailableForOrganizationException{}, true},
		{"organizations not in use", &orgtypes.AWSOrganizationsNotInUseException{}, true},
		{"wrapped not enabled", errors.Join(errors.New("call failed"), &orgtypes.PolicyTypeNotEnabledException{}), true},
		{"effective policy not found", &orgtypes.EffectivePolicyNotFoundException{}, false},
		{"unrelated error", errors.New("throttled"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isPolicyTypeUnavailable(tt.err))
		})
	}
}

func TestIsEffectivePolicyAbsent(t *testing.T) {
	assert.True(t, isEffectivePolicyAbsent(&orgtypes.EffectivePolicyNotFoundException{}))
	// A type that was never enabled has no effective policy either.
	assert.True(t, isEffectivePolicyAbsent(&orgtypes.PolicyTypeNotEnabledException{}))
	assert.False(t, isEffectivePolicyAbsent(errors.New("throttled")))
}

// Only the control-policy types use the IAM policy grammar. Every other type
// carries its own document format, and the enum is read from the SDK so a type
// added later defaults to "not IAM grammar" rather than being misparsed.
func TestPolicyTypeUsesIamGrammar(t *testing.T) {
	iamGrammar := map[orgtypes.PolicyType]bool{
		orgtypes.PolicyTypeServiceControlPolicy:  true,
		orgtypes.PolicyTypeResourceControlPolicy: true,
	}
	for _, policyType := range orgtypes.PolicyType("").Values() {
		assert.Equal(t, iamGrammar[policyType], policyTypeUsesIamGrammar(policyType),
			"unexpected grammar verdict for %s", policyType)
	}
}

// A non-IAM-grammar policy resolves to no statements without reading its
// content, which this exercises by leaving the runtime unset — parsing would
// need it and would panic.
func TestOrganizationPolicyStatementsSkipsNonIamGrammar(t *testing.T) {
	for _, policyType := range []orgtypes.PolicyType{
		orgtypes.PolicyTypeTagPolicy,
		orgtypes.PolicyTypeBackupPolicy,
		orgtypes.PolicyTypeDeclarativePolicyEc2,
		orgtypes.PolicyTypeAiservicesOptOutPolicy,
	} {
		policy := &mqlAwsOrganizationPolicy{Type: setString(string(policyType))}
		statements, err := policy.statements()
		require.NoError(t, err)
		assert.Equal(t, []any{}, statements, "expected no statements for %s", policyType)
	}
}

// Every effective policy type must also be a valid policy type, since the
// effective-policy list is derived from a separate SDK enum.
func TestEffectivePolicyTypesArePolicyTypes(t *testing.T) {
	policyTypes := map[string]bool{}
	for _, policyType := range orgtypes.PolicyType("").Values() {
		policyTypes[string(policyType)] = true
	}
	for _, effectiveType := range orgtypes.EffectivePolicyType("").Values() {
		assert.True(t, policyTypes[string(effectiveType)], "%s is not a known policy type", effectiveType)
		assert.False(t, policyTypeUsesIamGrammar(orgtypes.PolicyType(effectiveType)),
			"%s is a control policy, which has no effective-policy API", effectiveType)
	}
}
