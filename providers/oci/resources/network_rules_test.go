// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// The rule structs reach MQL as dicts via convert.JsonToDictSlice, so their
// json tags *are* the user-facing schema. These tests pin the emitted keys:
// an `omitempty` on a bool silently drops `false`, and a snake_case tag
// silently renames a documented field - neither shows up at compile time.

func TestSecurityListIngressRuleDictKeys(t *testing.T) {
	rules := []ingressSecurityRule{{
		Description: "ssh from anywhere",
		Stateless:   false,
		Protocol:    "6",
		Source:      "0.0.0.0/0",
		SourceType:  "CIDR_BLOCK",
	}}

	out, err := convert.JsonToDictSlice(rules)
	require.NoError(t, err)
	require.Len(t, out, 1)
	rule, ok := out[0].(map[string]any)
	require.True(t, ok)

	// A stateful rule must emit `stateless: false`, not drop the key. Dropping
	// it makes `all(stateless == false)` compare against null and fail every
	// correctly-configured rule.
	stateless, present := rule["stateless"]
	assert.True(t, present, "stateless key must be present for a stateful rule")
	assert.Equal(t, false, stateless)

	// camelCase, matching both the .lr documentation and the NSG rule shape.
	assert.Equal(t, "CIDR_BLOCK", rule["sourceType"])
	assert.NotContains(t, rule, "source_type")

	assert.Equal(t, "0.0.0.0/0", rule["source"])
	assert.Equal(t, "6", rule["protocol"])
}

func TestSecurityListEgressRuleDictKeys(t *testing.T) {
	rules := []egressSecurityRule{{
		Stateless:       false,
		Protocol:        "6",
		Destination:     "0.0.0.0/0",
		DestinationType: "CIDR_BLOCK",
	}}

	out, err := convert.JsonToDictSlice(rules)
	require.NoError(t, err)
	require.Len(t, out, 1)
	rule, ok := out[0].(map[string]any)
	require.True(t, ok)

	stateless, present := rule["stateless"]
	assert.True(t, present, "stateless key must be present for a stateful rule")
	assert.Equal(t, false, stateless)

	assert.Equal(t, "CIDR_BLOCK", rule["destinationType"])
	assert.NotContains(t, rule, "destination_type")
}

func TestSecurityListRuleStatelessTrueRoundTrips(t *testing.T) {
	out, err := convert.JsonToDictSlice([]ingressSecurityRule{{Stateless: true, Source: "10.0.0.0/8"}})
	require.NoError(t, err)
	rule := out[0].(map[string]any)
	assert.Equal(t, true, rule["stateless"])
}

// anyRuleStateless reads the key the mappers emit, on both the security-list
// ("stateless") and NSG ("isStateless") side. A mismatch between the two
// silently returns "no stateless rules".
func TestAnyRuleStatelessMatchesEmittedKeys(t *testing.T) {
	slRules, err := convert.JsonToDictSlice([]ingressSecurityRule{
		{Stateless: false, Source: "10.0.0.0/8"},
		{Stateless: true, Source: "0.0.0.0/0"},
	})
	require.NoError(t, err)
	assert.True(t, anyRuleStateless(slRules, "stateless"))

	nsgRules, err := convert.JsonToDictSlice([]nsgSecurityRule{
		{Direction: "INGRESS", IsStateless: true, Source: "0.0.0.0/0"},
	})
	require.NoError(t, err)
	assert.True(t, anyRuleStateless(nsgRules, "isStateless"))

	statefulOnly, err := convert.JsonToDictSlice([]ingressSecurityRule{{Stateless: false}})
	require.NoError(t, err)
	assert.False(t, anyRuleStateless(statefulOnly, "stateless"))
}

func TestOciAnySubnetAdmitsInternet(t *testing.T) {
	tests := []struct {
		name             string
		gates            []ociSubnetGate
		nsgOpenRuleCount int
		want             bool
	}{
		{
			name:  "no subnets",
			gates: nil,
			want:  false,
		},
		{
			name: "single subnet open on every axis",
			gates: []ociSubnetGate{
				{prohibitsIngress: false, routesToInternet: true, securityListAllows: true},
			},
			want: true,
		},
		{
			// The regression this function exists for. Aggregating the
			// security-list verdict across subnets combined the public
			// subnet's internet route with the private subnet's wide-open
			// default VCN security list into a false positive.
			name: "hardened public subnet + open private subnet must not combine",
			gates: []ociSubnetGate{
				{prohibitsIngress: false, routesToInternet: true, securityListAllows: false},
				{prohibitsIngress: false, routesToInternet: false, securityListAllows: true},
			},
			want: false,
		},
		{
			name: "an NSG rule opens ingress for the routed subnet",
			gates: []ociSubnetGate{
				{prohibitsIngress: false, routesToInternet: true, securityListAllows: false},
			},
			nsgOpenRuleCount: 1,
			want:             true,
		},
		{
			name: "prohibitInternetIngress blocks an otherwise open subnet",
			gates: []ociSubnetGate{
				{prohibitsIngress: true, routesToInternet: true, securityListAllows: true},
			},
			nsgOpenRuleCount: 1,
			want:             false,
		},
		{
			name: "no internet route blocks an otherwise open subnet",
			gates: []ociSubnetGate{
				{prohibitsIngress: false, routesToInternet: false, securityListAllows: true},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociAnySubnetAdmitsInternet(tt.gates, tt.nsgOpenRuleCount))
		})
	}
}
