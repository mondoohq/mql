// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNaclAllowsPublicIngress(t *testing.T) {
	// allowAll / denyAll are the rule shapes AWS creates by default.
	allowAll := func(n int) naclIngressRule {
		return naclIngressRule{ruleNumber: n, allow: true, public: true, protocol: "-1", allPorts: true}
	}
	denyAll := func(n int) naclIngressRule {
		return naclIngressRule{ruleNumber: n, allow: false, public: true, protocol: "-1", allPorts: true}
	}
	tcp := func(n int, allow bool, from, to int64) naclIngressRule {
		return naclIngressRule{ruleNumber: n, allow: allow, public: true, protocol: "6", fromPort: from, toPort: to}
	}

	tests := []struct {
		name  string
		rules []naclIngressRule
		want  bool
	}{
		{
			name:  "default nacl allows all",
			rules: []naclIngressRule{allowAll(100)},
			want:  true,
		},
		{
			// The regression this test previously encoded as want:false. A deny
			// scoped to one port does not shadow a broad allow -- the host is
			// still reachable on every other port.
			name:  "narrow deny does not shadow a broad allow",
			rules: []naclIngressRule{tcp(90, false, 3389, 3389), allowAll(100)},
			want:  true,
		},
		{
			name:  "deny-all genuinely shadows a later allow",
			rules: []naclIngressRule{denyAll(90), allowAll(100)},
			want:  false,
		},
		{
			name:  "deny on a different protocol does not shadow",
			rules: []naclIngressRule{tcp(90, false, 0, 65535), {ruleNumber: 100, allow: true, public: true, protocol: "17", allPorts: true}},
			want:  true,
		},
		{
			name:  "deny covering the exact allowed range shadows it",
			rules: []naclIngressRule{tcp(90, false, 0, 65535), tcp(100, true, 443, 443)},
			want:  false,
		},
		{
			name:  "deny partially overlapping the allowed range does not shadow",
			rules: []naclIngressRule{tcp(90, false, 400, 500), tcp(100, true, 443, 8443)},
			want:  true,
		},
		{
			name:  "bounded deny cannot shadow an all-ports allow on the same protocol",
			rules: []naclIngressRule{tcp(90, false, 443, 443), {ruleNumber: 100, allow: true, public: true, protocol: "6", allPorts: true}},
			want:  true,
		},
		{
			name:  "lower-numbered allow wins over later deny",
			rules: []naclIngressRule{denyAll(200), allowAll(100)},
			want:  true,
		},
		{
			name:  "only specific-cidr allow, no public rule",
			rules: []naclIngressRule{{ruleNumber: 100, allow: true, public: false, protocol: "-1", allPorts: true}},
			want:  false,
		},
		{
			name:  "no rules",
			rules: []naclIngressRule{},
			want:  false,
		},
		{
			name:  "non-public rules ignored, public deny decides",
			rules: []naclIngressRule{{ruleNumber: 50, allow: true, public: false, protocol: "-1", allPorts: true}, denyAll(100)},
			want:  false,
		},
		{
			name:  "input order does not matter",
			rules: []naclIngressRule{allowAll(100), tcp(90, false, 22, 22)},
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, naclAllowsPublicIngress(tt.rules))
		})
	}
}

func TestFunctionUrlIsPublic(t *testing.T) {
	assert.True(t, functionUrlIsPublic("NONE"))
	assert.True(t, functionUrlIsPublic("none"))
	assert.False(t, functionUrlIsPublic("AWS_IAM"))
	assert.False(t, functionUrlIsPublic(""))
}

func TestRouteAuthIsPublic(t *testing.T) {
	assert.True(t, routeAuthIsPublic("NONE"))
	assert.True(t, routeAuthIsPublic("none"))
	assert.True(t, routeAuthIsPublic(""), "unset authorization type defaults to no auth")
	assert.False(t, routeAuthIsPublic("AWS_IAM"))
	assert.False(t, routeAuthIsPublic("JWT"))
	assert.False(t, routeAuthIsPublic("CUSTOM"))
}

func TestEsDomainIsPublic(t *testing.T) {
	tests := []struct {
		name               string
		inVPC              bool
		policyAllowsPublic bool
		want               bool
	}{
		{"public endpoint, public policy", false, true, true},
		{"public endpoint, scoped policy", false, false, false},
		{"vpc domain, public policy", true, true, false},
		{"vpc domain, scoped policy", true, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, esDomainIsPublic(tt.inVPC, tt.policyAllowsPublic))
		})
	}
}

func TestOpenIngressRulesFromSecurityGroupsNil(t *testing.T) {
	// A nil security-group TValue (e.g. a Neptune instance whose parent cluster
	// could not be located) must yield no open rules rather than panicking.
	rules, err := openIngressRulesFromSecurityGroups(nil)
	require.NoError(t, err)
	assert.Empty(t, rules)
}
