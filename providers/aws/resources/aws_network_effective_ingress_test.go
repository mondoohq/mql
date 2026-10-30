// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// naclRule builds an ordered network ACL rule for the evaluation tests.
func naclRule(number int, allow bool, protocol, cidr string, from, to int64) naclIngressRule {
	r := naclIngressRule{
		ruleNumber: number,
		allow:      allow,
		protocol:   protocol,
		cidr:       cidr,
		public:     cidrIsPublic(cidr),
	}
	if from < 0 || to < 0 {
		r.allPorts = true
	} else {
		r.fromPort, r.toPort = from, to
	}
	return r
}

func TestEvaluateNaclIngressRules(t *testing.T) {
	allowAllV4 := naclRule(100, true, "-1", "0.0.0.0/0", -1, -1)

	tests := []struct {
		name    string
		rules   []naclIngressRule
		traffic naclIngressRule
		verdict string
		matched int
	}{
		{
			name:    "default allow-all permits everything",
			rules:   []naclIngressRule{allowAllV4},
			traffic: trafficRule("tcp", "0.0.0.0/0", newPortRange(443, 443)),
			verdict: naclVerdictAllow,
			matched: 0,
		},
		{
			name: "narrow deny in front of broad allow denies only its own port",
			rules: []naclIngressRule{
				naclRule(90, false, "6", "0.0.0.0/0", 3389, 3389),
				allowAllV4,
			},
			traffic: trafficRule("tcp", "0.0.0.0/0", newPortRange(3389, 3389)),
			verdict: naclVerdictDeny,
			matched: 0,
		},
		{
			name: "traffic on another port falls through the narrow deny",
			rules: []naclIngressRule{
				naclRule(90, false, "6", "0.0.0.0/0", 3389, 3389),
				allowAllV4,
			},
			traffic: trafficRule("tcp", "0.0.0.0/0", newPortRange(443, 443)),
			verdict: naclVerdictAllow,
			matched: 1,
		},
		{
			name:    "nothing matches, so the implicit final deny applies",
			rules:   []naclIngressRule{naclRule(100, true, "6", "10.0.0.0/8", 443, 443)},
			traffic: trafficRule("tcp", "0.0.0.0/0", newPortRange(22, 22)),
			verdict: naclVerdictDeny,
			matched: -1,
		},
		{
			name:    "empty rule list denies",
			rules:   []naclIngressRule{},
			traffic: trafficRule("tcp", "0.0.0.0/0", newPortRange(443, 443)),
			verdict: naclVerdictDeny,
			matched: -1,
		},
		{
			name:    "deny narrower than the traffic is partial, not a full deny",
			rules:   []naclIngressRule{naclRule(90, false, "6", "10.0.0.0/8", -1, -1), allowAllV4},
			traffic: trafficRule("tcp", "0.0.0.0/0", newPortRange(443, 443)),
			verdict: naclVerdictPartial,
			matched: 0,
		},
		{
			name:    "allow narrower than the traffic is also partial",
			rules:   []naclIngressRule{naclRule(100, true, "6", "0.0.0.0/0", 400, 500)},
			traffic: trafficRule("tcp", "0.0.0.0/0", newPortRange(443, 8443)),
			verdict: naclVerdictPartial,
			matched: 0,
		},
		{
			name:    "a different protocol is skipped entirely",
			rules:   []naclIngressRule{naclRule(90, false, "17", "0.0.0.0/0", -1, -1), allowAllV4},
			traffic: trafficRule("tcp", "0.0.0.0/0", newPortRange(443, 443)),
			verdict: naclVerdictAllow,
			matched: 1,
		},
		{
			name:    "a non-overlapping source is skipped entirely",
			rules:   []naclIngressRule{naclRule(90, false, "-1", "192.168.0.0/16", -1, -1), allowAllV4},
			traffic: trafficRule("tcp", "10.0.0.0/8", newPortRange(443, 443)),
			verdict: naclVerdictAllow,
			matched: 1,
		},
		{
			name:    "a wider deny covers narrower traffic",
			rules:   []naclIngressRule{naclRule(90, false, "-1", "0.0.0.0/0", -1, -1), allowAllV4},
			traffic: trafficRule("tcp", "10.1.0.0/16", newPortRange(443, 443)),
			verdict: naclVerdictDeny,
			matched: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, idx := evaluateNaclIngressRules(tt.rules, tt.traffic)
			assert.Equal(t, tt.verdict, verdict)
			assert.Equal(t, tt.matched, idx)
		})
	}
}

// TestEvaluateNaclIngressAddressFamily pins the fix for a rule set where an IPv4
// deny used to shadow an IPv6 allow. The two never match the same packet, so the
// IPv6 traffic must reach the allow.
func TestEvaluateNaclIngressAddressFamily(t *testing.T) {
	rules := []naclIngressRule{
		naclRule(90, false, "-1", "0.0.0.0/0", -1, -1),
		naclRule(100, true, "-1", "::/0", -1, -1),
	}

	verdict, idx := evaluateNaclIngressRules(rules, trafficRule("tcp", "::/0", newPortRange(443, 443)))
	assert.Equal(t, naclVerdictAllow, verdict, "an IPv4 deny must not decide IPv6 traffic")
	assert.Equal(t, 1, idx)

	// The IPv4 side still denies.
	verdict, idx = evaluateNaclIngressRules(rules, trafficRule("tcp", "0.0.0.0/0", newPortRange(443, 443)))
	assert.Equal(t, naclVerdictDeny, verdict)
	assert.Equal(t, 0, idx)
}

// TestNaclAllowsPublicIngressAddressFamily covers the same fix through the
// existing public-reachability entry point.
func TestNaclAllowsPublicIngressAddressFamily(t *testing.T) {
	assert.True(t, naclAllowsPublicIngress([]naclIngressRule{
		naclRule(90, false, "-1", "0.0.0.0/0", -1, -1),
		naclRule(100, true, "-1", "::/0", -1, -1),
	}), "an IPv4 deny-all does not shadow an IPv6 allow-all")

	// Same family still shadows.
	assert.False(t, naclAllowsPublicIngress([]naclIngressRule{
		naclRule(90, false, "-1", "0.0.0.0/0", -1, -1),
		naclRule(100, true, "-1", "0.0.0.0/0", -1, -1),
	}))
}

func TestNaclIngressRuleCovers(t *testing.T) {
	broad := naclRule(100, true, "-1", "0.0.0.0/0", -1, -1)
	narrow := naclRule(200, true, "6", "10.0.0.0/8", 443, 443)

	assert.True(t, broad.covers(narrow))
	assert.False(t, narrow.covers(broad))
	assert.True(t, narrow.covers(narrow))

	// Same protocol and ports, but a source that does not contain the other.
	a := naclRule(100, true, "6", "10.1.0.0/16", 443, 443)
	b := naclRule(200, true, "6", "10.2.0.0/16", 443, 443)
	assert.False(t, a.covers(b))
	assert.False(t, b.covers(a))
}

func TestVerdictIsReachable(t *testing.T) {
	assert.True(t, verdictIsReachable(naclVerdictAllow))
	assert.True(t, verdictIsReachable(naclVerdictPartial), "part of the range gets through")
	assert.True(t, verdictIsReachable(naclVerdictUnknown), "an unread ACL must not read as protected")
	assert.False(t, verdictIsReachable(naclVerdictDeny))
}

func TestUserIdGroupPairIds(t *testing.T) {
	pairs := []any{
		map[string]any{"GroupId": "sg-aaa", "UserId": "123456789012"},
		map[string]any{"GroupId": "sg-bbb"},
	}
	assert.Equal(t, []string{"sg-aaa", "sg-bbb"}, userIdGroupPairIds(pairs))
	assert.Equal(t, []string{}, userIdGroupPairIds([]any{}))

	// Malformed entries are skipped rather than panicking, and an empty GroupId
	// is not a reference.
	assert.Equal(t, []string{}, userIdGroupPairIds([]any{
		"not-a-map",
		nil,
		map[string]any{"GroupId": 42},
		map[string]any{"GroupId": ""},
		map[string]any{"UserId": "123456789012"},
	}))
}

func TestReferencedByOtherGroup(t *testing.T) {
	refs := map[string][]string{
		"sg-self":  {"sg-self"},
		"sg-used":  {"sg-self", "sg-other"},
		"sg-mixed": {"sg-mixed", "sg-other"},
	}

	// The common "allow from myself" group is still unused when nothing else
	// points at it.
	assert.False(t, referencedByOtherGroup(refs, "sg-self"))
	assert.True(t, referencedByOtherGroup(refs, "sg-used"))
	assert.True(t, referencedByOtherGroup(refs, "sg-mixed"), "a self-reference does not mask a real one")

	assert.False(t, referencedByOtherGroup(refs, "sg-absent"))
	assert.False(t, referencedByOtherGroup(map[string][]string{}, "sg-any"))
	assert.False(t, referencedByOtherGroup(nil, "sg-any"))
}
