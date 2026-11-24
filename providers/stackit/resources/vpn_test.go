// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	vpn "github.com/stackitcloud/stackit-sdk-go/services/vpn/v1api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeBgpRules(t *testing.T, payload string) []vpn.BGPFilterRule {
	t.Helper()
	var list vpn.BGPFilterRuleList
	require.NoError(t, json.Unmarshal([]byte(payload), &list))
	return list.GetRules()
}

func TestSortBgpRules(t *testing.T) {
	// Synthetic: rules listed out of order, one without a sequence; no live account was checked.
	rules := sortBgpRules(decodeBgpRules(t, `{"rules":[`+
		`{"id":"c","action":"DENY"},{"id":"b","action":"PERMIT","sequence":20},{"id":"a","action":"PERMIT","sequence":10}]}`))
	got := []string{rules[0].GetId(), rules[1].GetId(), rules[2].GetId()}
	assert.Equal(t, []string{"a", "b", "c"}, got)
}

func TestBgpFilterRuleArgs(t *testing.T) {
	// Synthetic: a bounded permit and a bare deny-all; no live account was checked.
	rules := decodeBgpRules(t, `{"rules":[`+
		`{"id":"r1","action":"PERMIT","sequence":10,"match":{"prefixes":["10.0.0.0/8"],"minPrefixLength":16,`+
		`"maxPrefixLength":24,"asPathContainsAny":[65001,65002],"firstASN":65000,"peer":"169.254.0.1"},"set":{"localPreference":200}},`+
		`{"id":"r2","action":"DENY"}]}`)

	bounded := bgpFilterRuleArgs("k1", &rules[0])
	assert.Equal(t, "PERMIT", bounded["action"].Value)
	assert.Equal(t, []any{"10.0.0.0/8"}, bounded["prefixes"].Value)
	assert.Equal(t, int64(16), bounded["minPrefixLength"].Value)
	assert.Equal(t, int64(24), bounded["maxPrefixLength"].Value)
	assert.Equal(t, []any{int64(65001), int64(65002)}, bounded["asPathContainsAny"].Value)
	assert.Equal(t, int64(65000), bounded["firstAsn"].Value)
	assert.Equal(t, int64(200), bounded["localPreference"].Value)
	assert.Equal(t, int64(10), bounded["sequence"].Value)

	bare := bgpFilterRuleArgs("k2", &rules[1])
	assert.Equal(t, "DENY", bare["action"].Value)
	assert.Nil(t, bare["minPrefixLength"].Value, "an unbounded length is null, not 0")
	assert.Nil(t, bare["maxPrefixLength"].Value)
	assert.Nil(t, bare["sequence"].Value)
	assert.Nil(t, bare["localPreference"].Value)
	assert.Equal(t, []any{}, bare["prefixes"].Value)
	assert.Equal(t, []any{}, bare["asPathContainsAny"].Value)
}
