// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

func TestCloudfwSwitchEnabled(t *testing.T) {
	assert.True(t, cloudfwSwitchEnabled(tea.Int32(1)))
	assert.False(t, cloudfwSwitchEnabled(tea.Int32(0)))
	// an unread switch must not report protection nobody confirmed
	assert.False(t, cloudfwSwitchEnabled(nil))
	assert.False(t, cloudfwSwitchEnabled(tea.Int32(2)))
}

func TestCloudfwPolicyEnabled(t *testing.T) {
	tests := []struct {
		release  *string
		expected bool
	}{
		{new("true"), true},
		{new("True"), true},
		{new(" true "), true},
		{new("false"), false},
		{new(""), false},
		{nil, false},
	}
	for _, test := range tests {
		assert.Equal(t, test.expected, cloudfwPolicyEnabled(test.release),
			"release %v", tea.StringValue(test.release))
	}
}

func TestCloudfwVpcFirewallEnabled(t *testing.T) {
	assert.True(t, cloudfwVpcFirewallEnabled(new("opened")))
	assert.True(t, cloudfwVpcFirewallEnabled(new("OPENED")))
	assert.False(t, cloudfwVpcFirewallEnabled(new("closed")))
	// a pair with no firewall configured carries traffic uninspected, exactly
	// as a closed one does
	assert.False(t, cloudfwVpcFirewallEnabled(new("notconfigured")))
	assert.False(t, cloudfwVpcFirewallEnabled(nil))
}

func TestCloudfwNatFirewallEnabled(t *testing.T) {
	assert.True(t, cloudfwNatFirewallEnabled(new("normal")))
	// abnormal means the firewall exists but is not inspecting, which must not
	// read as protected
	assert.False(t, cloudfwNatFirewallEnabled(new("abnormal")))
	assert.False(t, cloudfwNatFirewallEnabled(new("opening")))
	assert.False(t, cloudfwNatFirewallEnabled(new("closed")))
	assert.False(t, cloudfwNatFirewallEnabled(nil))
}

func TestCloudfwCrossAccount(t *testing.T) {
	tests := []struct {
		name        string
		local, peer *int64
		expected    bool
	}{
		{"same account", tea.Int64(1000), tea.Int64(1000), false},
		{"different accounts", tea.Int64(1000), tea.Int64(2000), true},
		// a missing owner is not evidence of a foreign peer
		{"peer owner absent", tea.Int64(1000), nil, false},
		{"local owner absent", nil, tea.Int64(2000), false},
		{"both absent", nil, nil, false},
		{"zero owner", tea.Int64(0), tea.Int64(2000), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, cloudfwCrossAccount(test.local, test.peer))
		})
	}
}

func TestCloudfwOwnerString(t *testing.T) {
	assert.Equal(t, "1234", cloudfwOwnerString(tea.Int64(1234)))
	// an absent owner stays blank rather than becoming the literal "0"
	assert.Equal(t, "", cloudfwOwnerString(nil))
	assert.Equal(t, "", cloudfwOwnerString(tea.Int64(0)))
}

func TestCloudfwPolicyMore(t *testing.T) {
	tests := []struct {
		name      string
		collected int
		total     *string
		expected  bool
	}{
		{"more pages remain", 50, new("120"), true},
		{"all collected", 120, new("120"), false},
		{"over-collected", 130, new("120"), false},
		{"whitespace tolerated", 10, new(" 20 "), true},
		// an unusable total must terminate the walk, not loop forever
		{"absent total", 10, nil, false},
		{"unparseable total", 10, new("many"), false},
		{"empty total", 10, new(""), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, cloudfwPolicyMore(test.collected, test.total))
		})
	}
}

func TestEpochSeconds(t *testing.T) {
	got := epochSeconds(tea.Int64(1579261141))
	if assert.NotNil(t, got) {
		assert.Equal(t, "2020-01-17T11:39:01Z", got.Format("2006-01-02T15:04:05Z"))
	}
	// a zero timestamp must stay null: rendering it would report 1 January 1970
	// as a real date
	assert.Nil(t, epochSeconds(tea.Int64(0)))
	assert.Nil(t, epochSeconds(nil))
}
