// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantLow  int64
		wantHigh int64
		wantOK   bool
	}{
		// The forms the ECS and VPC APIs actually return.
		{name: "single port", in: "22/22", wantLow: 22, wantHigh: 22, wantOK: true},
		{name: "rdp", in: "3389/3389", wantLow: 3389, wantHigh: 3389, wantOK: true},
		{name: "span", in: "80/443", wantLow: 80, wantHigh: 443, wantOK: true},
		{name: "every port written explicitly", in: "1/65535", wantLow: 1, wantHigh: 65535, wantOK: true},

		// -1/-1 is how a rule says "every port", including every rule whose
		// protocol carries no ports. It has to resolve to the full span or a
		// port-containment query silently skips the widest rules there are.
		{name: "every port written as the sentinel", in: "-1/-1", wantLow: 1, wantHigh: 65535, wantOK: true},

		// A lone -1 is not a span.
		{name: "sentinel on the low side only", in: "-1/443", wantOK: false},
		{name: "sentinel on the high side only", in: "22/-1", wantOK: false},

		// Absent and malformed input must leave the fields null rather than
		// report a port the rule never named.
		{name: "empty", in: "", wantOK: false},
		{name: "whitespace only", in: "   ", wantOK: false},
		{name: "no bounds at all", in: "/", wantOK: false},
		{name: "low bound missing", in: "/443", wantOK: false},
		{name: "high bound missing", in: "22/", wantOK: false},
		{name: "not a number", in: "ssh/ssh", wantOK: false},
		{name: "three parts", in: "22/80/443", wantOK: false},

		// Out of range on either side.
		{name: "zero is not a port", in: "0/65535", wantOK: false},
		{name: "above the maximum port", in: "1/65536", wantOK: false},
		{name: "negative other than the sentinel", in: "-2/-2", wantOK: false},

		// Tolerated shapes.
		{name: "bare port", in: "22", wantLow: 22, wantHigh: 22, wantOK: true},
		{name: "surrounding whitespace", in: " 22/22 ", wantLow: 22, wantHigh: 22, wantOK: true},
		{name: "whitespace around each bound", in: "22 / 80", wantLow: 22, wantHigh: 80, wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			low, high, ok := parsePortRange(tt.in)
			require.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				return
			}
			assert.Equal(t, tt.wantLow, low)
			assert.Equal(t, tt.wantHigh, high)
		})
	}
}

// TestParsePortRangeReportsBoundsAsWritten guards against a well-meaning
// normalization: a reversed range is reported as it was read, because swapping
// the bounds would invent a rule the service was never asked for.
func TestParsePortRangeReportsBoundsAsWritten(t *testing.T) {
	low, high, ok := parsePortRange("443/80")
	require.True(t, ok)
	assert.Equal(t, int64(443), low)
	assert.Equal(t, int64(80), high)
}

// TestPortRangeCoversAdminPorts asserts the containment question the Mondoo
// Alibaba policy asks of these fields, which is the whole reason they exist.
func TestPortRangeCoversAdminPorts(t *testing.T) {
	covers := func(portRange string, port int64) bool {
		low, high, ok := parsePortRange(portRange)
		if !ok {
			return false
		}
		return low <= port && high >= port
	}

	// SSH.
	assert.True(t, covers("22/22", 22))
	assert.True(t, covers("20/30", 22))
	assert.True(t, covers("1/65535", 22))
	assert.True(t, covers("-1/-1", 22))
	assert.False(t, covers("23/24", 22))
	assert.False(t, covers("80/443", 22))

	// RDP.
	assert.True(t, covers("3389/3389", 3389))
	assert.True(t, covers("3000/4000", 3389))
	assert.True(t, covers("-1/-1", 3389))
	assert.False(t, covers("3390/3400", 3389))

	// An unreadable range must not answer the question at all.
	assert.False(t, covers("", 22))
	assert.False(t, covers("ssh", 22))
}

func TestPortRangeBounds(t *testing.T) {
	low, high := portRangeBounds("22/80")
	require.NotNil(t, low)
	require.NotNil(t, high)
	assert.Equal(t, int64(22), *low)
	assert.Equal(t, int64(80), *high)

	// An unresolved range yields no pointers, so both schema fields read null
	// rather than reporting port 0.
	low, high = portRangeBounds("")
	assert.Nil(t, low)
	assert.Nil(t, high)

	low, high = portRangeBounds("not-a-range")
	assert.Nil(t, low)
	assert.Nil(t, high)
}
