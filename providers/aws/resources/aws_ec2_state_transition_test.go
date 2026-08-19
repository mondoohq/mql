// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/llx"
)

func TestParseStateTransitionTime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
		want   *time.Time
	}{
		{
			// The case that mattered: a running instance reports an empty reason,
			// so there is no transition time and the field must be null. This used
			// to yield a zero time.Time presented as a real value.
			name:   "a running instance has no reason",
			reason: "",
			want:   nil,
		},
		{
			name:   "a stopped instance reports the timestamp",
			reason: "User initiated (2026-04-05 20:44:17 GMT)",
			want:   timePtr(time.Date(2026, 4, 5, 20, 44, 17, 0, time.UTC)),
		},
		{
			name:   "a terminated instance reports the same shape",
			reason: "User initiated (2026-05-31 04:36:20 GMT)",
			want:   timePtr(time.Date(2026, 5, 31, 4, 36, 20, 0, time.UTC)),
		},
		{
			name:   "a reason with no parenthesised timestamp is null",
			reason: "Client.InstanceInitiatedShutdown: Instance initiated shutdown",
			want:   nil,
		},
		{
			name:   "a reason in another timezone is not matched",
			reason: "User initiated (2026-04-05 20:44:17 PST)",
			want:   nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseStateTransitionTime(tc.reason)
			if tc.want == nil {
				assert.Nil(t, got, "expected a null transition time")
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.want.UTC(), got.UTC())
		})
	}
}

// A reason that names a transition but carries an unparsable timestamp keeps the
// existing past sentinel: something did happen, so null would be wrong too.
func TestParseStateTransitionTimeKeepsThePastSentinelOnAParseFailure(t *testing.T) {
	got := parseStateTransitionTime("User initiated (2026-13-45 99:99:99 GMT)")

	require.NotNil(t, got)
	assert.Equal(t, llx.NeverPastTime, *got)
}

// The zero time.Time is what made this a wrong answer rather than a missing one:
// it is a real, very old date, so `stateTransitionTime < time.now - 30*time.day`
// was true for every running instance in the account.
func TestZeroTimeWouldCompareAsAncient(t *testing.T) {
	var zero time.Time

	require.True(t, zero.Before(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)),
		"the zero time is older than any real timestamp, which is why reporting "+
			"it instead of null inverted staleness checks")
	assert.Nil(t, parseStateTransitionTime(""),
		"the empty reason must not produce that value")
}
