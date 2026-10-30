// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestTimeIsSet(t *testing.T) {
	set := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	zero := time.Time{}
	epoch := time.Unix(0, 0)

	tests := []struct {
		name string
		in   *time.Time
		want bool
	}{
		{name: "nil pointer", in: nil, want: false},
		{name: "zero time (0001-01-01)", in: &zero, want: false},
		{name: "real timestamp", in: &set, want: true},
		// Tailscale's "unset" is the Go zero time; a genuine Unix epoch 0 is
		// non-zero in Go terms and is treated as set.
		{name: "unix epoch 0", in: &epoch, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := timeIsSet(tc.in); got != tc.want {
				t.Fatalf("timeIsSet(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestOptionalTimeValue(t *testing.T) {
	set := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

	// An unset Tailscale timestamp is the Go zero instant, and it has to reach
	// MQL as null. Reporting 0001-01-01 would date a key that never expires to
	// the year 1.
	require.Nil(t, optionalTimeValue(time.Time{}))

	got := optionalTimeValue(set)
	require.NotNil(t, got)
	assert.Equal(t, set, *got)

	// Unix epoch 0 is a real instant, not Tailscale's "unset".
	epoch := optionalTimeValue(time.Unix(0, 0))
	require.NotNil(t, epoch)
	assert.Equal(t, time.Unix(0, 0), *epoch)
}

// authKeyWithExpiry builds the resource the way createTailscaleAuthKeyResource
// does, so the predicates under test see exactly what a scan would put in front
// of them.
func authKeyWithExpiry(expires, revoked time.Time) *mqlTailscaleAuthKey {
	key := &mqlTailscaleAuthKey{}
	key.Expires.Data = optionalTimeValue(expires)
	key.Expires.State = plugin.StateIsSet
	if key.Expires.Data == nil {
		key.Expires.State |= plugin.StateIsNull
	}
	key.Revoked.Data = optionalTimeValue(revoked)
	key.Revoked.State = plugin.StateIsSet
	if key.Revoked.Data == nil {
		key.Revoked.State |= plugin.StateIsNull
	}
	return key
}

func TestAuthKeyExpiryPredicates(t *testing.T) {
	var (
		never  = time.Time{}
		past   = time.Now().Add(-24 * time.Hour)
		future = time.Now().Add(24 * time.Hour)
	)

	tests := []struct {
		name              string
		expires           time.Time
		revoked           time.Time
		wantHasExpiration bool
		wantIsExpired     bool
		wantIsRevoked     bool
	}{
		{
			// The bug this guards: Tailscale spells "this key never expires"
			// as the zero instant. A never-expiring key is not an expired key,
			// it is the longest-lived credential in the tailnet.
			name:              "no expiration set",
			expires:           never,
			revoked:           never,
			wantHasExpiration: false,
			wantIsExpired:     false,
			wantIsRevoked:     false,
		},
		{
			name:              "expiration in the past",
			expires:           past,
			revoked:           never,
			wantHasExpiration: true,
			wantIsExpired:     true,
			wantIsRevoked:     false,
		},
		{
			name:              "expiration in the future",
			expires:           future,
			revoked:           never,
			wantHasExpiration: true,
			wantIsExpired:     false,
			wantIsRevoked:     false,
		},
		{
			// Revoked and expired are independent. A revoked key that never
			// had an expiration is still not "expired".
			name:              "revoked with no expiration",
			expires:           never,
			revoked:           past,
			wantHasExpiration: false,
			wantIsExpired:     false,
			wantIsRevoked:     true,
		},
		{
			name:              "revoked and expired",
			expires:           past,
			revoked:           past,
			wantHasExpiration: true,
			wantIsExpired:     true,
			wantIsRevoked:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := authKeyWithExpiry(tc.expires, tc.revoked)

			hasExpiration, err := key.hasExpiration()
			require.NoError(t, err)
			assert.Equal(t, tc.wantHasExpiration, hasExpiration, "hasExpiration")

			isExpired, err := key.isExpired()
			require.NoError(t, err)
			assert.Equal(t, tc.wantIsExpired, isExpired, "isExpired")

			isRevoked, err := key.isRevoked()
			require.NoError(t, err)
			assert.Equal(t, tc.wantIsRevoked, isRevoked, "isRevoked")
		})
	}
}

// TestNaiveExpiryComparisonInvertsNeverExpiringKey pins the inversion the fix
// exists to remove. `expires < time.now` is the comparison the field's name
// invites, and against the raw SDK value it answers "expired" for the one key
// that will never expire, reporting the riskiest credential in the tailnet as
// the safe one.
func TestNaiveExpiryComparisonInvertsNeverExpiringKey(t *testing.T) {
	now := time.Now()

	// What the SDK hands us for a key created with no expiration.
	var neverExpires time.Time
	require.True(t, neverExpires.IsZero())

	// The naive comparison, as an MQL author would write it against a field
	// that carried the zero instant through.
	naivelyExpired := neverExpires.Before(now)
	assert.True(t, naivelyExpired,
		"the zero instant compares as long past, which is the inversion")

	// isExpired answers correctly on the same key.
	key := authKeyWithExpiry(neverExpires, time.Time{})
	isExpired, err := key.isExpired()
	require.NoError(t, err)
	assert.False(t, isExpired,
		"a key with no expiration has not expired")

	// And the field itself now reaches MQL as null rather than as the year 1,
	// so the naive comparison has no bogus date to compare against.
	assert.Nil(t, key.Expires.Data)

	hasExpiration, err := key.hasExpiration()
	require.NoError(t, err)
	assert.False(t, hasExpiration,
		"hasExpiration is what finds the never-expiring key")
}
