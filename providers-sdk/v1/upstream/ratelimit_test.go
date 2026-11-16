// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package upstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/types/known/durationpb"
)

func busyErr(t *testing.T, delay time.Duration) error {
	t.Helper()
	st := status.New(codes.ResourceExhausted, "busy")
	if delay > 0 {
		var err error
		st, err = st.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(delay)})
		require.NoError(t, err)
	}
	return st.Err()
}

// fakeTime replaces the clock and sleep; sleeping advances the fake clock.
func fakeTime(t *testing.T, sleepErr error) *[]time.Duration {
	t.Helper()
	now := time.Unix(1000, 0)
	var sleeps []time.Duration
	oldSleep, oldNow, oldLog := rateLimitSleep, rateLimitNow, log.Logger
	log.Logger = zerolog.Nop()
	rateLimitNow = func() time.Time { return now }
	rateLimitSleep = func(_ context.Context, d time.Duration) error {
		if sleepErr != nil {
			return sleepErr
		}
		sleeps = append(sleeps, d)
		now = now.Add(d)
		return nil
	}
	t.Cleanup(func() { rateLimitSleep, rateLimitNow, log.Logger = oldSleep, oldNow, oldLog })
	return &sleeps
}

func TestRetryRateLimitedHonoursRetryInfo(t *testing.T) {
	sleeps := fakeTime(t, nil)
	calls := 0
	err := RetryRateLimited(context.Background(), "test", time.Minute, func() error {
		calls++
		if calls <= 2 {
			return busyErr(t, 7*time.Second)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []time.Duration{7 * time.Second, 7 * time.Second}, *sleeps)
}

func TestRetryRateLimitedBackoffWithoutRetryInfo(t *testing.T) {
	sleeps := fakeTime(t, nil)
	calls := 0
	err := RetryRateLimited(context.Background(), "test", time.Hour, func() error {
		calls++
		if calls <= 5 {
			return busyErr(t, 0)
		}
		return nil
	})
	require.NoError(t, err)
	require.Len(t, *sleeps, 5)
	for _, d := range *sleeps {
		assert.Greater(t, d, time.Duration(0))
		assert.LessOrEqual(t, d, 60*time.Second)
	}
}

func TestRetryRateLimitedStopsAtBudget(t *testing.T) {
	sleeps := fakeTime(t, nil)
	err := RetryRateLimited(context.Background(), "test", 20*time.Second, func() error {
		return busyErr(t, 7*time.Second)
	})
	require.Error(t, err)
	assert.Equal(t, []time.Duration{7 * time.Second, 7 * time.Second}, *sleeps)
	assert.True(t, errors.Is(err, ErrRateLimitBudgetSpent))
	var se interface{ GRPCStatus() *status.Status }
	require.True(t, errors.As(err, &se))
	assert.Equal(t, codes.ResourceExhausted, se.GRPCStatus().Code())
}

func TestRetryRateLimitedOtherErrorReturnsAtOnce(t *testing.T) {
	sleeps := fakeTime(t, nil)
	want := status.Error(codes.Unavailable, "down")
	calls := 0
	err := RetryRateLimited(context.Background(), "test", time.Minute, func() error {
		calls++
		return want
	})
	assert.Equal(t, want, err)
	assert.Equal(t, 1, calls)
	assert.Empty(t, *sleeps)
}

func TestRetryRateLimitedCtxCancelled(t *testing.T) {
	fakeTime(t, context.Canceled)
	err := RetryRateLimited(context.Background(), "test", time.Minute, func() error {
		return busyErr(t, time.Second)
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, errors.Is(err, ErrRateLimitBudgetSpent))
}
