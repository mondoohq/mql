// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package upstream

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestRetryableRPCError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unavailable", status.Error(codes.Unavailable, "down"), true},
		{"deadline", status.Error(codes.DeadlineExceeded, "slow"), true},
		{"resource exhausted", status.Error(codes.ResourceExhausted, "throttled"), true},
		{"aborted", status.Error(codes.Aborted, "conflict"), true},
		{"plain transport error (unknown)", errors.New("connection reset"), true},
		{"unauthenticated", status.Error(codes.Unauthenticated, "no creds"), false},
		{"permission denied", status.Error(codes.PermissionDenied, "nope"), false},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad"), false},
		{"not found", status.Error(codes.NotFound, "missing"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RetryableRPCError(tt.err))
		})
	}
}

func TestRetryableHTTPStatus(t *testing.T) {
	assert.True(t, RetryableHTTPStatus(http.StatusTooManyRequests))
	assert.True(t, RetryableHTTPStatus(http.StatusInternalServerError))
	assert.True(t, RetryableHTTPStatus(http.StatusBadGateway))
	assert.False(t, RetryableHTTPStatus(http.StatusOK))
	assert.False(t, RetryableHTTPStatus(http.StatusBadRequest))
	assert.False(t, RetryableHTTPStatus(http.StatusUnauthorized))
	assert.False(t, RetryableHTTPStatus(http.StatusForbidden))
}

func TestRetryAfter(t *testing.T) {
	mk := func(v string) http.Header {
		h := http.Header{}
		if v != "" {
			h.Set("Retry-After", v)
		}
		return h
	}
	assert.Equal(t, 5*time.Second, RetryAfter(mk("5")))
	assert.Equal(t, time.Duration(0), RetryAfter(mk("")))
	assert.Equal(t, time.Duration(0), RetryAfter(mk("Wed, 21 Oct 2026 07:28:00 GMT"))) // HTTP-date form unsupported
	assert.Equal(t, time.Duration(0), RetryAfter(mk("-1")))
}

func TestWithRetry_SucceedsImmediately(t *testing.T) {
	calls := 0
	err := WithRetry(context.Background(), "op", func() (bool, time.Duration, error) {
		calls++
		return false, 0, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestWithRetry_RetriesThenSucceeds(t *testing.T) {
	calls := 0
	err := WithRetry(context.Background(), "op", func() (bool, time.Duration, error) {
		calls++
		if calls < 3 {
			return true, time.Nanosecond, errors.New("transient")
		}
		return false, 0, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 3, calls)
}

func TestWithRetry_NonRetryableFailsFast(t *testing.T) {
	calls := 0
	err := WithRetry(context.Background(), "op", func() (bool, time.Duration, error) {
		calls++
		return false, 0, errors.New("permanent")
	})
	require.Error(t, err)
	assert.Equal(t, 1, calls, "non-retryable error must not retry")
}

func setPaceBudget(t *testing.T, d time.Duration) {
	old := paceBudget
	paceBudget = d
	t.Cleanup(func() { paceBudget = old })
}

func TestWithRetry_ExhaustsAttempts(t *testing.T) {
	setPaceBudget(t, 0)
	calls := 0
	err := WithRetry(context.Background(), "op", func() (bool, time.Duration, error) {
		calls++
		return true, time.Nanosecond, errors.New("always transient")
	})
	require.Error(t, err)
	assert.Equal(t, DefaultRetryAttempts, calls)
}

func TestWithRetry_PacedWaitsDoNotUseAttempts(t *testing.T) {
	calls := 0
	err := WithRetry(context.Background(), "op", func() (bool, time.Duration, error) {
		calls++
		if calls <= 2*DefaultRetryAttempts {
			return true, time.Nanosecond, errors.New("busy")
		}
		return false, 0, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2*DefaultRetryAttempts+1, calls)
}

func TestWithRetry_PaceBudgetEnds(t *testing.T) {
	setPaceBudget(t, 200*time.Millisecond)
	calls := 0
	err := WithRetry(context.Background(), "op", func() (bool, time.Duration, error) {
		calls++
		return true, 50 * time.Millisecond, errors.New("busy")
	})
	require.Error(t, err)
	// 1 to 4 paced waits fit in the budget (each waits at least 50ms, and the
	// first fits unless the first call takes 150ms), then attempts count again.
	assert.Greater(t, calls, DefaultRetryAttempts)
	assert.LessOrEqual(t, calls, DefaultRetryAttempts+4)
}

func TestWithRetry_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := WithRetry(ctx, "op", func() (bool, time.Duration, error) {
		calls++
		cancel() // cancel before the backoff wait
		return true, time.Hour, errors.New("transient")
	})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, calls)
}

func TestRetryRPC_FailsFastOnPermanent(t *testing.T) {
	calls := 0
	err := RetryRPC(context.Background(), "rpc", func() error {
		calls++
		return status.Error(codes.Unauthenticated, "no creds")
	})
	require.Error(t, err)
	assert.Equal(t, 1, calls, "permanent RPC error must not retry")
}

func TestRetryInfoDelay(t *testing.T) {
	st, err := status.New(codes.ResourceExhausted, "busy").
		WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(7 * time.Second)})
	require.NoError(t, err)
	d, ok := RetryInfoDelay(st.Err())
	assert.True(t, ok)
	assert.Equal(t, 7*time.Second, d)

	long, err := status.New(codes.ResourceExhausted, "busy").
		WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(24 * time.Hour)})
	require.NoError(t, err)
	d, ok = RetryInfoDelay(long.Err())
	assert.True(t, ok)
	assert.Equal(t, 60*time.Second, d, "capped")

	_, ok = RetryInfoDelay(status.Error(codes.ResourceExhausted, "busy"))
	assert.False(t, ok)
	_, ok = RetryInfoDelay(errors.New("plain"))
	assert.False(t, ok)
}

func TestRetryRPC_WaitsRetryInfoDelay(t *testing.T) {
	st, err := status.New(codes.ResourceExhausted, "busy").
		WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(50 * time.Millisecond)})
	require.NoError(t, err)

	calls := 0
	start := time.Now()
	err = RetryRPC(context.Background(), "op", func() error {
		calls++
		if calls == 1 {
			return st.Err()
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	assert.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
}
