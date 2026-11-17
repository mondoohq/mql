// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package upstream

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

// Retry tuning for upstream calls. Transient failures (network blips, 5xx, 429,
// transient RPC codes) are retried with bounded exponential backoff and full
// jitter rather than failing the whole operation.
const (
	// DefaultRetryAttempts is the maximum number of attempts WithRetry makes.
	DefaultRetryAttempts = 5

	retryBaseBackoff = 500 * time.Millisecond
	retryMaxBackoff  = 30 * time.Second
)

// WithRetry runs fn up to DefaultRetryAttempts times. fn reports whether its
// error is retryable and an optional explicit wait (e.g. a parsed Retry-After
// header). Backoff is exponential with full jitter, capped at retryMaxBackoff,
// and aborts promptly on context cancellation. A nil error returns immediately;
// `what` labels the operation in the returned error.
func WithRetry(ctx context.Context, what string, fn func() (retryable bool, retryAfter time.Duration, err error)) error {
	var lastErr error
	for attempt := 1; attempt <= DefaultRetryAttempts; attempt++ {
		retryable, retryAfter, err := fn()
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable || attempt == DefaultRetryAttempts {
			break
		}
		wait := retryAfter
		if wait <= 0 {
			wait = retryBackoff(attempt)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: %w (after %d attempt(s), last error: %v)", what, ctx.Err(), attempt, lastErr)
		case <-time.After(wait):
		}
	}
	return fmt.Errorf("%s (after %d attempt(s)): %w", what, DefaultRetryAttempts, lastErr)
}

// RetryRPC retries a Mondoo upstream RPC on transient errors (see
// RetryableRPCError) with bounded exponential backoff, or with the server's
// RetryInfo delay when the error carries one. Permanent errors
// (Unauthenticated, PermissionDenied, InvalidArgument, NotFound, …) fail fast
// without spending the attempt budget. The call must be idempotent — the caller
// is responsible for only wrapping RPCs that are safe to repeat.
func RetryRPC(ctx context.Context, what string, fn func() error) error {
	return WithRetry(ctx, what, func() (bool, time.Duration, error) {
		err := fn()
		wait, _ := RetryInfoDelay(err)
		return RetryableRPCError(err), wait, err
	})
}

// RetryInfoDelay extracts google.rpc.RetryInfo.retry_delay from a ranger status
// error. It reports false when there is no positive delay.
func RetryInfoDelay(err error) (time.Duration, bool) {
	st, ok := status.FromError(err)
	if !ok {
		return 0, false
	}
	for _, d := range st.Details() {
		if ri, ok := d.(*errdetails.RetryInfo); ok {
			if delay := ri.GetRetryDelay().AsDuration(); delay > 0 {
				return delay, true
			}
		}
	}
	return 0, false
}

// RetryableRPCError reports whether a ranger RPC error is transient and worth
// retrying. A nil error is not retryable. Transient codes (Unavailable,
// DeadlineExceeded, ResourceExhausted, Aborted) cover backend hiccups and
// overload; Unknown covers raw transport/network failures that never carry a
// ranger status. Permanent codes fail fast.
func RetryableRPCError(err error) bool {
	if err == nil {
		return false
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted,
		codes.Aborted, codes.Unknown:
		return true
	default:
		return false
	}
}

// RetryableHTTPStatus reports whether an HTTP response status warrants a retry:
// 429 (rate limited) and any 5xx (transient server/storage error). Other 4xx
// are permanent (bad request, auth, expired URL) and are not retried.
func RetryableHTTPStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// RetryAfter parses a Retry-After header (delay-seconds form) into a duration,
// returning 0 when absent or unparseable so the caller falls back to backoff.
func RetryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// retryBackoff returns the exponential-with-full-jitter delay for the given
// attempt (1-based), capped at retryMaxBackoff. Jitter spreads retries across a
// fleet so they don't synchronize into a thundering herd.
func retryBackoff(attempt int) time.Duration {
	// Guard against shift/multiply overflow (which would wrap to a negative
	// duration) for large attempts: clamp to retryMaxBackoff.
	d := retryMaxBackoff
	if shift := attempt - 1; shift < 62 {
		if scaled := retryBaseBackoff * (1 << shift); scaled > 0 && scaled < retryMaxBackoff {
			d = scaled
		}
	}
	return time.Duration(rand.Int64N(int64(d)) + 1) //nolint:gosec // jitter, not security-sensitive
}
