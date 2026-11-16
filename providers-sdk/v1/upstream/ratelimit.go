// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package upstream

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

const (
	rateLimitBaseBackoff = time.Second
	rateLimitMaxBackoff  = 60 * time.Second
)

// ErrRateLimitBudgetSpent marks an error returned once the budget ran out while
// the server kept refusing.
var ErrRateLimitBudgetSpent = errors.New("rate-limit retry budget spent")

// Replaceable in tests.
var (
	rateLimitNow   = time.Now
	rateLimitSleep = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
)

// RetryRateLimited runs fn; while fn returns ResourceExhausted it waits (the
// server's RetryInfo delay, or a full-jitter backoff of at most 60s) and retries
// until the budget or ctx ends. Any other result, including nil, is returned
// as is. A wait that would cross the budget deadline is not taken; the error
// then wraps both ErrRateLimitBudgetSpent and the last refusal.
func RetryRateLimited(ctx context.Context, what string, budget time.Duration, fn func() error) error {
	deadline := rateLimitNow().Add(budget)
	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil || status.Code(err) != codes.ResourceExhausted {
			return err
		}
		wait, ok := RetryInfoDelay(err)
		if !ok {
			wait = rateLimitBackoff(attempt)
		}
		if rateLimitNow().Add(wait).After(deadline) {
			return fmt.Errorf("%s: %w: %w", what, ErrRateLimitBudgetSpent, err)
		}
		log.Info().Str("call", what).Dur("retry_in", wait).Msg("Mondoo Platform is busy, retrying later")
		if serr := rateLimitSleep(ctx, wait); serr != nil {
			return fmt.Errorf("%s: %w (last error: %v)", what, serr, err)
		}
	}
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

// rateLimitBackoff is exponential from 1s with full jitter, capped at 60s.
func rateLimitBackoff(attempt int) time.Duration {
	d := rateLimitMaxBackoff
	if shift := attempt - 1; shift < 62 {
		if scaled := rateLimitBaseBackoff * (1 << shift); scaled > 0 && scaled < rateLimitMaxBackoff {
			d = scaled
		}
	}
	return time.Duration(rand.Int64N(int64(d)) + 1) //nolint:gosec // jitter, not security-sensitive
}
