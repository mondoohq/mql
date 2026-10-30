// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/databricks/databricks-sdk-go/apierr"
)

// The classifiers below decide whether a failed read reports null ("I was not
// allowed to look"), an empty collection ("the feature is not here"), or an
// error. Getting that wrong in the permissive direction is what makes a
// security check pass on data nobody read, so each case is pinned, including
// the one that matters most: a transport failure is not a server answer and
// must classify as neither.

func TestDatabricksStatusCode(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantOK  bool
		wantVal int
	}{
		{name: "nil error", err: nil, wantOK: false},
		{
			name:    "plain api error",
			err:     &apierr.APIError{StatusCode: 403, ErrorCode: "PERMISSION_DENIED"},
			wantOK:  true,
			wantVal: 403,
		},
		{
			name:    "wrapped api error",
			err:     fmt.Errorf("listing functions: %w", &apierr.APIError{StatusCode: 404}),
			wantOK:  true,
			wantVal: 404,
		},
		{
			// A dropped connection is not something the server said. Reporting
			// a status for it would let a network blip degrade a field to null
			// or to an empty list, and the audit over it would pass.
			name:   "transport error is not an api error",
			err:    &net.OpError{Op: "dial", Err: errors.New("connection refused")},
			wantOK: false,
		},
		{
			name:   "context cancellation is not an api error",
			err:    context.Canceled,
			wantOK: false,
		},
		{
			name:   "plain error",
			err:    errors.New("something went wrong"),
			wantOK: false,
		},
		{
			// An APIError carrying no status never came from a response we can
			// read a verdict out of.
			name:   "api error with no status",
			err:    &apierr.APIError{ErrorCode: "IO_ERROR"},
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := databricksStatusCode(tc.err)
			if ok != tc.wantOK {
				t.Fatalf("databricksStatusCode() ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.wantVal {
				t.Fatalf("databricksStatusCode() = %d, want %d", got, tc.wantVal)
			}
		})
	}
}

func TestIsDatabricksUnreadable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "unauthorized", err: &apierr.APIError{StatusCode: 401}, want: true},
		{name: "forbidden", err: &apierr.APIError{StatusCode: 403}, want: true},
		{name: "wrapped forbidden", err: fmt.Errorf("wrapped: %w", &apierr.APIError{StatusCode: 403}), want: true},
		// 404 is a genuine absence, not a permission failure: it must not turn
		// a missing feature into a null posture verdict.
		{name: "not found is not a permission failure", err: &apierr.APIError{StatusCode: 404}, want: false},
		{name: "bad request", err: &apierr.APIError{StatusCode: 400}, want: false},
		{name: "rate limited", err: &apierr.APIError{StatusCode: 429}, want: false},
		{name: "server error", err: &apierr.APIError{StatusCode: 500}, want: false},
		{name: "transport error", err: &net.OpError{Op: "read", Err: errors.New("reset by peer")}, want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDatabricksUnreadable(tc.err); got != tc.want {
				t.Fatalf("isDatabricksUnreadable() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsDatabricksFeatureUnavailable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "securable not enabled", err: &apierr.APIError{StatusCode: 400}, want: true},
		{name: "endpoint not served", err: &apierr.APIError{StatusCode: 404}, want: true},
		{name: "not implemented", err: &apierr.APIError{StatusCode: 501}, want: true},
		// A permission failure must never read as "the feature is not here",
		// which would turn it into an empty list.
		{name: "forbidden is not an absent feature", err: &apierr.APIError{StatusCode: 403}, want: false},
		{name: "unauthorized is not an absent feature", err: &apierr.APIError{StatusCode: 401}, want: false},
		{name: "rate limited", err: &apierr.APIError{StatusCode: 429}, want: false},
		{name: "server error", err: &apierr.APIError{StatusCode: 503}, want: false},
		{name: "transport error", err: &net.OpError{Op: "dial", Err: errors.New("no route to host")}, want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDatabricksFeatureUnavailable(tc.err); got != tc.want {
				t.Fatalf("isDatabricksFeatureUnavailable() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The two classifiers must not overlap. If a status could be read as both an
// absent feature and a permission failure, the same error would produce an
// empty list on one field and a null on another.
func TestClassifiersAreDisjoint(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 409, 429, 500, 501, 503} {
		err := &apierr.APIError{StatusCode: code}
		if isDatabricksUnreadable(err) && isDatabricksFeatureUnavailable(err) {
			t.Fatalf("status %d classifies as both unreadable and feature-unavailable", code)
		}
	}
}
