// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ociTestServiceError is a stand-in for the SDK's service error. The SDK's own
// type is unexported behind common.IsServiceError, which matches on this
// interface, so implementing it is the only way to build one in a test.
type ociTestServiceError struct {
	status int
	code   string
	msg    string
}

func (e ociTestServiceError) Error() string           { return e.msg }
func (e ociTestServiceError) GetHTTPStatusCode() int  { return e.status }
func (e ociTestServiceError) GetMessage() string      { return e.msg }
func (e ociTestServiceError) GetCode() string         { return e.code }
func (e ociTestServiceError) GetOpcRequestID() string { return "test-request-id" }

func TestOciCloudGuardNotSubscribed(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			// The regression this guards. A tenancy that never onboarded Cloud
			// Guard answers every call this way, and it is the most common state
			// to query, so it has to read as "off" rather than as a failure.
			name: "not subscribed",
			err: ociTestServiceError{
				status: http.StatusNotFound,
				code:   "NotAuthorizedOrNotFound",
				msg:    "Cloudguard subscription is not available",
			},
			want: true,
		},
		{
			// Must NOT be swallowed: an under-scoped token would otherwise be
			// reported as a clean "Cloud Guard is disabled".
			name: "authorization failure",
			err: ociTestServiceError{
				status: http.StatusForbidden,
				code:   "NotAuthorizedOrNotFound",
				msg:    "not authorized",
			},
			want: false,
		},
		{
			name: "bad credentials",
			err:  ociTestServiceError{status: http.StatusUnauthorized, code: "NotAuthenticated", msg: "bad key"},
			want: false,
		},
		{
			name: "throttled",
			err:  ociTestServiceError{status: http.StatusTooManyRequests, code: "TooManyRequests", msg: "slow down"},
			want: false,
		},
		{
			name: "malformed request",
			err:  ociTestServiceError{status: http.StatusBadRequest, code: "InvalidParameter", msg: "bad params"},
			want: false,
		},
		{"transport error", errors.New("connection refused"), false},
		{"no error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociCloudGuardNotSubscribed(tt.err))
		})
	}
}

func TestOciReferentGone(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "service 404",
			err:  ociTestServiceError{status: http.StatusNotFound, code: "BucketNotFound", msg: "gone"},
			want: true,
		},
		{
			// An ONS topic is resolved by scanning the listing, not by a GET, so
			// its absence arrives as a sentinel with no HTTP status attached.
			// Before this was recognised, one connector pointing at a deleted
			// topic failed the whole connector listing.
			name: "ons topic sentinel",
			err:  fmt.Errorf("%w: %s", errOciOnsTopicNotFound, "ocid1.onstopic.oc1.phx.example"),
			want: true,
		},
		{"bare sentinel", errOciOnsTopicNotFound, true},
		{
			name: "authorization failure is not absence",
			err:  ociTestServiceError{status: http.StatusForbidden, code: "NotAuthorizedOrNotFound", msg: "denied"},
			want: false,
		},
		{"unrelated error", errors.New("connection refused"), false},
		{"no error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociReferentGone(tt.err))
		})
	}
}
