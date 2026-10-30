// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/stretchr/testify/assert"
)

func TestOciZprEnforced(t *testing.T) {
	enforcingState := &ociZprState{
		enabled:   true,
		enforcing: map[string]bool{"zpr-prod": true},
	}

	tests := []struct {
		name       string
		state      *ociZprState
		attributes map[string]any
		want       bool
	}{
		{
			name:       "enforcing namespace on an onboarded tenancy",
			state:      enforcingState,
			attributes: map[string]any{"zpr-prod": map[string]any{"tier": "db"}},
			want:       true,
		},
		{
			// The distinction the whole field exists for: an audit-mode
			// namespace evaluates the policy and then admits the traffic, so
			// reporting it as enforcing would suppress a real exposure.
			name:       "audit-only namespace does not enforce",
			state:      enforcingState,
			attributes: map[string]any{"zpr-audit": map[string]any{"tier": "db"}},
			want:       false,
		},
		{
			// Equally load-bearing in the other direction: labels alone do
			// nothing until the tenancy has onboarded ZPR.
			name: "enforcing namespace but ZPR is switched off",
			state: &ociZprState{
				enabled:   false,
				enforcing: map[string]bool{"zpr-prod": true},
			},
			attributes: map[string]any{"zpr-prod": map[string]any{"tier": "db"}},
			want:       false,
		},
		{
			name:       "no attributes at all",
			state:      enforcingState,
			attributes: nil,
			want:       false,
		},
		{
			// A namespace key present but empty labels nothing, so it must not
			// count as governed.
			name:       "namespace key with no attributes under it",
			state:      enforcingState,
			attributes: map[string]any{"zpr-prod": map[string]any{}},
			want:       false,
		},
		{
			name:       "namespace value that is not a map is ignored",
			state:      enforcingState,
			attributes: map[string]any{"zpr-prod": "unexpected"},
			want:       false,
		},
		{
			name:       "one enforcing namespace among several is enough",
			state:      enforcingState,
			attributes: map[string]any{"zpr-audit": map[string]any{"a": "1"}, "zpr-prod": map[string]any{"b": "2"}},
			want:       true,
		},
		{
			name:       "namespace matching is case insensitive",
			state:      enforcingState,
			attributes: map[string]any{"ZPR-PROD": map[string]any{"tier": "db"}},
			want:       true,
		},
		{
			// A failed lookup yields the zero state. It must read as not
			// enforced so internetReachable keeps reporting the opening rather
			// than hiding it behind a control that was never confirmed.
			name:       "zero state fails open",
			state:      &ociZprState{enforcing: map[string]bool{}},
			attributes: map[string]any{"zpr-prod": map[string]any{"tier": "db"}},
			want:       false,
		},
		{
			name:       "nil state fails open",
			state:      nil,
			attributes: map[string]any{"zpr-prod": map[string]any{"tier": "db"}},
			want:       false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, ociZprEnforced(test.state, test.attributes))
		})
	}
}

// serviceError is the shape common.IsServiceError recognises, so the classifier
// can be exercised without reaching the API.
type serviceError struct {
	status int
	code   string
}

func (e serviceError) Error() string           { return e.code }
func (e serviceError) GetHTTPStatusCode() int  { return e.status }
func (e serviceError) GetMessage() string      { return e.code }
func (e serviceError) GetCode() string         { return e.code }
func (e serviceError) GetOpcRequestID() string { return "" }

var _ common.ServiceError = serviceError{}

func TestOciZprAbsent(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "404 means no configuration to read",
			err:  serviceError{status: 404, code: "NotAuthorizedOrNotFound"},
			want: true,
		},
		{
			// A permission gap must not be read as an absent service anywhere
			// else, and here 403 is a distinct status the API does use.
			name: "403 is not an absence",
			err:  serviceError{status: 403, code: "NotAuthorized"},
			want: false,
		},
		{
			name: "429 throttling is not an absence",
			err:  serviceError{status: 429, code: "TooManyRequests"},
			want: false,
		},
		{
			name: "500 is not an absence",
			err:  serviceError{status: 500, code: "InternalServerError"},
			want: false,
		},
		{
			// The classifier must not match a transport failure, or a network
			// blip would degrade to "ZPR not onboarded" for the whole scan.
			name: "a DNS failure is not an absence",
			err:  &net.DNSError{Err: "no such host", IsNotFound: true},
			want: false,
		},
		{
			name: "an unrelated error is not an absence",
			err:  errors.New("boom"),
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, ociZprAbsent(test.err))
		})
	}
}
