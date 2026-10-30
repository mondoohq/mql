// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	betaodataerrors "github.com/microsoftgraph/msgraph-beta-sdk-go/models/odataerrors"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

func odataErrWithCode(code string) *odataerrors.ODataError {
	payload := odataerrors.NewMainError()
	payload.SetCode(&code)
	err := odataerrors.NewODataError()
	err.SetErrorEscaped(payload)
	return err
}

func betaODataErrWithCode(code string) *betaodataerrors.ODataError {
	payload := betaodataerrors.NewMainError()
	payload.SetCode(&code)
	err := betaodataerrors.NewODataError()
	err.SetErrorEscaped(payload)
	return err
}

func TestGraphErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil error", nil, ""},
		{"plain error", errors.New("boom"), ""},
		{"v1 odata error", odataErrWithCode("Request_ResourceNotFound"), "Request_ResourceNotFound"},
		{"beta odata error", betaODataErrWithCode("Request_ResourceNotFound"), "Request_ResourceNotFound"},
		{"other v1 code", odataErrWithCode("Authorization_RequestDenied"), "Authorization_RequestDenied"},
		{"wrapped odata error", fmt.Errorf("fetching assignments: %w", odataErrWithCode("Request_ResourceNotFound")), "Request_ResourceNotFound"},
		{"odata error with no payload", odataerrors.NewODataError(), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, graphErrorCode(tc.err))
		})
	}
}

// The classifier gates a retry, so it must not fire on a transport failure --
// retrying without $expand would silently drop the principal detail from every
// assignment on what is really a network problem.
func TestIsResourceNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"v1 resource not found", odataErrWithCode("Request_ResourceNotFound"), true},
		{"beta resource not found", betaODataErrWithCode("Request_ResourceNotFound"), true},
		{"wrapped resource not found", fmt.Errorf("wrapped: %w", odataErrWithCode("Request_ResourceNotFound")), true},
		{"permission denied is not a missing resource", odataErrWithCode("Authorization_RequestDenied"), false},
		{"throttling is not a missing resource", odataErrWithCode("TooManyRequests"), false},
		{"transport error is not a missing resource", &net.DNSError{Err: "no such host"}, false},
		{"plain error", errors.New("Request_ResourceNotFound"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isResourceNotFound(tc.err))
		})
	}
}

func odataErrWithHeaders(status int, retryAfter string) *odataerrors.ODataError {
	err := odataErrWithCode("Error")
	err.ResponseStatusCode = status
	if retryAfter != "" {
		headers := abstractions.NewResponseHeaders()
		headers.Add("Retry-After", retryAfter)
		err.SetResponseHeaders(headers)
	}
	return err
}

func TestClassifyGraphErrorKinds(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want llx.ErrorKind
	}{
		{"401", odataErrWithHeaders(401, ""), llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{"403", odataErrWithHeaders(403, ""), llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"429", odataErrWithHeaders(429, ""), llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS},
		{"500", odataErrWithHeaders(500, ""), llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"503 beta", func() error {
			e := betaODataErrWithCode("ServiceUnavailable")
			e.ResponseStatusCode = 503
			return e
		}(), llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"wrapped 429", fmt.Errorf("listing: %w", odataErrWithHeaders(429, "")), llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS},
		{"404 stays unclassified", odataErrWithHeaders(404, ""), llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
		{"400 stays unclassified", odataErrWithHeaders(400, ""), llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
		{"transport failure stays unclassified", &net.DNSError{Err: "no such host"}, llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, llx.KindOf(classifyGraphError(tc.err, "Policy.Read.All")))
		})
	}
	assert.NoError(t, classifyGraphError(nil))
}

func TestClassifyGraphErrorRetryAfter(t *testing.T) {
	var classified *llx.Error
	assert.True(t, errors.As(classifyGraphError(odataErrWithHeaders(429, "17")), &classified))
	assert.Equal(t, 17*time.Second, classified.RetryAfter)

	classified = nil
	assert.True(t, errors.As(classifyGraphError(odataErrWithHeaders(429, "")), &classified))
	assert.Zero(t, classified.RetryAfter, "no header means no hint")
}

func TestGraphRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		header string
		want   time.Duration
		ok     bool
	}{
		{"seconds", "30", 30 * time.Second, true},
		{"seconds with spaces", " 5 ", 5 * time.Second, true},
		{"http date", now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second, true},
		{"date in the past", now.Add(-time.Minute).Format(http.TimeFormat), 0, false},
		{"zero seconds", "0", 0, false},
		{"negative seconds", "-3", 0, false},
		{"garbage", "soon", 0, false},
		{"absent", "", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, ok := graphRetryAfter(odataErrWithHeaders(429, tc.header), now)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, d)
		})
	}
	_, ok := graphRetryAfter(errors.New("plain"), now)
	assert.False(t, ok)

	// the beta SDK's ODataError carries its headers the same way
	beta := betaODataErrWithCode("TooManyRequests")
	beta.ResponseStatusCode = 429
	betaHeaders := abstractions.NewResponseHeaders()
	betaHeaders.Add("Retry-After", "12")
	beta.SetResponseHeaders(betaHeaders)
	d, ok := graphRetryAfter(beta, now)
	assert.True(t, ok)
	assert.Equal(t, 12*time.Second, d)
}
