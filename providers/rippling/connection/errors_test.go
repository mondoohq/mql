// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"

	"go.mondoo.com/mql/llx"
)

func TestClassifyStatus(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		status int
		want   llx.ErrorKind
	}{
		{http.StatusUnauthorized, llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{http.StatusForbidden, llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{http.StatusTooManyRequests, llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS},
		{http.StatusInternalServerError, llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{http.StatusGatewayTimeout, llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		// Statuses that name no kind stay unclassified.
		{http.StatusBadRequest, llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
		{http.StatusNotFound, llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			base := fmt.Errorf("rippling API /x returned %d", tc.status)
			err := classifyStatus(base, tc.status, http.Header{}, now)
			if got := llx.KindOf(err); got != tc.want {
				t.Fatalf("kind = %v, want %v", got, tc.want)
			}
			if !errors.Is(err, base) {
				t.Fatalf("classified error %v no longer wraps the API error", err)
			}
		})
	}
}

func TestClassifyStatusRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	retryAfterOf := func(header string) time.Duration {
		h := http.Header{}
		if header != "" {
			h.Set("Retry-After", header)
		}
		var e *llx.Error
		if !errors.As(classifyStatus(errors.New("429"), http.StatusTooManyRequests, h, now), &e) {
			t.Fatalf("Retry-After %q: 429 was not classified", header)
		}
		return e.RetryAfter
	}
	if got := retryAfterOf("7"); got != 7*time.Second {
		t.Errorf("seconds form: RetryAfter = %v, want 7s", got)
	}
	if got := retryAfterOf(now.Add(90 * time.Second).Format(http.TimeFormat)); got != 90*time.Second {
		t.Errorf("HTTP-date form: RetryAfter = %v, want 90s", got)
	}
	if got := retryAfterOf(""); got != 0 {
		t.Errorf("no header: RetryAfter = %v, want 0", got)
	}
	if got := retryAfterOf("soon"); got != 0 {
		t.Errorf("unparsable header: RetryAfter = %v, want 0", got)
	}
	if got := retryAfterOf(now.Add(-time.Minute).Format(http.TimeFormat)); got != 0 {
		t.Errorf("date in the past: RetryAfter = %v, want 0", got)
	}
}

func TestClassifyTransport(t *testing.T) {
	refused := &url.Error{Op: "Get", URL: "https://api.rippling.com", Err: &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}
	timeout := &url.Error{Op: "Get", URL: "https://api.rippling.com", Err: &net.DNSError{Err: "i/o timeout", IsTimeout: true}}
	dnsMiss := &url.Error{Op: "Get", URL: "https://api.rippling.com", Err: &net.DNSError{Err: "no such host", IsNotFound: true}}
	cases := []struct {
		name string
		err  error
		want llx.ErrorKind
	}{
		{"connection refused", refused, llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"timeout", timeout, llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"deadline", fmt.Errorf("get: %w", context.DeadlineExceeded), llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		// A transport failure is never a refusal by the API.
		{"dns failure", dnsMiss, llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
		{"cancelled", fmt.Errorf("get: %w", context.Canceled), llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
		{"tls", errors.New("tls: failed to verify certificate"), llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := llx.KindOf(classifyTransport(tc.err)); got != tc.want {
				t.Fatalf("kind = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRequestsClassifyErrors pins that classification is wired into both
// request paths: a refused call reaches the resource as an error of the right
// kind, never as an empty list or a blank company.
func TestRequestsClassifyErrors(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		want    llx.ErrorKind
	}{
		{"unauthorized", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}, llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{"forbidden", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}, llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"rate limited", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
		}, llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS},
		{"server error", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}, llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"undecodable body", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"not":"a list"}`)
		}, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/list", func(t *testing.T) {
			c, closeFn := testConn(t, tc.handler)
			defer closeFn()
			_, err := getPaginated[Employee](context.Background(), c, "/platform/api/employees")
			if got := llx.KindOf(err); got != tc.want {
				t.Fatalf("kind = %v (err %v), want %v", got, err, tc.want)
			}
		})
		t.Run(tc.name+"/company", func(t *testing.T) {
			c, closeFn := testConn(t, tc.handler)
			defer closeFn()
			_, err := c.GetCompany(context.Background())
			if got := llx.KindOf(err); got != tc.want {
				t.Fatalf("kind = %v (err %v), want %v", got, err, tc.want)
			}
		})
	}
}
