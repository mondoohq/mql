// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.mondoo.com/mql/llx"
)

// classifyStatus maps a Rippling API error response to its ADR 046 kind. A
// status that names no kind is returned unchanged, since an unclassified error
// is better than a wrong kind. That includes 404: every path read here is a
// fixed, company-wide list, and Rippling does not document what a 404 from one
// means.
func classifyStatus(err error, status int, header http.Header, now time.Time) error {
	switch {
	case status == http.StatusUnauthorized:
		return llx.Unauthenticated(err)
	case status == http.StatusForbidden:
		return llx.Forbidden(err)
	case status == http.StatusTooManyRequests:
		if d, ok := parseRetryAfter(header.Get("Retry-After"), now); ok && d > 0 {
			return llx.TooManyRequests(err, llx.WithRetryAfter(d))
		}
		return llx.TooManyRequests(err)
	case status >= 500:
		return llx.Unavailable(err)
	}
	return err
}

// classifyTransport maps a request that got no HTTP answer at all. Only a
// timeout and a refused connection are classified, as Unavailable; a cancelled
// query, a DNS failure, a TLS error or a failed token exchange is returned
// unchanged.
func classifyTransport(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ECONNREFUSED) {
		return llx.Unavailable(err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return llx.Unavailable(err)
	}
	return err
}

// parseRetryAfter decodes a Retry-After header in either RFC 9110 form
// (delay-seconds or HTTP-date). ok is false when the header is absent or in
// neither form.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second, true
	}
	if t, err := http.ParseTime(value); err == nil {
		return t.Sub(now), true
	}
	return 0, false
}
