// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"net"
	"net/http"
	"syscall"
	"time"

	"go.mondoo.com/mql/llx"
)

// classifyStatus maps a Gusto API error response to its ADR 046 kind. A status
// that names no kind (400, 409, 422, ...) is returned unchanged, since an
// unclassified error is better than a wrong kind.
//
// Every Gusto path this provider reads names a company, so a 404 means the
// company it asked about could not be read: NotFound, not an empty answer.
func classifyStatus(err error, status int, header http.Header, now time.Time) error {
	switch {
	case status == http.StatusUnauthorized:
		return llx.Unauthenticated(err)
	case status == http.StatusForbidden:
		return llx.Forbidden(err)
	case status == http.StatusNotFound:
		return llx.NotFound(err)
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
// query, a DNS failure or a TLS error is returned unchanged.
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
