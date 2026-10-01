// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/packages/pagination"
	"go.mondoo.com/mql/llx"
)

// notFoundMeaning says what a 404 from an Admin API call means for the
// question being asked.
type notFoundMeaning int

const (
	// endpointUnavailable is a 404 from a fixed organization path. The
	// Enterprise-only endpoints (RBAC, plugins, spend limits) answer 404 to an
	// organization they are not offered to, exactly as if they did not exist,
	// so the question does not apply to this organization.
	endpointUnavailable notFoundMeaning = iota
	// parentMissing is a 404 from a path naming a parent object, such as a
	// group's member list. The parent is gone, so the call could not answer.
	parentMissing
)

// classifyAdminError maps a refused Admin API call to its ADR 046 kind. An
// error the API did not answer with a status, such as a transport failure, is
// returned unchanged.
func classifyAdminError(err error, on404 notFoundMeaning, permissions ...string) error {
	if err == nil {
		return nil
	}
	var apiErr *anthropic.Error
	if !errors.As(err, &apiErr) {
		return err
	}

	switch status := apiErr.StatusCode; {
	case status == http.StatusUnauthorized:
		return llx.Unauthenticated(err)
	case status == http.StatusForbidden:
		if len(permissions) > 0 {
			return llx.Forbidden(err, llx.WithPermissions(permissions...))
		}
		return llx.Forbidden(err)
	case status == http.StatusNotFound:
		if on404 == endpointUnavailable {
			return llx.NotApplicable(err)
		}
		return llx.NotFound(err)
	case status == http.StatusTooManyRequests:
		if d, ok := retryAfter(apiErr.Response); ok {
			return llx.TooManyRequests(err, llx.WithRetryAfter(d))
		}
		return llx.TooManyRequests(err)
	case status >= 500:
		return llx.Unavailable(err)
	}
	return err
}

// retryAfter reads a Retry-After header given in seconds.
func retryAfter(resp *http.Response) (time.Duration, bool) {
	if resp == nil {
		return 0, false
	}
	secs, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || secs < 0 {
		return 0, false
	}
	return time.Duration(secs) * time.Second, true
}

// maxAdminPages bounds a cursor walk. At the page sizes requested here it is
// far beyond any real organization, and it stops a server that keeps handing
// out cursors from holding a scan forever.
const maxAdminPages = 1000

// collectCursorPages walks a next_page cursor listing to its end.
//
// The SDK's auto-pager follows next_page for as long as the server hands one
// out. A cursor the server repeats would loop forever, so a repeated cursor and
// a walk past maxAdminPages are reported as errors rather than as a silently
// shortened list, which every assertion over the list would accept.
func collectCursorPages[T any](page *pagination.PageCursor[T], err error) ([]T, error) {
	if err != nil {
		return nil, err
	}
	all := []T{}
	seen := map[string]bool{}
	for pages := 1; page != nil; pages++ {
		all = append(all, page.Data...)
		next := page.NextPage
		if next == "" || len(page.Data) == 0 {
			break
		}
		if seen[next] {
			return nil, llx.MalformedData(fmt.Errorf("pagination cursor %q was returned twice", next))
		}
		if pages >= maxAdminPages {
			return nil, fmt.Errorf("stopped after %d pages without reaching the end of the list", maxAdminPages)
		}
		seen[next] = true
		page, err = page.GetNextPage()
		if err != nil {
			return nil, err
		}
	}
	return all, nil
}
