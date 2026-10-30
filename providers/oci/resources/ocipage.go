// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
)

// OCI paginates almost every list API the same way: the request carries an
// opaque `Page` token and the response returns the next one as `OpcNextPage`,
// nil when the collection is exhausted. That uniformity is why one helper can
// cover the whole provider.
//
// It replaces a loop that was hand-written at every list call in this package.
// Each copy was correct, but the shape has a silent failure mode: leave the
// loop out and the lister returns the first page and looks like a complete
// answer. An inventory tool reporting a confident subset is worse than one
// reporting an error, and nothing about a missing loop looks wrong on review.
// Going through a helper makes the paging a property of the call rather than
// something each author has to remember.

// ociPaginate collects every page of an OCI list call.
//
// The callback issues one request for the given page token - nil on the first
// call - and returns that page's items along with the next token. Returning a
// nil token ends the walk.
//
// An error ends the walk and discards what was collected. That is deliberate:
// a partial list that is indistinguishable from a complete one is exactly the
// outcome the callers' error handling is built to avoid, and the pool wrappers
// upstream decide which failures are expected (an absent regional endpoint, an
// unreadable compartment) and which under-report resources.
func ociPaginate[T any](ctx context.Context, page func(ctx context.Context, page *string) ([]T, *string, error)) ([]T, error) {
	var items []T
	var cursor *string
	for {
		batch, next, err := page(ctx, cursor)
		if err != nil {
			return nil, err
		}
		items = append(items, batch...)
		if next == nil {
			return items, nil
		}
		// A cursor that does not advance is the one shape this loop cannot
		// survive: the same page is requested forever, items grows without
		// bound, and the scan hangs with no error to attribute it to. OCI page
		// cursors are opaque but must move, so an unchanged one is a broken
		// response rather than a signal to keep asking. Reported rather than
		// truncated, for the same reason an error discards the partial result
		// above - a silently short list is indistinguishable from a complete
		// one.
		//
		// A plain comparison is correct here. The cursor is an opaque
		// continuation marker the service just handed back, not a credential
		// being authenticated, and it is compared only against the value this
		// same loop sent - so there is no secret for a timing side channel to
		// leak.
		if cursor != nil && *next == *cursor {
			return nil, errors.New("oci: pagination did not advance, the service returned the same page cursor twice")
		}
		cursor = next
	}
}

// ociScimPaginate collects every page of a SCIM list call against an identity
// domain.
//
// The identity-domains API does not use OCI's page tokens. It is SCIM, so
// paging is a 1-based `startIndex` with a `count`, and the response reports
// `totalResults` rather than a next-page token. ociScimNextIndex owns the
// termination rule, including the case where a domain omits totalResults
// entirely and a short page is the only signal that the collection is done.
//
// The callback returns the page's resources and the response's totalResults so
// that the caller keeps control of which field of the SCIM envelope to read -
// each list wraps its resources under a differently named member - and of how
// to wrap the error, which carries the domain name for attribution.
func ociScimPaginate[T any](ctx context.Context, page func(ctx context.Context, startIndex int) ([]T, *int, error)) ([]T, error) {
	var items []T
	startIndex := 1
	for {
		batch, total, err := page(ctx, startIndex)
		if err != nil {
			return nil, err
		}
		items = append(items, batch...)
		next, more := ociScimNextIndex(startIndex, len(batch), total, ociScimPageSize)
		if !more {
			return items, nil
		}
		startIndex = next
	}
}
