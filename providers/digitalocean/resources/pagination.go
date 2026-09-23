// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"
)

// listPerPage is the page size every paginated list requests. godo caps
// per_page at 200.
const listPerPage = 200

// listFunc is the shape of a paginated godo list method. Matching it exactly
// means a method value can be handed to paginate with no type annotation,
// because T is inferred from the method:
//
//	droplets, err := paginate(ctx, client.Droplets.List)
//
// List methods that take an extra argument (a parent id, a filter) are wrapped
// in a closure with the same shape.
type listFunc[T any] func(context.Context, *godo.ListOptions) ([]T, *godo.Response, error)

// paginate walks a godo list endpoint to completion and returns every item.
//
// It exists so the termination condition is written once. Hand-rolled loops
// have to re-derive it per lister, and the ways to get it wrong are quiet
// ones: breaking on the first page truncates a list with no error, and
// dereferencing a response godo did not return panics the provider, which
// takes down the whole scan rather than the one field.
func paginate[T any](ctx context.Context, list listFunc[T]) ([]T, error) {
	opt := &godo.ListOptions{PerPage: listPerPage}
	var all []T
	for {
		page, resp, err := list(ctx, opt)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)

		// godo returns a nil response alongside a nil error on endpoints that
		// answer with no pagination envelope, so every nil is checked before
		// anything is dereferenced.
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			return all, nil
		}

		current, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}

		// Stuck-cursor guard. An endpoint that ignores the page parameter
		// answers the same page forever while still advertising a next
		// link, and the loop above would then never terminate: the scan
		// hangs and the item list grows without bound. Requiring the
		// cursor to move forward turns that into a reported failure
		// instead, because silently returning the pages collected so far
		// would be a truncated list presented as a complete one.
		next := current + 1
		if next <= opt.Page {
			return nil, fmt.Errorf("pagination did not advance past page %d, so the endpoint is repeating a page", opt.Page)
		}
		opt.Page = next
	}
}

// tokenListFunc fetches one page of a page-token list endpoint. It returns
// the page's items and the token of the next page, empty on the last page.
type tokenListFunc[T any] func(ctx context.Context, pageToken string) ([]T, string, error)

// paginateToken walks a page-token list endpoint (the hosted agents APIs)
// to completion and returns every item.
//
// A token the loop has already requested means the endpoint is handing back
// a page it has served before; following it would never terminate, so it is
// reported as an error rather than returning a truncated list as complete.
func paginateToken[T any](ctx context.Context, list tokenListFunc[T]) ([]T, error) {
	var all []T
	seen := map[string]struct{}{}
	token := ""
	for {
		page, next, err := list(ctx, token)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if next == "" {
			return all, nil
		}
		if _, ok := seen[next]; ok || next == token {
			return nil, fmt.Errorf("pagination returned page token %q again, so the endpoint is repeating a page", next)
		}
		seen[token] = struct{}{}
		token = next
	}
}
