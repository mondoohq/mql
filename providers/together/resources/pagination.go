// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/togethercomputer/together-go/packages/pagination"
)

// collectPages walks every page of a cursor-paginated list, starting from the
// first page and the error of the call that fetched it, and returns all items.
//
// The SDK's auto-pager follows next_cursor for as long as the server returns
// one, so a server that hands back a cursor it already returned would page
// forever. A repeated cursor is reported as an error instead of being
// followed: returning the pages read so far would report a partial list as if
// it were complete.
func collectPages[T any](page *pagination.CursorPagination[T], err error) ([]T, error) {
	if err != nil {
		return nil, err
	}

	var items []T
	seen := map[string]struct{}{}
	for page != nil {
		items = append(items, page.Data...)
		next := page.NextCursor
		if len(page.Data) == 0 || next == "" {
			break
		}
		if _, dup := seen[next]; dup {
			return nil, fmt.Errorf("together: list pagination returned cursor %q twice", next)
		}
		seen[next] = struct{}{}

		page, err = page.GetNextPage()
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}
