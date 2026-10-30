// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// cursorPager is the shape of the openai-go auto-pagers. Every cursor
// paginated list endpoint hands one back, so a single walk covers all of them.
type cursorPager[T any] interface {
	Next() bool
	Current() T
	Err() error
}

// walkPages drives an openai-go auto-pager and stops as soon as an item
// identifier repeats.
//
// The auto-pager pages by setting `after` to the identifier of the last item it
// received, and it keeps going while the response says `has_more`. Neither the
// pager nor the SDK checks that the cursor advanced, so an endpoint that
// ignores `after` answers with the same page forever and the walk never
// returns: the scan hangs instead of failing. An identifier that has already
// been visited means the endpoint stopped making progress, which is the point
// to stop at.
func walkPages[T any](pager cursorPager[T], idOf func(T) string, visit func(T) error) error {
	seen := map[string]struct{}{}
	for pager.Next() {
		item := pager.Current()
		if id := idOf(item); id != "" {
			if _, duplicate := seen[id]; duplicate {
				break
			}
			seen[id] = struct{}{}
		}
		if err := visit(item); err != nil {
			return err
		}
	}
	return pager.Err()
}
