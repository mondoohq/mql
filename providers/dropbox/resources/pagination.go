// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// pagedFetch abstracts the Dropbox "list" + "list/continue" cursor pattern
// used by nearly every team/... list endpoint. first calls the initial list
// endpoint; next calls the continuation endpoint with the cursor returned by
// the previous call. Both return the page's items, the next cursor, and
// whether more pages remain. It works equally well for endpoints that expose
// a single reusable route (e.g. devices/list_members_devices), where the
// caller's first/next closures simply invoke that same route with and
// without a cursor.
func pagedFetch[T any](
	first func() ([]T, string, bool, error),
	next func(cursor string) ([]T, string, bool, error),
) ([]T, error) {
	items, cursor, hasMore, err := first()
	if err != nil {
		return nil, err
	}
	all := append([]T{}, items...)
	for hasMore {
		items, cursor, hasMore, err = next(cursor)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
	}
	return all, nil
}
