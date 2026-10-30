// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers/zoom/connection"
)

func (r *mqlZoom) id() (string, error) {
	return "zoom", nil
}

// conn returns the Zoom connection backing this runtime.
func (r *mqlZoom) conn() *connection.ZoomConnection {
	return r.MqlRuntime.Connection.(*connection.ZoomConnection)
}

// strToAnyList converts a []string into an MQL string-array value, treating
// a nil slice as an empty list.
func strToAnyList(s []string) []any {
	res := make([]any, 0, len(s))
	for _, v := range s {
		res = append(res, v)
	}
	return res
}

// intToAnyList converts an []int64 into an MQL int-array value, treating a nil
// slice as an empty list.
func intToAnyList(s []int64) []any {
	res := make([]any, 0, len(s))
	for _, v := range s {
		res = append(res, v)
	}
	return res
}
