// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// strArray wraps a []string as an MQL string array.
func strArray(xs []string) *llx.RawData {
	res := make([]any, len(xs))
	for i := range xs {
		res[i] = xs[i]
	}
	return llx.ArrayData(res, types.String)
}

// idItem is the common {"id": "..."} shape NextDNS uses for simple lists
// (security TLDs, native tracker ecosystems, ...).
type idItem struct {
	ID string `json:"id"`
}

// idItemsToStrings extracts the ids from a list of idItem.
func idItemsToStrings(items []idItem) []string {
	res := make([]string, len(items))
	for i := range items {
		res[i] = items[i].ID
	}
	return res
}

// timeOrNil converts an optional timestamp to MQL data, returning nil when
// the source value is absent.
func timeOrNil(t *time.Time) *llx.RawData {
	if t == nil {
		return llx.NilData
	}
	return llx.TimeDataPtr(t)
}
