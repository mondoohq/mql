// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"bytes"
	"sync/atomic"

	"go.mondoo.com/mql"
)

// features holds the scan's features for the whole provider process. It is
// process-wide because the call sites that read it (StructuredErrors, ADR 046
// §9, or a native Windows path) have no connection or context at hand, and
// because the client sends one feature set per scan.
var features atomic.Pointer[mql.Features]

// ReadFeatures records the features a Connect request carried. The SDK calls
// it for every Connect and MockConnect it serves, so a provider running in its
// own process never has to. An in-process provider is covered by the runtime
// that connects it.
//
// A request without features says nothing about them and leaves the current
// value alone. Not every Connect forwards the scan's features (delayed
// discovery connects with the asset alone), and letting such a request turn
// the flag off would switch a provider back to v13 behavior halfway through
// a scan. A request with features always decides, so a long-running process
// picks up a flag that was turned off again.
func ReadFeatures(b []byte) {
	if len(b) == 0 {
		return
	}
	f := mql.Features(bytes.Clone(b))
	features.Store(&f)
}

// FeatureActive reports whether the scan's features include f. It is false
// until a Connect request carried features.
func FeatureActive(f mql.Feature) bool {
	cur := features.Load()
	return cur != nil && cur.IsActive(f)
}

// StructuredErrors reports whether a refusal is returned as a classified error
// (ADR 046 §9). Off, a migrated call site returns what it returned in v13:
//
//	if err != nil {
//		if !plugin.StructuredErrors() && Is400AccessDeniedError(err) {
//			return []any{}, nil // v13 behavior
//		}
//		return nil, classifyAwsError(err, "organizations:ListAccounts")
//	}
//
// In v15 the flag becomes the default and those branches are deleted.
func StructuredErrors() bool {
	return FeatureActive(mql.StructuredErrors)
}
