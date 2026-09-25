// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"sync/atomic"

	"go.mondoo.com/mql"
)

// structuredErrors holds the StructuredErrors feature for the whole provider
// process (ADR 046 §9). It is process-wide because the call sites that read
// it have no connection or context at hand, and because the client sends one
// feature set per scan.
var structuredErrors atomic.Bool

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
func ReadFeatures(features []byte) {
	if len(features) == 0 {
		return
	}
	structuredErrors.Store(mql.Features(features).IsActive(mql.StructuredErrors))
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
	return structuredErrors.Load()
}
