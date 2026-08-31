// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"regexp"
	"sync"
	"sync/atomic"
)

// regexCacheMax bounds the number of cached patterns. A pattern usually comes from a policy
// literal, so the number of distinct patterns is small. A pattern can also come from scanned
// data, so the cache must not grow without a limit.
const regexCacheMax = 128

var (
	regexCache    sync.Map // map[string]*regexp.Regexp
	regexCacheLen atomic.Int64
)

// compiledRegex returns the compiled form of pattern. The regex operators run once per array
// element, and the pattern is the same for every element, so compiling it once per operator
// call is wasteful. Compiling a pattern allocates about 12 KB.
//
// It panics on an invalid pattern, exactly like the regexp.MustCompile call it replaces.
func compiledRegex(pattern string) *regexp.Regexp {
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}

	r := regexp.MustCompile(pattern)

	// Stop storing once the cache is full. The check is intentionally lock-free. Concurrent
	// callers can pass it before LoadOrStore updates the counter, so the cache holds
	// approximately regexCacheMax patterns for the life of the process.
	if regexCacheLen.Load() < regexCacheMax {
		if _, loaded := regexCache.LoadOrStore(pattern, r); !loaded {
			regexCacheLen.Add(1)
		}
	}
	return r
}
