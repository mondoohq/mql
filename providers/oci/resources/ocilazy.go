// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"sync/atomic"
)

// Most OCI list APIs return a summary. The fields an audit actually wants -
// a bastion's client CIDR allow list, a tunnel's negotiated crypto, a
// connector's source and target - come from a per-resource Get call that the
// listing does not make. So a handful of computed fields on the same resource
// share one deferred fetch, and because the executor resolves fields
// concurrently that fetch has to be guarded.
//
// Every one of those sites had hand-rolled the same double-checked lock. The
// three types here are that idiom, written once.
//
// The guard is an atomic.Bool rather than a plain bool because the fast path
// reads it before taking the mutex, and a plain read racing the locked write is
// a data race. The atomic also carries the happens-before edge that makes the
// cached value safe to read unlocked: a goroutine observing the flag as true is
// guaranteed to see every write sequenced before it was stored.
//
// The types differ only in what they do with a failure, and that difference is
// deliberate:
//
//   - ociLazy remembers the error. A resource the caller is not allowed to read
//     is asked for once, not once per field sharing the fetch.
//   - ociRetryLazy and ociOnce remember only success, so a transient failure is
//     retried by the next accessor rather than being reported for the rest of
//     the scan.
//
// Both policies were already in the provider, split across files with nothing
// marking which was which. Picking one for every site would change results, so
// the choice stays where it is - but it is now stated by the field's type
// instead of being a property of whoever wrote that file.

// ociOnce guards a fetch that populates the resource's fields directly rather
// than returning a value. Only success is remembered; see the note above.
type ociOnce struct {
	lock sync.Mutex
	done atomic.Bool
}

// do runs fetch at most once successfully. Concurrent callers arriving during
// the fetch block until it finishes and then observe its result.
func (o *ociOnce) do(fetch func() error) error {
	if o.done.Load() {
		return nil
	}

	o.lock.Lock()
	defer o.lock.Unlock()
	if o.done.Load() {
		return nil
	}

	if err := fetch(); err != nil {
		return err
	}
	o.done.Store(true)
	return nil
}

// ociLazy caches the value of a deferred detail fetch together with its error,
// so a fetch that fails is not repeated by the other fields sharing it.
type ociLazy[T any] struct {
	lock sync.Mutex
	done atomic.Bool
	val  T
	err  error
}

// get runs fetch at most once and returns its result to every caller.
func (l *ociLazy[T]) get(fetch func() (T, error)) (T, error) {
	if l.done.Load() {
		return l.val, l.err
	}

	l.lock.Lock()
	defer l.lock.Unlock()
	if l.done.Load() {
		return l.val, l.err
	}

	l.val, l.err = fetch()
	l.done.Store(true)
	return l.val, l.err
}

// ociRetryLazy caches the value of a deferred detail fetch, remembering only
// success, so a transient failure is retried by the next accessor.
type ociRetryLazy[T any] struct {
	once ociOnce
	val  T
}

// get runs fetch until it succeeds once, then returns the cached value to every
// later caller. A failing fetch returns the zero value alongside its error.
func (l *ociRetryLazy[T]) get(fetch func() (T, error)) (T, error) {
	err := l.once.do(func() error {
		v, err := fetch()
		if err != nil {
			return err
		}
		l.val = v
		return nil
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return l.val, nil
}
