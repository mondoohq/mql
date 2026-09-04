// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package syncx

import "sync"

type Map[T any] struct {
	sync.Map
}

func (r *Map[T]) Get(key string) (T, bool) {
	res, ok := r.Load(key)
	if !ok {
		var zero T
		return zero, ok
	}
	return res.(T), true
}

func (r *Map[T]) Set(key string, value T) {
	r.Store(key, value)
}

// GetOrSet returns the value already stored under the key, if there is one.
// Otherwise it stores the given value and returns that. The second return
// value reports whether the key was already present.
//
// Use this instead of a Get followed by a Set whenever the value is a shared
// object with an identity: the Get/Set pair is a check-then-act race, so two
// callers that both miss the Get will both Set and hand out two different
// objects for one key. GetOrSet is atomic, so every caller converges on the
// same instance.
func (r *Map[T]) GetOrSet(key string, value T) (T, bool) {
	res, loaded := r.LoadOrStore(key, value)
	return res.(T), loaded
}
