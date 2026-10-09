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

// Range calls f for each key and value in the map, stopping when f returns
// false. It shadows sync.Map's Range, which hands back untyped values.
func (r *Map[T]) Range(f func(key string, value T) bool) {
	r.Map.Range(func(k, v any) bool {
		return f(k.(string), v.(T))
	})
}
