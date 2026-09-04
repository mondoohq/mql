// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package plugin

type Resources[T any] interface {
	Get(key string) (T, bool)
	Set(key string, value T)
	// GetOrSet stores the value only if the key is still free and returns
	// whichever value is canonical for that key, so that concurrent callers
	// converge on one instance instead of racing a Get/Set pair.
	GetOrSet(key string, value T) (T, bool)
}
