// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "sync"

// memo runs a load once per key and hands every caller the same answer, the
// error included. A project-wide list that every repository and branch of the
// project reads, such as the branch policies, is fetched once per client.
// Retries happen inside the load, so caching an error does not turn one
// throttled request into a permanent failure.
type memo[T any] struct {
	m sync.Map
}

type memoEntry[T any] struct {
	once sync.Once
	val  T
	err  error
}

func (m *memo[T]) get(key string, load func() (T, error)) (T, error) {
	e, _ := m.m.LoadOrStore(key, &memoEntry[T]{})
	entry := e.(*memoEntry[T])
	entry.once.Do(func() { entry.val, entry.err = load() })
	return entry.val, entry.err
}
