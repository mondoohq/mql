// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The executor resolves a resource's fields concurrently, so several accessors
// sharing one deferred fetch call these helpers at the same time. Run the whole
// file under -race: the ordering these tests exercise is exactly what the
// hand-rolled versions got wrong.

const lazyGoroutines = 64

// runConcurrently calls fn from lazyGoroutines goroutines released together, so
// they contend on the guard rather than arriving one after another.
func runConcurrently(fn func()) {
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for range lazyGoroutines {
		done.Go(func() {
			start.Wait()
			fn()
		})
	}
	start.Done()
	done.Wait()
}

func TestOciOnceRunsFetchOnce(t *testing.T) {
	var once ociOnce
	var calls atomic.Int64

	runConcurrently(func() {
		require.NoError(t, once.do(func() error {
			calls.Add(1)
			return nil
		}))
	})

	assert.Equal(t, int64(1), calls.Load(), "fetch must run exactly once across concurrent callers")
}

func TestOciOnceRetriesAfterFailure(t *testing.T) {
	var once ociOnce
	var calls atomic.Int64
	wantErr := errors.New("boom")

	// Only success is remembered, so a failing fetch is attempted again.
	for range 3 {
		err := once.do(func() error {
			calls.Add(1)
			return wantErr
		})
		require.ErrorIs(t, err, wantErr)
	}
	assert.Equal(t, int64(3), calls.Load(), "a failed fetch must not be cached")

	require.NoError(t, once.do(func() error {
		calls.Add(1)
		return nil
	}))
	assert.Equal(t, int64(4), calls.Load())

	// ...and once it succeeds it is never run again.
	require.NoError(t, once.do(func() error {
		t.Error("fetch ran again after success")
		return nil
	}))
}

func TestOciLazyCachesValueAndError(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		var lazy ociLazy[*string]
		var calls atomic.Int64
		want := "detail"

		runConcurrently(func() {
			got, err := lazy.get(func() (*string, error) {
				calls.Add(1)
				return &want, nil
			})
			require.NoError(t, err)
			// Reading through the returned pointer is the race the atomic
			// guard exists to prevent: without it a caller can observe the
			// flag set before the value is visible.
			require.NotNil(t, got)
			assert.Equal(t, "detail", *got)
		})

		assert.Equal(t, int64(1), calls.Load())
	})

	t.Run("error is cached", func(t *testing.T) {
		var lazy ociLazy[*string]
		var calls atomic.Int64
		wantErr := errors.New("not authorized")

		// A resource the caller cannot read is asked for once, not once per
		// field sharing the fetch.
		for range 5 {
			got, err := lazy.get(func() (*string, error) {
				calls.Add(1)
				return nil, wantErr
			})
			require.ErrorIs(t, err, wantErr)
			assert.Nil(t, got)
		}
		assert.Equal(t, int64(1), calls.Load(), "a failed fetch must be cached")
	})
}

func TestOciRetryLazyCachesOnlySuccess(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		var lazy ociRetryLazy[*string]
		var calls atomic.Int64
		want := "detail"

		runConcurrently(func() {
			got, err := lazy.get(func() (*string, error) {
				calls.Add(1)
				return &want, nil
			})
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, "detail", *got)
		})

		assert.Equal(t, int64(1), calls.Load())
	})

	t.Run("failure is retried then cached", func(t *testing.T) {
		var lazy ociRetryLazy[*string]
		var calls atomic.Int64
		wantErr := errors.New("throttled")
		want := "detail"

		got, err := lazy.get(func() (*string, error) {
			calls.Add(1)
			return nil, wantErr
		})
		require.ErrorIs(t, err, wantErr)
		assert.Nil(t, got, "a failed fetch reports the zero value, not a partial one")

		got, err = lazy.get(func() (*string, error) {
			calls.Add(1)
			return &want, nil
		})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "detail", *got)
		assert.Equal(t, int64(2), calls.Load(), "the transient failure must be retried")

		got, err = lazy.get(func() (*string, error) {
			t.Error("fetch ran again after success")
			return nil, nil
		})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "detail", *got)
	})

	t.Run("nil is a cached result", func(t *testing.T) {
		// OCI answers some detail calls with an absent sub-struct, so a nil
		// value is a legitimate success and must not be re-fetched.
		var lazy ociRetryLazy[*string]
		var calls atomic.Int64

		for range 3 {
			got, err := lazy.get(func() (*string, error) {
				calls.Add(1)
				return nil, nil
			})
			require.NoError(t, err)
			assert.Nil(t, got)
		}
		assert.Equal(t, int64(1), calls.Load())
	})
}

// TestOciLazyZeroValueIsUsable pins the property the generated resource structs
// depend on: an Internal struct is created zero-initialized and never has an
// explicit constructor, so every guard here has to work as declared.
func TestOciLazyZeroValueIsUsable(t *testing.T) {
	type internal struct {
		once  ociOnce
		lazy  ociLazy[int]
		retry ociRetryLazy[int]
	}
	var s internal

	require.NoError(t, s.once.do(func() error { return nil }))

	v, err := s.lazy.get(func() (int, error) { return 7, nil })
	require.NoError(t, err)
	assert.Equal(t, 7, v)

	v, err = s.retry.get(func() (int, error) { return 9, nil })
	require.NoError(t, err)
	assert.Equal(t, 9, v)
}
