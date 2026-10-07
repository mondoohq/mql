// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemoLoadsEachKeyOnce(t *testing.T) {
	var m memo[int]
	var calls atomic.Int32
	load := func() (int, error) {
		calls.Add(1)
		return 42, nil
	}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := m.get("a", load)
			assert.NoError(t, err)
			assert.Equal(t, 42, v)
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), calls.Load())

	_, _ = m.get("b", load)
	assert.Equal(t, int32(2), calls.Load(), "another key loads again")
}

func TestMemoKeepsTheError(t *testing.T) {
	var m memo[int]
	var calls atomic.Int32
	boom := errors.New("boom")
	load := func() (int, error) {
		calls.Add(1)
		return 0, boom
	}

	_, err := m.get("a", load)
	assert.ErrorIs(t, err, boom)
	_, err = m.get("a", load)
	assert.ErrorIs(t, err, boom)
	assert.Equal(t, int32(1), calls.Load())
}
