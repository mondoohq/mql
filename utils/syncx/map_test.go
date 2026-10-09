// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package syncx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapRange(t *testing.T) {
	var m Map[int]
	m.Set("a", 1)
	m.Set("b", 2)

	seen := map[string]int{}
	m.Range(func(key string, value int) bool {
		seen[key] = value
		return true
	})
	assert.Equal(t, map[string]int{"a": 1, "b": 2}, seen)

	visits := 0
	m.Range(func(string, int) bool {
		visits++
		return false
	})
	assert.Equal(t, 1, visits, "returning false stops the walk")
}
