// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPreviousMinor(t *testing.T) {
	minors := map[int]string{34: "a", 36: "b", 38: "c"}
	m, sha := previousMinor(minors, 38)
	assert.Equal(t, 36, m)
	assert.Equal(t, "b", sha)
	_, sha = previousMinor(minors, 34)
	assert.Empty(t, sha)
}
