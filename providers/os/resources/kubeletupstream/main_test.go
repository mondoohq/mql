// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"
	"time"

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

func TestRetryDelay(t *testing.T) {
	assert.Equal(t, 60*time.Second, retryDelay("60", 10*time.Second))
	// never shorter than the backoff, never longer than the cap
	assert.Equal(t, 10*time.Second, retryDelay("1", 10*time.Second))
	assert.Equal(t, maxRetryDelay, retryDelay("3600", 10*time.Second))
	// absent, or an HTTP date, which GitHub does not send
	assert.Equal(t, 20*time.Second, retryDelay("", 20*time.Second))
	assert.Equal(t, 20*time.Second, retryDelay("Wed, 21 Oct 2026 07:28:00 GMT", 20*time.Second))
}
