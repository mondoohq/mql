// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScimReachedEnd(t *testing.T) {
	// TotalResults is authoritative: keep paging until we've moved past it,
	// even when a page is shorter than scimPageSize (Atlassian caps count
	// server-side, so a short page is NOT the end).
	t.Run("short page with more remaining does not stop", func(t *testing.T) {
		// Server capped the page at 50 though we asked for scimPageSize; 250 total.
		// nextStartIndex = 1 + 50 = 51, still <= 250 -> keep going.
		assert.False(t, scimReachedEnd(51, 50, 250))
	})

	t.Run("stops once past the total", func(t *testing.T) {
		// Fetched the final chunk: nextStartIndex 251 > 250 -> stop.
		assert.True(t, scimReachedEnd(251, 50, 250))
	})

	t.Run("full page mid-stream keeps going", func(t *testing.T) {
		assert.False(t, scimReachedEnd(scimPageSize+1, scimPageSize, 3*scimPageSize))
	})

	t.Run("exact boundary stops", func(t *testing.T) {
		// total == scimPageSize, one full page: nextStartIndex scimPageSize+1 > total.
		assert.True(t, scimReachedEnd(scimPageSize+1, scimPageSize, scimPageSize))
	})

	t.Run("no total falls back to short-page heuristic", func(t *testing.T) {
		// totalResults omitted (0): a short page means the end.
		assert.True(t, scimReachedEnd(51, 50, 0))
		// a full page means keep going.
		assert.False(t, scimReachedEnd(scimPageSize+1, scimPageSize, 0))
	})
}
