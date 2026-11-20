// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDistinctPrincipalIDs(t *testing.T) {
	// Synthetic: role assignment lists repeat a principal once per grant and
	// carry an empty ID for a grant whose principal ARM did not report.
	got := distinctPrincipalIDs([]string{
		"aaa", "bbb", "", "aaa", "BBB", "ccc",
	})
	assert.Equal(t, []string{"aaa", "bbb", "ccc"}, got)

	assert.Empty(t, distinctPrincipalIDs(nil))
	assert.Empty(t, distinctPrincipalIDs([]string{""}))
}

func TestEntraPrincipalID(t *testing.T) {
	// Synthetic: one principal seen from two subscriptions of one scan.
	a := entraPrincipalID("sub-a", "8F3C9A2E-1B4D-4E5F-9A6B-7C8D9E0F1A2B")
	b := entraPrincipalID("sub-b", "8f3c9a2e-1b4d-4e5f-9a6b-7c8d9e0f1a2b")
	assert.NotEqual(t, a, b, "the same principal in two subscriptions must not share a cache entry")
	assert.Equal(t, a, entraPrincipalID("sub-a", "8f3c9a2e-1b4d-4e5f-9a6b-7c8d9e0f1a2b"),
		"the object ID's case must not split one principal into two entries")
}
