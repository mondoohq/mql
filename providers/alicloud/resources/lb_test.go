// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestStrPtrHelpers covers the shared slice-flattening helpers that build the
// typed security-group, vSwitch, and certificate cross-references, ensuring nil
// and empty entries are dropped so a resolver is never handed a blank id.
func TestStrPtrHelpers(t *testing.T) {
	t.Run("strPtrsToStrings drops nil and empty", func(t *testing.T) {
		assert.Equal(t, []string{}, strPtrsToStrings(nil))
		assert.Equal(t, []string{"sg-a", "sg-b"}, strPtrsToStrings([]*string{new("sg-a"), new(""), nil, new("sg-b")}))
	})
	t.Run("strPtrsToAny returns []any of non-empty strings", func(t *testing.T) {
		assert.Equal(t, []any{}, strPtrsToAny(nil))
		assert.Equal(t, []any{"cert-1", "cert-2"}, strPtrsToAny([]*string{new("cert-1"), new(""), new("cert-2")}))
	})
}

// TestIsInternetFacing covers the load-balancer internet-exposure derivation
// shared by the CLB, ALB, and NLB internetFacing() accessors. This is the crux
// of the public-exposure finding, so it must not misclassify.
func TestIsInternetFacing(t *testing.T) {
	assert.True(t, isInternetFacing("Internet"))
	assert.True(t, isInternetFacing("internet"))     // case-insensitive
	assert.True(t, isInternetFacing("  Internet  ")) // whitespace-tolerant
	assert.False(t, isInternetFacing("Intranet"))
	assert.False(t, isInternetFacing(""))
	assert.False(t, isInternetFacing("internal"))
}
