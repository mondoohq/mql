// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/ai_audit"
	"github.com/stretchr/testify/assert"
)

func TestSortedUserAgentNames(t *testing.T) {
	// The API hands the agents back as a map and Go randomizes map iteration,
	// so without sorting two scans of the same unchanged zone would emit the
	// list in different orders and read as a change.
	rules := map[string]ai_audit.RobotGetResponseUserAgent{
		"GPTBot":            {},
		"*":                 {},
		"CCBot":             {},
		"Google-Extended":   {},
		"anthropic-ai":      {},
		"Applebot-Extended": {},
	}

	want := []string{"*", "Applebot-Extended", "CCBot", "GPTBot", "Google-Extended", "anthropic-ai"}

	// Repeat: a single pass can match by luck when the map is small.
	for range 20 {
		assert.Equal(t, want, sortedUserAgentNames(rules))
	}
}

func TestSortedUserAgentNamesHandlesEmpty(t *testing.T) {
	assert.Empty(t, sortedUserAgentNames(nil))
	assert.Empty(t, sortedUserAgentNames(map[string]ai_audit.RobotGetResponseUserAgent{}))
}

func TestStrAnySlice(t *testing.T) {
	assert.Equal(t, []any{"/admin", "/private"}, strAnySlice([]string{"/admin", "/private"}))

	// An agent with no disallow rules must produce an empty list, not nil: the
	// difference decides whether "crawler is unrestricted" renders as a fact or
	// as a missing value.
	got := strAnySlice(nil)
	assert.NotNil(t, got)
	assert.Empty(t, got)
}
