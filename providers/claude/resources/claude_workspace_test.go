// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeModel(t *testing.T, payload string) anthropic.ModelInfo {
	t.Helper()
	var m anthropic.ModelInfo
	require.NoError(t, json.Unmarshal([]byte(payload), &m))
	return m
}

// Synthetic: a deprecated model with a scheduled retirement, shaped after the
// Models API reference; no live account was checked.
func TestModelArgs_Deprecated(t *testing.T) {
	args := modelArgs(decodeModel(t, `{
		"id": "claude-opus-4-5-20251101",
		"type": "model",
		"display_name": "Claude Opus 4.5",
		"created_at": "2025-11-01T00:00:00Z",
		"line": "opus",
		"lifecycle": "deprecated",
		"deprecated_at": "2026-10-22T00:00:00Z",
		"retires_at": "2027-01-22T00:00:00Z"
	}`))

	assert.Equal(t, "opus", args["family"].Value)
	assert.Equal(t, "deprecated", args["lifecycle"].Value)
	assert.Equal(t, time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC), *args["deprecatedAt"].Value.(*time.Time))
	assert.Equal(t, time.Date(2027, 1, 22, 0, 0, 0, 0, time.UTC), *args["retiresAt"].Value.(*time.Time))
}

// Synthetic: an active model in no line; no live account was checked.
//
// The family comes from the API's line, never from the id, so an id that
// reads like a family still reports null. The lifecycle timestamps the API
// sends as null must read as null, not as 1 January of year 1.
func TestModelArgs_ActiveWithoutLine(t *testing.T) {
	args := modelArgs(decodeModel(t, `{
		"id": "claude-sonnet-experimental",
		"type": "model",
		"display_name": "Experimental",
		"created_at": "2026-01-01T00:00:00Z",
		"line": null,
		"lifecycle": "active",
		"deprecated_at": null,
		"retires_at": null
	}`))

	assert.Nil(t, args["family"].Value)
	assert.Equal(t, "active", args["lifecycle"].Value)
	assert.Nil(t, args["deprecatedAt"].Value)
	assert.Nil(t, args["retiresAt"].Value)
}
