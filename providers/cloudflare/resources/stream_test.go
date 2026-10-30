// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStreamLiveInputsNilMeta exercises the previously panic-prone path where
// `result.Meta["name"].(string)` would panic if `meta` was nil or the key was
// missing or non-string. Cloudflare's stream API allows arbitrary user-set
// metadata, so all three shapes are realistic.
func TestStreamLiveInputsNilMeta(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/stream/live_inputs", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{
			"success": true, "errors": [], "messages": [],
			"result": [
				{"uid": "input-1", "modified": "", "created": "", "deleteRecordingAfterDays": 30, "meta": null},
				{"uid": "input-2", "deleteRecordingAfterDays": 0, "meta": {}},
				{"uid": "input-3", "deleteRecordingAfterDays": 7, "meta": {"name": 12345}},
				{"uid": "input-4", "deleteRecordingAfterDays": 1, "meta": {"name": "explicit-name"}}
			]
		}`)
	})

	result, err := acc.liveInputs()
	require.NoError(t, err)
	require.Len(t, result, 4)

	got := make(map[string]string, len(result))
	for _, r := range result {
		li := r.(*mqlCloudflareStreamsLiveInput)
		got[li.Uid.Data] = li.Name.Data
	}

	// Missing/null/non-string `name` all fall back to "" rather than panicking.
	assert.Equal(t, "", got["input-1"])
	assert.Equal(t, "", got["input-2"])
	assert.Equal(t, "", got["input-3"])
	assert.Equal(t, "explicit-name", got["input-4"])
}
