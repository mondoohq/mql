// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestInferenceRouterArgs_Decode(t *testing.T) {
	// Synthetic: shape from godo's InferenceRouter json tags; no router
	// existed in the test account.
	raw := `{
		"uuid": "ir-1",
		"name": "support-router",
		"description": "routes support traffic",
		"created_at": "2026-06-01T10:00:00Z",
		"config": {
			"fallback_models": ["llama3.3-70b-instruct", "openai-gpt-4o"],
			"policies": [{"task_slug": "code-generation", "models": ["anthropic-claude-sonnet"]}]
		}
	}`
	var ir godo.InferenceRouter
	require.NoError(t, json.Unmarshal([]byte(raw), &ir))
	args, err := inferenceRouterArgs(&ir)
	require.NoError(t, err)
	assert.Equal(t, "digitalocean.gradientai.inferenceRouter/ir-1", args["__id"].Value)
	assert.Equal(t, "support-router", args["name"].Value)
	assert.Equal(t, []any{"llama3.3-70b-instruct", "openai-gpt-4o"}, args["fallbackModels"].Value)
	assert.Equal(t, []any{map[string]any{
		"task_slug": "code-generation",
		"models":    []any{"anthropic-claude-sonnet"},
	}}, args["policies"].Value)
	assert.NotNil(t, args["createdAt"].Value)
	assert.Nil(t, args["updatedAt"].Value)
}

func TestInferenceRouterArgs_NoConfig(t *testing.T) {
	// Synthetic: a router read without a config block.
	args, err := inferenceRouterArgs(&godo.InferenceRouter{UUID: "ir-2"})
	require.NoError(t, err)
	assert.Equal(t, []any{}, args["fallbackModels"].Value)
	assert.Nil(t, args["policies"].Value)
}

func TestInferenceRouterArgs_MalformedPolicies(t *testing.T) {
	// Synthetic: policies that are not valid JSON surface as malformed data.
	_, err := inferenceRouterArgs(&godo.InferenceRouter{UUID: "ir-3", Config: &godo.InferenceRouterConfig{Policies: json.RawMessage(`{"x":`)}})
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
}

func TestRawJSONDict(t *testing.T) {
	got, err := rawJSONDict(nil)
	require.NoError(t, err)
	assert.Nil(t, got)

	got, err = rawJSONDict(json.RawMessage(`null`))
	require.NoError(t, err)
	assert.Nil(t, got)

	got, err = rawJSONDict(json.RawMessage(`{"a":1}`))
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"a": float64(1)}, got)
}
