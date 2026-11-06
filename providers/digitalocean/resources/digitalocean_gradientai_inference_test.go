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

func TestInferenceRouterSummaryArgs(t *testing.T) {
	// Measured: shape of GET /v2/gen-ai/models/routers on a DigitalOcean team, 2026-11-06.
	var s godo.InferenceRouterSummary
	require.NoError(t, json.Unmarshal([]byte(`{"uuid":"11f1c36a-5ebf-0a46-aee4-4e013e2ddde4","name":"inference-router","description":"DigitalOcean managed Inference Router"}`), &s))
	args := inferenceRouterSummaryArgs(&s)
	assert.Equal(t, "digitalocean.gradientai.inferenceRouter/11f1c36a-5ebf-0a46-aee4-4e013e2ddde4", args["__id"].Value)
	assert.Equal(t, "inference-router", args["name"].Value)
	assert.Equal(t, "DigitalOcean managed Inference Router", args["description"].Value)
}

func TestInferenceRouterConfig_Decode(t *testing.T) {
	// Synthetic: shape from godo's InferenceRouter json tags; no router with
	// a config existed in the test account.
	raw := `{
		"uuid": "ir-1",
		"config": {
			"fallback_models": ["llama3.3-70b-instruct", "openai-gpt-4o"],
			"policies": [{"task_slug": "code-generation", "models": ["anthropic-claude-sonnet"]}]
		}
	}`
	var ir godo.InferenceRouter
	require.NoError(t, json.Unmarshal([]byte(raw), &ir))
	assert.Equal(t, []any{"llama3.3-70b-instruct", "openai-gpt-4o"}, inferenceRouterFallbackModels(&ir))
	p, err := inferenceRouterPolicies(&ir)
	require.NoError(t, err)
	assert.Equal(t, []any{map[string]any{
		"task_slug": "code-generation",
		"models":    []any{"anthropic-claude-sonnet"},
	}}, p)
}

func TestInferenceRouterConfig_Absent(t *testing.T) {
	// Measured: GET /v2/gen-ai/models/routers/{uuid} for the managed default
	// router returns no config block (2026-11-06).
	ir := &godo.InferenceRouter{UUID: "ir-2"}
	assert.Equal(t, []any{}, inferenceRouterFallbackModels(ir))
	p, err := inferenceRouterPolicies(ir)
	require.NoError(t, err)
	assert.Nil(t, p)

	// Synthetic: a router deleted since the list (404) reads as no config.
	assert.Equal(t, []any{}, inferenceRouterFallbackModels(nil))
	p, err = inferenceRouterPolicies(nil)
	require.NoError(t, err)
	assert.Nil(t, p)
}

func TestInferenceRouterPolicies_Malformed(t *testing.T) {
	// Synthetic: policies that are not valid JSON surface as malformed data.
	_, err := inferenceRouterPolicies(&godo.InferenceRouter{UUID: "ir-3", Config: &godo.InferenceRouterConfig{Policies: json.RawMessage(`{"x":`)}})
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
