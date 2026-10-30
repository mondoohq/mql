// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	together "github.com/togethercomputer/together-go"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func newTestModel(id, displayName string) *mqlTogetherModel {
	return &mqlTogetherModel{
		Id:          plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
		DisplayName: plugin.TValue[string]{Data: displayName, State: plugin.StateIsSet},
	}
}

func TestModelFamily(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"meta-llama/Llama-3.3-70B-Instruct-Turbo", "Llama"},
		{"meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo", "Llama"},
		{"Qwen/Qwen2.5-72B-Instruct-Turbo", "Qwen"},
		{"mistralai/Mistral-7B-v0.1", "Mistral"},
		{"mistralai/Mixtral-8x7B-Instruct-v0.1", "Mixtral"},
		{"google/Gemma-2-9B-it", "Gemma"},
		{"deepseek-ai/DeepSeek-V3", "DeepSeek"},
		{"microsoft/Phi-3-mini-4k-instruct", "Phi"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := newTestModel(tt.id, "")
			got, err := m.family()
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestModelParameterSize(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"meta-llama/Llama-3.3-70B-Instruct-Turbo", "70B"},
		{"meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo", "8B"},
		{"Qwen/Qwen2.5-72B-Instruct-Turbo", "72B"},
		{"mistralai/Mistral-7B-v0.1", "7B"},
		{"mistralai/Mixtral-8x7B-Instruct-v0.1", "8x7B"},
		{"google/Gemma-2-9B-it", "9B"},
		{"openai/gpt-4o", ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := newTestModel(tt.id, "")
			got, err := m.parameterSize()
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestModelQuantization(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"meta-llama/Llama-3.3-70B-Instruct-Turbo", ""},
		{"org/Model-7B-fp8", "fp8"},
		{"org/Model-7B-int4-variant", "int4"},
		{"org/Model-7B-AWQ", "awq"},
		{"org/Model-7B-GPTQ", "gptq"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := newTestModel(tt.id, "")
			got, err := m.quantization()
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestModelDescription(t *testing.T) {
	m := newTestModel("meta-llama/Llama-3.3-70B-Instruct-Turbo", "Llama 3.3 70B Instruct Turbo")
	got, err := m.description()
	assert.NoError(t, err)
	assert.Equal(t, "Llama 3.3 70B Instruct Turbo", got)
}

func TestParseTimeStr(t *testing.T) {
	t.Run("empty string returns nil", func(t *testing.T) {
		assert.Nil(t, parseTimeStr(""))
	})

	t.Run("unparseable string returns nil", func(t *testing.T) {
		assert.Nil(t, parseTimeStr("not-a-timestamp"))
		assert.Nil(t, parseTimeStr("1719878400")) // unix epoch is not an accepted layout
	})

	want := time.Date(2026, 6, 20, 15, 4, 5, 0, time.UTC)
	tests := []struct {
		name  string
		input string
		want  time.Time
	}{
		{"RFC3339", "2026-06-20T15:04:05Z", want},
		{"RFC3339Nano", "2026-06-20T15:04:05.000000000Z", want},
		{"no timezone", "2026-06-20T15:04:05", want},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTimeStr(tt.input)
			if assert.NotNil(t, got) {
				assert.True(t, got.Equal(tt.want), "got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTimeOrNil(t *testing.T) {
	t.Run("zero time returns nil", func(t *testing.T) {
		assert.Nil(t, timeOrNil(time.Time{}))
	})

	t.Run("set time returns pointer", func(t *testing.T) {
		want := time.Date(2026, 6, 20, 15, 4, 5, 0, time.UTC)
		got := timeOrNil(want)
		if assert.NotNil(t, got) {
			assert.True(t, got.Equal(want))
		}
	})
}

func TestIsAccessDenied(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"401 unauthorized", &together.Error{StatusCode: 401}, true},
		{"403 forbidden", &together.Error{StatusCode: 403}, true},
		{"404 not found", &together.Error{StatusCode: 404}, false},
		{"500 server error", &together.Error{StatusCode: 500}, false},
		{"non-API error", errors.New("connection refused"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAccessDenied(tt.err))
		})
	}
}

func TestParseContextLength(t *testing.T) {
	// Synthetic: the catalog serializes the length as a decimal string.
	n := parseContextLength("131072")
	require.NotNil(t, n)
	assert.Equal(t, int64(131072), *n)

	for _, absent := range []string{"", "  ", "0", "-1", "128k"} {
		assert.Nil(t, parseContextLength(absent), "%q is not a context length", absent)
	}
}

func decodeSupportedModel(t *testing.T, body string) together.SupportedModel {
	t.Helper()
	var m together.SupportedModel
	require.NoError(t, json.Unmarshal([]byte(body), &m))
	return m
}

func TestSupportedModelArgs(t *testing.T) {
	// Synthetic: shaped like the documented supported-model entry; values invented.
	m := decodeSupportedModel(t, `{
	  "id": "sm-0000",
	  "name": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
	  "displayName": "Llama 3.3 70B Instruct Turbo",
	  "displayType": "chat",
	  "publisher": "Meta",
	  "contextLength": "131072",
	  "createdAt": "2026-01-01T00:00:00Z",
	  "description": "Instruction-tuned Llama 3.3",
	  "pricing": {"input": 0.88, "output": 0.88}
	}`)

	args := supportedModelArgs(m)
	assert.Equal(t, "meta-llama/Llama-3.3-70B-Instruct-Turbo", args["id"].Value,
		"the model id is the inference name the family and size parsers read, not the catalog id")
	assert.Equal(t, "meta-llama/Llama-3.3-70B-Instruct-Turbo", args["__id"].Value)
	assert.Equal(t, "chat", args["type"].Value)
	assert.Equal(t, "Meta", args["organization"].Value)
	assert.Equal(t, int64(131072), args["contextLength"].Value)
	assert.Equal(t, 0.88, args["pricingInput"].Value)
	assert.Equal(t, 0.88, args["pricingOutput"].Value)
	assert.Equal(t, "Instruction-tuned Llama 3.3", args["description"].Value)
	assert.Nil(t, args["license"].Value)
	assert.Nil(t, args["link"].Value)
}

func TestSupportedModelArgsWithoutServerlessPricing(t *testing.T) {
	// Synthetic: a dedicated-only model carries no serverless pricing.
	m := decodeSupportedModel(t, `{"id": "sm-1", "name": "org/model-7B", "displayName": "Model 7B"}`)

	args := supportedModelArgs(m)
	assert.Nil(t, args["pricingInput"].Value, "no price is not a free model")
	assert.Nil(t, args["pricingOutput"].Value)
	assert.Nil(t, args["contextLength"].Value)
	_, hasDescription := args["description"]
	assert.False(t, hasDescription, "an empty description falls back to the display name")
}

func TestFileProcessed(t *testing.T) {
	// Synthetic: the documented processing states, plus the absent case.
	decode := func(body string) together.FileResponse {
		var f together.FileResponse
		require.NoError(t, json.Unmarshal([]byte(body), &f))
		return f
	}

	done := fileProcessed(decode(`{"id": "file-1", "processing_status": "COMPLETED"}`))
	require.NotNil(t, done)
	assert.True(t, *done)

	for _, status := range []string{"PENDING", "QUEUED", "RUNNING", "FAILED", "INVALID_FORMAT"} {
		got := fileProcessed(decode(`{"id": "file-1", "processing_status": "` + status + `"}`))
		require.NotNil(t, got, status)
		assert.False(t, *got, status)
	}

	assert.Nil(t, fileProcessed(decode(`{"id": "file-1"}`)), "a file without a status has no answer")
}
