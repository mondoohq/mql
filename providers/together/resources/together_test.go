// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	together "github.com/togethercomputer/together-go"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/together/connection"
	"go.mondoo.com/mql/utils/syncx"
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

// newRoutedTogether builds a together resource whose client talks to a stub
// that serves each body at the exact API path it is keyed by, and answers 404
// for anything else.
func newRoutedTogether(t *testing.T, routes map[string]string) *mqlTogether {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	conn, err := connection.NewTogetherConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			connection.OptionToken:   "not-a-real-key",
			connection.OptionBaseURL: srv.URL,
		},
	})
	require.NoError(t, err)

	return &mqlTogether{MqlRuntime: &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}}
}

// wandbKeyMarker stands in for a Weights & Biases API key. No field of the
// schema may carry it, even if the API were to echo one back.
const wandbKeyMarker = "WANDB-KEY-MUST-NOT-LEAK"

func decodeFineTune(t *testing.T, body string) together.FineTuningListResponseData {
	t.Helper()
	var j together.FineTuningListResponseData
	require.NoError(t, json.Unmarshal([]byte(body), &j))
	return j
}

func TestFineTuneArgsDecodeProvenance(t *testing.T) {
	// Synthetic: shaped like the documented fine-tune list entry; no live account was checked.
	j := decodeFineTune(t, `{
	  "id": "ft-0000",
	  "status": "completed",
	  "created_at": "2026-10-01T12:00:00Z",
	  "updated_at": "2026-10-02T12:00:00Z",
	  "started_at": "2026-10-01T12:05:00Z",
	  "user_id": "user-1111",
	  "from_hf_model": "example-org/example-model",
	  "hf_model_revision": "rev-2222",
	  "from_checkpoint": "ft-9999:10",
	  "training_method": {"method": "dpo", "dpo_beta": 0.1},
	  "training_type": {"type": "Lora", "lora_r": 8, "lora_alpha": 16},
	  "wandb_project_name": "example-project",
	  "wandb_api_key": "`+wandbKeyMarker+`",
	  "owner_address": "owner-3333"
	}`)

	args := fineTuneArgs(j)
	assert.Equal(t, "example-org/example-model", args["fromHfModel"].Value)
	assert.Equal(t, "rev-2222", args["hfModelRevision"].Value)
	assert.Equal(t, "ft-9999:10", args["fromCheckpoint"].Value)
	assert.Equal(t, "dpo", args["trainingMethod"].Value)
	assert.Equal(t, "Lora", args["trainingType"].Value)
	assert.Equal(t, "example-project", args["wandbProjectName"].Value)
	assert.Equal(t, "owner-3333", args["ownerAddress"].Value)
	assert.Equal(t, "user-1111", args["userId"].Value)
	assert.Equal(t, time.Date(2026, 10, 1, 12, 5, 0, 0, time.UTC), *args["startedAt"].Value.(*time.Time))

	for name, v := range args {
		if s, ok := v.Value.(string); ok {
			assert.NotContains(t, s, wandbKeyMarker, "%s carries the Weights & Biases key", name)
		}
	}
}

func TestFineTuneArgsAbsentProvenanceIsNull(t *testing.T) {
	// Synthetic: a job trained from a Together AI model with no optional provenance; no live account was checked.
	args := fineTuneArgs(decodeFineTune(t, `{"id": "ft-0001", "status": "queued", "user_id": "user-1111"}`))

	for _, field := range []string{"fromHfModel", "hfModelRevision", "fromCheckpoint", "trainingMethod", "trainingType", "wandbProjectName", "ownerAddress", "startedAt"} {
		assert.Nil(t, args[field].Value, "%s is not reported and must be null, not empty", field)
	}
}

// filesFixture is shaped like the documented GET v1/files response.
// Synthetic: the values are invented; no live account was checked.
const filesFixture = `{"data": [
  {"id": "file-train", "filename": "train.jsonl", "purpose": "fine-tune", "FileType": "jsonl", "bytes": 10, "created_at": 1760000000},
  {"id": "file-input", "filename": "requests.jsonl", "purpose": "batch-api", "FileType": "jsonl", "bytes": 20, "created_at": 1760000000},
  {"id": "file-output", "filename": "results.jsonl", "purpose": "batch-api", "FileType": "jsonl", "bytes": 30, "created_at": 1760000000}
]}`

func TestFineTuneDatasetsResolveThroughTheFileList(t *testing.T) {
	// Synthetic: one job whose training file is listed and whose validation file is not; no live account was checked.
	r := newRoutedTogether(t, map[string]string{
		"/v1/fine-tunes": `{"data": [{"id": "ft-0000", "status": "completed", "user_id": "u",
		  "training_file": "file-train", "validation_file": "file-gone"}]}`,
		"/v1/files": filesFixture,
	})

	jobs, err := r.fineTunes()
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	job := jobs[0].(*mqlTogetherFineTune)

	training, err := job.trainingDataset()
	require.NoError(t, err)
	require.NotNil(t, training)
	assert.Equal(t, "train.jsonl", training.Filename.Data)

	validation, err := job.validationDataset()
	require.NoError(t, err)
	assert.Nil(t, validation)
	assertNull(t, job.ValidationDataset, "validationDataset")
}

func TestBatchReferencesResolveThroughTheAccountLists(t *testing.T) {
	// Synthetic: a finished batch with no error file, against a catalog that lists its model; no live account was checked.
	r := newRoutedTogether(t, map[string]string{
		"/v1/batches": `[{"id": "batch-0000", "status": "COMPLETED", "model_id": "example-org/Example-8B",
		  "input_file_id": "file-input", "output_file_id": "file-output"}]`,
		"/v1/files": filesFixture,
		"/v2/supported-models": `{"data": [{"name": "example-org/Other-70B", "displayName": "Other 70B"},
		  {"name": "example-org/Example-8B", "displayName": "Example 8B"}]}`,
	})

	batches, err := r.batches()
	require.NoError(t, err)
	require.Len(t, batches, 1)
	batch := batches[0].(*mqlTogetherBatch)

	model, err := batch.model()
	require.NoError(t, err)
	require.NotNil(t, model)
	assert.Equal(t, "Example 8B", model.DisplayName.Data)

	input, err := batch.inputFile()
	require.NoError(t, err)
	require.NotNil(t, input)
	assert.Equal(t, "requests.jsonl", input.Filename.Data)

	output, err := batch.outputFile()
	require.NoError(t, err)
	require.NotNil(t, output)
	assert.Equal(t, "results.jsonl", output.Filename.Data)

	errorFile, err := batch.errorFile()
	require.NoError(t, err)
	assert.Nil(t, errorFile)
	assertNull(t, batch.ErrorFile, "errorFile")
}

func TestBatchModelOutsideTheCatalogIsNull(t *testing.T) {
	// Synthetic: a batch run on a model the catalog does not list, as a fine-tuned model is not; no live account was checked.
	r := newRoutedTogether(t, map[string]string{
		"/v1/batches":          `[{"id": "batch-0001", "status": "COMPLETED", "model_id": "acct/my-finetune"}]`,
		"/v2/supported-models": `{"data": [{"name": "example-org/Example-8B", "displayName": "Example 8B"}]}`,
	})

	batches, err := r.batches()
	require.NoError(t, err)
	require.Len(t, batches, 1)
	batch := batches[0].(*mqlTogetherBatch)

	model, err := batch.model()
	require.NoError(t, err)
	assert.Nil(t, model)
	assertNull(t, batch.Model, "model")
	assert.Equal(t, "acct/my-finetune", batch.ModelId.Data)
}
