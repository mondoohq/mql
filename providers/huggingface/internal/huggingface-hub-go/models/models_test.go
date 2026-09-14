// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The HuggingFace API returns "gated" either as a bool (false) or as a string
// ("auto"/"manual"); both must decode without error.
func TestGatedValueUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		gated   bool
		mode    string
		wantErr bool
	}{
		{"bool false", `false`, false, "false", false},
		{"bool true", `true`, true, "true", false},
		{"string auto", `"auto"`, true, "auto", false},
		{"string manual", `"manual"`, true, "manual", false},
		{"string false", `"false"`, false, "false", false},
		{"string empty", `""`, false, "", false},
		{"unexpected number", `5`, false, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var g GatedValue
			err := json.Unmarshal([]byte(tt.json), &g)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.gated, g.IsGated)
			assert.Equal(t, tt.mode, g.Mode)
		})
	}
}

func TestModelListUnmarshal(t *testing.T) {
	// Bare array form (the normal list response).
	var arr ModelList
	require.NoError(t, json.Unmarshal([]byte(`[{"id":"a/1"},{"id":"a/2"}]`), &arr))
	require.Len(t, arr.Models, 2)
	assert.Equal(t, "a/1", arr.Models[0].ID)

	// Object-wrapped form.
	var obj ModelList
	require.NoError(t, json.Unmarshal([]byte(`{"models":[{"id":"a/1"}]}`), &obj))
	require.Len(t, obj.Models, 1)

	// A "gated" string inside a list entry must not break array decoding.
	var gated ModelList
	require.NoError(t, json.Unmarshal([]byte(`[{"id":"a/1","gated":"manual"}]`), &gated))
	require.Len(t, gated.Models, 1)
	assert.True(t, gated.Models[0].Gated.IsGated)
}

// Responses built with expand[] carry no modelId at all, because the model
// endpoint's allowlist has no such name. Without the backfill the shipped
// modelId field comes back empty for every listed model, so this pins it. A
// modelId the server does send must survive untouched.
func TestModelListNormalizeBackfillsModelID(t *testing.T) {
	// Live shape of an expand[] response: id present, modelId absent.
	var expanded ModelList
	require.NoError(t, json.Unmarshal([]byte(
		`[{"id":"meta-llama/Llama-3.2-1B-Instruct","gated":"manual"}]`), &expanded))
	require.Len(t, expanded.Models, 1)
	assert.Equal(t, "meta-llama/Llama-3.2-1B-Instruct", expanded.Models[0].ModelID)

	// A server-supplied modelId is not overwritten.
	var explicit ModelList
	require.NoError(t, json.Unmarshal([]byte(
		`[{"id":"acme/new","modelId":"acme/legacy"}]`), &explicit))
	require.Len(t, explicit.Models, 1)
	assert.Equal(t, "acme/legacy", explicit.Models[0].ModelID)

	// The object-wrapped form goes through the same backfill.
	var wrapped ModelList
	require.NoError(t, json.Unmarshal([]byte(`{"models":[{"id":"acme/one"}]}`), &wrapped))
	require.Len(t, wrapped.Models, 1)
	assert.Equal(t, "acme/one", wrapped.Models[0].ModelID)
}

// Without expand[] the model list endpoint omits gated, disabled, sha, author
// and lastModified entirely, so a listed gated model decoded from that response
// reads as ungated. The expanded response is what carries the truth.
func TestModelDecodeGatedFromExpandedList(t *testing.T) {
	// Live: /api/models?author=meta-llama (no expand) omits gated altogether.
	var bare ModelList
	require.NoError(t, json.Unmarshal([]byte(
		`[{"id":"meta-llama/Llama-3.2-1B-Instruct","likes":1649,"private":false}]`), &bare))
	require.Len(t, bare.Models, 1)
	assert.Empty(t, bare.Models[0].Gated.Mode,
		"an omitted gated field must not decode to a mode")

	// Live: the same request with expand[]=gated&expand[]=disabled&expand[]=sha.
	var expanded ModelList
	require.NoError(t, json.Unmarshal([]byte(
		`[{"id":"meta-llama/Llama-3.2-1B-Instruct","author":"meta-llama","disabled":false,`+
			`"gated":"manual","lastModified":"2024-10-24T15:07:51.000Z",`+
			`"sha":"9213176726f574b556790deb65791e0c5aa438b6","createdAt":"2024-09-18T15:12:47.000Z"}]`), &expanded))
	require.Len(t, expanded.Models, 1)
	m := expanded.Models[0]
	assert.True(t, m.Gated.IsGated)
	assert.Equal(t, "manual", m.Gated.Mode)
	assert.Equal(t, "meta-llama", m.Author)
	assert.Equal(t, "9213176726f574b556790deb65791e0c5aa438b6", m.Sha)
	assert.Equal(t, "2024-10-24T15:07:51.000Z", m.LastModified)
	assert.Equal(t, "2024-09-18T15:12:47.000Z", m.CreatedAt)
}

func TestDatasetAndSpaceListUnmarshal(t *testing.T) {
	var dl DatasetList
	require.NoError(t, json.Unmarshal([]byte(`[{"id":"a/d1"}]`), &dl))
	require.Len(t, dl.Datasets, 1)

	var sl SpaceList
	require.NoError(t, json.Unmarshal([]byte(`[{"id":"a/s1"}]`), &sl))
	require.Len(t, sl.Spaces, 1)
}

func TestWebhookListUnmarshal(t *testing.T) {
	// Bare array form.
	var arr WebhookList
	require.NoError(t, json.Unmarshal([]byte(`[{"id":"w1"},{"id":"w2"}]`), &arr))
	require.Len(t, arr, 2)

	// Object-wrapped form.
	var obj WebhookList
	require.NoError(t, json.Unmarshal([]byte(`{"webhooks":[{"id":"w1"}]}`), &obj))
	require.Len(t, obj, 1)
	assert.Equal(t, "w1", obj[0].ID)
}
