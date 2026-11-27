// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: an endpoint shaped after EndpointWithStatus in the Inference
// Endpoints OpenAPI document; no live account was checked.
func TestInferenceEndpointDecode(t *testing.T) {
	data := []byte(`{
		"name":"chat","type":"public",
		"provider":{"vendor":"aws","region":"us-east-1"},
		"compute":{"accelerator":"gpu","instanceType":"nvidia-a10g","instanceSize":"x1",
			"scaling":{"minReplica":0,"maxReplica":4}},
		"model":{"repository":"acme/llm","framework":"pytorch","revision":"abc123","image":{},
			"secrets":{"OPENAI_KEY":"sk-secret","HF_TOKEN":null}},
		"status":{"state":"running","url":"https://x.endpoints.huggingface.cloud",
			"createdAt":"2026-01-02T03:04:05Z","updatedAt":"2026-01-03T03:04:05Z",
			"lastUsedAt":"2026-01-04T03:04:05Z",
			"createdBy":{"id":"u1","name":"alice"},"updatedBy":{"id":"u2","name":"bob"},
			"message":"","readyReplica":1,"targetReplica":1}
	}`)

	var ep InferenceEndpoint
	require.NoError(t, json.Unmarshal(data, &ep))
	assert.Equal(t, "public", ep.Type)
	assert.Equal(t, "aws", ep.Provider.Vendor)
	assert.Equal(t, "us-east-1", ep.Provider.Region)
	assert.Equal(t, "nvidia-a10g", ep.Compute.InstanceType)
	require.NotNil(t, ep.Compute.Scaling.MinReplica)
	assert.Equal(t, int64(0), *ep.Compute.Scaling.MinReplica)
	require.NotNil(t, ep.Compute.Scaling.MaxReplica)
	assert.Equal(t, int64(4), *ep.Compute.Scaling.MaxReplica)
	require.NotNil(t, ep.Model.Revision)
	assert.Equal(t, "abc123", *ep.Model.Revision)
	require.NotNil(t, ep.Status.LastUsedAt)
	assert.Equal(t, "2026-01-04T03:04:05Z", *ep.Status.LastUsedAt)
	assert.Equal(t, "alice", ep.Status.CreatedBy.Name)
	assert.Equal(t, "bob", ep.Status.UpdatedBy.Name)

	// Only the secret names survive decoding, sorted; no value is kept.
	assert.Equal(t, SecretNames{"HF_TOKEN", "OPENAI_KEY"}, ep.Model.Secrets)
	raw, err := json.Marshal(ep)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "sk-secret")
}

// Synthetic: an endpoint missing every optional field; no live account showed
// this. Absent values must stay nil rather than decode to zero.
func TestInferenceEndpointDecodeAbsentFields(t *testing.T) {
	var ep InferenceEndpoint
	require.NoError(t, json.Unmarshal([]byte(`{"name":"bare","model":{"revision":null},"status":{"lastUsedAt":null}}`), &ep))
	assert.Nil(t, ep.Model.Revision)
	assert.Nil(t, ep.Model.Secrets)
	assert.Nil(t, ep.Status.LastUsedAt)
	assert.Nil(t, ep.Compute.Scaling.MinReplica)
	assert.Nil(t, ep.Compute.Scaling.MaxReplica)
}

// Synthetic: secrets maps in the shapes the spec allows; no live account was
// checked.
func TestSecretNamesUnmarshal(t *testing.T) {
	var s SecretNames
	require.NoError(t, json.Unmarshal([]byte(`null`), &s))
	assert.Nil(t, s)

	require.NoError(t, json.Unmarshal([]byte(`{}`), &s))
	assert.NotNil(t, s)
	assert.Empty(t, s)

	assert.Error(t, json.Unmarshal([]byte(`["A"]`), &s))
}
