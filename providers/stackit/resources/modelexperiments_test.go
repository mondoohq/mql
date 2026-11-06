// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	modelexperiments "github.com/stackitcloud/stackit-sdk-go/services/modelexperiments/v1api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Synthetic: shape of the v1 ListInstances response from the SDK's OpenAPI
// model; no live instance was available.
const instanceJSON = `{
  "id": "0b4f6c2e-1111-4a8e-9d55-6f0e5f3b9a10",
  "name": "ml-tracking",
  "description": "team tracking server",
  "url": "https://ml-tracking.mlflow.eu01.stackit.cloud",
  "bucketName": "model-experiments-abc123",
  "deletedExperimentRetention": "30d",
  "state": "active",
  "region": "eu01",
  "labels": {"env": "prod"}
}`

func TestModelExperimentsInstanceArgs(t *testing.T) {
	var inst modelexperiments.Instance
	require.NoError(t, json.Unmarshal([]byte(instanceJSON), &inst))
	args := modelExperimentsInstanceArgs(&inst)

	assert.Equal(t, "0b4f6c2e-1111-4a8e-9d55-6f0e5f3b9a10", args["id"].Value)
	assert.Equal(t, "ml-tracking", args["name"].Value)
	assert.Equal(t, "https://ml-tracking.mlflow.eu01.stackit.cloud", args["url"].Value)
	assert.Equal(t, "30d", args["deletedExperimentRetention"].Value)
	assert.Equal(t, "active", args["state"].Value)
	assert.Equal(t, "eu01", args["region"].Value)
	assert.Equal(t, map[string]any{"env": "prod"}, args["labels"].Value)
	assert.Equal(t, "", args["errorMessage"].Value)
	assert.NotContains(t, args, "bucketName")
}

func TestModelExperimentsInstanceArgsAbsentLabels(t *testing.T) {
	// Synthetic: an instance created without labels omits the key.
	var inst modelexperiments.Instance
	require.NoError(t, json.Unmarshal([]byte(`{"id":"x","name":"n","state":"creating","url":"u"}`), &inst))
	args := modelExperimentsInstanceArgs(&inst)
	assert.Equal(t, map[string]any{}, args["labels"].Value)
	assert.Equal(t, "", args["deletedExperimentRetention"].Value)
}

func TestModelExperimentsTokenArgs(t *testing.T) {
	// Synthetic: token metadata as returned by ListInstanceTokens.
	var tok modelexperiments.TokenMetadata
	require.NoError(t, json.Unmarshal([]byte(`{
	  "id": "7c0e",
	  "name": "ci",
	  "region": "eu01",
	  "state": "active",
	  "validUntil": "2027-01-02T03:04:05Z",
	  "labels": {"owner": "ci"}
	}`), &tok))
	args := modelExperimentsTokenArgs(&tok)

	assert.Equal(t, "7c0e", args["id"].Value)
	assert.Equal(t, "active", args["state"].Value)
	assert.Equal(t, time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC), *(args["validUntil"].Value.(*time.Time)))
	assert.Equal(t, map[string]any{"owner": "ci"}, args["labels"].Value)
	assert.NotContains(t, args, "content")
}

func TestModelExperimentsTokenArgsNoExpiry(t *testing.T) {
	// Synthetic: a zero validUntil reads as null, not year 1.
	tok := modelexperiments.TokenMetadata{Id: "t", Name: "n", Region: "eu01", State: "inactive"}
	args := modelExperimentsTokenArgs(&tok)
	assert.Nil(t, args["validUntil"].Value)
}

func bucket(name string) *mqlStackitObjectStorageBucket {
	return &mqlStackitObjectStorageBucket{
		Name: plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
	}
}

func TestFindBucket(t *testing.T) {
	list := []any{bucket("other"), bucket("model-experiments-abc123")}
	got := findBucket(list, "model-experiments-abc123")
	require.NotNil(t, got)
	assert.Equal(t, "model-experiments-abc123", got.Name.Data)

	assert.Nil(t, findBucket(list, "missing"))
	assert.Nil(t, findBucket(nil, "model-experiments-abc123"))
}

func TestObjectStorageBucketRefEmptyNameIsNull(t *testing.T) {
	var field plugin.TValue[*mqlStackitObjectStorageBucket]
	got, err := objectStorageBucketRef(nil, "", &field)
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State)
}
