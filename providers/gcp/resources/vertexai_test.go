// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/aiplatform/apiv1/aiplatformpb"
	"github.com/stretchr/testify/assert"
)

func TestVertexaiEndpointInternetReachable(t *testing.T) {
	cases := []struct {
		name    string
		network string
		psc     bool
		want    bool
	}{
		// Synthetic: an endpoint with no network and no PSC, served on the
		// shared {region}-aiplatform.googleapis.com host or, when dedicated,
		// on its own public DNS name.
		{name: "shared or dedicated public endpoint", want: true},
		// Synthetic: an endpoint peered into a VPC network.
		{name: "VPC-peered endpoint", network: "projects/123/global/networks/default", want: false},
		// Synthetic: an endpoint exposed only through Private Service Connect.
		{name: "PSC endpoint", psc: true, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, vertexaiEndpointInternetReachable(tc.network, tc.psc))
		})
	}
}

func TestVertexaiPscEnabled(t *testing.T) {
	// Synthetic: PSC set only through the current config message, the way the
	// API reports endpoints created after the top-level flag was deprecated.
	assert.True(t, vertexaiPscEnabled(false, &aiplatformpb.PrivateServiceConnectConfig{EnablePrivateServiceConnect: true}))
	// Synthetic: PSC set only through the deprecated top-level flag.
	assert.True(t, vertexaiPscEnabled(true, nil))
	// Synthetic: a config message that does not enable PSC.
	assert.False(t, vertexaiPscEnabled(false, &aiplatformpb.PrivateServiceConnectConfig{}))
	// Synthetic: no PSC configuration at all.
	assert.False(t, vertexaiPscEnabled(false, nil))
}

func TestRagCorpusBackendOf(t *testing.T) {
	t.Run("RAG managed database", func(t *testing.T) {
		// Synthetic: the default backend of a new corpus.
		b := ragCorpusBackendOf(&aiplatformpb.RagCorpus{
			BackendConfig: &aiplatformpb.RagCorpus_VectorDbConfig{VectorDbConfig: &aiplatformpb.RagVectorDbConfig{
				VectorDb: &aiplatformpb.RagVectorDbConfig_RagManagedDb_{RagManagedDb: &aiplatformpb.RagVectorDbConfig_RagManagedDb{}},
			}},
		})
		assert.Equal(t, "ragManagedDb", b.backendType)
		assert.Empty(t, b.pineconeIndexName)
		assert.Equal(t, secretVersionRef{}, b.apiKeySecret)
	})

	t.Run("Pinecone with an API key secret", func(t *testing.T) {
		// Synthetic: a corpus whose embeddings live in Pinecone, reached with a
		// key held in Secret Manager.
		b := ragCorpusBackendOf(&aiplatformpb.RagCorpus{
			BackendConfig: &aiplatformpb.RagCorpus_VectorDbConfig{VectorDbConfig: &aiplatformpb.RagVectorDbConfig{
				VectorDb: &aiplatformpb.RagVectorDbConfig_Pinecone_{Pinecone: &aiplatformpb.RagVectorDbConfig_Pinecone{IndexName: "docs-index"}},
				ApiAuth: &aiplatformpb.ApiAuth{AuthConfig: &aiplatformpb.ApiAuth_ApiKeyConfig_{
					ApiKeyConfig: &aiplatformpb.ApiAuth_ApiKeyConfig{ApiKeySecretVersion: "projects/p1/secrets/pinecone-key/versions/3"},
				}},
			}},
		})
		assert.Equal(t, "pinecone", b.backendType)
		assert.Equal(t, "docs-index", b.pineconeIndexName)
		assert.Equal(t, secretVersionRef{project: "p1", secret: "pinecone-key", version: "3"}, b.apiKeySecret)
		assert.Empty(t, b.servingConfig)
	})

	t.Run("Vertex Vector Search", func(t *testing.T) {
		// Synthetic: a corpus backed by a Vector Search index.
		b := ragCorpusBackendOf(&aiplatformpb.RagCorpus{
			BackendConfig: &aiplatformpb.RagCorpus_VectorDbConfig{VectorDbConfig: &aiplatformpb.RagVectorDbConfig{
				VectorDb: &aiplatformpb.RagVectorDbConfig_VertexVectorSearch_{VertexVectorSearch: &aiplatformpb.RagVectorDbConfig_VertexVectorSearch{
					IndexEndpoint: "projects/p1/locations/us-central1/indexEndpoints/1",
					Index:         "projects/p1/locations/us-central1/indexes/2",
				}},
			}},
		})
		assert.Equal(t, "vertexVectorSearch", b.backendType)
	})

	t.Run("Vertex AI Search", func(t *testing.T) {
		// Synthetic: a corpus that retrieves from a Vertex AI Search serving config.
		cfg := "projects/p1/locations/global/collections/default_collection/engines/e1/servingConfigs/default_search"
		b := ragCorpusBackendOf(&aiplatformpb.RagCorpus{
			BackendConfig: &aiplatformpb.RagCorpus_VertexAiSearchConfig{VertexAiSearchConfig: &aiplatformpb.VertexAiSearchConfig{ServingConfig: cfg}},
		})
		assert.Equal(t, "vertexAiSearch", b.backendType)
		assert.Equal(t, cfg, b.servingConfig)
	})

	t.Run("no backend reported", func(t *testing.T) {
		// Synthetic: the API omits the backend.
		assert.Equal(t, ragCorpusBackend{}, ragCorpusBackendOf(&aiplatformpb.RagCorpus{}))
	})
}

func TestParseSecretVersionName(t *testing.T) {
	// Synthetic: a global secret pinned to a version.
	assert.Equal(t, secretVersionRef{project: "p1", secret: "s1", version: "3"},
		parseSecretVersionName("projects/p1/secrets/s1/versions/3"))
	// Synthetic: a regional secret following latest.
	assert.Equal(t, secretVersionRef{project: "p1", location: "us-east1", secret: "s1", version: "latest"},
		parseSecretVersionName("projects/p1/locations/us-east1/secrets/s1/versions/latest"))
	// Synthetic: a secret name without a version is not a version name.
	assert.Equal(t, secretVersionRef{}, parseSecretVersionName("projects/p1/secrets/s1"))
	// Synthetic: empty when no API key is configured.
	assert.Equal(t, secretVersionRef{}, parseSecretVersionName(""))
}
