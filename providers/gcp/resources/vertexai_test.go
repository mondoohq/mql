// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"cloud.google.com/go/aiplatform/apiv1/aiplatformpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		assert.Equal(t, "projects/p1/locations/us-central1/indexes/2", b.vectorSearchIndex)
		assert.Equal(t, "projects/p1/locations/us-central1/indexEndpoints/1", b.vectorSearchIndexEndpoint)
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

func TestReasoningEngineDeploymentOf(t *testing.T) {
	t.Run("source code deployment from Developer Connect", func(t *testing.T) {
		// Synthetic: an ADK agent deployed from a Git repository with plain
		// and secret-backed env vars, a PSC interface and scaling bounds.
		minI, maxI := int32(1), int32(5)
		spec := &aiplatformpb.ReasoningEngineSpec{
			DeploymentSpec: &aiplatformpb.ReasoningEngineSpec_DeploymentSpec{
				Env: []*aiplatformpb.EnvVar{{Name: "MODE", Value: "prod"}, {Name: "REGION", Value: "us"}},
				SecretEnv: []*aiplatformpb.SecretEnvVar{
					{Name: "DB_PASSWORD", SecretRef: &aiplatformpb.SecretRef{Secret: "db-password", Version: "3"}},
					{Name: "DB_PASSWORD_OLD", SecretRef: &aiplatformpb.SecretRef{Secret: "db-password", Version: "2"}},
					{Name: "SHARED", SecretRef: &aiplatformpb.SecretRef{Secret: "projects/shared-proj/secrets/api-key"}},
					{Name: "BROKEN"},
				},
				PscInterfaceConfig: &aiplatformpb.PscInterfaceConfig{NetworkAttachment: "projects/p1/regions/us-central1/networkAttachments/agents"},
				MinInstances:       &minI,
				MaxInstances:       &maxI,
			},
			DeploymentSource: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec_{SourceCodeSpec: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec{
				Source: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec_DeveloperConnectSource_{
					DeveloperConnectSource: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec_DeveloperConnectSource{
						Config: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec_DeveloperConnectConfig{
							GitRepositoryLink: "projects/p1/locations/us-central1/connections/gh/gitRepositoryLinks/agent",
							Revision:          "main",
						},
					},
				},
				LanguageSpec: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec_PythonSpec_{
					PythonSpec: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec_PythonSpec{Version: "3.12"},
				},
			}},
		}

		d := reasoningEngineDeploymentOf(spec, "p1")
		assert.Equal(t, []string{"MODE", "REGION"}, d.envVarNames)
		assert.Equal(t, []reasoningEngineSecretRef{
			{project: "p1", secret: "db-password"},
			{project: "shared-proj", secret: "api-key"},
		}, d.secrets)
		assert.Equal(t, "projects/p1/regions/us-central1/networkAttachments/agents", d.networkAttachment)
		require.NotNil(t, d.minInstances)
		assert.Equal(t, int64(1), *d.minInstances)
		require.NotNil(t, d.maxInstances)
		assert.Equal(t, int64(5), *d.maxInstances)
		assert.Equal(t, "projects/p1/locations/us-central1/connections/gh/gitRepositoryLinks/agent", d.sourceRepository)
		assert.Equal(t, "main", d.revision)
		assert.Equal(t, "3.12", d.pythonVersion)
		assert.Empty(t, d.containerImage)
	})

	t.Run("container deployment", func(t *testing.T) {
		// Synthetic: an agent deployed from a container image, no scaling set.
		spec := &aiplatformpb.ReasoningEngineSpec{
			DeploymentSource: &aiplatformpb.ReasoningEngineSpec_ContainerSpec_{ContainerSpec: &aiplatformpb.ReasoningEngineSpec_ContainerSpec{
				ImageUri: "us-docker.pkg.dev/p1/agents/agent:1",
			}},
		}
		d := reasoningEngineDeploymentOf(spec, "p1")
		assert.Equal(t, "us-docker.pkg.dev/p1/agents/agent:1", d.containerImage)
		assert.Nil(t, d.minInstances)
		assert.Nil(t, d.maxInstances)
		assert.Empty(t, d.envVarNames)
		assert.Empty(t, d.secrets)
		assert.Empty(t, d.sourceRepository)
	})

	t.Run("pickled package", func(t *testing.T) {
		// Synthetic: the older package spec carries the Python version.
		spec := &aiplatformpb.ReasoningEngineSpec{
			PackageSpec: &aiplatformpb.ReasoningEngineSpec_PackageSpec{PythonVersion: "3.10"},
		}
		assert.Equal(t, "3.10", reasoningEngineDeploymentOf(spec, "p1").pythonVersion)
	})

	t.Run("no spec", func(t *testing.T) {
		// Synthetic: the API returned no spec.
		d := reasoningEngineDeploymentOf(nil, "p1")
		assert.Empty(t, d.envVarNames)
		assert.Nil(t, d.minInstances)
	})
}

func TestParseReasoningEngineSecret(t *testing.T) {
	// Synthetic: the documented bare secret name, a full name, and malformed values.
	assert.Equal(t, reasoningEngineSecretRef{project: "p1", secret: "s"}, parseReasoningEngineSecret("s", "p1"))
	assert.Equal(t, reasoningEngineSecretRef{project: "p2", secret: "s"}, parseReasoningEngineSecret("projects/p2/secrets/s", "p1"))
	assert.Equal(t, reasoningEngineSecretRef{}, parseReasoningEngineSecret("", "p1"))
	assert.Equal(t, reasoningEngineSecretRef{}, parseReasoningEngineSecret("projects/p2/secrets/s/versions/1", "p1"))
}

func TestVertexaiNameWithoutProject(t *testing.T) {
	// Synthetic: list results use the project number, references the ID.
	assert.Equal(t, "locations/us-central1/indexes/2", vertexaiNameWithoutProject("projects/123/locations/us-central1/indexes/2"))
	assert.Equal(t,
		vertexaiNameWithoutProject("projects/123/locations/us-central1/indexes/2"),
		vertexaiNameWithoutProject("projects/my-proj/locations/us-central1/indexes/2"))
	assert.Equal(t, "indexes/2", vertexaiNameWithoutProject("indexes/2"))
}

func TestVertexaiIamPolicyBindingsRefusals(t *testing.T) {
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })

	// Synthetic: the gRPC codes a GetIamPolicy call answers with.
	denied := status.Error(codes.PermissionDenied, "caller lacks aiplatform.endpoints.getIamPolicy")
	unimplemented := status.Error(codes.Unimplemented, "method not supported for this resource")
	unavailable := status.Error(codes.Unavailable, "backend unavailable")

	for _, structured := range []bool{false, true} {
		if structured {
			plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
		} else {
			plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)}))
		}

		res, err := vertexaiIamPolicyBindings(nil, "projects/p/locations/l/endpoints/1", nil, denied, "aiplatform.endpoints.getIamPolicy")
		assert.Nil(t, res)
		if structured {
			require.Error(t, err)
			assert.True(t, errors.Is(err, llx.ErrForbidden))
		} else {
			assert.NoError(t, err)
		}

		res, err = vertexaiIamPolicyBindings(nil, "projects/p/locations/l/reasoningEngines/1", nil, unimplemented)
		assert.Nil(t, res)
		if structured {
			require.Error(t, err)
			assert.True(t, errors.Is(err, llx.ErrNotApplicable))
		} else {
			assert.NoError(t, err)
		}

		_, err = vertexaiIamPolicyBindings(nil, "projects/p/locations/l/endpoints/1", nil, unavailable)
		assert.Equal(t, unavailable, err)
	}
}

func TestVertexaiRegionalLocations(t *testing.T) {
	// Synthetic: ListLocations answers with regions, a global entry, a
	// multi-region and a duplicate.
	got := vertexaiRegionalLocations([]string{"us-central1", "global", "europe-west4", "us", "us-central1", "me-central2"})
	assert.Equal(t, []string{"us-central1", "europe-west4", "me-central2"}, got)

	assert.Empty(t, vertexaiRegionalLocations(nil))
}

func TestVertexaiCandidateRegionsFallsBackWithoutConnection(t *testing.T) {
	// Synthetic: no runtime to ask, so the built-in list is used.
	svc := &mqlGcpProjectVertexaiService{}
	assert.Equal(t, vertexaiRegions, svc.candidateRegions())
}
