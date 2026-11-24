// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaviate/weaviate/entities/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/weaviate/connection"
	"go.mondoo.com/mql/types"
)

// newTestServer serves handler behind the metadata endpoint the Go client
// reads when it is first built.
func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/meta" {
			_, _ = w.Write([]byte(`{"version":"1.38.0"}`))
			return
		}
		handler.ServeHTTP(w, r)
	}))
}

// serverRuntime returns a runtime whose connection reaches srv.
func serverRuntime(t *testing.T, srv *httptest.Server) *plugin.Runtime {
	t.Helper()
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	host, port, err := net.SplitHostPort(u.Host)
	require.NoError(t, err)
	conf := &inventory.Config{
		Type:    "weaviate",
		Options: map[string]string{"host": host, "port": port},
	}
	conn, err := connection.NewWeaviateConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf)
	require.NoError(t, err)
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

// testInstance builds an instance resource without running its init, which
// would probe the server's metadata and access control.
func testInstance(t *testing.T, runtime *plugin.Runtime, modules ...string) *mqlWeaviateInstance {
	t.Helper()
	mods := make([]any, 0, len(modules))
	for _, m := range modules {
		mods = append(mods, m)
	}
	res, err := CreateResource(runtime, "weaviate.instance", map[string]*llx.RawData{
		"__id":    llx.StringData("http://weaviate.test:8080"),
		"modules": llx.ArrayData(mods, types.String),
	})
	require.NoError(t, err)
	return res.(*mqlWeaviateInstance)
}

func decodeClass(t *testing.T, body string) *models.Class {
	t.Helper()
	var class models.Class
	require.NoError(t, json.Unmarshal([]byte(body), &class))
	return &class
}

// Synthetic: a class shaped after models.Class JSON tags and the settings the
// generative-openai, reranker-cohere, and text2vec-openai modules accept; no
// live server was checked.
const ragClassBody = `{
  "class": "Article",
  "vectorizer": "none",
  "moduleConfig": {
    "generative-openai": {"model": "gpt-4o", "baseURL": "https://llm-proxy.example.internal/v1", "apiKey": "sk-secret"},
    "reranker-cohere": {"model": "rerank-v3.5"},
    "text2vec-openai": {"baseURL": "https://api.openai.com"}
  },
  "vectorConfig": {
    "title": {"vectorizer": {"text2vec-openai": {"model": "text-embedding-3-small"}}, "vectorIndexType": "hnsw"},
    "imported": {"vectorizer": {"none": {}}, "vectorIndexType": "flat"}
  },
  "objectTtlConfig": {"enabled": true, "defaultTtl": 86400, "deleteOn": "_creationTimeUnix", "filterExpiredObjects": false},
  "replicationConfig": {"factor": 3, "deletionStrategy": "TimeBasedResolution"},
  "multiTenancyConfig": {"enabled": true}
}`

func TestCollectionArgs(t *testing.T) {
	args := collectionArgs("http://weaviate.test:8080", decodeClass(t, ragClassBody))

	assert.Equal(t, "generative-openai", args["generativeModule"].Value)
	assert.Equal(t, "reranker-cohere", args["rerankerModule"].Value)
	assert.Equal(t, map[string]any{
		"generative-openai": "https://llm-proxy.example.internal/v1",
		"text2vec-openai":   "https://api.openai.com",
	}, args["moduleEndpoints"].Value)
	assert.Equal(t, map[string]any{"title": "text2vec-openai", "imported": "none"}, args["vectorizers"].Value)
	assert.Equal(t, true, args["objectTtlEnabled"].Value)
	assert.Equal(t, int64(86400), args["objectTtlDefault"].Value)
	assert.Equal(t, "_creationTimeUnix", args["objectTtlDeleteOn"].Value)
	assert.Equal(t, "TimeBasedResolution", args["replicationDeletionStrategy"].Value)
	assert.Equal(t, int64(3), args["replicationFactor"].Value)
	assert.Equal(t, true, args["multiTenancyEnabled"].Value)

	for k, v := range args {
		if s, ok := v.Value.(string); ok {
			assert.NotContains(t, s, "sk-secret", "field %s", k)
		}
	}
}

// Synthetic: a class with no module, named-vector, time-to-live, or
// replication configuration; no live server was checked. Every setting that
// only means something when configured reads null, not a zero value.
func TestCollectionArgsAbsent(t *testing.T) {
	args := collectionArgs("http://weaviate.test:8080", decodeClass(t, `{"class": "Plain", "vectorizer": "none"}`))

	assert.Nil(t, args["generativeModule"].Value)
	assert.Nil(t, args["rerankerModule"].Value)
	assert.Nil(t, args["objectTtlDefault"].Value)
	assert.Nil(t, args["objectTtlDeleteOn"].Value)
	assert.Nil(t, args["replicationDeletionStrategy"].Value)
	assert.Equal(t, false, args["objectTtlEnabled"].Value)
	assert.Empty(t, args["moduleEndpoints"].Value)
	assert.Empty(t, args["vectorizers"].Value)
}

// Synthetic: endpoint settings under each key the server's modules use; no
// live server was checked.
func TestModuleEndpoints(t *testing.T) {
	got := moduleEndpoints(map[string]any{
		"generative-google":      map[string]any{"apiEndpoint": "us-central1-aiplatform.googleapis.com", "projectId": "p"},
		"generative-aws":         map[string]any{"service": "sagemaker", "endpoint": "my-endpoint"},
		"text2vec-huggingface":   map[string]any{"endpointURL": "https://hf.example/models/x"},
		"text2vec-transformers":  map[string]any{"inferenceUrl": "http://t2v:8080"},
		"text2vec-cohere":        map[string]any{"baseUrl": "https://cohere.example"},
		"generative-anthropic":   map[string]any{"baseURL": "", "model": "claude"},
		"qna-openai":             map[string]any{"model": "x"},
		"text2vec-contextionary": nil,
		// baseURL wins over the others when a module sets more than one.
		"generative-openai": map[string]any{"endpoint": "ignored", "baseURL": "https://openai.example"},
	})
	assert.Equal(t, map[string]any{
		"generative-google":     "us-central1-aiplatform.googleapis.com",
		"generative-aws":        "my-endpoint",
		"text2vec-huggingface":  "https://hf.example/models/x",
		"text2vec-transformers": "http://t2v:8080",
		"text2vec-cohere":       "https://cohere.example",
		"generative-openai":     "https://openai.example",
	}, got)

	assert.Empty(t, moduleEndpoints(nil))
	assert.Empty(t, moduleEndpoints("not-an-object"))
}

// Synthetic: credentials in the places a URL can carry them; no live server
// was checked.
func TestRedactEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://user:pass@llm.example/v1?api-key=secret#frag": "https://llm.example/v1",
		"https://llm.example/v1?":                              "https://llm.example/v1",
		"http://t2v:8080":                                      "http://t2v:8080",
		"us-central1-aiplatform.googleapis.com":                "us-central1-aiplatform.googleapis.com",
		"my-sagemaker-endpoint":                                "my-sagemaker-endpoint",
	}
	for in, want := range cases {
		assert.Equal(t, want, redactEndpoint(in), in)
	}
}

// Synthetic: module-config objects; no live server was checked.
func TestModuleWithPrefix(t *testing.T) {
	cfg := map[string]any{"text2vec-openai": map[string]any{}, "reranker-voyageai": map[string]any{}}
	got := moduleWithPrefix(cfg, rerankerModulePrefix)
	require.NotNil(t, got)
	assert.Equal(t, "reranker-voyageai", *got)
	assert.Nil(t, moduleWithPrefix(cfg, generativeModulePrefix))
	assert.Nil(t, moduleWithPrefix(nil, generativeModulePrefix))
}

// Synthetic: a server that refuses every request; no live server was checked.
// A collection without multi-tenancy must not ask for tenants, which the
// server refuses for it.
func TestTenantsSkipsSingleTenantCollection(t *testing.T) {
	var calls atomic.Int32
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer srv.Close()
	runtime := serverRuntime(t, srv)

	args := collectionArgs("http://weaviate.test:8080", decodeClass(t, `{"class": "Plain"}`))
	res, err := CreateResource(runtime, "weaviate.collection", args)
	require.NoError(t, err)
	tenants, err := res.(*mqlWeaviateCollection).tenants()
	require.NoError(t, err)
	assert.Empty(t, tenants)
	assert.Equal(t, int32(0), calls.Load())
}

// Synthetic: a GET /v1/schema/Article/tenants body shaped after models.Tenant;
// no live server was checked.
func TestTenants(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/schema/Article/tenants", r.URL.Path)
		_, _ = w.Write([]byte(`[{"name":"tenantA","activityStatus":"ACTIVE"},{"name":"tenantB","activityStatus":"OFFLOADED"}]`))
	}))
	defer srv.Close()
	runtime := serverRuntime(t, srv)

	res, err := CreateResource(runtime, "weaviate.collection", collectionArgs("http://weaviate.test:8080", decodeClass(t, ragClassBody)))
	require.NoError(t, err)
	list, err := res.(*mqlWeaviateCollection).tenants()
	require.NoError(t, err)
	require.Len(t, list, 2)
	a := list[0].(*mqlWeaviateCollectionTenant)
	b := list[1].(*mqlWeaviateCollectionTenant)
	assert.Equal(t, "tenantA", a.Name.Data)
	assert.Equal(t, "ACTIVE", a.ActivityStatus.Data)
	assert.Equal(t, "OFFLOADED", b.ActivityStatus.Data)
	assert.NotEqual(t, a.MqlID(), b.MqlID())
	assert.Equal(t, "http://weaviate.test:8080/collection/Article/tenant/tenantA", a.MqlID())
}
