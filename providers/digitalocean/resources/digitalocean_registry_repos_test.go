// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/utils/syncx"
)

// routedRuntime points a real connection at a server that answers each path
// in routes with its body, and fails the test on any other path.
func routedRuntime(t *testing.T, routes map[string]string) *plugin.Runtime {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			t.Errorf("unexpected request to %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"id":"not_found","message":"not found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	t.Setenv("DIGITALOCEAN_TOKEN", "test-token")
	conn, err := connection.NewDigitaloceanConnection(0, &inventory.Asset{},
		&inventory.Config{Options: map[string]string{}})
	require.NoError(t, err)

	base, err := url.Parse(srv.URL + "/")
	require.NoError(t, err)
	conn.Client().BaseURL = base

	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

// The account-wide repository list used to read only the legacy
// single-registry endpoint, which names the default registry. On an account
// with a second registry every repository in it was missing, with no error.
// The legacy endpoint is served here naming only "alpha", so reading it
// instead of the registries listing drops "beta/api" and fails the test.
func TestRegistryRepositoriesCoversEveryRegistry(t *testing.T) {
	runtime := routedRuntime(t, map[string]string{
		"/v2/registries":                    `{"registries":[{"name":"alpha"},{"name":"beta"}]}`,
		"/v2/registry":                      `{"registry":{"name":"alpha"}}`,
		"/v2/registry/subscription":         `{}`,
		"/v2/registry/alpha/repositoriesV2": `{"repositories":[{"registry_name":"alpha","name":"web"}]}`,
		"/v2/registry/beta/repositoriesV2":  `{"repositories":[{"registry_name":"beta","name":"api"}]}`,
	})
	r := &mqlDigitalocean{MqlRuntime: runtime}

	out, err := r.registryRepositories()
	require.NoError(t, err)

	var got []string
	for _, o := range out {
		repo, ok := o.(*mqlDigitaloceanRegistryRepository)
		require.True(t, ok)
		got = append(got, repo.RegistryName.Data+"/"+repo.Name.Data)
	}
	sort.Strings(got)
	assert.Equal(t, []string{"alpha/web", "beta/api"}, got)
}

// An account with no registry is a real, empty answer.
func TestRegistryRepositoriesNoRegistryIsEmpty(t *testing.T) {
	runtime := routedRuntime(t, map[string]string{
		"/v2/registries":            `{"registries":[]}`,
		"/v2/registry/subscription": `{}`,
	})
	r := &mqlDigitalocean{MqlRuntime: runtime}

	out, err := r.registryRepositories()
	require.NoError(t, err)
	assert.NotNil(t, out)
	assert.Empty(t, out)
}

func TestDatabaseEngineHasPools(t *testing.T) {
	assert.True(t, databaseEngineHasPools("pg"))
	for _, engine := range []string{"mysql", "redis", "valkey", "mongodb", "kafka", "opensearch", ""} {
		assert.False(t, databaseEngineHasPools(engine), engine)
	}
}

// A MySQL cluster holds no pools, so pools answers [] without calling the
// pools endpoint. routedRuntime serves no routes here and fails the test on
// any request, so dropping the engine gate fails it.
func TestDatabasePoolsSkipsNonPostgres(t *testing.T) {
	r := &mqlDigitaloceanDatabase{
		MqlRuntime: routedRuntime(t, map[string]string{}),
		Id:         plugin.TValue[string]{Data: "db-1", State: plugin.StateIsSet},
		Engine:     plugin.TValue[string]{Data: "mysql", State: plugin.StateIsSet},
	}

	out, err := r.pools()
	require.NoError(t, err)
	assert.NotNil(t, out)
	assert.Empty(t, out)
}
