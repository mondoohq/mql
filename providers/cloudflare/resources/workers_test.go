// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestWorkers(env *testEnv) *mqlCloudflareWorkers {
	w := &mqlCloudflareWorkers{MqlRuntime: env.Runtime}
	w.AccountID = testAccountID
	return w
}

// TestWorkersDistinctIDs is the regression guard for the __id collision: the
// cloudflare.workers.worker resource has no id() method, so without an explicit
// __id every worker shared the empty cache key ("cloudflare.workers.worker\x00")
// and every row aliased the first script. Assert two scripts resolve to two
// distinct resources with their own data.
func TestWorkersDistinctIDs(t *testing.T) {
	env := setupTestEnv(t)
	env.Mux.HandleFunc("/accounts/"+testAccountID+"/workers/scripts", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"errors":[],"messages":[],"result":[
			{"id":"script-a","etag":"etag-a","size":100},
			{"id":"script-b","etag":"etag-b","size":200}
		]}`)
	})

	res, err := newTestWorkers(env).workers()
	require.NoError(t, err)
	require.Len(t, res, 2)

	w0 := res[0].(*mqlCloudflareWorkersWorker)
	w1 := res[1].(*mqlCloudflareWorkersWorker)

	assert.NotEqual(t, w0.MqlID(), w1.MqlID(), "each worker must get a distinct cache key")
	assert.Equal(t, "script-a", w0.Id.Data)
	assert.Equal(t, "script-b", w1.Id.Data)
	assert.Equal(t, int64(100), w0.Size.Data)
	assert.Equal(t, int64(200), w1.Size.Data)
}

// TestWorkersListDegradesOnForbidden verifies a gated/permission-limited
// account degrades to an empty list rather than failing the whole query.
func TestWorkersListDegradesOnForbidden(t *testing.T) {
	env := setupTestEnv(t)
	env.Mux.HandleFunc("/accounts/"+testAccountID+"/workers/scripts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`)
	})

	// workers() itself propagates the fetch error (the list is a core Workers
	// call, not a gated sub-resource); pages(), a gated add-on, degrades.
	env.Mux.HandleFunc("/accounts/"+testAccountID+"/pages/projects", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`)
	})

	pages, err := newTestWorkers(env).pages()
	require.NoError(t, err, "pages() must degrade on 403, not error")
	assert.Empty(t, pages)
}

// TestWorkersPages verifies the pages() implementation maps a project's
// canonical deployment (previously pages() was a stub returning empty).
func TestWorkersPages(t *testing.T) {
	env := setupTestEnv(t)
	env.Mux.HandleFunc("/accounts/"+testAccountID+"/pages/projects", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"errors":[],"messages":[],"result":[
			{"id":"proj-1","name":"marketing-site","production_branch":"main",
			 "canonical_deployment":{"id":"dep-1","short_id":"dep1","project_id":"proj-1",
			   "project_name":"marketing-site","environment":"production",
			   "url":"https://marketing.pages.dev","aliases":["https://www.example.com"]}},
			{"id":"proj-2","name":"no-deploy-yet","production_branch":"main","canonical_deployment":null}
		],"result_info":{"page":1,"total_pages":1}}`)
	})

	pages, err := newTestWorkers(env).pages()
	require.NoError(t, err)
	require.Len(t, pages, 1, "a project without a canonical deployment is skipped")

	p := pages[0].(*mqlCloudflareWorkersPage)
	assert.Equal(t, "dep-1", p.Id.Data)
	assert.Equal(t, "marketing-site", p.ProjectName.Data)
	assert.Equal(t, "production", p.Environment.Data)
	assert.Equal(t, "https://marketing.pages.dev", p.Url.Data)
	assert.Equal(t, "main", p.ProductionBranch.Data)
}

// TestWorkersUnboundAccountIssuesNoRequest is the regression guard for the empty
// account id. `cloudflare.workers` reached bare (not via
// cloudflare.account.workers) was built with no AccountID, so every accessor
// requested /accounts//workers/scripts and friends. Those 404, and a 404
// degrades to an empty list, so a malformed request read as "nothing deployed".
// Fail before issuing the request.
func TestWorkersUnboundAccountIssuesNoRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*mqlCloudflareWorkers) ([]any, error)
	}{
		{"workers", (*mqlCloudflareWorkers).workers},
		{"pages", (*mqlCloudflareWorkers).pages},
		{"secrets", (*mqlCloudflareWorkers).secrets},
		{"pageEnvVars", (*mqlCloudflareWorkers).pageEnvVars},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := setupTestEnv(t)
			env.Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("no request may be issued without an account: %s", r.URL.Path)
			})

			res, err := tc.call(&mqlCloudflareWorkers{MqlRuntime: env.Runtime})
			require.ErrorIs(t, err, errNoAccountBound)
			assert.Nil(t, res, "must not degrade to an empty list, which would pass vacuously")
		})
	}
}
