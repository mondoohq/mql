// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: a one-key page shaped after the Admin API reference; no live
// organization was checked.
//
// Without owner_project_access the endpoint applies its membership-based
// visibility rules and can leave out enabled keys, so the list must ask for
// every key with `any`.
func TestProjectAPIKeyPagerRequestsEveryKey(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/organization/projects/proj_abc/api_keys", r.URL.Path)
		query = r.URL.Query().Get("owner_project_access")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"object":"organization.project.api_key",
			"id":"key_abc","name":"ci","redacted_value":"sk-...abcd","created_at":1730419200,
			"owner_project_access":"inactive","owner":{"type":"user","user":{"id":"user-abc"}}}],
			"has_more":false}`))
	}))
	defer srv.Close()

	client := testAdminClient(srv.URL)
	iter := projectAPIKeyPager(context.Background(), &client, "proj_abc")
	require.True(t, iter.Next())
	require.NoError(t, iter.Err())

	assert.Equal(t, "any", query)
	assert.Equal(t, "key_abc", iter.Current().ID)
}

// Synthetic: owner_project_access values from the Admin API reference; no live
// organization was checked.
func TestOwnerProjectAccess(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want *bool
	}{
		{"active", `{"id":"key_a","owner_project_access":"active"}`, new(true)},
		{"inactive", `{"id":"key_b","owner_project_access":"inactive"}`, new(false)},
		{"absent", `{"id":"key_c"}`, nil},
		{"null", `{"id":"key_d","owner_project_access":null}`, nil},
		{"unlisted value", `{"id":"key_e","owner_project_access":"suspended"}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := decodeJSON[openai.ProjectAPIKey](t, tc.json)
			assert.Equal(t, tc.want, ownerProjectAccess(k.OwnerProjectAccess))
		})
	}
}
