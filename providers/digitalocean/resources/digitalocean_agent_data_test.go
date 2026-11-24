// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: plans in the shape of godo's ADSPlansResponse JSON, one region listed twice; no live account was checked.
func TestAgentDataPlanRegions(t *testing.T) {
	var plans godo.ADSPlansResponse
	require.NoError(t, json.Unmarshal([]byte(`{"plans":[
		{"region_slug":"nyc3","available_for_create":true},
		{"region_slug":"ams3","available_for_create":false},
		{"region_slug":"nyc3"},{"region_slug":""}
	]}`), &plans))
	assert.Equal(t, []string{"nyc3", "ams3"}, agentDataPlanRegions(&plans))
	assert.Nil(t, agentDataPlanRegions(nil))
}

// Synthetic: token pagination whose total arrives as a decimal string; no live account was checked.
func TestListAgentDataTokensFollowsTotal(t *testing.T) {
	var pages []string
	client := newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/data-cloud-platform/nyc3/tokens", r.URL.Path)
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"tokens":[{"id":"t-%s"}],"total":"2"}`, page)
	})
	tokens, err := listAgentDataTokens(context.Background(), client.ADS, "nyc3")
	require.NoError(t, err)
	require.Len(t, tokens, 2)
	assert.Equal(t, []string{"1", "2"}, pages)
}

// Synthetic: a token summary in the shape of godo's ADSTokenSummary JSON; no live account was checked.
func TestAgentDataTokenArgs(t *testing.T) {
	var tok godo.ADSTokenSummary
	require.NoError(t, json.Unmarshal([]byte(`{"id":"t-1","name":"ci","created_at":"2026-10-01T10:00:00Z","purpose":"TOKEN_PURPOSE_QUERY","query_hosts":["q.nyc3.example"],"workspace_uuids":["ws-1"]}`), &tok))
	args, err := agentDataTokenArgs(&tok, "nyc3")
	require.NoError(t, err)
	assert.Equal(t, "TOKEN_PURPOSE_QUERY", args["purpose"].Value)
	assert.Equal(t, []any{"q.nyc3.example"}, args["queryHosts"].Value)
	assert.NotNil(t, args["createdAt"].Value)
	assert.Nil(t, args["expiresAt"].Value, "a token without an expiry never expires and reads null")

	// Token ids are listed per region, so the key carries the region.
	other, err := agentDataTokenArgs(&tok, "ams3")
	require.NoError(t, err)
	assert.NotEqual(t, args["__id"].Value, other["__id"].Value)
}

// Synthetic: workspaces swept over the plan regions, one of which does not offer the service (404); a token resolves its workspace; no live account was checked.
func TestAgentDataWorkspacesAndTokens(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/data-cloud-platform/plans":                        {200, `{"plans":[{"region_slug":"nyc3"},{"region_slug":"sfo3"}]}`},
		"/v2/data-cloud-platform/nyc3/workspaces":              {200, `{"workspaces":[{"uuid":"ws-1","name":"analytics","status":"active","query_endpoint":"q.nyc3.example"}]}`},
		"/v2/data-cloud-platform/nyc3/tokens":                  {200, `{"tokens":[{"id":"t-1","workspace_uuids":["ws-1","ws-deleted"]}],"total":"1"}`},
		"/v2/data-cloud-platform/nyc3/workspaces/ws-1/secrets": {200, `{"secret_keys":["warehouse"]}`},
	})
	root, err := parentDigitalocean(rt)
	require.NoError(t, err)

	ws, err := root.agentDataWorkspaces()
	require.NoError(t, err)
	require.Len(t, ws, 1)
	w := ws[0].(*mqlDigitaloceanAgentDataWorkspace)
	assert.Equal(t, "nyc3", w.Region.Data, "a workspace that omits its region is in the region it was listed from")

	keys, err := w.secretKeys()
	require.NoError(t, err)
	assert.Equal(t, []any{"warehouse"}, keys)

	toks, err := root.agentDataTokens()
	require.NoError(t, err)
	require.Len(t, toks, 1)
	bound, err := toks[0].(*mqlDigitaloceanAgentDataToken).workspaces()
	require.NoError(t, err)
	require.Len(t, bound, 1, "a binding to a deleted workspace is skipped")
	assert.Equal(t, "ws-1", bound[0].(*mqlDigitaloceanAgentDataWorkspace).Id.Data)
}

// Synthetic: a refusal in a region other than a 403/404 fails the list rather than reading as no workspaces; no live account was checked.
func TestAgentDataWorkspacesUnauthenticatedFails(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/data-cloud-platform/plans":           {200, `{"plans":[{"region_slug":"nyc3"}]}`},
		"/v2/data-cloud-platform/nyc3/workspaces": {401, `{"id":"unauthorized","message":"bad token"}`},
	})
	root, err := parentDigitalocean(rt)
	require.NoError(t, err)
	_, err = root.agentDataWorkspaces()
	require.Error(t, err)
}
