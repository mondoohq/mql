// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func handleDatasetList(env *testEnv, body string) {
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/logs/explorer/datasets", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, body)
	})
}

func datasetsOf(t *testing.T, env *testEnv) []*mqlCloudflareLogExplorerDataset {
	t.Helper()
	acc := createTestAccount(t, env)
	list, err := acc.logExplorerDatasets()
	require.NoError(t, err)

	out := make([]*mqlCloudflareLogExplorerDataset, 0, len(list))
	for _, entry := range list {
		out = append(out, entry.(*mqlCloudflareLogExplorerDataset))
	}
	return out
}

// deletionProtection is the field an audit turns on, so its JSON tag has to be
// pinned: a mistyped tag decodes to false and reports every dataset as
// unprotected, which is the direction that produces false findings.
func TestLogExplorerDatasetDecoding(t *testing.T) {
	env := setupTestEnv(t)
	handleDatasetList(env, fmt.Sprintf(`{"success":true,"result":[
		{"dataset_id":"ds-protected","dataset":"http_requests","deletion_protection":true,"enabled":true,
		 "object_type":"account","object_id":%q,
		 "created_at":"2026-01-02T03:04:05Z","updated_at":"2026-02-03T04:05:06Z"},
		{"dataset_id":"ds-open","dataset":"firewall_events","deletion_protection":false,"enabled":false,
		 "object_type":"zone","object_id":%q,
		 "created_at":"2026-01-02T03:04:05Z","updated_at":"2026-02-03T04:05:06Z"}
	]}`, testAccountID, testZoneID))

	got := datasetsOf(t, env)
	require.Len(t, got, 2)

	assert.Equal(t, "ds-protected", got[0].DatasetId.Data)
	assert.Equal(t, "http_requests", got[0].Dataset.Data)
	assert.True(t, got[0].DeletionProtection.Data)
	assert.True(t, got[0].Enabled.Data)
	assert.Equal(t, "account", got[0].ObjectType.Data)
	assert.Equal(t, testAccountID, got[0].ObjectId.Data)
	require.NotNil(t, got[0].CreatedAt.Data)
	assert.Equal(t, 2026, got[0].CreatedAt.Data.Year())

	assert.False(t, got[1].DeletionProtection.Data)
	assert.False(t, got[1].Enabled.Data)
	assert.Equal(t, "zone", got[1].ObjectType.Data)
	assert.Equal(t, testZoneID, got[1].ObjectId.Data)

	// Distinct datasets must not share a cache entry.
	assert.NotEqual(t, got[0].MqlID(), got[1].MqlID())
}

// An account-scoped dataset has no zone, and must report null rather than
// resolving to an arbitrary one.
func TestLogExplorerDatasetZoneNullForAccountScope(t *testing.T) {
	env := setupTestEnv(t)
	handleDatasetList(env, fmt.Sprintf(`{"success":true,"result":[
		{"dataset_id":"ds-1","dataset":"http_requests","deletion_protection":true,"enabled":true,
		 "object_type":"account","object_id":%q,
		 "created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z"}
	]}`, testAccountID))

	got := datasetsOf(t, env)
	require.Len(t, got, 1)

	zone, err := got[0].zone()
	require.NoError(t, err)
	assert.Nil(t, zone)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, got[0].Zone.State)
}

// A zone-scoped dataset has to be read back through its zone path. Reading it
// under the account path answers 404, which degrades to a null filter and would
// read as "retains everything" on a dataset that filters.
func TestLogExplorerDatasetFilterUsesZoneScope(t *testing.T) {
	env := setupTestEnv(t)
	handleDatasetList(env, fmt.Sprintf(`{"success":true,"result":[
		{"dataset_id":"ds-zone","dataset":"http_requests","deletion_protection":false,"enabled":true,
		 "object_type":"zone","object_id":%q,
		 "created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z"}
	]}`, testZoneID))

	accountPathHit := false
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/logs/explorer/datasets/ds-zone", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		accountPathHit = true
		w.WriteHeader(http.StatusNotFound)
		jsonResponse(w, `{"success":false,"errors":[{"code":1000,"message":"not found"}]}`)
	})
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/logs/explorer/datasets/ds-zone", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":{"dataset_id":"ds-zone","dataset":"http_requests",
			"deletion_protection":false,"enabled":true,"object_type":"zone","object_id":"z","fields":[],
			"filter":"http.response.code ge 500",
			"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z"}}`)
	})

	got := datasetsOf(t, env)
	require.Len(t, got, 1)

	filter, err := got[0].filter()
	require.NoError(t, err)
	assert.Equal(t, "http.response.code ge 500", filter)
	assert.False(t, accountPathHit, "a zone-scoped dataset must not be read under the account path")
}

// A dataset the token cannot read reports a null filter, never the empty string
// that means "retains every entry".
func TestLogExplorerDatasetFilterUnreadableIsNull(t *testing.T) {
	env := setupTestEnv(t)
	handleDatasetList(env, fmt.Sprintf(`{"success":true,"result":[
		{"dataset_id":"ds-1","dataset":"http_requests","deletion_protection":true,"enabled":true,
		 "object_type":"account","object_id":%q,
		 "created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z"}
	]}`, testAccountID))

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/logs/explorer/datasets/ds-1", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
	})

	got := datasetsOf(t, env)
	require.Len(t, got, 1)

	filter, err := got[0].filter()
	require.NoError(t, err)
	assert.Equal(t, "", filter)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, got[0].Filter.State)
}
