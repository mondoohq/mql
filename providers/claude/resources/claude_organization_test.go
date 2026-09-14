// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/claude/connection"
)

func decodeWorkspace(t *testing.T, payload string) connection.AdminWorkspace {
	t.Helper()
	var w connection.AdminWorkspace
	require.NoError(t, json.Unmarshal([]byte(payload), &w))
	return w
}

// A live workspace has no archive date. Reporting the zero time instead of
// null dates every active workspace to year 1, so a query looking for the
// workspaces archived before a cutoff returns the entire organization.
func TestWorkspaceArgsLiveWorkspaceReadsNullArchivedAt(t *testing.T) {
	w := decodeWorkspace(t, `{
		"id": "wrkspc_0000",
		"type": "workspace",
		"name": "platform",
		"display_color": "#6C5BB9",
		"created_at": "2026-01-15T09:00:00Z",
		"archived_at": null,
		"data_residency": {
			"workspace_geo": "us",
			"default_inference_geo": "us",
			"allowed_inference_geos": "unrestricted"
		}
	}`)

	args, err := workspaceArgs(w)
	require.NoError(t, err)

	assert.Nil(t, args["archivedAt"].Value)
	assert.Equal(t, "platform", args["name"].Value)
	assert.Equal(t, "us", args["workspaceGeo"].Value)
	assert.Equal(t, []interface{}{"unrestricted"}, args["allowedInferenceGeos"].Value)
}

// An archived workspace reports when it was archived, which is the whole
// reason to list archived workspaces at all.
func TestWorkspaceArgsArchivedWorkspaceCarriesTimestamp(t *testing.T) {
	w := decodeWorkspace(t, `{
		"id": "wrkspc_0001",
		"type": "workspace",
		"name": "retired-team",
		"display_color": "#111111",
		"created_at": "2025-03-04T12:00:00Z",
		"archived_at": "2026-02-01T18:30:00Z"
	}`)

	args, err := workspaceArgs(w)
	require.NoError(t, err)

	require.NotNil(t, args["archivedAt"].Value)
	assert.Equal(t, time.Date(2026, 2, 1, 18, 30, 0, 0, time.UTC), args["archivedAt"].Value.(*time.Time).UTC())
	assert.Equal(t, "wrkspc_0001", args["__id"].Value)

	// A workspace with no data_residency block must not invent a geo. An
	// empty string is the API saying nothing, not "no restriction".
	assert.Equal(t, "", args["workspaceGeo"].Value)
	assert.Equal(t, []interface{}{}, args["allowedInferenceGeos"].Value)
}

// A malformed timestamp has to surface as an error rather than resolve to the
// zero time, which would read as an archived workspace on an active one.
func TestWorkspaceArgsRejectsUnparseableArchivedAt(t *testing.T) {
	w := decodeWorkspace(t, `{
		"id": "wrkspc_0002",
		"created_at": "2025-03-04T12:00:00Z",
		"archived_at": "yesterday"
	}`)

	_, err := workspaceArgs(w)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "archivedAt")
}
