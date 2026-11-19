// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	cs "github.com/codesphere-cloud/cs-go/api/openapi_client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: workspaces shaped per the API schema, decoded by the vendor
// client; no live Codesphere account was available.
func TestWorkspaceArgs(t *testing.T) {
	var w cs.WorkspacesGetWorkspace200Response
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": 101, "teamId": 12, "name": "api", "planId": 8, "isPrivateRepo": true,
		"replicas": 2, "dataCenterId": 2, "userId": 42,
		"gitUrl": "https://ghp_secret@github.com/acme/api.git", "initialBranch": "main",
		"sourceWorkspaceId": 99, "welcomeMessage": null, "vpnConfig": "office",
		"restricted": true, "collectTraces": false, "persistentLogs": true,
		"devDomain": "101-3000.dev.example.com", "baseImage": "ubuntu-24.04",
		"createdAt": "2026-02-03T04:05:06Z"
	}`), &w))
	args := workspaceArgs(&w)
	assert.Equal(t, int64(101), args["id"].Value)
	assert.Equal(t, "https://xxxxx@github.com/acme/api.git", args["gitUrl"].Value)
	assert.Equal(t, true, args["isPrivateRepo"].Value)
	assert.Equal(t, true, args["restricted"].Value)
	assert.Equal(t, false, args["collectTraces"].Value)
	assert.Equal(t, true, args["persistentLogs"].Value)
	assert.Equal(t, true, args["hasVpnConfig"].Value)
	assert.Nil(t, args["welcomeMessage"].Value)
	assert.Equal(t, "101-3000.dev.example.com", args["devDomain"].Value)

	var bare cs.WorkspacesGetWorkspace200Response
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": 102, "teamId": 12, "name": "scratch", "planId": 8, "isPrivateRepo": false,
		"replicas": 1, "dataCenterId": 2, "userId": 42,
		"gitUrl": null, "initialBranch": null, "sourceWorkspaceId": null,
		"welcomeMessage": null, "vpnConfig": null,
		"restricted": false, "collectTraces": false, "persistentLogs": false,
		"createdAt": "2026-02-03T04:05:06Z"
	}`), &bare))
	args = workspaceArgs(&bare)
	assert.Nil(t, args["gitUrl"].Value, "no repository is null, not an empty string")
	assert.Nil(t, args["initialBranch"].Value)
	assert.Nil(t, args["devDomain"].Value)
	assert.Equal(t, false, args["hasVpnConfig"].Value)
}
