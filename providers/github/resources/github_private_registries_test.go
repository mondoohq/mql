// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Synthetic: repository ids picked from a listing; no target showed this.
func TestReposByID(t *testing.T) {
	mk := func(id int64) *mqlGithubRepository {
		return &mqlGithubRepository{Id: plugin.TValue[int64]{Data: id, State: plugin.StateIsSet}}
	}
	a, b, c := mk(1), mk(2), mk(3)
	got := reposByID([]any{a, b, c}, []int64{3, 1, 99})
	assert.Equal(t, []any{a, c}, got)
	assert.Empty(t, reposByID([]any{a}, nil))
}

// Synthetic: a registry listing entry as GitHub documents it; no target showed
// this.
func TestPrivateRegistryArgs(t *testing.T) {
	var p github.PrivateRegistry
	require.NoError(t, json.Unmarshal([]byte(`{
		"name": "MAVEN_REPOSITORY_SECRET", "registry_type": "maven_repository",
		"username": "monalisa", "visibility": "selected"
	}`), &p))
	args := privateRegistryArgs("o", &p)
	assert.Equal(t, "maven_repository", args["registryType"].Value)
	assert.Equal(t, "selected", args["visibility"].Value)
	assert.Equal(t, llx.NilData, args["authType"], "an absent auth type is null, not empty")
	assert.Equal(t, llx.NilData, args["replacesBase"], "an absent flag is null, not false")
	assert.Equal(t, llx.NilData, args["awsRoleName"])
}
