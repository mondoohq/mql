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
)

// Synthetic: one secret name in three stores; no target showed this.
func TestCodespacesSecretIDIsScoped(t *testing.T) {
	org := codespacesSecretID(scopeOrganization, "o", "", "TOKEN")
	repo := codespacesSecretID(scopeRepository, "o", "r", "TOKEN")
	other := codespacesSecretID(scopeRepository, "o", "s", "TOKEN")
	assert.NotEqual(t, org, repo)
	assert.NotEqual(t, repo, other)
}

// Synthetic: codespace records with and without a machine; no target showed
// these.
func TestCodespaceArgs(t *testing.T) {
	var c github.Codespace
	require.NoError(t, json.Unmarshal([]byte(`{"id": 1, "name": "cs", "state": "Shutdown"}`), &c))
	args := codespaceArgs("o", &c)
	assert.Equal(t, "Shutdown", args["state"].Value)
	assert.Equal(t, llx.NilData, args["machineCpus"], "an absent machine is null, not 0 CPUs")
	assert.Equal(t, llx.NilData, args["retentionExpiresAt"])
	assert.Equal(t, llx.NilData, args["prebuild"])

	require.NoError(t, json.Unmarshal([]byte(`{"id": 1, "machine": {"name": "standardLinux", "cpus": 4, "memory_in_bytes": 8589934592}, "idle_timeout_minutes": 30}`), &c))
	args = codespaceArgs("o", &c)
	assert.Equal(t, int64(4), args["machineCpus"].Value)
	assert.Equal(t, int64(8589934592), args["machineMemoryInBytes"].Value)
	assert.Equal(t, int64(30), args["idleTimeoutMinutes"].Value)
}
