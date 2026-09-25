// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const twoClusterKubeconfig = `apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: dev-cluster
  cluster:
    server: https://dev.example.com:6443
- name: prod-cluster
  cluster:
    server: https://prod.example.com:6443
contexts:
- name: dev
  context:
    cluster: dev-cluster
    user: dev-user
- name: prod
  context:
    cluster: prod-cluster
    user: prod-user
users:
- name: dev-user
  user: {}
- name: prod-user
  user: {}
`

func writeKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.WriteFile(path, []byte(twoClusterKubeconfig), 0o600))
	return path
}

// TestBuildConfigFromFlagsContext pins that the requested context selects the
// cluster. Passing an empty context used to be the only thing the connection
// ever did, so --context prod silently scanned whatever current-context was
// while still labelling the asset "prod".
func TestBuildConfigFromFlagsContext(t *testing.T) {
	path := writeKubeconfig(t)

	tests := []struct {
		name       string
		context    string
		wantServer string
	}{
		{name: "no context falls back to current-context", context: "", wantServer: "https://dev.example.com:6443"},
		{name: "explicit context selects its cluster", context: "prod", wantServer: "https://prod.example.com:6443"},
		{name: "explicit current-context is still honored", context: "dev", wantServer: "https://dev.example.com:6443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := buildConfigFromFlags("", path, tt.context)
			require.NoError(t, err)
			assert.Equal(t, tt.wantServer, cfg.Host)
		})
	}
}

// TestBuildConfigFromFlagsUnknownContext pins that a context that is not in the
// kubeconfig is an error. It used to be accepted, and the scan silently ran
// against current-context under the requested name.
func TestBuildConfigFromFlagsUnknownContext(t *testing.T) {
	path := writeKubeconfig(t)

	_, err := buildConfigFromFlags("", path, "does-not-exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does-not-exist")
}
