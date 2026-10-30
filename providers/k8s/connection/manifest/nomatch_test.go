// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func manifestDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	}
	return dir
}

func connectManifest(t *testing.T, dir string) error {
	t.Helper()
	asset := &inventory.Asset{Connections: []*inventory.Config{{
		Options: map[string]string{"path": dir},
	}}}
	_, err := NewConnection(0, asset, WithManifestFile(dir))
	return err
}

func TestK8sRejectsFoldersWithNoObjects(t *testing.T) {
	tests := map[string]map[string]string{
		"plain config yaml":    {"settings.yaml": "log_level: debug\nregion: us-east-1\n"},
		"a helm template":      {"templates/deployment.yaml": "kind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n"},
		"nothing but a readme": {"README.md": "# docs\n"},
		// A kustomization declares a kind, so it decodes as an unstructured
		// object: without the skip it would make every Kustomize directory look
		// like a folder of manifests and emit a second asset beside the
		// kustomize one.
		"only a kustomization": {"kustomization.yaml": "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: []\n"},
	}

	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			err := connectManifest(t, manifestDir(t, files))
			require.Error(t, err)
			assert.True(t, plugin.IsNoMatchError(err), err)
		})
	}
}

func TestK8sAcceptsAFolderOfManifests(t *testing.T) {
	dir := manifestDir(t, map[string]string{
		"deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
		"service.yaml":    "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n",
		// Ignored, and must not stop the two real manifests from being read.
		"kustomization.yaml": "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: []\n",
	})
	assert.NoError(t, connectManifest(t, dir))
}
