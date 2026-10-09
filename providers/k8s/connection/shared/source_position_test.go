// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildManifestPositionIndex(t *testing.T) {
	manifest := []byte(`apiVersion: v1
kind: Namespace
metadata:
  name: web
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
  namespace: web
data:
  key: value
---
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Service
    metadata:
      name: frontend
      namespace: web
---
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: web
`)

	index := BuildManifestPositionIndex(manifest, "deploy/web.yaml")

	assert.Equal(t, map[string]SourcePosition{
		"namespace:web":          {Path: "deploy/web.yaml", StartLine: 1, EndLine: 4},
		"configmap:web:settings": {Path: "deploy/web.yaml", StartLine: 6, EndLine: 12},
		"service:web:frontend":   {Path: "deploy/web.yaml", StartLine: 17, EndLine: 21},
	}, index, "a List is expanded to its items, and a document without a name is skipped")
}

func TestBuildManifestPositionIndex_Empty(t *testing.T) {
	assert.Empty(t, BuildManifestPositionIndex(nil, "x.yaml"))
}

func TestLoadManifestFiles_Directory(t *testing.T) {
	dir := "../../resources/testdata/source-context"
	files, err := LoadManifestFiles(dir)
	require.NoError(t, err)
	require.Len(t, files, 2)

	for i, name := range []string{"a.yaml", "b.yaml"} {
		assert.Equal(t, filepath.Join(dir, name), files[i].Path)
		assert.Contains(t, string(files[i].Content), "name: web-"+name[:1])
	}

	// The merged stream is what the parser reads; it keeps the separator
	// between files.
	merged := string(MergeManifests(files))
	assert.Equal(t, string(files[0].Content)+"\n---\n"+string(files[1].Content)+"\n---\n", merged)
}
