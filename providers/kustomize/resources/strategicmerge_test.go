// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const inlineSMP = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  template:
    spec:
      containers:
      - name: nginx
        securityContext:
          privileged: true`

// A `patchesStrategicMerge` entry is either a file path or an inline patch
// body. Kustomize itself disambiguates by trying to read the entry as a file
// (types.Kustomization.FixKustomizationPreMarshalling), and so must we — the
// provider used to force the path branch unconditionally, which left `content`
// empty for an inline patch and put a multi-line YAML blob in `path`.
func TestStrategicMergePatchEntry(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deployment-patch.yaml"), []byte(inlineSMP), 0o600))

	t.Run("an existing file is a path", func(t *testing.T) {
		p := strategicMergePatchEntry(dir, "deployment-patch.yaml")
		assert.Equal(t, "deployment-patch.yaml", p.Path)
		assert.Empty(t, p.Patch)
	})

	t.Run("an inline body is a patch", func(t *testing.T) {
		p := strategicMergePatchEntry(dir, inlineSMP)
		assert.Empty(t, p.Path, "a multi-line YAML body is not a path")
		assert.Equal(t, inlineSMP, p.Patch)
	})

	t.Run("a nonexistent path stays a path", func(t *testing.T) {
		// Kustomize would fail the build; reporting it as a path (which then
		// reads as an empty patch, with a warning) keeps the old behavior for
		// a genuine typo rather than dumping a filename into `content`.
		p := strategicMergePatchEntry(dir, "missing-patch.yaml")
		assert.Equal(t, "missing-patch.yaml", p.Path)
		assert.Empty(t, p.Patch)
	})

	t.Run("a directory is not a patch file", func(t *testing.T) {
		require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0o750))
		p := strategicMergePatchEntry(dir, "subdir")
		assert.Equal(t, "subdir", p.Path, "a directory is not readable as a patch body")
		assert.Empty(t, p.Patch)
	})

	t.Run("a single-line inline patch is still inline", func(t *testing.T) {
		body := "{apiVersion: apps/v1, kind: Deployment, metadata: {name: nginx}}"
		p := strategicMergePatchEntry(dir, body)
		assert.Empty(t, p.Path)
		assert.Equal(t, body, p.Patch)
	})
}

// The user-visible consequence: an inline strategic-merge patch must surface
// its body through `content`, so `patches.where(content.contains("privileged"))`
// finds it. It used to return "" and the policy passed vacuously.
func TestInlineStrategicMergePatchExposesContent(t *testing.T) {
	dir := t.TempDir()
	rt := newTestRuntime()

	p := strategicMergePatchEntry(dir, inlineSMP)
	mqlP, err := newMqlKustomizePatch(rt, dir, 0, &p, hintStrategicMerge)
	require.NoError(t, err)

	assert.Contains(t, mqlP.Content.Data, "privileged: true")
	assert.Empty(t, mqlP.Path.Data, "an inline patch has no path")
	assert.Equal(t, patchFormatStrategicMerge, mqlP.Format.Data)
}

func TestFileStrategicMergePatchExposesContent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(inlineSMP), 0o600))
	rt := newTestRuntime()

	p := strategicMergePatchEntry(dir, "p.yaml")
	mqlP, err := newMqlKustomizePatch(rt, dir, 0, &p, hintStrategicMerge)
	require.NoError(t, err)

	assert.Contains(t, mqlP.Content.Data, "privileged: true")
	assert.Equal(t, "p.yaml", mqlP.Path.Data)
}
