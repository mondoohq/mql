// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
	kustomizeTypes "sigs.k8s.io/kustomize/api/types"
)

func newTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

// TestNewMqlKustomizeImageUniqueID ensures two images that share a name (legal
// in kustomize — e.g. one overrides the tag, one the digest) get distinct
// __ids, so the second isn't dropped by a resource-cache collision.
func TestNewMqlKustomizeImageUniqueID(t *testing.T) {
	rt := newTestRuntime()

	a, err := newMqlKustomizeImage(rt, "kustomization.yaml", 0, kustomizeTypes.Image{Name: "nginx", NewTag: "1.0"})
	require.NoError(t, err)
	b, err := newMqlKustomizeImage(rt, "kustomization.yaml", 1, kustomizeTypes.Image{Name: "nginx", Digest: "sha256:abc"})
	require.NoError(t, err)

	assert.NotEqual(t, a.__id, b.__id, "same-name images must have distinct __ids")
}

// TestReplacementTargetsWithoutFieldPaths ensures a target that specifies a
// Select but omits fieldPaths still produces a target row (it was previously
// dropped because the only emission happened inside the fieldPaths loop).
func TestReplacementTargetsWithoutFieldPaths(t *testing.T) {
	r := &mqlKustomizeReplacement{MqlRuntime: newTestRuntime()}
	r.kustPath = "kustomization.yaml"
	r.replacementTargets = []*kustomizeTypes.TargetSelector{
		{Select: &kustomizeTypes.Selector{}, FieldPaths: nil},                          // no fieldPaths -> 1 row
		{Select: &kustomizeTypes.Selector{}, FieldPaths: []string{"spec.a", "spec.b"}}, // -> 2 rows
		nil, // a bare `- ` list entry -> skipped
	}

	targets, err := r.targets()
	require.NoError(t, err)
	assert.Len(t, targets, 3, "target with no fieldPaths must still emit one row")
}

// TestPatchOperationValueSerializesAsDict guards the regression where an
// integer patch value (e.g. `value: 3`) crashed the `value` accessor: yaml.v3
// decodes integer scalars to Go `int`, which the llx dict serializer rejects.
// The decoded operation values must be JSON-native so `.value` serializes
// cleanly, including integers nested inside maps.
func TestPatchOperationValueSerializesAsDict(t *testing.T) {
	patch := &kustomizeTypes.Patch{Patch: "" +
		"- op: replace\n" +
		"  path: /spec/replicas\n" +
		"  value: 3\n" +
		"- op: add\n" +
		"  path: /spec/template/spec/containers/0/resources\n" +
		"  value:\n" +
		"    limits:\n" +
		"      cpu: 2\n"}

	p, err := newMqlKustomizePatch(newTestRuntime(), "kustomization.yaml", 0, patch, hintNone)
	require.NoError(t, err)
	require.Equal(t, patchFormatJSON6902, p.format)

	ops, err := p.operations()
	require.NoError(t, err)
	require.Len(t, ops, 2)

	for _, o := range ops {
		op := o.(*mqlKustomizePatchOperation)
		// Result() runs the same raw->primitive conversion the runtime uses
		// when the field crosses the plugin boundary; a non-JSON-native value
		// surfaces here as a non-empty Error.
		res := llx.DictData(op.Value.Data).Result()
		assert.Empty(t, res.Error, "operation value must serialize as a JSON-native dict")
	}

	// The bare integer is normalized to float64 (matching the manifest dict path).
	first := ops[0].(*mqlKustomizePatchOperation)
	assert.Equal(t, float64(3), first.Value.Data, "integer values normalize to float64")
}

// TestNewMqlKustomizePatchContentFromFile ensures a file-based patch surfaces
// the file's body through the `content` field rather than an empty string.
func TestNewMqlKustomizePatchContentFromFile(t *testing.T) {
	dir := t.TempDir()
	body := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: myapp\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "patch.yaml"), []byte(body), 0o600))

	p, err := newMqlKustomizePatch(newTestRuntime(), dir, 0, &kustomizeTypes.Patch{Path: "patch.yaml"}, hintNone)
	require.NoError(t, err)
	assert.Equal(t, body, p.Content.Data, "file-based patch must expose the file body as content")
	assert.Equal(t, patchFormatStrategicMerge, p.format)
}

// TestNewMqlKustomizePatchReadsFile ensures a patch that references a JSON6902
// file (relative to the kustomization dir) is actually read and classified —
// not silently misclassified as an empty strategic-merge patch — while a path
// that escapes the directory is refused.
func TestNewMqlKustomizePatchReadsFile(t *testing.T) {
	dir := t.TempDir()
	patchBody := "- op: replace\n  path: /spec/replicas\n  value: 3\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "patch.yaml"), []byte(patchBody), 0o600))

	t.Run("reads a contained patch file", func(t *testing.T) {
		p, err := newMqlKustomizePatch(newTestRuntime(), dir, 0, &kustomizeTypes.Patch{Path: "patch.yaml"}, hintNone)
		require.NoError(t, err)
		assert.Equal(t, patchFormatJSON6902, p.format)

		ops, err := p.operations()
		require.NoError(t, err)
		require.Len(t, ops, 1)
	})

	t.Run("refuses a path escaping the kustomization dir", func(t *testing.T) {
		// Write a would-be patch outside the kustomization directory.
		outside := filepath.Join(filepath.Dir(dir), "escape.yaml")
		require.NoError(t, os.WriteFile(outside, []byte(patchBody), 0o600))
		defer os.Remove(outside)

		p, err := newMqlKustomizePatch(newTestRuntime(), dir, 0, &kustomizeTypes.Patch{Path: "../escape.yaml"}, hintNone)
		require.NoError(t, err)
		// Not read -> falls back to an empty strategic-merge patch.
		assert.Equal(t, patchFormatStrategicMerge, p.format)
		ops, err := p.operations()
		require.NoError(t, err)
		assert.Empty(t, ops)
	})
}
