// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// A directory with a kustomization.yaml that fails YAML parsing used
// to be silently swallowed: loadKustomizations fell through to a
// subdir scan, returned [], and the connection saw "no kustomization
// found." Now the parse error propagates so the operator sees what's
// actually wrong.
func TestLoadKustomizations_MalformedRootPropagates(t *testing.T) {
	_, err := loadKustomizations("../testdata/malformed")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrNoKustomization),
		"a parse error must not look like ErrNoKustomization (which only means \"no file here\")")
}

// Sanity check the sentinel: a directory with no kustomization
// filename at any of the recognized names still produces ErrNoKustomization.
func TestLoadSingleKustomization_NoFileReturnsSentinel(t *testing.T) {
	_, err := loadSingleKustomization("../testdata/empty-dir")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoKustomization))
}

// The basic fixture still loads (regression for the sentinel refactor).
func TestLoadKustomizations_BasicFixtureStillWorks(t *testing.T) {
	entries, err := loadKustomizations("../testdata/basic")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "../testdata/basic", entries[0].Path)
}

// A one-level subdir scan silently missed the canonical Kustomize layout:
// base/ alongside overlays/<env>/, where the real deployment overlays live
// two levels below the root. Pointing at the root found only base/ and
// dropped every overlay. The scan now recurses, stopping at each directory
// that owns a kustomization.
func TestLoadKustomizations_RecursesIntoNestedOverlays(t *testing.T) {
	entries, err := loadKustomizations("../testdata/nested-overlays")
	require.NoError(t, err)

	got := map[string]bool{}
	for _, e := range entries {
		got[e.Path] = true
	}
	assert.Truef(t, got["../testdata/nested-overlays/base"], "base should be discovered, got %v", got)
	assert.Truef(t, got["../testdata/nested-overlays/overlays/dev"], "dev overlay (depth 2) should be discovered, got %v", got)
	assert.Truef(t, got["../testdata/nested-overlays/overlays/prod"], "prod overlay (depth 2) should be discovered, got %v", got)
	assert.Len(t, entries, 3)
}

// A directory that owns a kustomization owns its whole subtree; the scan must
// not descend into it and emit a second entry for a nested resources/ dir that
// happens to carry its own kustomization file.
func TestLoadKustomizations_DoesNotDescendIntoOwnedSubtree(t *testing.T) {
	tmp := t.TempDir()
	// Root has no kustomization, so the scan recurses.
	overlay := filepath.Join(tmp, "overlay")
	nested := filepath.Join(overlay, "components", "extra")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	kust := []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n")
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), kust, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(nested, "kustomization.yaml"), kust, 0o644))

	entries, err := loadKustomizations(tmp)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the owning overlay dir should be discovered, not its nested subtree")
	assert.Equal(t, overlay, entries[0].Path)
}

// FixKustomization reconciles deprecated field aliases into the modern
// fields. Without it the raw-field accessors silently omit entries declared
// with the older syntax (bases, imageTags, singular env).
func TestLoadSingleKustomization_MergesDeprecatedFields(t *testing.T) {
	entry, err := loadSingleKustomization("../testdata/deprecated-fields")
	require.NoError(t, err)
	k := entry.Kustomization

	assert.Contains(t, k.Resources, "../base", "bases: entry should be merged into resources")

	require.Len(t, k.Images, 1, "imageTags: entry should be merged into images")
	assert.Equal(t, "nginx", k.Images[0].Name)
	assert.Equal(t, "1.2.3", k.Images[0].NewTag)

	require.Len(t, k.ConfigMapGenerator, 1)
	assert.Contains(t, k.ConfigMapGenerator[0].EnvSources, "config.env",
		"singular env: should be merged into envs")
}

// NewKustomizeConnection used to deref asset.Connections[0] unconditionally;
// passing a nil asset or one with no connections now produces a clear error
// instead of a runtime panic.
func TestNewKustomizeConnection_NilAssetRejected(t *testing.T) {
	_, err := NewKustomizeConnection(0, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one connection")
}

func TestNewKustomizeConnection_NoConnectionsRejected(t *testing.T) {
	_, err := NewKustomizeConnection(0, &inventory.Asset{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one connection")
}

// The cleaned-path discovery means entry.Path always matches conn.Path()
// regardless of whether the caller passes "./foo", "./foo/", or "foo".
func TestNewKustomizeConnection_PathIsCleaned(t *testing.T) {
	cases := []string{
		"../testdata/basic",
		"../testdata/basic/",
		"./../testdata/basic",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			conn, err := NewKustomizeConnection(0, &inventory.Asset{
				Connections: []*inventory.Config{
					{Options: map[string]string{"path": in}},
				},
			}, nil)
			require.NoError(t, err)
			require.Len(t, conn.Kustomizations(), 1)
			// conn.Path() and the entry path should always agree —
			// they're both derived from the same cleaned input.
			assert.Equal(t, conn.Path(), conn.Kustomizations()[0].Path,
				"entry.Path must equal conn.Path() to keep cache keys stable")
		})
	}
}

// Subdir scan must skip hidden dirs (.git, .terraform) and a short list of
// well-known noise dirs (node_modules, vendor, …). A misconfigured path at
// a repo root would otherwise spend file handles on dirs that can't
// contain a kustomization.
func TestLoadKustomizations_SkipsHiddenAndNoiseDirs(t *testing.T) {
	tmp := t.TempDir()
	// Put no kustomization in the root so we trigger the subdir scan.
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".git"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "node_modules"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "vendor"), 0o755))
	// Put a malformed kustomization.yaml in each — if the scan visited
	// them, the warn log would fire. We can't assert log output directly,
	// but we can assert the scan returns cleanly (no entries) without
	// inspecting these dirs.
	bad := []byte("not: [valid: yaml")
	for _, name := range []string{".git", "node_modules", "vendor"} {
		require.NoError(t, os.WriteFile(
			filepath.Join(tmp, name, "kustomization.yaml"),
			bad, 0o644))
	}

	// Add one legitimate subdir with a real kustomization so the scan
	// has something to find — proves the skip-list only filters noise.
	realDir := filepath.Join(tmp, "real")
	require.NoError(t, os.MkdirAll(realDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(realDir, "kustomization.yaml"),
		[]byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"),
		0o644))

	entries, err := loadKustomizations(tmp)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the real subdir should be discovered")
	assert.Equal(t, realDir, entries[0].Path)
}

// BUG 8: two recognized kustomization filenames in one directory. The loader
// took whichever read first, so mql reported that file's static fields while
// `kustomize build` (and therefore the `resources` accessor) hard-errors with
// "Found multiple kustomization files under: ..." — a directory reported as
// half-valid. Mirror kustomize and refuse the directory outright.
func TestLoadSingleKustomization_MultipleFilesIsAnError(t *testing.T) {
	dir := t.TempDir()
	body := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(body), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Kustomization"), []byte(body), 0o600))

	_, err := loadSingleKustomization(dir)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrNoKustomization),
		"an ambiguous directory is not the same as an empty one")
	assert.Contains(t, err.Error(), "multiple kustomization files")
}

// A single recognized filename that is not the default still loads.
func TestLoadSingleKustomization_AlternateFilenameStillLoads(t *testing.T) {
	dir := t.TempDir()
	body := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: alt\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yml"), []byte(body), 0o600))

	entry, err := loadSingleKustomization(dir)
	require.NoError(t, err)
	assert.Equal(t, "alt", entry.Kustomization.Namespace)
}
