// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeVersionDir creates a fake installed version directory with the three
// provider payload files, so layout resolution/pruning can be exercised
// without a real provider binary.
func writeVersionDir(t *testing.T, containerDir, name, version string) string {
	t.Helper()
	vdir := filepath.Join(containerDir, version)
	require.NoError(t, os.MkdirAll(vdir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(vdir, name), []byte("binary"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(vdir, name+".json"), []byte(`{"name":"`+name+`","version":"`+version+`"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(vdir, name+".resources.json"), []byte(`{}`), 0o644))
	return vdir
}

func TestResolveActiveDir(t *testing.T) {
	name := "os"

	t.Run("versioned via pointer", func(t *testing.T) {
		dst := t.TempDir()
		container := providerContainerDir(dst, name)
		vdir := writeVersionDir(t, container, name, "13.4.1")
		require.NoError(t, writeCurrentPointerAtomic(container, "13.4.1"))

		got, legacy, ok := resolveActiveDir(container, name)
		require.True(t, ok)
		assert.False(t, legacy)
		assert.Equal(t, vdir, got)
	})

	t.Run("legacy flat layout", func(t *testing.T) {
		dst := t.TempDir()
		container := providerContainerDir(dst, name)
		require.NoError(t, os.MkdirAll(container, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(container, name+".json"), []byte(`{"version":"1"}`), 0o644))

		got, legacy, ok := resolveActiveDir(container, name)
		require.True(t, ok)
		assert.True(t, legacy)
		assert.Equal(t, container, got)
	})

	t.Run("dangling pointer falls back to flat", func(t *testing.T) {
		dst := t.TempDir()
		container := providerContainerDir(dst, name)
		require.NoError(t, os.MkdirAll(container, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(container, name+".json"), []byte(`{"version":"1"}`), 0o644))
		// Pointer names a version dir that does not exist.
		require.NoError(t, writeCurrentPointerAtomic(container, "99.0.0"))

		got, legacy, ok := resolveActiveDir(container, name)
		require.True(t, ok)
		assert.True(t, legacy)
		assert.Equal(t, container, got)
	})

	t.Run("nothing installed", func(t *testing.T) {
		dst := t.TempDir()
		container := providerContainerDir(dst, name)
		require.NoError(t, os.MkdirAll(container, 0o755))
		_, _, ok := resolveActiveDir(container, name)
		assert.False(t, ok)
	})
}

func TestCurrentPointerRoundTrip(t *testing.T) {
	container := t.TempDir()
	_, ok := readCurrentPointer(container)
	assert.False(t, ok)

	require.NoError(t, writeCurrentPointerAtomic(container, "13.4.2"))
	v, ok := readCurrentPointer(container)
	require.True(t, ok)
	assert.Equal(t, "13.4.2", v)

	// Overwrite is atomic and reflects the latest value.
	require.NoError(t, writeCurrentPointerAtomic(container, "13.4.3"))
	v, ok = readCurrentPointer(container)
	require.True(t, ok)
	assert.Equal(t, "13.4.3", v)
}

func TestPruneOldVersions(t *testing.T) {
	name := "os"
	dst := t.TempDir()
	container := providerContainerDir(dst, name)
	for _, v := range []string{"13.1.0", "13.2.0", "13.3.0", "13.4.0"} {
		writeVersionDir(t, container, name, v)
	}

	// Keep 2, protecting the active (13.4.0) and previous (13.3.0). Ordering is
	// by semver, so the result is deterministic: the two newest are kept and
	// the older two are removed.
	pruneOldVersions(container, name, 2, "13.4.0", "13.3.0")

	assert.DirExists(t, filepath.Join(container, "13.4.0"), "active must survive")
	assert.DirExists(t, filepath.Join(container, "13.3.0"), "previous must survive")
	assert.NoDirExists(t, filepath.Join(container, "13.2.0"), "older version pruned")
	assert.NoDirExists(t, filepath.Join(container, "13.1.0"), "oldest version pruned")

	assert.Equal(t, []string{"13.4.0", "13.3.0"}, listInstalledVersions(container, name))
}

func TestPruneNeverRemovesProtected(t *testing.T) {
	name := "os"
	dst := t.TempDir()
	container := providerContainerDir(dst, name)
	writeVersionDir(t, container, name, "13.1.0")

	// keep=1 with the only version protected: it must not be deleted.
	pruneOldVersions(container, name, 1, "13.1.0")
	assert.DirExists(t, filepath.Join(container, "13.1.0"))
}

func TestReadProviderVersion(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "os.json")
	require.NoError(t, os.WriteFile(good, []byte(`{"name":"os","version":"13.4.1"}`), 0o644))
	v, err := readProviderVersion(good)
	require.NoError(t, err)
	assert.Equal(t, "13.4.1", v)

	missing := filepath.Join(dir, "noversion.json")
	require.NoError(t, os.WriteFile(missing, []byte(`{"name":"os"}`), 0o644))
	_, err = readProviderVersion(missing)
	assert.Error(t, err)
}

func TestRemoveLegacyFlatFiles(t *testing.T) {
	name := "os"
	container := t.TempDir()
	// Legacy flat payload.
	require.NoError(t, os.WriteFile(filepath.Join(container, name), []byte("bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(container, name+".json"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(container, name+".resources.json"), []byte("{}"), 0o644))
	// A versioned install and pointer that now govern.
	writeVersionDir(t, container, name, "13.4.1")
	require.NoError(t, writeCurrentPointerAtomic(container, "13.4.1"))

	removeLegacyFlatFiles(container, name, name)

	assert.NoFileExists(t, filepath.Join(container, name))
	assert.NoFileExists(t, filepath.Join(container, name+".json"))
	assert.NoFileExists(t, filepath.Join(container, name+".resources.json"))
	// The versioned payload and pointer are untouched.
	assert.DirExists(t, filepath.Join(container, "13.4.1"))
	v, ok := readCurrentPointer(container)
	require.True(t, ok)
	assert.Equal(t, "13.4.1", v)
}
