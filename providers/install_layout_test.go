// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
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

// skipProviderHealthCheck lets a test install stub binaries, which cannot
// complete the plugin handshake.
func skipProviderHealthCheck(t *testing.T) {
	t.Helper()
	orig := providerHealthCheck
	providerHealthCheck = func(string) error { return nil }
	t.Cleanup(func() { providerHealthCheck = orig })
}

// A staging directory may belong to an install running in another process; only
// one old enough to have been left behind by a crash is removed.
func TestCleanupStagingDirs(t *testing.T) {
	container := t.TempDir()
	fresh := filepath.Join(container, stagingDirPrefix+"13.4.1-123")
	stale := filepath.Join(container, stagingDirPrefix+"13.4.0-456")
	require.NoError(t, os.MkdirAll(fresh, 0o755))
	require.NoError(t, os.MkdirAll(stale, 0o755))
	old := time.Now().Add(-2 * staleStagingAge)
	require.NoError(t, os.Chtimes(stale, old, old))
	writeVersionDir(t, container, "os", "13.3.0")

	cleanupStagingDirs(container)

	assert.DirExists(t, fresh)
	assert.NoDirExists(t, stale)
	assert.DirExists(t, filepath.Join(container, "13.3.0"), "version directories are not staging")
}

// makeProviderArchive builds an in-memory .tar.xz holding a fake provider's
// three payload files (binary + config JSON + resources JSON) for the given
// name and version, matching what InstallIO expects to unpack.
func makeProviderArchive(t *testing.T, name, version string) io.ReadCloser {
	t.Helper()

	var xzBuf bytes.Buffer
	xzw, err := xz.NewWriter(&xzBuf)
	require.NoError(t, err)
	tw := tar.NewWriter(xzw)

	files := map[string]string{
		name:                     "#!/bin/sh\nexit 0\n",
		name + ".json":           `{"name":"` + name + `","version":"` + version + `"}`,
		name + ".resources.json": `{"resources":{}}`,
	}
	for fname, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: fname,
			Mode: 0o755,
			Size: int64(len(content)),
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, xzw.Close())

	return io.NopCloser(bytes.NewReader(xzBuf.Bytes()))
}

// TestInstallIO_VersionedLayout exercises the full install path end to end:
// unpack -> versioned directory -> atomic pointer -> reinstall a newer version
// -> prune. Health-checking is skipped because a shell-script stub cannot
// complete the real plugin handshake; the versioning/pointer/rollback logic is
// what this test covers.
func TestInstallIO_VersionedLayout(t *testing.T) {
	dst := t.TempDir()
	name := "testprov"

	// Install v1.
	installed, err := InstallIO(makeProviderArchive(t, name, "13.1.0"), InstallConf{
		Dst:             dst,
		SkipHealthCheck: true,
	})
	require.NoError(t, err)
	require.Len(t, installed, 1)
	assert.Equal(t, name, installed[0].Name)

	container := providerContainerDir(dst, name)

	// The pointer names v1, and the payload lives in the versioned directory.
	v, ok := readCurrentPointer(container)
	require.True(t, ok)
	assert.Equal(t, "13.1.0", v)
	assert.FileExists(t, filepath.Join(container, "13.1.0", name+".json"))
	if runtime.GOOS != "windows" {
		stat, err := os.Stat(filepath.Join(container, "13.1.0"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o755), stat.Mode().Perm(), "other users must be able to read a system-wide install")
	}
	// The installed provider reads its payload from the versioned directory,
	// while Path stays the container (what delete removes, listings group by).
	assert.Equal(t, container, installed[0].Path)
	assert.Equal(t, filepath.Join(container, "13.1.0"), installed[0].dir())
	assert.Equal(t, filepath.Join(container, "13.1.0", name), installed[0].binPath())

	// readProviderDir (used by ListActive) resolves through the pointer.
	p, err := readProviderDir(container)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, container, p.Path)
	assert.Equal(t, filepath.Join(container, "13.1.0"), p.dir())

	// Install v2. The pointer flips; v1 is retained for rollback.
	_, err = InstallIO(makeProviderArchive(t, name, "13.2.0"), InstallConf{
		Dst:             dst,
		SkipHealthCheck: true,
	})
	require.NoError(t, err)
	v, _ = readCurrentPointer(container)
	assert.Equal(t, "13.2.0", v)
	assert.DirExists(t, filepath.Join(container, "13.2.0"))
	assert.DirExists(t, filepath.Join(container, "13.1.0"), "previous version retained for rollback")

	// Install v3 with keep=2: the oldest (v1) is pruned, active + previous kept.
	_, err = InstallIO(makeProviderArchive(t, name, "13.3.0"), InstallConf{
		Dst:             dst,
		SkipHealthCheck: true,
		KeepVersions:    2,
	})
	require.NoError(t, err)
	v, _ = readCurrentPointer(container)
	assert.Equal(t, "13.3.0", v)
	assert.DirExists(t, filepath.Join(container, "13.3.0"))
	assert.DirExists(t, filepath.Join(container, "13.2.0"))
	assert.NoDirExists(t, filepath.Join(container, "13.1.0"), "oldest version pruned")
}

// TestInstallIO_MigratesLegacyFlatLayout proves a pre-existing flat install is
// read correctly, and that the next install activates a versioned directory
// next to it without removing the flat files an older build still reads.
func TestInstallIO_MigratesLegacyFlatLayout(t *testing.T) {
	dst := t.TempDir()
	name := "legacyprov"
	container := providerContainerDir(dst, name)
	require.NoError(t, os.MkdirAll(container, 0o755))

	// Synthetic: a flat install as written by every release before the
	// versioned layout (files directly in the container).
	require.NoError(t, os.WriteFile(filepath.Join(container, name), []byte("bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(container, name+".json"), []byte(`{"name":"`+name+`","version":"12.0.0"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(container, name+".resources.json"), []byte(`{}`), 0o644))

	// The reader resolves the legacy flat layout.
	p, err := readProviderDir(container)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, container, p.Path)
	assert.Equal(t, container, p.dir(), "legacy flat payload read from the container root")

	_, err = InstallIO(makeProviderArchive(t, name, "13.0.0"), InstallConf{
		Dst:             dst,
		SkipHealthCheck: true,
	})
	require.NoError(t, err)

	v, ok := readCurrentPointer(container)
	require.True(t, ok)
	assert.Equal(t, "13.0.0", v)
	assert.DirExists(t, filepath.Join(container, "13.0.0"))
	assert.FileExists(t, filepath.Join(container, name+".json"), "flat files stay for older builds")

	// This build reads the versioned payload, not the flat one.
	p, err = readProviderDir(container)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, filepath.Join(container, "13.0.0"), p.dir())
}

// A binary that fails its health check never becomes active: the previous
// version stays current and nothing of the new one is left behind.
func TestInstallIO_FailedHealthCheckKeepsPreviousVersion(t *testing.T) {
	dst := t.TempDir()
	name := "testprov"
	container := providerContainerDir(dst, name)

	skipProviderHealthCheck(t)
	_, err := InstallIO(makeProviderArchive(t, name, "13.1.0"), InstallConf{Dst: dst})
	require.NoError(t, err)

	var checked string
	providerHealthCheck = func(bin string) error {
		checked = bin
		return errors.New("exec format error")
	}
	_, err = InstallIO(makeProviderArchive(t, name, "13.2.0"), InstallConf{Dst: dst})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "testprov-13.2.0 failed its health check")
	assert.Equal(t, name, filepath.Base(checked), "the staged binary is what gets checked")

	v, ok := readCurrentPointer(container)
	require.True(t, ok)
	assert.Equal(t, "13.1.0", v, "the previous version stays active")
	assert.NoDirExists(t, filepath.Join(container, "13.2.0"))
	entries, err := os.ReadDir(container)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), stagingDirPrefix), "staging directory left behind: %s", e.Name())
	}
}

// A schema-only package never starts a health check (there is nothing to
// start), and for a version that is already fully installed it keeps the
// binary instead of dropping it.
func TestInstallIO_SchemaOnlyPackage(t *testing.T) {
	dst := t.TempDir()
	name := "testprov"
	container := providerContainerDir(dst, name)
	providerHealthCheck = func(string) error { return errors.New("must not be called") }
	t.Cleanup(func() { providerHealthCheck = healthCheckProvider })

	schemaOnly := func(version string) io.ReadCloser {
		archive, err := buildTarXz(map[string][]byte{
			name + ".json":           []byte(`{"name":"` + name + `","version":"` + version + `"}`),
			name + ".resources.json": []byte(`{"resources":{}}`),
		})
		require.NoError(t, err)
		return io.NopCloser(bytes.NewReader(archive))
	}

	installed, err := InstallIO(schemaOnly("13.1.0"), InstallConf{Dst: dst})
	require.NoError(t, err)
	require.Len(t, installed, 1)
	assert.False(t, installed[0].HasBinary)
	v, _ := readCurrentPointer(container)
	assert.Equal(t, "13.1.0", v)

	// Complete the install, then lay the schema-only package over it again.
	_, err = InstallIO(makeProviderArchive(t, name, "13.1.0"), InstallConf{Dst: dst, SkipHealthCheck: true})
	require.NoError(t, err)
	installed, err = InstallIO(schemaOnly("13.1.0"), InstallConf{Dst: dst})
	require.NoError(t, err)
	require.Len(t, installed, 1)
	assert.True(t, installed[0].HasBinary, "the installed binary survives a schema-only reinstall")
	assert.FileExists(t, filepath.Join(container, "13.1.0", name))
}

// The version names a directory, so one that would climb out of the container
// is refused before anything is written.
func TestInstallIO_RejectsVersionWithPath(t *testing.T) {
	dst := t.TempDir()
	skipProviderHealthCheck(t)

	_, err := InstallIO(makeProviderArchive(t, "testprov", "../../escaped"), InstallConf{Dst: dst})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version")
	assert.NoDirExists(t, filepath.Join(dst, "escaped"))
	assert.NoDirExists(t, filepath.Join(filepath.Dir(dst), "escaped"))
}
