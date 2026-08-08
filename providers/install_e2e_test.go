// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
)

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
	// The installed provider resolves to the versioned directory.
	assert.Equal(t, filepath.Join(container, "13.1.0"), installed[0].Path)

	// readProviderDir (used by ListActive) resolves through the pointer.
	p, err := readProviderDir(container)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, filepath.Join(container, "13.1.0"), p.Path)

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
// read correctly and then migrated to the versioned layout by the next install.
func TestInstallIO_MigratesLegacyFlatLayout(t *testing.T) {
	dst := t.TempDir()
	name := "legacyprov"
	container := providerContainerDir(dst, name)
	require.NoError(t, os.MkdirAll(container, 0o755))

	// Seed a legacy flat install (files directly in the container).
	require.NoError(t, os.WriteFile(filepath.Join(container, name), []byte("bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(container, name+".json"), []byte(`{"name":"`+name+`","version":"12.0.0"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(container, name+".resources.json"), []byte(`{}`), 0o644))

	// The reader resolves the legacy flat layout.
	p, err := readProviderDir(container)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, container, p.Path, "legacy flat payload read from the container root")

	// Installing a newer version migrates to versioned layout and removes the
	// stray flat files.
	_, err = InstallIO(makeProviderArchive(t, name, "13.0.0"), InstallConf{
		Dst:             dst,
		SkipHealthCheck: true,
	})
	require.NoError(t, err)

	v, ok := readCurrentPointer(container)
	require.True(t, ok)
	assert.Equal(t, "13.0.0", v)
	assert.NoFileExists(t, filepath.Join(container, name+".json"), "legacy flat files removed after migration")
	assert.DirExists(t, filepath.Join(container, "13.0.0"))
}
