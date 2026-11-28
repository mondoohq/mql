// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runtime

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func TestRuntimeImageLazyFlattenBudgetCleansAndReleasesSlot(t *testing.T) {
	tmpRoot := t.TempDir()
	fixtureDir := t.TempDir()
	t.Setenv("MONDOO_TMP_DIR", tmpRoot)

	// The compressed OCI layer is small, but its flattened filesystem tar is
	// deliberately larger than the remaining budget.
	var layerTar bytes.Buffer
	tw := tar.NewWriter(&layerTar)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "payload", Mode: 0o644, Size: 1 << 20}))
	_, err := tw.Write(make([]byte, 1<<20))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layerTar.Bytes())), nil
	})
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)
	fixture := filepath.Join(fixtureDir, "image.tar")
	imageDigest := writeTestOCILayoutTarFromImage(t, fixture, img)
	fixtureInfo, err := os.Stat(fixture)
	require.NoError(t, err)
	_, layoutDir, err := imageFromOCILayoutTar(fixture, imageDigest, -1)
	require.NoError(t, err)
	layoutBytes, err := directoryBytes(layoutDir)
	require.NoError(t, err)
	require.NoError(t, os.RemoveAll(layoutDir))
	// Exact export+layout budget leaves zero bytes for the lazy flattened tar.
	maxBytes := fixtureInfo.Size() + layoutBytes

	oldExporter := exportRuntimeImage
	exportRuntimeImage = func(_ context.Context, _, _, path, _, _ string) error {
		in, err := os.Open(fixture)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(path)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	}
	t.Cleanup(func() { exportRuntimeImage = oldExporter })

	config := func() *inventory.Config {
		return &inventory.Config{
			Type: shared.Type_RuntimeImage.String(),
			Host: "registry.example.com/team/app:1.2.3",
			Options: map[string]string{
				OPTION_RUNTIME_IMAGE_KIND:       "containerd",
				OPTION_RUNTIME_IMAGE_DIGEST:     imageDigest,
				OPTION_RUNTIME_IMAGE_ENDPOINT:   "unix:///run/containerd.sock",
				OPTION_RUNTIME_IMAGE_ALLOW_PULL: "false",
				OPTION_RUNTIME_IMAGE_MAX_BYTES:  strconv.FormatInt(maxBytes, 10),
				OPTION_RUNTIME_IMAGE_MAX_IMAGES: "1",
				"disable-cache":                 "true",
			},
		}
	}

	conn, err := NewRuntimeImage(1, config(), &inventory.Asset{})
	require.NoError(t, err)
	require.ErrorIs(t, conn.Fetch(), errRuntimeImageTooLarge)
	entries, err := os.ReadDir(tmpRoot)
	require.NoError(t, err)
	assert.Empty(t, entries, "lazy extraction failure must remove every runtime-image temporary")

	// The failed connection was never explicitly closed. Reacquisition proves
	// the lazy failure released the max-concurrent-images slot exactly once.
	second, err := NewRuntimeImage(2, config(), &inventory.Asset{})
	require.NoError(t, err)
	conn.Close()
	conn.Close()
	second.Close()
}

func TestRuntimeImageSlotReleaseIsIdempotent(t *testing.T) {
	options := map[string]string{OPTION_RUNTIME_IMAGE_MAX_IMAGES: "1"}
	release, err := acquireRuntimeImageOptionSlot(options, OPTION_RUNTIME_IMAGE_MAX_IMAGES, t.Name())
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		release()
		release()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("repeated release blocked")
	}
	assert.Empty(t, runtimeImageSemaphore(t.Name(), 1))
	secondRelease, err := acquireRuntimeImageOptionSlot(options, OPTION_RUNTIME_IMAGE_MAX_IMAGES, t.Name())
	require.NoError(t, err)
	secondRelease()
}
