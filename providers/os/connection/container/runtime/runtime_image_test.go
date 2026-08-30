// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runtime

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/containerd/images"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	tarconn "go.mondoo.com/mql/providers/os/connection/tar"
)

func TestRuntimeImageConnectionExportsContainerdImage(t *testing.T) {
	tmpDir := t.TempDir()
	ociTar := filepath.Join(tmpDir, "image.tar")
	imageDigest := writeTestOCILayoutTar(t, ociTar)

	type exportCall struct {
		endpoint     string
		namespace    string
		imageRef     string
		targetDigest string
	}
	var calls []exportCall
	oldExporter := exportRuntimeImage
	exportRuntimeImage = func(_ context.Context, endpoint, namespace, exportPath, imageRef, targetDigest string) error {
		calls = append(calls, exportCall{
			endpoint:     endpoint,
			namespace:    namespace,
			imageRef:     imageRef,
			targetDigest: targetDigest,
		})
		in, err := os.Open(ociTar)
		require.NoError(t, err)
		defer in.Close()
		out, err := os.Create(exportPath)
		require.NoError(t, err)
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	}
	t.Cleanup(func() {
		exportRuntimeImage = oldExporter
	})

	conf := &inventory.Config{
		Type: shared.Type_RuntimeImage.String(),
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:       "containerd",
			OPTION_RUNTIME_IMAGE_DIGEST:     imageDigest,
			OPTION_RUNTIME_IMAGE_ENDPOINT:   "unix:///host/run/containerd/containerd.sock",
			OPTION_RUNTIME_IMAGE_NAMESPACES: "k8s.io",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL: "false",
			"disable-cache":                 "true",
		},
	}
	asset := &inventory.Asset{}

	conn, err := NewRuntimeImage(1, conf, asset)
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, "container-image", conn.Kind())
	assert.Equal(t, shared.Type_RuntimeImage.String(), conn.Runtime())
	assert.NotEmpty(t, conn.PlatformIdentifier)
	assert.NotEmpty(t, asset.PlatformIds)
	assert.Contains(t, asset.Labels, "mondoo.com/runtime-image-ref")
	require.Len(t, calls, 1)
	assert.Equal(t, "unix:///host/run/containerd/containerd.sock", calls[0].endpoint)
	assert.Equal(t, "k8s.io", calls[0].namespace)
	assert.Equal(t, "registry.example.com/team/app:1.2.3", calls[0].imageRef)
	assert.Equal(t, imageDigest, calls[0].targetDigest)
}

func TestRuntimeImageConnectionFallsBackToNextDelegateCandidate(t *testing.T) {
	tmpDir := t.TempDir()
	ociTar := filepath.Join(tmpDir, "image.tar")
	imageDigest := writeTestOCILayoutTar(t, ociTar)

	type exportCall struct {
		endpoint  string
		namespace string
	}
	var calls []exportCall
	var observedConfigDelegateIDs []string
	var conf *inventory.Config
	oldExporter := exportRuntimeImage
	exportRuntimeImage = func(_ context.Context, endpoint, namespace, exportPath, _, _ string) error {
		calls = append(calls, exportCall{endpoint: endpoint, namespace: namespace})
		observedConfigDelegateIDs = append(observedConfigDelegateIDs, conf.Options[OPTION_RUNTIME_IMAGE_DELEGATE_ID])
		if endpoint == "unix:///host/run/containerd-primary.sock" {
			return errors.New("primary content store is unavailable")
		}
		in, err := os.Open(ociTar)
		require.NoError(t, err)
		defer in.Close()
		out, err := os.Create(exportPath)
		require.NoError(t, err)
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	}
	t.Cleanup(func() {
		exportRuntimeImage = oldExporter
	})

	candidates, err := json.Marshal([]runtimeImageDelegateCandidate{
		{
			ID:         "containerd-primary",
			Kind:       "containerd",
			Endpoint:   "unix:///host/run/containerd-primary.sock",
			Namespaces: []string{"prod"},
			ReadOnly:   true,
		},
		{
			ID:         "containerd-secondary",
			Kind:       "containerd",
			Endpoint:   "unix:///host/run/containerd-secondary.sock",
			Namespaces: []string{"k8s.io"},
			ReadOnly:   true,
		},
	})
	require.NoError(t, err)

	conf = &inventory.Config{
		Type: shared.Type_RuntimeImage.String(),
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:                "containerd",
			OPTION_RUNTIME_IMAGE_DELEGATE_ID:         "containerd-primary",
			OPTION_RUNTIME_IMAGE_DELEGATE_CANDIDATES: string(candidates),
			OPTION_RUNTIME_IMAGE_DIGEST:              imageDigest,
			OPTION_RUNTIME_IMAGE_ENDPOINT:            "unix:///host/run/containerd-primary.sock",
			OPTION_RUNTIME_IMAGE_NAMESPACES:          "prod",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL:          "false",
			"disable-cache":                          "true",
		},
	}
	asset := &inventory.Asset{}

	conn, err := NewRuntimeImage(1, conf, asset)
	require.NoError(t, err)
	defer conn.Close()

	require.Len(t, calls, 2)
	assert.Equal(t, exportCall{endpoint: "unix:///host/run/containerd-primary.sock", namespace: "prod"}, calls[0])
	assert.Equal(t, exportCall{endpoint: "unix:///host/run/containerd-secondary.sock", namespace: "k8s.io"}, calls[1])
	assert.Equal(t, []string{"containerd-primary", "containerd-primary"}, observedConfigDelegateIDs)
	assert.Equal(t, "containerd-secondary", conf.Options[OPTION_RUNTIME_IMAGE_DELEGATE_ID])
	assert.Equal(t, "containerd-secondary", asset.Labels["mondoo.com/runtime-delegate-id"])
}

func TestRuntimeImageConnectionRejectsUnsupportedDelegate(t *testing.T) {
	_, err := NewRuntimeImage(1, &inventory.Config{
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND: "cri-o",
		},
	}, &inventory.Asset{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "containerd delegates only")
}

func TestRuntimeImageConnectionRejectsPulls(t *testing.T) {
	_, err := NewRuntimeImage(1, &inventory.Config{
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:       "containerd",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL: "true",
		},
	}, &inventory.Asset{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support registry pulls")
}

func TestRuntimeImageConnectionRejectsEmptyEndpoint(t *testing.T) {
	_, err := NewRuntimeImage(1, &inventory.Config{
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:       "containerd",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL: "false",
		},
	}, &inventory.Asset{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a containerd endpoint")
}

func TestRuntimeImageConnectionRejectsRelativeEndpoint(t *testing.T) {
	_, err := NewRuntimeImage(1, &inventory.Config{
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:       "containerd",
			OPTION_RUNTIME_IMAGE_ENDPOINT:   "run/containerd/containerd.sock",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL: "false",
		},
	}, &inventory.Asset{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute unix socket path")
}

func TestRuntimeImageConnectionRejectsInvalidNamespace(t *testing.T) {
	_, err := NewRuntimeImage(1, &inventory.Config{
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:       "containerd",
			OPTION_RUNTIME_IMAGE_ENDPOINT:   "unix:///host/run/containerd/containerd.sock",
			OPTION_RUNTIME_IMAGE_NAMESPACES: "k8s.io,../../host",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL: "false",
		},
	}, &inventory.Asset{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid containerd namespace")
}

func TestRuntimeImageConnectionRejectsInvalidImageRef(t *testing.T) {
	_, err := NewRuntimeImage(1, &inventory.Config{
		Host: "registry.example.com/team/app:latest\n--flag",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:       "containerd",
			OPTION_RUNTIME_IMAGE_ENDPOINT:   "unix:///host/run/containerd/containerd.sock",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL: "false",
		},
	}, &inventory.Asset{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid runtime image reference")
}

func TestRuntimeImageConnectionUsesDigestQualifiedImageRef(t *testing.T) {
	tmpDir := t.TempDir()
	ociTar := filepath.Join(tmpDir, "image.tar")
	imageDigest := writeTestOCILayoutTar(t, ociTar)

	var gotImageRef string
	var gotTargetDigest string
	oldExporter := exportRuntimeImage
	exportRuntimeImage = func(_ context.Context, _, _, exportPath, imageRef, targetDigest string) error {
		gotImageRef = imageRef
		gotTargetDigest = targetDigest
		in, err := os.Open(ociTar)
		require.NoError(t, err)
		defer in.Close()
		out, err := os.Create(exportPath)
		require.NoError(t, err)
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	}
	t.Cleanup(func() {
		exportRuntimeImage = oldExporter
	})

	conf := &inventory.Config{
		Type: shared.Type_RuntimeImage.String(),
		Host: "registry.example.com/team/app@" + imageDigest,
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:       "containerd",
			OPTION_RUNTIME_IMAGE_ENDPOINT:   "unix:///host/run/containerd/containerd.sock",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL: "false",
			"disable-cache":                 "true",
		},
	}
	asset := &inventory.Asset{}

	conn, err := NewRuntimeImage(1, conf, asset)
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, "registry.example.com/team/app@"+imageDigest, gotImageRef)
	assert.Equal(t, imageDigest, gotTargetDigest)
}

func TestRuntimeImageConnectionLimitsConcurrentExports(t *testing.T) {
	runtimeImageSemaphores = sync.Map{}
	tmpDir := t.TempDir()
	ociTar := filepath.Join(tmpDir, "image.tar")
	imageDigest := writeTestOCILayoutTar(t, ociTar)

	var active int32
	var maxActive int32
	oldExporter := exportRuntimeImage
	exportRuntimeImage = func(_ context.Context, _, _, exportPath, _, _ string) error {
		current := atomic.AddInt32(&active, 1)
		for {
			max := atomic.LoadInt32(&maxActive)
			if current <= max || atomic.CompareAndSwapInt32(&maxActive, max, current) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
		in, err := os.Open(ociTar)
		require.NoError(t, err)
		defer in.Close()
		out, err := os.Create(exportPath)
		require.NoError(t, err)
		defer out.Close()
		_, err = io.Copy(out, in)
		atomic.AddInt32(&active, -1)
		return err
	}
	t.Cleanup(func() {
		exportRuntimeImage = oldExporter
	})

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := NewRuntimeImage(1, runtimeImageConcurrencyConfig(imageDigest), &inventory.Asset{})
			if err != nil {
				errs <- err
				return
			}
			conn.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), maxActive)
}

func TestRuntimeImageConnectionHoldsImageSlotUntilClose(t *testing.T) {
	runtimeImageSemaphores = sync.Map{}
	tmpDir := t.TempDir()
	ociTar := filepath.Join(tmpDir, "image.tar")
	imageDigest := writeTestOCILayoutTar(t, ociTar)

	oldExporter := exportRuntimeImage
	exportRuntimeImage = func(_ context.Context, _, _, exportPath, _, _ string) error {
		in, err := os.Open(ociTar)
		require.NoError(t, err)
		defer in.Close()
		out, err := os.Create(exportPath)
		require.NoError(t, err)
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	}
	t.Cleanup(func() {
		exportRuntimeImage = oldExporter
	})

	conn, err := NewRuntimeImage(1, runtimeImageConcurrencyConfig(imageDigest), &inventory.Asset{})
	require.NoError(t, err)

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		conn, err := NewRuntimeImage(2, runtimeImageConcurrencyConfig(imageDigest), &inventory.Asset{})
		if err == nil {
			conn.Close()
		}
		done <- err
	}()
	<-started

	select {
	case err := <-done:
		require.NoError(t, err)
		t.Fatal("second runtime image connection acquired the image slot before the first connection closed")
	case <-time.After(50 * time.Millisecond):
	}

	conn.Close()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("second runtime image connection did not acquire the image slot after the first connection closed")
	}
}

func TestRuntimeImageConnectionExtractsMultiLayerImageWithSingleLayerReader(t *testing.T) {
	runtimeImageSemaphores = sync.Map{}
	tmpDir := t.TempDir()
	ociTar := filepath.Join(tmpDir, "image.tar")
	img, err := random.Image(256, 3)
	require.NoError(t, err)
	imageDigest := writeTestOCILayoutTarFromImage(t, ociTar, img)

	oldExporter := exportRuntimeImage
	exportRuntimeImage = func(_ context.Context, _, _, exportPath, _, _ string) error {
		in, err := os.Open(ociTar)
		require.NoError(t, err)
		defer in.Close()
		out, err := os.Create(exportPath)
		require.NoError(t, err)
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	}
	t.Cleanup(func() {
		exportRuntimeImage = oldExporter
	})

	conf := &inventory.Config{
		Type: shared.Type_RuntimeImage.String(),
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:         "containerd",
			OPTION_RUNTIME_IMAGE_DIGEST:       imageDigest,
			OPTION_RUNTIME_IMAGE_ENDPOINT:     "unix:///host/run/containerd/containerd.sock",
			OPTION_RUNTIME_IMAGE_NAMESPACES:   "k8s.io",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL:   "false",
			OPTION_RUNTIME_IMAGE_MAX_LAYER_IO: "1",
		},
	}
	conn, err := NewRuntimeImage(1, conf, &inventory.Asset{})
	require.NoError(t, err)
	defer conn.Close()

	done := make(chan error, 1)
	go func() {
		fs, ok := conn.FileSystem().(*tarconn.FS)
		if !ok {
			done <- errors.New("runtime image did not use tar filesystem")
			return
		}
		if len(fs.FileMap) == 0 {
			done <- errors.New("runtime image filesystem was not loaded")
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("runtime image extraction deadlocked with layer reader throttling")
	}
}

func TestRuntimeImageConnectionRejectsDigestMissingFromExport(t *testing.T) {
	tmpDir := t.TempDir()
	ociTar := filepath.Join(tmpDir, "image.tar")
	writeTestOCILayoutTar(t, ociTar)

	oldExporter := exportRuntimeImage
	exportRuntimeImage = func(_ context.Context, _, _, exportPath, _, _ string) error {
		in, err := os.Open(ociTar)
		require.NoError(t, err)
		defer in.Close()
		out, err := os.Create(exportPath)
		require.NoError(t, err)
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	}
	t.Cleanup(func() {
		exportRuntimeImage = oldExporter
	})

	_, err := NewRuntimeImage(1, &inventory.Config{
		Type: shared.Type_RuntimeImage.String(),
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:       "containerd",
			OPTION_RUNTIME_IMAGE_DIGEST:     "sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000",
			OPTION_RUNTIME_IMAGE_ENDPOINT:   "unix:///host/run/containerd/containerd.sock",
			OPTION_RUNTIME_IMAGE_NAMESPACES: "k8s.io",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL: "false",
			"disable-cache":                 "true",
		},
	}, &inventory.Asset{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), `digest "sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000" not found in oci layout`)
}

func TestRuntimeImageConnectionRejectsInvalidDigest(t *testing.T) {
	_, err := NewRuntimeImage(1, &inventory.Config{
		Type: shared.Type_RuntimeImage.String(),
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:       "containerd",
			OPTION_RUNTIME_IMAGE_DIGEST:     "sha256:111122223333",
			OPTION_RUNTIME_IMAGE_ENDPOINT:   "unix:///host/run/containerd/containerd.sock",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL: "false",
		},
	}, &inventory.Asset{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid runtime image digest")
}

func TestRuntimeImageLayerReadersThrottle(t *testing.T) {
	var active int32
	var maxActive int32
	layer := throttledLayer{
		Layer: fakeRuntimeLayer{
			open: func() (io.ReadCloser, error) {
				return &trackedReadCloser{
					Reader: &trackedSlowReader{
						Reader: strings.NewReader("layer"),
						active: &active,
						max:    &maxActive,
					},
					close: func() {},
				}, nil
			},
		},
		sem: make(chan struct{}, 1),
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rc, err := layer.Uncompressed()
			require.NoError(t, err)
			_, err = rc.Read(make([]byte, 1))
			require.NoError(t, err)
			require.NoError(t, rc.Close())
		}()
	}
	close(start)
	wg.Wait()
	assert.Equal(t, int32(1), maxActive)
}

func TestRuntimeImageLayerReadersReleaseSlotAfterEachRead(t *testing.T) {
	layer := throttledLayer{
		Layer: fakeRuntimeLayer{
			open: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("layer")), nil
			},
		},
		sem: make(chan struct{}, 1),
	}

	first, err := layer.Uncompressed()
	require.NoError(t, err)
	second, err := layer.Uncompressed()
	require.NoError(t, err)

	_, err = first.Read(make([]byte, 1))
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := second.Read(make([]byte, 1))
		done <- err
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("second layer stream remained blocked after the first read completed")
	}

	require.NoError(t, first.Close())
	require.NoError(t, second.Close())
}

func TestRuntimeImageConnectionRejectsInvalidConcurrencyOptions(t *testing.T) {
	_, err := NewRuntimeImage(1, &inventory.Config{
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:       "containerd",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL: "false",
			OPTION_RUNTIME_IMAGE_MAX_IMAGES: "zero",
		},
	}, &inventory.Asset{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "runtime-cache-max-concurrent-images must be a positive integer")
}

func TestContainerdAddress(t *testing.T) {
	assert.Equal(t, "/host/run/containerd/containerd.sock", containerdAddress("unix:///host/run/containerd/containerd.sock"))
}

func runtimeImageConcurrencyConfig(imageDigest string) *inventory.Config {
	return &inventory.Config{
		Type: shared.Type_RuntimeImage.String(),
		Host: "registry.example.com/team/app:1.2.3",
		Options: map[string]string{
			OPTION_RUNTIME_IMAGE_KIND:       "containerd",
			OPTION_RUNTIME_IMAGE_DIGEST:     imageDigest,
			OPTION_RUNTIME_IMAGE_ENDPOINT:   "unix:///host/run/containerd/containerd.sock",
			OPTION_RUNTIME_IMAGE_NAMESPACES: "k8s.io",
			OPTION_RUNTIME_IMAGE_ALLOW_PULL: "false",
			OPTION_RUNTIME_IMAGE_MAX_IMAGES: "1",
			"disable-cache":                 "true",
		},
	}
}

type fakeRuntimeLayer struct {
	open func() (io.ReadCloser, error)
}

func (f fakeRuntimeLayer) Digest() (v1.Hash, error) {
	return v1.Hash{Algorithm: "sha256", Hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
}

func (f fakeRuntimeLayer) DiffID() (v1.Hash, error) {
	return v1.Hash{Algorithm: "sha256", Hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, nil
}

func (f fakeRuntimeLayer) Compressed() (io.ReadCloser, error) {
	return f.open()
}

func (f fakeRuntimeLayer) Uncompressed() (io.ReadCloser, error) {
	return f.open()
}

func (f fakeRuntimeLayer) Size() (int64, error) {
	return 5, nil
}

func (f fakeRuntimeLayer) MediaType() (types.MediaType, error) {
	return types.OCILayer, nil
}

type trackedReadCloser struct {
	io.Reader
	close func()
	once  sync.Once
}

func (r *trackedReadCloser) Close() error {
	r.once.Do(r.close)
	return nil
}

type trackedSlowReader struct {
	*strings.Reader
	active *int32
	max    *int32
}

func (r *trackedSlowReader) Read(p []byte) (int, error) {
	current := atomic.AddInt32(r.active, 1)
	for {
		max := atomic.LoadInt32(r.max)
		if current <= max || atomic.CompareAndSwapInt32(r.max, max, current) {
			break
		}
	}
	time.Sleep(25 * time.Millisecond)
	n, err := r.Reader.Read(p)
	atomic.AddInt32(r.active, -1)
	return n, err
}

func TestContainerdImageNameByDigest(t *testing.T) {
	want := digest.FromString("manifest")
	name, ok := containerdImageNameByDigest([]images.Image{
		{Name: "registry.example.com/team/app:old"},
		{Name: "registry.example.com/team/app:1.2.3"},
		{Name: "registry.example.com/team/app@sha256:" + want.Hex()},
	}, "sha256:"+want.Hex())
	require.False(t, ok)
	assert.Empty(t, name)

	name, ok = containerdImageNameByDigest([]images.Image{
		{Name: "registry.example.com/team/app:old"},
		{Name: "registry.example.com/team/app:1.2.3", Target: withDigest(want)},
	}, "docker-pullable://registry.example.com/team/app@sha256:"+want.Hex())
	require.True(t, ok)
	assert.Equal(t, "registry.example.com/team/app:1.2.3", name)
}

func TestContainerdImageNamePrefersTargetDigestOverMutableTag(t *testing.T) {
	oldDigest := digest.FromString("old-manifest")
	newDigest := digest.FromString("new-manifest")
	store := &fakeImageStore{
		byName: map[string]images.Image{
			"registry.example.com/team/app:latest": {
				Name:   "registry.example.com/team/app:latest",
				Target: withDigest(oldDigest),
			},
		},
		list: []images.Image{
			{Name: "registry.example.com/team/app:latest", Target: withDigest(oldDigest)},
			{Name: "registry.example.com/team/app@sha256:" + newDigest.Hex(), Target: withDigest(newDigest)},
		},
	}

	name, err := containerdImageName(context.Background(), store, "registry.example.com/team/app:latest", "sha256:"+newDigest.Hex())

	require.NoError(t, err)
	assert.Equal(t, "registry.example.com/team/app@sha256:"+newDigest.Hex(), name)
}

func TestContainerdImageNameRejectsTagDigestMismatch(t *testing.T) {
	oldDigest := digest.FromString("old-manifest")
	newDigest := digest.FromString("new-manifest")
	store := &fakeImageStore{
		byName: map[string]images.Image{
			"registry.example.com/team/app:latest": {
				Name:   "registry.example.com/team/app:latest",
				Target: withDigest(oldDigest),
			},
		},
		list: []images.Image{
			{Name: "registry.example.com/team/app:latest", Target: withDigest(oldDigest)},
		},
	}

	name, err := containerdImageName(context.Background(), store, "registry.example.com/team/app:latest", "sha256:"+newDigest.Hex())

	require.Error(t, err)
	assert.Empty(t, name)
	assert.Contains(t, err.Error(), "not requested digest")
}

type fakeImageStore struct {
	byName  map[string]images.Image
	list    []images.Image
	listErr error
}

func (s *fakeImageStore) Get(_ context.Context, name string) (images.Image, error) {
	img, ok := s.byName[name]
	if !ok {
		return images.Image{}, errors.New("not found")
	}
	return img, nil
}

func (s *fakeImageStore) List(context.Context, ...string) ([]images.Image, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.list, nil
}

func (s *fakeImageStore) Create(context.Context, images.Image) (images.Image, error) {
	return images.Image{}, errors.New("read-only")
}

func (s *fakeImageStore) Update(context.Context, images.Image, ...string) (images.Image, error) {
	return images.Image{}, errors.New("read-only")
}

func (s *fakeImageStore) Delete(context.Context, string, ...images.DeleteOpt) error {
	return errors.New("read-only")
}

func writeTestOCILayoutTar(t *testing.T, out string) string {
	t.Helper()

	img, err := random.Image(128, 1)
	require.NoError(t, err)
	return writeTestOCILayoutTarFromImage(t, out, img)
}

func writeTestOCILayoutTarFromImage(t *testing.T, out string, img v1.Image) string {
	t.Helper()

	layoutDir := filepath.Join(t.TempDir(), "layout")
	lp, err := layout.Write(layoutDir, empty.Index)
	require.NoError(t, err)
	digest, err := img.Digest()
	require.NoError(t, err)
	require.NoError(t, lp.AppendImage(img))

	f, err := os.Create(out)
	require.NoError(t, err)
	defer f.Close()
	tw := tar.NewWriter(f)
	defer tw.Close()

	require.NoError(t, filepath.WalkDir(layoutDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == layoutDir {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(layoutDir, path)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	}))

	return digest.String()
}

func TestExtractTarFileWritesSafeRegularFiles(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "safe.tar")
	dest := filepath.Join(tmpDir, "dest")
	writeSingleEntryTar(t, src, "blobs/sha256/layer", tar.TypeReg, []byte("layer-data"))

	require.NoError(t, extractTarFile(src, dest))

	data, err := os.ReadFile(filepath.Join(dest, "blobs", "sha256", "layer"))
	require.NoError(t, err)
	assert.Equal(t, "layer-data", string(data))
}

func TestExtractTarFileRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name      string
		entryName string
		typeflag  byte
	}{
		{name: "parent traversal", entryName: "../outside", typeflag: tar.TypeReg},
		{name: "absolute path", entryName: filepath.Join(string(filepath.Separator), "tmp", "outside"), typeflag: tar.TypeReg},
		{name: "symlink", entryName: "link", typeflag: tar.TypeSymlink},
		{name: "hardlink", entryName: "link", typeflag: tar.TypeLink},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			src := filepath.Join(tmpDir, "unsafe.tar")
			dest := filepath.Join(tmpDir, "dest")
			writeSingleEntryTar(t, src, test.entryName, test.typeflag, []byte("data"))

			require.Error(t, extractTarFile(src, dest))
			assert.NoFileExists(t, filepath.Join(tmpDir, "outside"))
		})
	}
}

func writeSingleEntryTar(t *testing.T, out, name string, typeflag byte, data []byte) {
	t.Helper()

	f, err := os.Create(out)
	require.NoError(t, err)
	defer f.Close()

	tw := tar.NewWriter(f)
	defer tw.Close()

	hdr := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(data)),
		Typeflag: typeflag,
	}
	if typeflag != tar.TypeReg {
		hdr.Size = 0
		hdr.Linkname = "../outside"
	}
	require.NoError(t, tw.WriteHeader(hdr))
	if typeflag == tar.TypeReg {
		_, err = tw.Write(data)
		require.NoError(t, err)
	}
}

func withDigest(d digest.Digest) ocispec.Descriptor {
	return ocispec.Descriptor{Digest: d}
}
