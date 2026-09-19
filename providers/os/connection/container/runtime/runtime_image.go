// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runtime

import (
	stdtar "archive/tar"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	contentapi "github.com/containerd/containerd/api/services/content/v1"
	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	apitypes "github.com/containerd/containerd/api/types"
	contentproxy "github.com/containerd/containerd/content/proxy"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/images/archive"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/pkg/dialer"
	"github.com/containerd/platforms"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/cli/tmp"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/container"
	"go.mondoo.com/mql/providers/os/connection/shared"
	tarconn "go.mondoo.com/mql/providers/os/connection/tar"
	"go.mondoo.com/mql/providers/os/id/containerid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

const (
	OPTION_RUNTIME_IMAGE_REF                 = "runtime-cache-image-ref"
	OPTION_RUNTIME_IMAGE_DIGEST              = "runtime-cache-image-digest"
	OPTION_RUNTIME_IMAGE_KIND                = "runtime-cache-kind"
	OPTION_RUNTIME_IMAGE_DELEGATE_ID         = "runtime-cache-delegate-id"
	OPTION_RUNTIME_IMAGE_DELEGATE_CANDIDATES = "runtime-cache-delegate-candidates"
	OPTION_RUNTIME_IMAGE_ENDPOINT            = "runtime-cache-endpoint"
	OPTION_RUNTIME_IMAGE_NAMESPACES          = "runtime-cache-namespaces"
	OPTION_RUNTIME_IMAGE_EXPORT_TIMEOUT      = "runtime-cache-export-timeout"
	OPTION_RUNTIME_IMAGE_ALLOW_PULL          = "runtime-cache-allow-pull"
	OPTION_RUNTIME_IMAGE_MAX_IMAGES          = "runtime-cache-max-concurrent-images"
	OPTION_RUNTIME_IMAGE_MAX_LAYER_IO        = "runtime-cache-max-concurrent-layer-io"
)

const defaultContainerdNamespace = "k8s.io"

var exportRuntimeImage = exportContainerdImageWithClient

var runtimeImageSemaphores sync.Map

// NewRuntimeImage opens a node-local runtime image without pulling from a registry.
// It currently supports read-only containerd delegates by exporting the image
// from the mounted containerd content store and feeding it into the existing
// container-image tar scanner.
func NewRuntimeImage(id uint32, conf *inventory.Config, asset *inventory.Asset) (*tarconn.Connection, error) {
	if conf == nil {
		return nil, errors.New("runtime image connection requires configuration")
	}
	if conf.Options == nil {
		conf.Options = map[string]string{}
	}

	kind := strings.TrimSpace(conf.Options[OPTION_RUNTIME_IMAGE_KIND])
	if kind == "" {
		kind = "containerd"
	}
	if kind != "containerd" {
		return nil, fmt.Errorf("runtime image connection supports containerd delegates only, got %q", kind)
	}
	if strings.EqualFold(conf.Options[OPTION_RUNTIME_IMAGE_ALLOW_PULL], "true") {
		return nil, errors.New("runtime image connection does not support registry pulls")
	}
	releaseImageSlot, err := acquireRuntimeImageOptionSlot(conf.Options, OPTION_RUNTIME_IMAGE_MAX_IMAGES, "image")
	if err != nil {
		return nil, err
	}
	releaseSlotOnError := true
	defer func() {
		if releaseSlotOnError {
			releaseImageSlot()
		}
	}()

	imageRef := strings.TrimSpace(conf.Options[OPTION_RUNTIME_IMAGE_REF])
	if imageRef == "" {
		imageRef = strings.TrimSpace(conf.Host)
	}
	if imageRef == "" {
		return nil, errors.New("runtime image connection requires an image reference")
	}
	if err := validateRuntimeImageRef(imageRef); err != nil {
		return nil, err
	}

	exportPath, cleanup, err := exportContainerdImageWithFallback(conf, imageRef)
	if err != nil {
		return nil, err
	}

	img, layoutDir, err := imageFromOCILayoutTar(exportPath, conf.Options[OPTION_RUNTIME_IMAGE_DIGEST])
	if err != nil {
		cleanup()
		return nil, err
	}
	cleanupDirs := []string{exportPath, layoutDir}

	if layerReaders, err := positiveRuntimeImageOption(conf.Options, OPTION_RUNTIME_IMAGE_MAX_LAYER_IO); err != nil {
		cleanup()
		for _, dir := range cleanupDirs {
			_ = os.RemoveAll(dir)
		}
		return nil, err
	} else if layerReaders > 0 {
		img = throttledImage{Image: img, sem: runtimeImageSemaphore("layer", layerReaders)}
	}
	if conf.Options["disable-cache"] != "true" {
		cacheDir, err := tmp.Dir()
		if err != nil {
			cleanup()
			_ = os.RemoveAll(layoutDir)
			return nil, err
		}
		img = cache.Image(img, cache.NewFilesystemCache(cacheDir))
		cleanupDirs = append(cleanupDirs, cacheDir)
	}

	conf.Type = shared.Type_RuntimeImage.String()
	conf.Runtime = shared.Type_RuntimeImage.String()

	var releaseOnce sync.Once
	conn, err := container.NewImageConnectionWithCloseFn(id, conf, asset, img, nil, func() {
		releaseOnce.Do(releaseImageSlot)
	}, cleanupDirs...)
	if err != nil {
		cleanup()
		for _, dir := range cleanupDirs {
			_ = os.RemoveAll(dir)
		}
		return nil, err
	}
	releaseSlotOnError = false

	conn.PlatformKind = "container-image"
	conn.PlatformRuntime = shared.Type_RuntimeImage.String()

	hash, err := img.Digest()
	if err == nil {
		identifier := containerid.MondooContainerImageID(hash.String())
		conn.PlatformIdentifier = identifier
		conn.Metadata.Name = containerid.ShortContainerImageID(hash.String())
		if asset.Name == "" {
			asset.Name = imageRef + "@" + containerid.ShortContainerImageID(hash.String())
		}
		if len(asset.PlatformIds) == 0 {
			asset.PlatformIds = []string{identifier}
		} else if !slices.Contains(asset.PlatformIds, identifier) {
			asset.PlatformIds = append(asset.PlatformIds, identifier)
		}
	}

	if asset.Labels == nil {
		asset.Labels = map[string]string{}
	}
	asset.Labels["mondoo.com/runtime-image-ref"] = imageRef
	if digest := strings.TrimSpace(conf.Options[OPTION_RUNTIME_IMAGE_DIGEST]); digest != "" {
		asset.Labels["mondoo.com/runtime-image-digest"] = digest
	}
	if delegateID := strings.TrimSpace(conf.Options[OPTION_RUNTIME_IMAGE_DELEGATE_ID]); delegateID != "" {
		asset.Labels["mondoo.com/runtime-delegate-id"] = delegateID
	}

	return conn, nil
}

func acquireRuntimeImageOptionSlot(options map[string]string, key, scope string) (func(), error) {
	limit, err := positiveRuntimeImageOption(options, key)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		return func() {}, nil
	}
	sem := runtimeImageSemaphore(scope, limit)
	sem <- struct{}{}
	return func() {
		<-sem
	}, nil
}

func positiveRuntimeImageOption(options map[string]string, key string) (int, error) {
	if options == nil {
		return 0, nil
	}
	raw := strings.TrimSpace(options[key])
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return value, nil
}

func runtimeImageSemaphore(scope string, limit int) chan struct{} {
	key := fmt.Sprintf("%s:%d", scope, limit)
	actual, _ := runtimeImageSemaphores.LoadOrStore(key, make(chan struct{}, limit))
	return actual.(chan struct{})
}

type runtimeImageDelegateCandidate struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Endpoint   string   `json:"endpoint"`
	Namespaces []string `json:"namespaces"`
	ReadOnly   bool     `json:"readonly"`
}

type throttledImage struct {
	v1.Image
	sem chan struct{}
}

func (i throttledImage) Layers() ([]v1.Layer, error) {
	layers, err := i.Image.Layers()
	if err != nil {
		return nil, err
	}
	out := make([]v1.Layer, 0, len(layers))
	for _, layer := range layers {
		out = append(out, throttledLayer{Layer: layer, sem: i.sem})
	}
	return out, nil
}

func (i throttledImage) LayerByDigest(hash v1.Hash) (v1.Layer, error) {
	layer, err := i.Image.LayerByDigest(hash)
	if err != nil {
		return nil, err
	}
	return throttledLayer{Layer: layer, sem: i.sem}, nil
}

func (i throttledImage) LayerByDiffID(hash v1.Hash) (v1.Layer, error) {
	layer, err := i.Image.LayerByDiffID(hash)
	if err != nil {
		return nil, err
	}
	return throttledLayer{Layer: layer, sem: i.sem}, nil
}

type throttledLayer struct {
	v1.Layer
	sem chan struct{}
}

func (l throttledLayer) Compressed() (io.ReadCloser, error) {
	return l.withSlot(l.Layer.Compressed)
}

func (l throttledLayer) Uncompressed() (io.ReadCloser, error) {
	return l.withSlot(l.Layer.Uncompressed)
}

func (l throttledLayer) withSlot(open func() (io.ReadCloser, error)) (io.ReadCloser, error) {
	rc, err := open()
	if err != nil {
		return nil, err
	}
	if l.sem == nil {
		return rc, nil
	}
	return &throttledReadCloser{ReadCloser: rc, sem: l.sem}, nil
}

type throttledReadCloser struct {
	io.ReadCloser
	sem chan struct{}
}

func (r *throttledReadCloser) Read(p []byte) (int, error) {
	r.sem <- struct{}{}
	defer func() { <-r.sem }()
	return r.ReadCloser.Read(p)
}

func (r *throttledReadCloser) Close() error {
	return r.ReadCloser.Close()
}

func exportContainerdImageWithFallback(conf *inventory.Config, imageRef string) (string, func(), error) {
	candidates, err := runtimeImageDelegateCandidates(conf.Options[OPTION_RUNTIME_IMAGE_DELEGATE_CANDIDATES])
	if err != nil {
		return "", nil, err
	}
	if len(candidates) == 0 {
		return exportContainerdImage(conf, imageRef)
	}

	original := cloneStringMap(conf.Options)
	var errs []error
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.Kind) != "" && strings.TrimSpace(candidate.Kind) != "containerd" {
			errs = append(errs, fmt.Errorf("delegate %q: runtime image connection supports containerd delegates only, got %q", candidate.ID, candidate.Kind))
			continue
		}
		if !candidate.ReadOnly {
			errs = append(errs, fmt.Errorf("delegate %q: runtime image connection requires read-only delegates", candidate.ID))
			continue
		}
		candidateOptions := cloneStringMap(original)
		applyRuntimeImageDelegateCandidate(candidateOptions, candidate)
		candidateConfig, ok := proto.Clone(conf).(*inventory.Config)
		if !ok {
			return "", nil, errors.New("runtime image connection requires protobuf config")
		}
		candidateConfig.Options = candidateOptions
		exportPath, cleanup, err := exportContainerdImage(candidateConfig, imageRef)
		if err == nil {
			conf.Options = candidateOptions
			return exportPath, cleanup, nil
		}
		errs = append(errs, fmt.Errorf("delegate %q: %w", candidate.ID, err))
		log.Debug().Err(err).Str("delegate", candidate.ID).Str("image", imageRef).Msg("runtime image delegate export failed")
	}
	conf.Options = original
	return "", nil, fmt.Errorf("failed to export runtime image %q from configured delegates: %w", imageRef, errors.Join(errs...))
}

func runtimeImageDelegateCandidates(raw string) ([]runtimeImageDelegateCandidate, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var candidates []runtimeImageDelegateCandidate
	if err := json.Unmarshal([]byte(raw), &candidates); err != nil {
		return nil, fmt.Errorf("invalid runtime image delegate candidates: %w", err)
	}
	out := make([]runtimeImageDelegateCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		candidate.ID = strings.TrimSpace(candidate.ID)
		candidate.Kind = strings.TrimSpace(candidate.Kind)
		candidate.Endpoint = strings.TrimSpace(candidate.Endpoint)
		if candidate.Endpoint == "" {
			continue
		}
		endpoint, err := validatedContainerdEndpoint(candidate.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("delegate %q: %w", candidate.ID, err)
		}
		candidate.Endpoint = endpoint
		if candidate.Kind == "" {
			candidate.Kind = "containerd"
		}
		if candidate.ID == "" {
			candidate.ID = candidate.Kind
		}
		out = append(out, candidate)
	}
	return out, nil
}

func applyRuntimeImageDelegateCandidate(options map[string]string, candidate runtimeImageDelegateCandidate) {
	options[OPTION_RUNTIME_IMAGE_KIND] = candidate.Kind
	options[OPTION_RUNTIME_IMAGE_DELEGATE_ID] = candidate.ID
	options[OPTION_RUNTIME_IMAGE_ENDPOINT] = candidate.Endpoint
	options[OPTION_RUNTIME_IMAGE_NAMESPACES] = strings.Join(candidate.Namespaces, ",")
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func exportContainerdImage(conf *inventory.Config, imageRef string) (string, func(), error) {
	exportFile, err := tmp.File()
	if err != nil {
		return "", nil, err
	}
	_ = exportFile.Close()
	_ = os.Remove(exportFile.Name())
	cleanup := func() {
		_ = os.Remove(exportFile.Name())
	}

	endpoint, err := validatedContainerdEndpoint(conf.Options[OPTION_RUNTIME_IMAGE_ENDPOINT])
	if err != nil {
		cleanup()
		return "", nil, err
	}

	timeout := 10 * time.Minute
	if raw := strings.TrimSpace(conf.Options[OPTION_RUNTIME_IMAGE_EXPORT_TIMEOUT]); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("invalid runtime image export timeout %q: %w", raw, err)
		}
		timeout = parsed
	}

	namespaces, err := runtimeImageNamespaces(conf.Options[OPTION_RUNTIME_IMAGE_NAMESPACES])
	if err != nil {
		cleanup()
		return "", nil, err
	}
	targetDigest, err := validatedRuntimeImageDigest(conf.Options[OPTION_RUNTIME_IMAGE_DIGEST])
	if err != nil {
		cleanup()
		return "", nil, err
	}
	if targetDigest == "" {
		targetDigest, err = validatedRuntimeImageDigest(imageRef)
		if err != nil {
			cleanup()
			return "", nil, err
		}
	}
	var errs []error
	for _, namespace := range namespaces {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		err := exportRuntimeImage(ctx, endpoint, namespace, exportFile.Name(), imageRef, targetDigest)
		cancel()
		if err == nil {
			return exportFile.Name(), cleanup, nil
		}
		errs = append(errs, fmt.Errorf("namespace %q: %w", namespace, err))
		log.Debug().Err(err).Str("namespace", namespace).Str("image", imageRef).Msg("containerd image export failed")
	}

	cleanup()
	return "", nil, fmt.Errorf("failed to export runtime image %q from containerd: %w", imageRef, errors.Join(errs...))
}

func exportContainerdImageWithClient(ctx context.Context, endpoint, namespace, exportPath, imageRef, targetDigest string) error {
	address := containerdAddress(endpoint)
	conn, err := dialContainerd(ctx, address)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx = namespaces.WithNamespace(ctx, namespace)
	imageStore := &runtimeImageStore{client: imagesapi.NewImagesClient(conn)}
	contentStore := contentproxy.NewContentStore(contentapi.NewContentClient(conn))
	imageName, err := containerdImageName(ctx, imageStore, imageRef, targetDigest)
	if err != nil {
		return err
	}

	out, err := os.Create(exportPath)
	if err != nil {
		return err
	}
	defer out.Close()

	return archive.Export(ctx, contentStore, out,
		archive.WithImage(imageStore, imageName),
		archive.WithPlatform(platforms.DefaultStrict()),
	)
}

func dialContainerd(ctx context.Context, address string) (*grpc.ClientConn, error) {
	backoffConfig := backoff.DefaultConfig
	backoffConfig.MaxDelay = 3 * time.Second
	conn, err := grpc.NewClient(dialer.DialAddress(address),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoffConfig}),
		grpc.WithContextDialer(dialer.ContextDialer),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(defaults.DefaultMaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(defaults.DefaultMaxSendMsgSize),
		),
	)
	if err != nil {
		return nil, err
	}
	conn.Connect()
	if err := waitForGRPCReady(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func waitForGRPCReady(ctx context.Context, conn *grpc.ClientConn) error {
	for {
		state := conn.GetState()
		switch state {
		case connectivity.Ready:
			return nil
		case connectivity.Shutdown:
			return errors.New("containerd gRPC connection shut down before it became ready")
		}
		if !conn.WaitForStateChange(ctx, state) {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("containerd gRPC connection did not become ready; last state %s", state)
		}
	}
}

type runtimeImageStore struct {
	client imagesapi.ImagesClient
}

func (s *runtimeImageStore) Get(ctx context.Context, name string) (images.Image, error) {
	resp, err := s.client.Get(ctx, &imagesapi.GetImageRequest{Name: name})
	if err != nil {
		return images.Image{}, err
	}
	return runtimeImageFromProto(resp.Image), nil
}

func (s *runtimeImageStore) List(ctx context.Context, filters ...string) ([]images.Image, error) {
	resp, err := s.client.List(ctx, &imagesapi.ListImagesRequest{Filters: filters})
	if err != nil {
		return nil, err
	}
	out := make([]images.Image, 0, len(resp.Images))
	for _, image := range resp.Images {
		out = append(out, runtimeImageFromProto(image))
	}
	return out, nil
}

func (s *runtimeImageStore) Create(context.Context, images.Image) (images.Image, error) {
	return images.Image{}, errors.New("runtime image store is read-only")
}

func (s *runtimeImageStore) Update(context.Context, images.Image, ...string) (images.Image, error) {
	return images.Image{}, errors.New("runtime image store is read-only")
}

func (s *runtimeImageStore) Delete(context.Context, string, ...images.DeleteOpt) error {
	return errors.New("runtime image store is read-only")
}

func runtimeImageFromProto(image *imagesapi.Image) images.Image {
	if image == nil {
		return images.Image{}
	}
	var createdAt, updatedAt time.Time
	if image.CreatedAt != nil {
		createdAt = image.CreatedAt.AsTime()
	}
	if image.UpdatedAt != nil {
		updatedAt = image.UpdatedAt.AsTime()
	}
	return images.Image{
		Name:      image.Name,
		Labels:    image.Labels,
		Target:    runtimeImageDescriptorFromProto(image.Target),
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
}

func runtimeImageDescriptorFromProto(desc *apitypes.Descriptor) ocispec.Descriptor {
	if desc == nil {
		return ocispec.Descriptor{}
	}
	return ocispec.Descriptor{
		MediaType:   desc.MediaType,
		Size:        desc.Size,
		Digest:      digest.Digest(desc.Digest),
		Annotations: desc.Annotations,
	}
}

func containerdImageName(ctx context.Context, imageStore images.Store, imageRef, targetDigest string) (string, error) {
	normalizedDigest := normalizedTargetDigest(targetDigest)
	if normalizedDigest != "" {
		want, err := digest.Parse(normalizedDigest)
		if err != nil {
			return "", fmt.Errorf("invalid target digest %q: %w", targetDigest, err)
		}

		imgs, listErr := imageStore.List(ctx)
		if listErr == nil {
			if name, ok := containerdImageNameByDigest(imgs, normalizedDigest); ok {
				return name, nil
			}
		}

		img, getErr := imageStore.Get(ctx, imageRef)
		if getErr == nil {
			if digestEqual(img.Target.Digest, want) {
				return imageRef, nil
			}
			return "", fmt.Errorf("containerd image %q resolves to digest %q, not requested digest %q", imageRef, img.Target.Digest, want)
		}
		if listErr != nil {
			return "", fmt.Errorf("failed to find containerd image %q by digest %q: failed to list images: %w; failed to get image by name: %w", imageRef, want, listErr, getErr)
		}
		return "", fmt.Errorf("containerd image %q with digest %q not found in local image store: %w", imageRef, want, getErr)
	}

	_, getErr := imageStore.Get(ctx, imageRef)
	if getErr == nil {
		return imageRef, nil
	}

	imgs, err := imageStore.List(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to find containerd image %q by name: %w; failed to list images for digest fallback: %w", imageRef, getErr, err)
	}
	if name, ok := containerdImageNameByDigest(imgs, targetDigest); ok {
		return name, nil
	}
	return "", fmt.Errorf("containerd image %q not found in local image store: %w", imageRef, getErr)
}

func containerdImageNameByDigest(imgs []images.Image, targetDigest string) (string, bool) {
	targetDigest = normalizedTargetDigest(targetDigest)
	if targetDigest == "" {
		return "", false
	}
	want, err := digest.Parse(targetDigest)
	if err != nil {
		return "", false
	}
	for _, img := range imgs {
		if digestEqual(img.Target.Digest, want) {
			return img.Name, true
		}
	}
	return "", false
}

func runtimeImageNamespaces(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	namespaces := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if err := validateContainerdNamespace(part); err != nil {
			return nil, err
		}
		namespaces = append(namespaces, part)
	}
	if len(namespaces) == 0 {
		return []string{defaultContainerdNamespace}, nil
	}
	return namespaces, nil
}

func containerdAddress(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimPrefix(endpoint, "unix://")
	if endpoint == "" {
		return defaults.DefaultAddress
	}
	return endpoint
}

func validatedContainerdEndpoint(raw string) (string, error) {
	endpoint := strings.TrimSpace(raw)
	if endpoint == "" {
		return "", errors.New("runtime image connection requires a containerd endpoint")
	}
	if strings.ContainsAny(endpoint, "\x00\r\n") {
		return "", fmt.Errorf("invalid containerd endpoint %q", raw)
	}
	hasUnixScheme := strings.HasPrefix(endpoint, "unix://")
	socketPath := strings.TrimPrefix(endpoint, "unix://")
	if !filepath.IsAbs(socketPath) {
		return "", fmt.Errorf("containerd endpoint must be an absolute unix socket path, got %q", raw)
	}
	socketPath = filepath.Clean(socketPath)
	if hasUnixScheme {
		return "unix://" + socketPath, nil
	}
	return socketPath, nil
}

func validateContainerdNamespace(namespace string) error {
	if namespace == "" {
		return errors.New("containerd namespace must not be empty")
	}
	if strings.ContainsAny(namespace, "/\\:\x00\r\n,") {
		return fmt.Errorf("invalid containerd namespace %q", namespace)
	}
	for _, r := range namespace {
		if r == '.' || r == '_' || r == '-' ||
			(r >= '0' && r <= '9') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') {
			continue
		}
		return fmt.Errorf("invalid containerd namespace %q", namespace)
	}
	return nil
}

func validateRuntimeImageRef(imageRef string) error {
	if strings.ContainsAny(imageRef, "\x00\r\n") {
		return fmt.Errorf("invalid runtime image reference %q", imageRef)
	}
	if _, err := name.ParseReference(imageRef, name.WeakValidation); err == nil {
		return nil
	}
	if normalizedTargetDigest(imageRef) != "" {
		return nil
	}
	return fmt.Errorf("invalid runtime image reference %q", imageRef)
}

func validatedRuntimeImageDigest(raw string) (string, error) {
	normalized := normalizedTargetDigest(raw)
	if normalized == "" {
		return "", nil
	}
	parsed, err := digest.Parse(normalized)
	if err != nil {
		return "", fmt.Errorf("invalid runtime image digest %q: %w", raw, err)
	}
	return parsed.String(), nil
}

func imageFromOCILayoutTar(path string, targetDigest string) (v1.Image, string, error) {
	layoutDir, err := tmp.Dir()
	if err != nil {
		return nil, "", err
	}
	if err := extractTarFile(path, layoutDir); err != nil {
		_ = os.RemoveAll(layoutDir)
		return nil, "", err
	}

	idx, err := layout.ImageIndexFromPath(layoutDir)
	if err != nil {
		_ = os.RemoveAll(layoutDir)
		return nil, "", err
	}
	img, err := imageFromIndex(idx, normalizedTargetDigest(targetDigest))
	if err != nil {
		_ = os.RemoveAll(layoutDir)
		return nil, "", err
	}
	return img, layoutDir, nil
}

func imageFromIndex(idx v1.ImageIndex, targetDigest string) (v1.Image, error) {
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}

	if targetDigest != "" {
		img, err := imageByDigest(idx, manifest.Manifests, targetDigest)
		if err != nil {
			return nil, err
		}
		return img, nil
	}

	return firstImageFromIndex(idx, manifest.Manifests)
}

func imageByDigest(idx v1.ImageIndex, descriptors []v1.Descriptor, targetDigest string) (v1.Image, error) {
	for _, desc := range descriptors {
		if digestStringEqual(desc.Digest, targetDigest) && desc.MediaType.IsImage() {
			return idx.Image(desc.Digest)
		}
		if !desc.MediaType.IsIndex() {
			continue
		}
		child, err := idx.ImageIndex(desc.Digest)
		if err != nil {
			continue
		}
		childManifest, err := child.IndexManifest()
		if err != nil {
			continue
		}
		if digestStringEqual(desc.Digest, targetDigest) {
			return firstImageFromIndex(child, childManifest.Manifests)
		}
		if img, err := imageByDigest(child, childManifest.Manifests, targetDigest); err == nil {
			return img, nil
		}
	}
	return nil, fmt.Errorf("digest %q not found in oci layout", targetDigest)
}

func firstImageFromIndex(idx v1.ImageIndex, descriptors []v1.Descriptor) (v1.Image, error) {
	for _, preferLocalPlatform := range []bool{true, false} {
		for _, desc := range descriptors {
			if desc.MediaType.IsImage() {
				if preferLocalPlatform && !descriptorMatchesLocalPlatform(desc) {
					continue
				}
				return idx.Image(desc.Digest)
			}
			if desc.MediaType.IsIndex() {
				child, err := idx.ImageIndex(desc.Digest)
				if err != nil {
					continue
				}
				img, err := imageFromIndex(child, "")
				if err == nil {
					return img, nil
				}
			}
		}
	}

	return nil, errors.New("oci layout does not contain a runnable image")
}

func descriptorMatchesLocalPlatform(desc v1.Descriptor) bool {
	if desc.Platform == nil {
		return true
	}
	return (desc.Platform.OS == "" || desc.Platform.OS == runtime.GOOS) &&
		(desc.Platform.Architecture == "" || desc.Platform.Architecture == runtime.GOARCH)
}

func normalizedTargetDigest(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if idx := strings.LastIndex(ref, "@sha256:"); idx >= 0 {
		return ref[idx+1:]
	}
	if idx := strings.LastIndex(ref, "sha256:"); idx >= 0 {
		return ref[idx:]
	}
	return ""
}

func digestEqual(a, b digest.Digest) bool {
	return subtle.ConstantTimeCompare([]byte(a.String()), []byte(b.String())) == 1
}

func digestStringEqual(a interface{ String() string }, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a.String()), []byte(b)) == 1
}

func extractTarFile(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	cleanDest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	cleanDest = filepath.Clean(cleanDest)
	if err := os.MkdirAll(cleanDest, 0o755); err != nil {
		return err
	}
	root, err := os.OpenRoot(cleanDest)
	if err != nil {
		return err
	}
	defer root.Close()

	tr := stdtar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		cleanName := filepath.Clean(hdr.Name)
		if cleanName == "." || cleanName == "" {
			continue
		}
		if !filepath.IsLocal(cleanName) {
			return errors.New("unsafe tar path")
		}
		switch hdr.Typeflag {
		case stdtar.TypeDir:
			if err := root.MkdirAll(cleanName, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case stdtar.TypeReg, 0:
			if err := root.MkdirAll(filepath.Dir(cleanName), 0o755); err != nil {
				return err
			}
			out, err := root.OpenFile(cleanName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("unsupported tar entry type %d", hdr.Typeflag)
		}
	}
}
