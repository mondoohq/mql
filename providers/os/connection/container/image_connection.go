// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package container

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/cli/tmp"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/container/auth"
	"go.mondoo.com/mql/providers/os/connection/container/image"
	"go.mondoo.com/mql/providers/os/connection/tar"
	"go.mondoo.com/mql/providers/os/id/containerid"
	"go.mondoo.com/mql/providers/os/resources/discovery/container_registry"
)

const (
	// used to cache the oci format tar file when the inventory requests to create it alongside the extracted file system tar
	OPTION_FILE_OCI = "oci-path"
	// tar the image in the format you get when running `docker save <image> > <image>.tar` containing layers and manifest.json
	INCLUDE_OCI_TAR_OPT_KEY             = "include-oci-tar"
	optionRuntimeImageMaxBytes          = "runtime-cache-max-image-bytes"
	optionRuntimeImageMaxBytesRemaining = "runtime-cache-max-image-bytes-remaining"
)

var ErrRuntimeImageTooLarge = errors.New("runtime image exceeds configured byte limit")

// NewImageConnection uses a container image reference as input and creates a tar connection.
// Optional cleanupDirs are removed when the connection is closed.
func NewImageConnection(id uint32, conf *inventory.Config, asset *inventory.Asset, img v1.Image, ref name.Reference, cleanupDirs ...string) (*tar.Connection, error) {
	return NewImageConnectionWithCloseFn(id, conf, asset, img, ref, nil, cleanupDirs...)
}

func NewImageConnectionWithCloseFn(id uint32, conf *inventory.Config, asset *inventory.Asset, img v1.Image, ref name.Reference, closeFn func(), cleanupDirs ...string) (*tar.Connection, error) {
	// FIXME: DEPRECATED, remove in v12.0 vv
	// The DelayDiscovery flag should always be set from v12
	if conf.Options == nil || conf.Options[plugin.DISABLE_DELAYED_DISCOVERY_OPTION] == "" {
		conf.DelayDiscovery = true // Delay discovery, to make sure we don't directly download the image
	}
	// ^^
	return newImageTarConnectionWithCloseFn(id, conf, asset, img, ref, includeOciTar(conf), closeFn, cleanupDirs...)
}

// newImageTarConnection extracts img's flattened filesystem to a temporary tar
// file and wraps it in a tar.Connection. When includeOci is true and ref is
// non-nil, it also writes a sibling OCI-format tarball alongside. The temp
// files are removed on connection close, along with any cleanupDirs.
func newImageTarConnection(id uint32, conf *inventory.Config, asset *inventory.Asset, img v1.Image, ref name.Reference, includeOci bool, cleanupDirs ...string) (*tar.Connection, error) {
	return newImageTarConnectionWithCloseFn(id, conf, asset, img, ref, includeOci, nil, cleanupDirs...)
}

func newImageTarConnectionWithCloseFn(id uint32, conf *inventory.Config, asset *inventory.Asset, img v1.Image, ref name.Reference, includeOci bool, closeFn func(), cleanupDirs ...string) (*tar.Connection, error) {
	if conf.Options == nil {
		conf.Options = map[string]string{}
	}
	maxBytes := int64(-1)
	raw := conf.Options[optionRuntimeImageMaxBytesRemaining]
	internalBudget := raw != ""
	if raw == "" {
		raw = conf.Options[optionRuntimeImageMaxBytes]
	}
	if raw != "" {
		parsed, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || parsed < 0 || (!internalBudget && parsed < 1) {
			return nil, fmt.Errorf("invalid runtime image byte budget %q", raw)
		}
		maxBytes = parsed
	}

	extractedFsTar, err := tmp.File()
	if err != nil {
		return nil, err
	}
	conf.Options[tar.OPTION_FILE] = extractedFsTar.Name()

	var ociTar *os.File
	var closeOnce sync.Once
	cleanup := func() {
		closeOnce.Do(func() {
			_ = extractedFsTar.Close()
			if err := os.Remove(extractedFsTar.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
				log.Warn().Err(err).Str("tar", extractedFsTar.Name()).Msg("tar> failed to remove temporary tar file")
			}
			if ociTar != nil {
				_ = ociTar.Close()
				if err := os.Remove(ociTar.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
					log.Warn().Err(err).Str("tar", ociTar.Name()).Msg("tar> failed to remove temporary OCI tar file")
				}
			}
			for _, dir := range cleanupDirs {
				if dir == "" {
					continue
				}
				if err := os.RemoveAll(dir); err != nil {
					log.Warn().Err(err).Str("dir", dir).Msg("tar> failed to remove temporary cache directory")
				}
			}
			if closeFn != nil {
				closeFn()
			}
		})
	}
	if includeOci && ref != nil {
		ociTar, err = tmp.File()
		if err != nil {
			cleanup()
			return nil, err
		}
		conf.Options[OPTION_FILE_OCI] = ociTar.Name()
	}

	conn, err := tar.NewConnection(id, conf, asset,
		tar.WithFetchFn(func() (string, error) {
			log.Debug().Str("tar", extractedFsTar.Name()).Msg("tar> starting image extract to temporary file")
			var err error
			if maxBytes >= 0 {
				err = streamToTmpFileLimited(mutate.Extract(img), extractedFsTar, maxBytes)
			} else {
				err = tar.StreamToTmpFile(mutate.Extract(img), extractedFsTar)
			}
			if err != nil {
				log.Debug().Str("tar", extractedFsTar.Name()).Msg("tar> failed to save image tar")
				cleanup()
				return "", err
			}
			if ociTar != nil {
				log.Debug().Str("oci_tar", ociTar.Name()).Msg("tar> saving image in oci format")
				if err := tarball.Write(ref, img, ociTar); err != nil {
					cleanup()
					return "", err
				}
			}
			log.Debug().Str("tar", extractedFsTar.Name()).Msg("tar> extracted image to temporary file")
			return extractedFsTar.Name(), nil
		}),
		tar.WithCloseFn(func() {
			log.Debug().Str("tar", extractedFsTar.Name()).Msg("tar> remove temporary tar file on connection close")
			cleanup()
		}),
	)
	if err != nil {
		cleanup()
		return nil, err
	}
	return conn, nil
}

type limitedFileWriter struct {
	file         *os.File
	written, max int64
}

func (w *limitedFileWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.max-w.written {
		return 0, ErrRuntimeImageTooLarge
	}
	n, err := w.file.Write(p)
	w.written += int64(n)
	return n, err
}
func streamToTmpFileLimited(r io.ReadCloser, out *os.File, max int64) error {
	defer r.Close()
	defer out.Close()
	_, err := io.Copy(&limitedFileWriter{file: out, max: max}, r)
	return err
}

func includeOciTar(conf *inventory.Config) bool {
	return conf.Options[INCLUDE_OCI_TAR_OPT_KEY] == "true"
}

// NewRegistryImage loads a container image from a remote registry
func NewRegistryImage(id uint32, conf *inventory.Config, asset *inventory.Asset) (*tar.Connection, error) {
	ref, err := name.ParseReference(conf.Host, name.WeakValidation)
	if err != nil {
		return nil, errors.New("invalid container registry reference: " + conf.Host)
	}
	log.Debug().Str("ref", ref.Name()).Msg("found valid container registry reference")

	registryOpts, err := container_registry.RemoteOptionsFromConfigOptions(conf)
	if err != nil {
		return nil, err
	}
	registryOpts = append(registryOpts, auth.AuthOption(ref.Name(), conf.Credentials))
	img, err := image.LoadImageFromRegistry(ref, registryOpts...)
	if err != nil {
		return nil, err
	}
	if conf.Options == nil {
		conf.Options = map[string]string{}
	}

	// Wrap the image with a filesystem cache so that compressed layer data
	// is written to disk instead of being held in memory. This prevents OOM
	// kills when scanning large container images.
	var cleanupDirs []string
	if conf.Options["disable-cache"] != "true" {
		cacheDir, err := tmp.Dir()
		if err != nil {
			return nil, err
		}
		img = cache.Image(img, cache.NewFilesystemCache(cacheDir))
		cleanupDirs = append(cleanupDirs, cacheDir)
	}

	conn, err := NewImageConnection(id, conf, asset, img, ref, cleanupDirs...)
	if err != nil {
		for _, dir := range cleanupDirs {
			if err := os.RemoveAll(dir); err != nil {
				log.Warn().Err(err).Str("dir", dir).Msg("tar> failed to remove cache directory after connection error")
			}
		}
		return nil, err
	}

	var identifier string
	hash, err := img.Digest()
	if err == nil {
		identifier = containerid.MondooContainerImageID(hash.String())
	}

	conn.PlatformIdentifier = identifier
	conn.Metadata.Name = containerid.ShortContainerImageID(hash.String())

	repoName := ref.Context().Name()
	imgDigest := hash.String()
	containerAssetName := repoName + "@" + containerid.ShortContainerImageID(imgDigest)
	if asset.Name == "" {
		asset.Name = containerAssetName
	}
	if len(asset.PlatformIds) == 0 {
		asset.PlatformIds = []string{identifier}
	} else {
		if !slices.Contains(asset.PlatformIds, identifier) {
			asset.PlatformIds = append(asset.PlatformIds, identifier)
		}
	}

	// set the platform architecture using the image configuration
	imgConfig, err := img.ConfigFile()
	if err == nil {
		conn.PlatformArchitecture = imgConfig.Architecture
		conn.ImageConfig = tar.ImageConfigFrom(imgConfig)
	}

	labels := map[string]string{}
	labels["docker.io/digests"] = ref.String()

	manifest, err := img.Manifest()
	if err == nil {
		labels["mondoo.com/image-id"] = manifest.Config.Digest.String()
	}

	conn.Metadata.Labels = labels
	if asset.Labels == nil {
		asset.Labels = map[string]string{}
	}

	for k, v := range labels {
		asset.Labels[k] = v
	}

	return conn, err
}

// NewFromTar opens a container-image tar file (OCI format) and exposes its
// flattened filesystem as a tar.Connection. The input tar is re-extracted to a
// temporary flat tar; the original file is left untouched.
func NewFromTar(id uint32, conf *inventory.Config, asset *inventory.Asset) (*tar.Connection, error) {
	if conf == nil || len(conf.Options[tar.OPTION_FILE]) == 0 {
		return nil, errors.New("tar provider requires a valid tar file")
	}

	img, err := tarball.ImageFromPath(conf.Options[tar.OPTION_FILE], nil)
	if err != nil {
		return nil, err
	}
	return NewFromTarImage(id, conf, asset, img)
}

// NewFromTarImage is NewFromTar for an image tarball the caller already
// opened, so the archive is not parsed twice.
func NewFromTarImage(id uint32, conf *inventory.Config, asset *inventory.Asset, img v1.Image) (*tar.Connection, error) {

	// Resolve the digest before creating the tar connection so a Digest()
	// failure doesn't leak the temp file that newImageTarConnection allocates,
	// and so the caller surfaces the same error the pre-refactor code did
	// instead of silently ending up with an empty PlatformIdentifier.
	hash, err := img.Digest()
	if err != nil {
		return nil, err
	}

	// includeOci=false because the input *is* an OCI tar already; we don't need
	// to emit a second one. Pass nil ref since the OCI-write path is skipped.
	conn, err := newImageTarConnection(id, conf, asset, img, nil, false)
	if err != nil {
		return nil, err
	}

	conn.PlatformIdentifier = containerid.MondooContainerImageID(hash.String())
	if imgConfig, err := img.ConfigFile(); err == nil && imgConfig != nil {
		conn.ImageConfig = tar.ImageConfigFrom(imgConfig)
		conn.PlatformArchitecture = imgConfig.Architecture
	}
	return conn, nil
}

// OpenImageTarball opens path as a saved image (`docker save`, which carries
// a manifest.json). It reports false for anything else, such as an exported
// filesystem.
func OpenImageTarball(path string) (v1.Image, bool) {
	if path == "" {
		return nil, false
	}
	img, err := tarball.ImageFromPath(path, nil)
	if err != nil {
		return nil, false
	}
	return img, true
}
