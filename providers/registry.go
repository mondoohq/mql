// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/utils/httpx"
)

var DefaultUpdatesURL = "https://releases.mondoo.com"
var DefaultProviderRegistryURL = DefaultUpdatesURL + "/providers"

var registry ProviderRegistry = NewMondooProviderRegistry()

// SetProviderRegistry allows setting a custom provider registry implementation.
// It must be called before any provider installation occurs.
func SetProviderRegistry(r ProviderRegistry) {
	registry = r
}

// ProviderRegistry defines the interface for provider registries that can
// fetch provider versions and download provider packages.
type ProviderRegistry interface {
	// GetLatestVersion returns the latest version available for the given provider name
	GetLatestVersion(ctx context.Context, name string) (string, error)

	// DownloadProvider downloads a provider package and returns a ReadCloser for the content
	DownloadProvider(ctx context.Context, name, version, os, arch string) (io.ReadCloser, error)
}

// VerifiedRegistry is an optional extension of ProviderRegistry that can supply
// the verification sidecars (checksum manifest and detached signature) for a
// provider version. When a registry implements it, installVersion verifies
// downloads before installing them. Registries that do not implement it (e.g.
// simple test doubles) skip verification.
type VerifiedRegistry interface {
	// DownloadChecksums returns the raw SHA256SUMS manifest for a provider
	// version.
	DownloadChecksums(ctx context.Context, name, version string) ([]byte, error)

	// DownloadSignature returns the detached minisign signature over the
	// checksum manifest. ok is false (with a nil error) when no signature has
	// been published for this version, so callers can distinguish "unsigned"
	// from "failed to fetch".
	DownloadSignature(ctx context.Context, name, version string) (data []byte, ok bool, err error)
}

// MondooProviderRegistry implements ProviderRegistry for Mondoo's provider registry
type MondooProviderRegistry struct {
	BaseURL string
}

// MondooProviderRegistryOption defines a function type for configuring MondooProviderRegistry
type MondooProviderRegistryOption func(*MondooProviderRegistry)

// WithBaseURL sets the base URL for the provider registry
func WithBaseURL(baseURL string) MondooProviderRegistryOption {
	return func(r *MondooProviderRegistry) {
		r.BaseURL = baseURL
	}
}

// NewMondooProviderRegistry creates a new MondooProviderRegistry with the given options.
// By default, it uses "https://releases.mondoo.com/providers" as the base URL.
func NewMondooProviderRegistry(opts ...MondooProviderRegistryOption) *MondooProviderRegistry {
	r := &MondooProviderRegistry{
		BaseURL: DefaultProviderRegistryURL,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

func LatestVersion(ctx context.Context, name string) (string, error) {
	return registry.GetLatestVersion(ctx, name)
}

// GetLatestVersion fetches the latest version for the given provider name
func (r *MondooProviderRegistry) GetLatestVersion(ctx context.Context, name string) (string, error) {
	client, err := httpClientWithRetry()
	if err != nil {
		return "", err
	}

	latestURL, err := url.JoinPath(r.BaseURL, "latest.json")
	if err != nil {
		return "", errors.Wrap(err, "failed to construct latest version URL")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURL, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to build latest version request")
	}

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		log.Debug().Err(err).Msg("reading latest.json failed")
		return "", errors.New("failed to read response from upstream provider versions")
	}

	var upstreamVersions ProviderVersions
	err = json.Unmarshal(data, &upstreamVersions)
	if err != nil {
		log.Debug().Err(err).Msg("parsing latest.json failed")
		return "", errors.New("failed to parse response from upstream provider versions")
	}

	var latestVersion string
	for i := range upstreamVersions.Providers {
		if upstreamVersions.Providers[i].Name == name {
			latestVersion = upstreamVersions.Providers[i].Version
			break
		}
	}

	if latestVersion == "" {
		return "", errors.New("cannot determine latest version of provider '" + name + "'")
	}
	return latestVersion, nil
}

// DownloadProvider downloads a provider package from the registry
func (r *MondooProviderRegistry) DownloadProvider(ctx context.Context, name, version, os, arch string) (io.ReadCloser, error) {
	// Build the filename using the same pattern as the original
	filename := fmt.Sprintf("%s_%s_%s_%s.tar.xz", name, version, os, arch)

	// Construct the download URL using url.JoinPath for robust path handling
	downloadURL, err := url.JoinPath(r.BaseURL, name, version, filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct download URL")
	}

	log.Debug().Str("url", downloadURL).Msg("downloading provider from URL")

	client, err := httpx.ClientForDownload()
	if err != nil {
		return nil, err
	}

	res, err := client.Get(downloadURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to download "+name+"-"+version)
	}

	if res.StatusCode == http.StatusNotFound {
		return nil, errors.New("cannot find provider " + name + "-" + version + " under url " + downloadURL)
	} else if res.StatusCode != http.StatusOK {
		log.Debug().Str("url", downloadURL).Int("status", res.StatusCode).Msg("failed to download from URL (status code)")
		res.Body.Close()
		return nil, errors.New("failed to download " + name + "-" + version + ", received status code: " + res.Status)
	}

	// Wrap with idle timeout so slow-but-active downloads succeed while
	// truly stalled transfers are detected. Callers just read and close.
	return httpx.NewIdleTimeoutReader(res.Body, httpx.DownloadTimeout()), nil
}

// checksumFilename builds the name of the SHA256SUMS manifest for a version.
// The release pipeline names it "<name>_<version>_SHA256SUMS"
// (provider_bundler.sh).
func checksumFilename(name, version string) string {
	return fmt.Sprintf("%s_%s_SHA256SUMS", name, version)
}

// DownloadChecksums fetches the SHA256SUMS manifest for a provider version.
func (r *MondooProviderRegistry) DownloadChecksums(ctx context.Context, name, version string) ([]byte, error) {
	url, err := url.JoinPath(r.BaseURL, name, version, checksumFilename(name, version))
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct checksum URL")
	}
	data, _, err := r.fetch(ctx, url)
	if err != nil {
		return nil, errors.Wrap(err, "failed to download checksum manifest for "+name+"-"+version)
	}
	if data == nil {
		return nil, errors.New("checksum manifest not found for " + name + "-" + version)
	}
	return data, nil
}

// DownloadSignature fetches the detached minisign signature over the checksum
// manifest. A 404 is reported as ok=false with no error, so an as-yet-unsigned
// release does not fail verification under the 'auto' policy.
func (r *MondooProviderRegistry) DownloadSignature(ctx context.Context, name, version string) ([]byte, bool, error) {
	url, err := url.JoinPath(r.BaseURL, name, version, checksumFilename(name, version)+".sig")
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to construct signature URL")
	}
	data, notFound, err := r.fetch(ctx, url)
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to download signature for "+name+"-"+version)
	}
	if notFound || data == nil {
		return nil, false, nil
	}
	return data, true, nil
}

// fetch GETs a small sidecar file. It returns (nil, true, nil) on 404 so
// callers can treat "not published" distinctly from a transport error.
func (r *MondooProviderRegistry) fetch(ctx context.Context, url string) (data []byte, notFound bool, err error) {
	client, err := httpClientWithRetry()
	if err != nil {
		return nil, false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		return nil, true, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, false, errors.New("received status code " + res.Status + " for " + url)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, false, err
	}
	return body, false, nil
}
