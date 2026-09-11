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
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/utils/httpx"
	"golang.org/x/sync/singleflight"
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

	// DownloadProviderMetadata downloads only a provider's config (the
	// contents of <name>.json) and resource schema (the contents of
	// <name>.resources.json), without the provider binary.
	DownloadProviderMetadata(ctx context.Context, name, version string) (confJSON []byte, schemaJSON []byte, err error)
}

const (
	// How long a fetched latest.json is reused. Providers are started per
	// asset -- the coordinator shuts an idle one down when an asset's runtime
	// is removed, and the next asset starts it again -- so without this the
	// same 3.6KB file was fetched once per provider start: 170 blocking
	// requests and ~17s on a measured 169-asset scan, scaling linearly.
	//
	// An hour matches the existing UpdateProvidersConfig.RefreshInterval
	// default. The file changes a few times a week.
	defaultLatestVersionsTTL = time.Hour

	// A failed fetch is remembered only briefly. Long enough that an offline
	// scan does not repeat the retry storm for every provider start, short
	// enough that a transient blip recovers within the same run.
	failedLatestVersionsTTL = time.Minute
)

// MondooProviderRegistry implements ProviderRegistry for Mondoo's provider registry
type MondooProviderRegistry struct {
	BaseURL string

	// Channel is the release track provider versions resolve through. Empty
	// means "read it from config at fetch time", which is what the package-level
	// registry does.
	Channel string

	// CacheTTL is how long a fetched latest.json is reused. Zero means
	// defaultLatestVersionsTTL.
	CacheTTL time.Duration

	mu        sync.Mutex
	cached    *ProviderVersions
	cachedErr error
	cachedAt  time.Time

	// group collapses concurrent fetches into one. Provider starts overlap, so
	// without it every concurrent caller misses the cache and fetches its own
	// copy.
	group singleflight.Group

	// now is swapped in tests so cache expiry can be exercised without
	// sleeping. Nil means time.Now.
	now func() time.Time
}

// WithCacheTTL sets how long a fetched latest.json is reused.
func WithCacheTTL(ttl time.Duration) MondooProviderRegistryOption {
	return func(r *MondooProviderRegistry) {
		r.CacheTTL = ttl
	}
}

// MondooProviderRegistryOption defines a function type for configuring MondooProviderRegistry
type MondooProviderRegistryOption func(*MondooProviderRegistry)

// WithBaseURL sets the base URL for the provider registry
func WithBaseURL(baseURL string) MondooProviderRegistryOption {
	return func(r *MondooProviderRegistry) {
		r.BaseURL = baseURL
	}
}

// WithChannel pins the release track, overriding the configured one.
func WithChannel(channel string) MondooProviderRegistryOption {
	return func(r *MondooProviderRegistry) {
		r.Channel = channel
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

// channel returns the release track this registry resolves through.
//
// It is read at fetch time rather than captured in the constructor: the
// package-level registry is built during package init, long before
// InitViperConfig has read mondoo.yml, so a constructor would only ever see the
// default. Reading it here also means every path that reaches a provider
// install honours the setting, not just the ones that went through AttachCLIs.
func (r *MondooProviderRegistry) channel() string {
	if r.Channel != "" {
		return r.Channel
	}
	return config.GetUpdateChannel()
}

// pointerDocument is the document listing each provider's current version for
// this registry's channel. Providers live in one tree, so a channel changes
// which pointer is read and nothing else: the archive, provider.json and
// schema.json URLs are the same on every channel.
func (r *MondooProviderRegistry) pointerDocument() string {
	if r.channel() == config.ChannelPreview {
		return "preview.json"
	}
	return "latest.json"
}

func (r *MondooProviderRegistry) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

func (r *MondooProviderRegistry) ttl() time.Duration {
	if r.CacheTTL > 0 {
		return r.CacheTTL
	}
	return defaultLatestVersionsTTL
}

// cachedVersions returns the memoized document and whether it is still valid.
// A remembered failure is returned as such, so callers see the same error
// rather than each re-running the request behind it.
func (r *MondooProviderRegistry) cachedVersions() (*ProviderVersions, error, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cachedAt.IsZero() {
		return nil, nil, false
	}
	ttl := r.ttl()
	if r.cachedErr != nil {
		ttl = failedLatestVersionsTTL
	}
	if r.clock().Sub(r.cachedAt) >= ttl {
		return nil, nil, false
	}
	return r.cached, r.cachedErr, true
}

func (r *MondooProviderRegistry) storeVersions(v *ProviderVersions, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cached, r.cachedErr, r.cachedAt = v, err, r.clock()
}

// FlushVersionCache drops the memoized latest.json. Exported for tests and for
// callers that need to force a fresh read.
func (r *MondooProviderRegistry) FlushVersionCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cached, r.cachedErr, r.cachedAt = nil, nil, time.Time{}
}

// latestVersions returns the whole latest.json document, fetching it at most
// once per TTL.
//
// The document is memoized rather than the per-provider version: one file
// lists every provider, so a scan touching aws, os and core answers all three
// from a single request instead of three identical ones.
func (r *MondooProviderRegistry) latestVersions(ctx context.Context) (*ProviderVersions, error) {
	if v, err, ok := r.cachedVersions(); ok {
		return v, err
	}

	res, err, _ := r.group.Do("latest.json", func() (any, error) {
		// another caller may have completed while this one waited on the group
		if v, cerr, ok := r.cachedVersions(); ok {
			return v, cerr
		}
		v, ferr := r.fetchLatestVersions(ctx)
		r.storeVersions(v, ferr)
		return v, ferr
	})
	if err != nil {
		return nil, err
	}
	versions, _ := res.(*ProviderVersions)
	return versions, nil
}

func (r *MondooProviderRegistry) fetchLatestVersions(ctx context.Context) (*ProviderVersions, error) {
	client, err := httpClientWithRetry()
	if err != nil {
		return nil, err
	}

	pointer := r.pointerDocument()
	latestURL, err := url.JoinPath(r.BaseURL, pointer)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct latest version URL")
	}
	log.Debug().Str("url", latestURL).Str("channel", r.channel()).Msg("fetching provider versions")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build latest version request")
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		log.Debug().Err(err).Msg("reading latest.json failed")
		return nil, errors.New("failed to read response from upstream provider versions")
	}

	var upstreamVersions ProviderVersions
	err = json.Unmarshal(data, &upstreamVersions)
	if err != nil {
		log.Debug().Err(err).Msg("parsing latest.json failed")
		return nil, errors.New("failed to parse response from upstream provider versions")
	}

	return &upstreamVersions, nil
}

// GetLatestVersion fetches the latest version for the given provider name
func (r *MondooProviderRegistry) GetLatestVersion(ctx context.Context, name string) (string, error) {
	upstreamVersions, err := r.latestVersions(ctx)
	if err != nil {
		return "", err
	}
	if upstreamVersions == nil {
		return "", errors.New("cannot determine latest version of provider '" + name + "'")
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

// DownloadProviderMetadata downloads only a provider's config and resource
// schema. The registry publishes these alongside the binary archives as
// provider.json and schema.json, so schema-only installs don't have to pull
// the (much larger) provider binary down.
func (r *MondooProviderRegistry) DownloadProviderMetadata(ctx context.Context, name, version string) ([]byte, []byte, error) {
	confJSON, err := r.downloadReleaseFile(ctx, name, version, "provider.json")
	if err != nil {
		return nil, nil, err
	}

	schemaJSON, err := r.downloadReleaseFile(ctx, name, version, "schema.json")
	if err != nil {
		return nil, nil, err
	}

	return confJSON, schemaJSON, nil
}

// downloadReleaseFile fetches a single file from a provider's release
// directory, e.g. <base>/<name>/<version>/schema.json.
func (r *MondooProviderRegistry) downloadReleaseFile(ctx context.Context, name, version, filename string) ([]byte, error) {
	downloadURL, err := url.JoinPath(r.BaseURL, name, version, filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct download URL")
	}

	log.Debug().Str("url", downloadURL).Msg("downloading provider file from URL")

	client, err := httpClientWithRetry()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build download request")
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to download "+filename+" for "+name+"-"+version)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		return nil, errors.New("cannot find " + filename + " for provider " + name + "-" + version + " under url " + downloadURL)
	} else if res.StatusCode != http.StatusOK {
		log.Debug().Str("url", downloadURL).Int("status", res.StatusCode).Msg("failed to download from URL (status code)")
		return nil, errors.New("failed to download " + filename + " for " + name + "-" + version + ", received status code: " + res.Status)
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read "+filename+" for "+name+"-"+version)
	}
	return data, nil
}
