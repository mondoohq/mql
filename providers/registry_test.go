// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/cli/config"
)

func TestNewMondooProviderRegistry(t *testing.T) {
	tests := []struct {
		name     string
		opts     []MondooProviderRegistryOption
		expected string
	}{
		{
			name:     "default registry",
			opts:     nil,
			expected: "https://releases.mondoo.com/providers",
		},
		{
			name:     "custom base URL",
			opts:     []MondooProviderRegistryOption{WithBaseURL("https://my-registry.com/providers")},
			expected: "https://my-registry.com/providers",
		},
		{
			name:     "custom base URL with trailing slash",
			opts:     []MondooProviderRegistryOption{WithBaseURL("https://my-registry.com/providers/")},
			expected: "https://my-registry.com/providers/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewMondooProviderRegistry(tt.opts...)
			assert.Equal(t, tt.expected, registry.BaseURL)
		})
	}
}

func TestMondooProviderRegistry_GetLatestVersion(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest.json" {
			versions := ProviderVersions{
				Providers: []ProviderVersion{
					{Name: "aws", Version: "1.2.3"},
					{Name: "azure", Version: "2.4.6"},
					{Name: "gcp", Version: "3.1.4"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(versions); err != nil {
				http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	registry := NewMondooProviderRegistry(WithBaseURL(server.URL))

	tests := []struct {
		name     string
		provider string
		want     string
		wantErr  bool
	}{
		{
			name:     "existing provider",
			provider: "aws",
			want:     "1.2.3",
			wantErr:  false,
		},
		{
			name:     "another existing provider",
			provider: "azure",
			want:     "2.4.6",
			wantErr:  false,
		},
		{
			name:     "non-existing provider",
			provider: "nonexistent",
			want:     "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got, err := registry.GetLatestVersion(ctx, tt.provider)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "cannot determine latest version")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestMondooProviderRegistry_GetLatestVersion_InvalidJSON(t *testing.T) {
	// Test server returning invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("invalid json")) // nolint:errcheck
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	registry := NewMondooProviderRegistry(WithBaseURL(server.URL))
	ctx := context.Background()

	_, err := registry.GetLatestVersion(ctx, "aws")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestMondooProviderRegistry_DownloadProvider(t *testing.T) {
	expectedContent := "fake-provider-content"

	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the expected path format: /aws/1.2.3/aws_1.2.3_linux_amd64.tar.xz
		expectedPath := "/aws/1.2.3/aws_1.2.3_linux_amd64.tar.xz"
		if r.URL.Path == expectedPath {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write([]byte(expectedContent)) // nolint:errcheck
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	registry := NewMondooProviderRegistry(WithBaseURL(server.URL))
	ctx := context.Background()

	t.Run("successful download", func(t *testing.T) {
		reader, err := registry.DownloadProvider(ctx, "aws", "1.2.3", "linux", "amd64")
		require.NoError(t, err)
		defer reader.Close()

		content, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, expectedContent, string(content))
	})

	t.Run("provider not found", func(t *testing.T) {
		_, err := registry.DownloadProvider(ctx, "nonexistent", "1.0.0", "linux", "amd64")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot find provider")
	})
}

func TestMondooProviderRegistry_DownloadProviderMetadata(t *testing.T) {
	expectedConf := `{"Name":"aws","Version":"1.2.3"}`
	expectedSchema := `{"resources":{}}`

	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/aws/1.2.3/provider.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(expectedConf)) // nolint:errcheck
		case "/aws/1.2.3/schema.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(expectedSchema)) // nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	registry := NewMondooProviderRegistry(WithBaseURL(server.URL))
	ctx := context.Background()

	t.Run("successful download", func(t *testing.T) {
		conf, schema, err := registry.DownloadProviderMetadata(ctx, "aws", "1.2.3")
		require.NoError(t, err)
		assert.Equal(t, expectedConf, string(conf))
		assert.Equal(t, expectedSchema, string(schema))
	})

	t.Run("provider not found", func(t *testing.T) {
		_, _, err := registry.DownloadProviderMetadata(ctx, "nonexistent", "1.0.0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot find provider.json")
	})
}

// latestJSONServer serves latest.json and counts how many times it is asked.
func latestJSONServer(t *testing.T, hits *int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/latest.json" {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt64(hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ProviderVersions{Providers: []ProviderVersion{
			{Name: "aws", Version: "1.2.3"},
			{Name: "os", Version: "2.0.0"},
			{Name: "core", Version: "3.0.0"},
		}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The reason this cache exists. Providers are started per asset -- the
// coordinator shuts an idle provider down when an asset's runtime is removed
// and the next asset starts it again -- so this used to be one blocking
// request per provider start: 170 of them on a measured 169-asset scan.
func TestGetLatestVersionFetchesOncePerTTL(t *testing.T) {
	var hits int64
	reg := NewMondooProviderRegistry(WithBaseURL(latestJSONServer(t, &hits).URL))

	for i := 0; i < 50; i++ {
		v, err := reg.GetLatestVersion(context.Background(), "aws")
		require.NoError(t, err)
		assert.Equal(t, "1.2.3", v)
	}
	assert.Equal(t, int64(1), atomic.LoadInt64(&hits), "latest.json should be fetched once")
}

// One file lists every provider, so a scan touching several answers all of
// them from a single request rather than one identical request each.
func TestGetLatestVersionSharesOneFetchAcrossProviders(t *testing.T) {
	var hits int64
	reg := NewMondooProviderRegistry(WithBaseURL(latestJSONServer(t, &hits).URL))

	for name, want := range map[string]string{"aws": "1.2.3", "os": "2.0.0", "core": "3.0.0"} {
		v, err := reg.GetLatestVersion(context.Background(), name)
		require.NoError(t, err)
		assert.Equal(t, want, v)
	}
	assert.Equal(t, int64(1), atomic.LoadInt64(&hits))
}

// Provider starts overlap, so without single-flighting every concurrent
// caller misses the cache and fetches its own copy.
func TestGetLatestVersionCollapsesConcurrentFetches(t *testing.T) {
	var hits int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		<-release // hold the first request open so the rest pile up behind it
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ProviderVersions{Providers: []ProviderVersion{{Name: "aws", Version: "1.2.3"}}})
	}))
	defer srv.Close()
	reg := NewMondooProviderRegistry(WithBaseURL(srv.URL))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := reg.GetLatestVersion(context.Background(), "aws")
			assert.NoError(t, err)
			assert.Equal(t, "1.2.3", v)
		}()
	}
	close(release)
	wg.Wait()

	assert.Equal(t, int64(1), atomic.LoadInt64(&hits), "concurrent callers should share one fetch")
}

// The cache is a TTL, not a permanent memo: a long-running process must pick
// up a newly published provider without being restarted.
func TestGetLatestVersionRefetchesAfterTTL(t *testing.T) {
	var hits int64
	reg := NewMondooProviderRegistry(WithBaseURL(latestJSONServer(t, &hits).URL))

	now := time.Now()
	reg.now = func() time.Time { return now }

	_, err := reg.GetLatestVersion(context.Background(), "aws")
	require.NoError(t, err)
	assert.Equal(t, int64(1), atomic.LoadInt64(&hits))

	now = now.Add(defaultLatestVersionsTTL - time.Second) // still inside the window
	_, err = reg.GetLatestVersion(context.Background(), "aws")
	require.NoError(t, err)
	assert.Equal(t, int64(1), atomic.LoadInt64(&hits), "must not refetch before the TTL expires")

	now = now.Add(2 * time.Second) // now past it
	_, err = reg.GetLatestVersion(context.Background(), "aws")
	require.NoError(t, err)
	assert.Equal(t, int64(2), atomic.LoadInt64(&hits), "must refetch once the TTL expires")
}

// An offline scan must not repeat the request for every provider start, but a
// transient failure has to recover within the same run -- so failures are
// remembered on a much shorter TTL than successes.
func TestGetLatestVersionCachesFailuresBriefly(t *testing.T) {
	var hits int64
	var broken atomic.Bool
	broken.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		if broken.Load() {
			// malformed rather than a 5xx: the retrying client would otherwise
			// turn one logical failure into several requests
			_, _ = w.Write([]byte("{not json"))
			return
		}
		_ = json.NewEncoder(w).Encode(ProviderVersions{Providers: []ProviderVersion{{Name: "aws", Version: "1.2.3"}}})
	}))
	defer srv.Close()
	reg := NewMondooProviderRegistry(WithBaseURL(srv.URL))

	now := time.Now()
	reg.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		_, err := reg.GetLatestVersion(context.Background(), "aws")
		require.Error(t, err)
	}
	assert.Equal(t, int64(1), atomic.LoadInt64(&hits), "a failure must not be retried by every caller")

	// the failure TTL is short, so the run recovers on its own
	broken.Store(false)
	now = now.Add(failedLatestVersionsTTL + time.Second)
	v, err := reg.GetLatestVersion(context.Background(), "aws")
	require.NoError(t, err)
	assert.Equal(t, "1.2.3", v)
	assert.Equal(t, int64(2), atomic.LoadInt64(&hits))

	// a success must not then be re-fetched on the short failure TTL
	now = now.Add(2 * failedLatestVersionsTTL)
	_, err = reg.GetLatestVersion(context.Background(), "aws")
	require.NoError(t, err)
	assert.Equal(t, int64(2), atomic.LoadInt64(&hits), "a success is held for the full TTL")
}

func TestFlushVersionCacheForcesRefetch(t *testing.T) {
	var hits int64
	reg := NewMondooProviderRegistry(WithBaseURL(latestJSONServer(t, &hits).URL))

	_, err := reg.GetLatestVersion(context.Background(), "aws")
	require.NoError(t, err)
	reg.FlushVersionCache()
	_, err = reg.GetLatestVersion(context.Background(), "aws")
	require.NoError(t, err)

	assert.Equal(t, int64(2), atomic.LoadInt64(&hits))
}

// TestRegistryChannelSelectsPointerDocument pins that the release track changes
// which pointer document the registry reads, and nothing else. Providers live in
// one tree: a preview client downloads the same archives from the same URLs, it
// just resolves a different version for them.
func TestRegistryChannelSelectsPointerDocument(t *testing.T) {
	var requested []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)

		version := "13.53.4"
		if strings.HasSuffix(r.URL.Path, "/preview.json") {
			version = "14.0.0-rc.2"
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"providers":[{"name":"aws","version":"` + version + `"}]}`))
	}))
	defer server.Close()

	t.Run("stable reads latest.json", func(t *testing.T) {
		r := NewMondooProviderRegistry(WithBaseURL(server.URL), WithChannel(config.ChannelStable))
		v, err := r.GetLatestVersion(context.Background(), "aws")
		require.NoError(t, err)
		assert.Equal(t, "13.53.4", v)
	})

	t.Run("preview reads preview.json", func(t *testing.T) {
		r := NewMondooProviderRegistry(WithBaseURL(server.URL), WithChannel(config.ChannelPreview))
		v, err := r.GetLatestVersion(context.Background(), "aws")
		require.NoError(t, err)
		assert.Equal(t, "14.0.0-rc.2", v)
	})

	assert.Equal(t, []string{"/latest.json", "/preview.json"}, requested)
}

// TestRegistryChannelReadAtFetchTime pins the reason the channel is not captured
// in the constructor: the package-level registry is built during package init,
// before InitViperConfig has read mondoo.yml, so a constructor-time read would
// only ever see the default.
func TestRegistryChannelReadAtFetchTime(t *testing.T) {
	r := NewMondooProviderRegistry(WithBaseURL("https://example.com/providers"))

	viper.Set(config.KeyUpdateChannel, "")
	t.Cleanup(func() { viper.Set(config.KeyUpdateChannel, "") })
	assert.Equal(t, "latest.json", r.pointerDocument(), "built before config was loaded")

	// Same registry instance, config loaded afterwards.
	viper.Set(config.KeyUpdateChannel, "preview")
	assert.Equal(t, "preview.json", r.pointerDocument())

	// An explicit channel wins over config: that is what WithChannel is for.
	pinned := NewMondooProviderRegistry(WithChannel(config.ChannelStable))
	assert.Equal(t, "latest.json", pinned.pointerDocument())
}
