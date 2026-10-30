// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// httpGetBytes must reject a response that exceeds maxChartDownloadSize rather
// than silently truncating it (io.LimitReader returns EOF at the cap with no
// error). A body at or under the cap is returned intact.
func TestHttpGetBytesSizeLimit(t *testing.T) {
	orig := maxChartDownloadSize
	maxChartDownloadSize = 64
	defer func() { maxChartDownloadSize = orig }()
	capN := int(maxChartDownloadSize)

	t.Run("oversized response errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(strings.Repeat("A", capN+10)))
		}))
		defer srv.Close()

		_, err := httpGetBytes(srv.URL, "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maximum allowed size")
	})

	t.Run("body within the cap is returned intact", func(t *testing.T) {
		body := strings.Repeat("B", capN)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(body))
		}))
		defer srv.Close()

		data, err := httpGetBytes(srv.URL, "", "")
		require.NoError(t, err)
		assert.Equal(t, body, string(data))
	})
}

// latestChartVersion must pick the highest SEMVER entry, not the first-listed
// one and not the lexically-largest one (1.10.0 > 1.3.0 in semver but "1.10.0"
// < "1.3.0" as strings). Non-semver entries are ignored for ranking, and a
// repository whose versions are all non-semver still resolves to the first.
func TestLatestChartVersion(t *testing.T) {
	t.Run("highest semver wins regardless of order", func(t *testing.T) {
		got := latestChartVersion([]repoChartVersion{
			{Version: "1.2.0"},
			{Version: "1.10.0"},
			{Version: "1.3.0"},
		})
		assert.Equal(t, "1.10.0", got.Version)
	})

	t.Run("prerelease ranks below its release", func(t *testing.T) {
		got := latestChartVersion([]repoChartVersion{
			{Version: "2.0.0-rc.1"},
			{Version: "2.0.0"},
		})
		assert.Equal(t, "2.0.0", got.Version)
	})

	t.Run("non-semver entries are skipped for ranking", func(t *testing.T) {
		got := latestChartVersion([]repoChartVersion{
			{Version: "not-a-version"},
			{Version: "0.1.0"},
		})
		assert.Equal(t, "0.1.0", got.Version)
	})

	t.Run("all non-semver falls back to the first entry", func(t *testing.T) {
		got := latestChartVersion([]repoChartVersion{
			{Version: "latest"},
			{Version: "stable"},
		})
		assert.Equal(t, "latest", got.Version)
	})

	t.Run("empty slice returns the zero value without panicking", func(t *testing.T) {
		assert.NotPanics(t, func() {
			got := latestChartVersion(nil)
			assert.Equal(t, repoChartVersion{}, got)
		})
	})
}

// resolveChartInRepo maps a chart name (+ optional version) from a repository's
// index.yaml to a concrete archive URL: it selects the highest semver when no
// version is given, matches exactly when one is, resolves repo-relative URLs
// against the repository base, and errors clearly for missing chart/version.
func TestResolveChartInRepo(t *testing.T) {
	const index = `apiVersion: v1
entries:
  mychart:
    - version: 1.2.0
      urls:
        - charts/mychart-1.2.0.tgz
    - version: 1.10.0
      urls:
        - https://cdn.example.com/mychart-1.10.0.tgz
    - version: 1.3.0
      urls:
        - charts/mychart-1.3.0.tgz
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.yaml" {
			w.Write([]byte(index))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	t.Run("no version selects the highest semver (absolute URL passthrough)", func(t *testing.T) {
		url, err := resolveChartInRepo(srv.URL, "mychart", "", "", "")
		require.NoError(t, err)
		assert.Equal(t, "https://cdn.example.com/mychart-1.10.0.tgz", url)
	})

	t.Run("explicit version resolves a repo-relative URL against the base", func(t *testing.T) {
		url, err := resolveChartInRepo(srv.URL, "mychart", "1.2.0", "", "")
		require.NoError(t, err)
		assert.Equal(t, srv.URL+"/charts/mychart-1.2.0.tgz", url)
	})

	t.Run("unknown chart errors", func(t *testing.T) {
		_, err := resolveChartInRepo(srv.URL, "ghost", "", "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in repository")
	})

	t.Run("unknown version errors", func(t *testing.T) {
		_, err := resolveChartInRepo(srv.URL, "mychart", "9.9.9", "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version")
	})
}
