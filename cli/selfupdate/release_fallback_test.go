// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const manifest = `{"name":"mql","version":"13.39.0","files":[{"filename":"mql_13.39.0_linux_amd64.tar.gz","url":"https://example.invalid/mql.tar.gz","platform":"linux_amd64"}]}`

// layoutServer serves the manifest at one path and 404s everything else, which
// is how both real hosts behave for the layout they do not publish.
func layoutServer(t *testing.T, servePath string, notFoundBody string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == servePath {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(manifest))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(notFoundBody))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A host publishing the install-service layout answers on the first try.
func TestFallbackFindsTheServiceLayout(t *testing.T) {
	srv := layoutServer(t, "/package/mql/latest.json", "<html>not found</html>")

	release, err := getLatestReleaseFrom(context.Background(), ReleaseURLs(srv.URL, "mql", ""))
	require.NoError(t, err)
	assert.Equal(t, "13.39.0", release.Version)
}

// A bucket mirror publishes the other layout. This is the case the fallback
// exists for: updates_url naming a mirror that was never install-service shaped.
func TestFallbackFindsTheBucketLayout(t *testing.T) {
	srv := layoutServer(t, "/mql/latest.json", "<?xml version='1.0'?><Error/>")

	release, err := getLatestReleaseFrom(context.Background(), ReleaseURLs(srv.URL, "mql", ""))
	require.NoError(t, err)
	assert.Equal(t, "13.39.0", release.Version)
}

// A host serving neither must fail, and must report the error for the layout
// that was asked for first rather than the one tried last -- the second URL is
// one the operator never configured.
func TestFallbackReportsTheFirstError(t *testing.T) {
	srv := layoutServer(t, "/nothing/here.json", "nope")

	_, err := getLatestReleaseFrom(context.Background(), ReleaseURLs(srv.URL, "mql", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/package/mql/latest.json")
	assert.NotContains(t, err.Error(), "/mql/latest.json\"")
}

// A catch-all that answers every path with a 200 page must not be mistaken for
// a manifest. Unmarshalling into Release succeeds for any JSON object, so
// without the version check this would read as "no newer release" -- a silent
// no-op that never updates and never reports why.
func TestFallbackRejectsANonManifest200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"welcome"}`))
	}))
	t.Cleanup(srv.Close)

	_, err := getLatestReleaseFrom(context.Background(), ReleaseURLs(srv.URL, "mql", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no version")
}

// The fallback must not fire when the caller asked for exactly one URL.
func TestSingleURLIsNotRetriedElsewhere(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	cfg := Config{ReleaseURL: srv.URL + "/package/mql/latest.json"}
	_, err := getLatestReleaseFrom(context.Background(), cfg.releaseURLs())
	require.Error(t, err)
	assert.Equal(t, 1, hits, "one configured URL is one request")
}
