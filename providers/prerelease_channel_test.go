// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStableRefusesPrereleaseProvider covers the client half of the guard.
//
// On 2026-09-14 the notion provider had only ever been published as
// 14.0.0-rc.1, its stable pointer was filled in from preview, and a stable
// client installed a release candidate. The registry did everything right --
// resolved the channel, read latest.json -- and the document was wrong. This
// makes the client refuse it anyway.
func TestStableRefusesPrereleaseProvider(t *testing.T) {
	serve := func(t *testing.T, versions map[string]string) *httptest.Server {
		t.Helper()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			out := ProviderVersions{}
			for name, v := range versions {
				out.Providers = append(out.Providers, ProviderVersion{Name: name, Version: v})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		}))
		t.Cleanup(ts.Close)
		return ts
	}

	t.Run("stable refuses a pre-release", func(t *testing.T) {
		ts := serve(t, map[string]string{"notion": "14.0.0-rc.1"})
		r := NewMondooProviderRegistry(WithBaseURL(ts.URL), WithChannel("stable"))

		_, err := r.GetLatestVersion(context.Background(), "notion")
		require.Error(t, err, "a stable client must not be handed a pre-release")
		assert.Contains(t, err.Error(), "14.0.0-rc.1")
		assert.Contains(t, err.Error(), "stable")
	})

	t.Run("preview accepts it", func(t *testing.T) {
		ts := serve(t, map[string]string{"notion": "14.0.0-rc.1"})
		r := NewMondooProviderRegistry(WithBaseURL(ts.URL), WithChannel("preview"))

		v, err := r.GetLatestVersion(context.Background(), "notion")
		require.NoError(t, err, "the pre-release belongs on this channel")
		assert.Equal(t, "14.0.0-rc.1", v)
	})

	// The over-refusal case: a guard that rejects every stable resolution is a
	// worse outage than the bug it prevents.
	t.Run("stable still accepts a stable version", func(t *testing.T) {
		ts := serve(t, map[string]string{"aws": "13.53.4"})
		r := NewMondooProviderRegistry(WithBaseURL(ts.URL), WithChannel("stable"))

		v, err := r.GetLatestVersion(context.Background(), "aws")
		require.NoError(t, err)
		assert.Equal(t, "13.53.4", v)
	})

	// Build metadata is not a pre-release (SemVer 10). The edge tree's ordinary
	// release form carries it, so rejecting it would break those installs.
	t.Run("build metadata is not a pre-release", func(t *testing.T) {
		ts := serve(t, map[string]string{"mondoo": "6.7.0+41"})
		r := NewMondooProviderRegistry(WithBaseURL(ts.URL), WithChannel("stable"))

		v, err := r.GetLatestVersion(context.Background(), "mondoo")
		require.NoError(t, err)
		assert.Equal(t, "6.7.0+41", v)
	})
}
