// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeInstanceURL(t *testing.T) {
	// Synthetic: forms a user may type or paste.
	tests := map[string]string{
		"http://localhost:5678":               "http://localhost:5678",
		"http://localhost:5678/":              "http://localhost:5678",
		"n8n.example.com":                     "https://n8n.example.com",
		"https://n8n.example.com/api/v1":      "https://n8n.example.com",
		"https://n8n.example.com/api/v1/":     "https://n8n.example.com",
		"https://example.com/n8n/":            "https://example.com/n8n",
		"https://example.com/n8n/api/v1?x=1":  "https://example.com/n8n",
		"  https://n8n.example.com  ":         "https://n8n.example.com",
		"https://n8n.example.com/#/workflows": "https://n8n.example.com",
	}
	for in, want := range tests {
		got, err := normalizeInstanceURL(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	// Synthetic: no scheme n8n serves, no host, and credentials in the URL,
	// which would surface in the url field and the asset id.
	for _, bad := range []string{"", "ftp://n8n.example.com", "https://", "https://admin:secret@n8n.example.com", "https://admin@n8n.example.com"} {
		_, err := normalizeInstanceURL(bad)
		assert.Error(t, err, bad)
	}
}

func TestRedirectsKeepTheAPIKeyOnTheInstance(t *testing.T) {
	// Synthetic: an instance answering with a redirect to another host must
	// not receive the API key there; a redirect within the instance is fine.
	var leaked []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = append(leaked, r.Header.Get(apiKeyHeader))
		_, _ = w.Write([]byte(`{"data":[],"nextCursor":null}`))
	}))
	defer other.Close()

	instance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/tags":
			http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
		case "/api/v1/users":
			http.Redirect(w, r, "/api/v1/users-moved", http.StatusFound)
		case "/api/v1/users-moved":
			assert.Equal(t, "secret-key", r.Header.Get(apiKeyHeader))
			_, _ = w.Write([]byte(`{"data":[],"nextCursor":null}`))
		}
	}))
	defer instance.Close()

	c := &Client{baseURL: instance.URL, apiKey: "secret-key", http: &http.Client{CheckRedirect: sameOriginRedirects}}

	_, err := c.Tags(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirected")
	assert.Empty(t, leaked)

	_, err = c.Users(context.Background())
	assert.NoError(t, err)
}

func TestInstanceHost(t *testing.T) {
	// Synthetic: the host keys the asset, so a path-prefixed instance keeps its path.
	assert.Equal(t, "localhost:5678", InstanceHost("http://localhost:5678"))
	assert.Equal(t, "n8n.example.com", InstanceHost("https://n8n.example.com"))
	assert.Equal(t, "example.com/n8n", InstanceHost("https://example.com/n8n"))
}
