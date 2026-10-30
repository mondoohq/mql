// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// newTestAsset builds a minimal asset wired to conf, matching the shape expected
// by plugin.NewConnection (which reads asset.Connections[0]).
func newTestAsset(conf *inventory.Config) *inventory.Asset {
	asset := &inventory.Asset{}
	asset.Connections = []*inventory.Config{conf}
	return asset
}

func TestNewGrafanaConnection_Success(t *testing.T) {
	conf := &inventory.Config{
		Type:    "grafana",
		Options: map[string]string{"url": "https://grafana.example.com"},
		Credentials: []*vault.Credential{
			vault.NewPasswordCredential("", "test-token"),
		},
	}
	asset := newTestAsset(conf)

	conn, err := NewGrafanaConnection(1, asset, conf)
	require.NoError(t, err)
	require.NotNil(t, conn)

	assert.Equal(t, "https://grafana.example.com", conn.BaseURL())
	assert.Equal(t, "", conn.OrgID())
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/grafana/org", conn.Identifier())

	platform, err := conn.PlatformInfo()
	require.NoError(t, err)
	assert.Equal(t, "grafana-org", platform.Name)
	assert.Equal(t, "api", platform.Kind)
}

func TestNewGrafanaConnection_MissingToken(t *testing.T) {
	// Clear any ambient env token so the test is deterministic.
	t.Setenv("GRAFANA_TOKEN", "")

	conf := &inventory.Config{
		Type:    "grafana",
		Options: map[string]string{"url": "https://grafana.example.com"},
	}
	asset := newTestAsset(conf)

	_, err := NewGrafanaConnection(1, asset, conf)
	require.Error(t, err)
	assert.True(t, strings.Contains(strings.ToLower(err.Error()), "token"),
		"error should mention token, got: %s", err.Error())
}

func TestNewGrafanaConnection_MissingURL(t *testing.T) {
	t.Setenv("GRAFANA_URL", "")

	conf := &inventory.Config{
		Type: "grafana",
		Credentials: []*vault.Credential{
			vault.NewPasswordCredential("", "test-token"),
		},
	}
	asset := newTestAsset(conf)

	_, err := NewGrafanaConnection(1, asset, conf)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "URL"),
		"error should mention URL, got: %s", err.Error())
}

func TestNewGrafanaConnection_EnvFallback(t *testing.T) {
	t.Setenv("GRAFANA_TOKEN", "env-token")
	t.Setenv("GRAFANA_URL", "https://env.grafana.example.com")

	conf := &inventory.Config{
		Type: "grafana",
	}
	asset := newTestAsset(conf)

	conn, err := NewGrafanaConnection(1, asset, conf)
	require.NoError(t, err)
	assert.Equal(t, "https://env.grafana.example.com", conn.BaseURL())
}

func TestNewGrafanaConnection_URLTrailingSlash(t *testing.T) {
	conf := &inventory.Config{
		Type:    "grafana",
		Options: map[string]string{"url": "https://grafana.example.com/"},
		Credentials: []*vault.Credential{
			vault.NewPasswordCredential("", "test-token"),
		},
	}
	asset := newTestAsset(conf)

	conn, err := NewGrafanaConnection(1, asset, conf)
	require.NoError(t, err)
	assert.Equal(t, "https://grafana.example.com", conn.BaseURL(),
		"BaseURL must strip trailing slash")
}

func TestGrafanaConnection_Get(t *testing.T) {
	var capturedAuth, capturedAccept string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1,"name":"Main Org."}`))
	}))
	t.Cleanup(srv.Close)

	conf := &inventory.Config{
		Type:    "grafana",
		Options: map[string]string{"url": srv.URL},
		Credentials: []*vault.Credential{
			vault.NewPasswordCredential("", "testtoken"),
		},
	}
	asset := newTestAsset(conf)

	conn, err := NewGrafanaConnection(1, asset, conf)
	require.NoError(t, err)

	resp, err := conn.Get(context.Background(), "/api/org")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "Bearer testtoken", capturedAuth)
	assert.Equal(t, "application/json", capturedAccept)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotEmpty(t, body)
}

func TestGrafanaConnection_Identifier(t *testing.T) {
	t.Run("without org-id", func(t *testing.T) {
		conf := &inventory.Config{
			Type:    "grafana",
			Options: map[string]string{"url": "https://grafana.example.com"},
			Credentials: []*vault.Credential{
				vault.NewPasswordCredential("", "test-token"),
			},
		}
		conn, err := NewGrafanaConnection(1, newTestAsset(conf), conf)
		require.NoError(t, err)

		id := conn.Identifier()
		assert.Equal(t, "//platformid.api.mondoo.app/runtime/grafana/org", id)
		assert.True(t, strings.HasSuffix(id, "/org"),
			"without org-id, identifier should end at /org")
	})

	t.Run("with org-id", func(t *testing.T) {
		conf := &inventory.Config{
			Type:    "grafana",
			Options: map[string]string{"url": "https://grafana.example.com", "org-id": "42"},
			Credentials: []*vault.Credential{
				vault.NewPasswordCredential("", "test-token"),
			},
		}
		conn, err := NewGrafanaConnection(1, newTestAsset(conf), conf)
		require.NoError(t, err)

		id := conn.Identifier()
		assert.True(t, strings.Contains(id, "org-id") || strings.HasSuffix(id, "/42"),
			"identifier should include the org-id value, got: %s", id)
		assert.Equal(t, "//platformid.api.mondoo.app/runtime/grafana/org/42", id)
	})
}
