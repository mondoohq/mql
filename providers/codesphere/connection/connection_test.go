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
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// Synthetic: URL validation and normalization; no live Codesphere account was
// available.
func TestParseAPIURL(t *testing.T) {
	t.Setenv("CS_API", "")

	u, err := ParseAPIURL("")
	require.NoError(t, err)
	assert.Equal(t, DefaultAPIURL, u.String())

	u, err = ParseAPIURL("https://codesphere.example.com/api/")
	require.NoError(t, err)
	assert.Equal(t, "https://codesphere.example.com/api", u.String(), "trailing slash dropped")

	for _, bad := range []string{"codesphere.example.com/api", "ftp://codesphere.example.com", "https://", "://x"} {
		_, err := ParseAPIURL(bad)
		assert.Error(t, err, bad)
	}
}

func testConnection(t *testing.T, apiURL string) *CodesphereConnection {
	t.Helper()
	conf := &inventory.Config{
		Options:     map[string]string{OptionAPIURL: apiURL},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", "test-token")},
	}
	conn, err := NewCodesphereConnection(1, &inventory.Asset{}, conf)
	require.NoError(t, err)
	return conn
}

// Synthetic: the API redirects a call to the data center that serves the
// object, on another host; the token must survive the redirect.
func TestRedirectKeepsAuthorization(t *testing.T) {
	var gotAuth string
	dc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer dc.Close()
	// Same server, different host name, so the default client would drop the
	// header.
	dcURL := strings.Replace(dc.URL, "127.0.0.1", "localhost", 1)

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dcURL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer front.Close()

	conn := testConnection(t, front.URL)
	list, _, err := conn.API().TeamsAPI.TeamsListTeams(conn.Context()).Execute()
	require.NoError(t, err)
	assert.Empty(t, list)
	assert.Equal(t, "Bearer test-token", gotAuth)
}

func TestNewConnectionRequiresToken(t *testing.T) {
	t.Setenv("CS_TOKEN", "")
	_, err := NewCodesphereConnection(1, &inventory.Asset{}, &inventory.Config{Options: map[string]string{}})
	assert.ErrorContains(t, err, "token is required")
}

// Synthetic: CS_API is the fallback when no URL is given.
func TestParseAPIURLFromEnv(t *testing.T) {
	t.Setenv("CS_API", "https://private.example.com/api")
	u, err := ParseAPIURL("")
	require.NoError(t, err)
	assert.Equal(t, "private.example.com", u.Host)
}
