// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
// object, on another host. The token follows to a data center on the API's
// domain and never to another domain. Every host name resolves to one test
// server, which records the Authorization header each host received.
func TestRedirectAuthorization(t *testing.T) {
	gotAuth := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if host == "api.example.com" {
			http.Redirect(w, r, "http://"+r.URL.Query().Get("to")+"/api/teams", http.StatusTemporaryRedirect)
			return
		}
		gotAuth[host] = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	client := newHTTPClient(&url.URL{Scheme: "http", Host: "api.example.com", Path: "/api"})
	client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
	for _, to := range []string{"dc1.example.com", "evil.example.org", "1-3000.dc1.example.com"} {
		req, err := http.NewRequest(http.MethodGet, "http://api.example.com/api/teams?to="+to, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer test-token")
		res, err := client.Do(req)
		require.NoError(t, err)
		res.Body.Close()
	}
	// The default client would drop the token here, since the hosts differ.
	assert.Equal(t, "Bearer test-token", gotAuth["dc1.example.com"])
	assert.Empty(t, gotAuth["evil.example.org"])
	assert.Empty(t, gotAuth["1-3000.dc1.example.com"], "a workspace host under the domain")
}

// Synthetic: which redirect targets may receive the API token.
func TestTrustedRedirect(t *testing.T) {
	u := func(s string) *url.URL {
		v, err := url.Parse(s)
		require.NoError(t, err)
		return v
	}
	api := u("https://cloud.codesphere.com/api")
	assert.True(t, trustedRedirect(api, u("https://cloud.codesphere.com/api/teams")))
	assert.True(t, trustedRedirect(api, u("https://2.codesphere.com/api/teams")), "data center beside the API host")
	assert.False(t, trustedRedirect(api, u("http://2.codesphere.com/api/teams")), "no downgrade to http")
	assert.False(t, trustedRedirect(api, u("https://2.codesphere.com/login")), "outside the API base path")
	assert.False(t, trustedRedirect(api, u("https://2.codesphere.com/apiary")), "a prefix of the base path is not under it")
	assert.False(t, trustedRedirect(api, u("https://71-3000.2.codesphere.com/api/teams")), "workspace host below a data center")
	assert.False(t, trustedRedirect(api, u("https://codesphere.com/api/teams")), "parent domain is not a sibling")
	assert.False(t, trustedRedirect(api, u("https://codesphere.com.evil.example/api")), "look-alike domain")
	assert.False(t, trustedRedirect(api, u("https://evil.example/api")))
	assert.False(t, trustedRedirect(u("https://codesphere.com/api"), u("https://other.com/api")), "siblings under a public suffix")
	assert.False(t, trustedRedirect(u("https://cs.github.io/api"), u("https://other.github.io/api")), "siblings under a public suffix")
	assert.False(t, trustedRedirect(u("http://127.0.0.1:8080/api"), u("http://127.0.0.2:8080/api")), "IP addresses only match themselves")
	assert.True(t, trustedRedirect(u("http://127.0.0.1:8080/api"), u("http://127.0.0.1:9090/api/teams")))
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
