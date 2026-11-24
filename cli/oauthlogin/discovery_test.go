// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// tokenWith is a token response with the given extra fields.
func tokenWith(extra map[string]any, accessToken string) *oauth2.Token {
	return (&oauth2.Token{AccessToken: accessToken}).WithExtra(extra)
}

// newFakeAPI is an API endpoint that is not a login server: it serves only
// the protected resource metadata, through pointer.
func newFakeAPI(t *testing.T, pointer func(apiURL string) (int, any)) *httptest.Server {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc(ProtectedResourcePath, func(w http.ResponseWriter, r *http.Request) {
		status, body := pointer(srv.URL)
		writeJSON(w, status, body)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func pointerTo(loginServers ...string) func(string) (int, any) {
	return func(apiURL string) (int, any) {
		return http.StatusOK, map[string]any{"resource": apiURL, "authorization_servers": loginServers}
	}
}

// An API endpoint that publishes no pointer is its own login server. A server
// that guards every unknown path answers the anonymous request with 401 or
// 403, not with 404, and that means the same.
func TestDiscover_NoPointerMeansTheEndpointIsTheLoginServer(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden} {
		f := newFakeAS(t)
		f.pointer = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }
		md, err := Discover(context.Background(), f.srv.Client(), f.issuer(), false)
		require.NoError(t, err, status)
		assert.Equal(t, f.issuer(), md.Issuer, status)
	}
}

// The API endpoint names a login server on another host. The metadata is
// read there, and its issuer must be that host, not the API endpoint.
func TestDiscover_FollowsThePointer(t *testing.T) {
	login := newFakeAS(t)
	api := newFakeAPI(t, pointerTo(login.issuer()))

	md, err := Discover(context.Background(), login.srv.Client(), api.URL, false)
	require.NoError(t, err)
	assert.Equal(t, login.issuer(), md.Issuer)
	assert.Equal(t, login.issuer()+"/oauth/token", md.TokenEndpoint)

	// the named server says it is somebody else
	login.metadataIssuer = api.URL
	_, err = Discover(context.Background(), login.srv.Client(), api.URL, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestDiscover_RefusesABadPointer(t *testing.T) {
	login := newFakeAS(t)
	for name, pointer := range map[string]func(string) (int, any){
		"about another resource": func(string) (int, any) {
			return http.StatusOK, map[string]any{"resource": "https://other.example.com", "authorization_servers": []string{login.issuer()}}
		},
		"no login server":     pointerTo(),
		"two login servers":   pointerTo(login.issuer(), "https://second.example.com"),
		"not a URL":           pointerTo("not a url"),
		"plain http, remote":  pointerTo("http://login.example.com"),
		"a server error":      func(string) (int, any) { return http.StatusInternalServerError, map[string]any{} },
		"not the JSON we ask": func(string) (int, any) { return http.StatusOK, []string{"x"} },
	} {
		api := newFakeAPI(t, pointer)
		_, err := Discover(context.Background(), login.srv.Client(), api.URL, false)
		assert.Error(t, err, name)
	}
}

// A whole login where the login server is another host than the API. The
// login requests go to the login server. What is stored keeps the two apart:
// api_endpoint is the API, the issuer is the login server.
func TestLogin_LoginServerOnAnotherHost(t *testing.T) {
	login := newFakeAS(t)
	login.noAPIEndpoint = true
	api := newFakeAPI(t, pointerTo(login.issuer()))

	opts := testOptions(login, ModeDevice)
	opts.Endpoint = api.URL
	res, err := Login(context.Background(), opts)
	require.NoError(t, err)

	assert.Equal(t, 1, login.tokenCalls, "the token request went to the login server")
	assert.Equal(t, login.issuer(), res.Issuer)
	assert.Equal(t, api.URL, res.Endpoint)

	cfg := res.ConfigValues()
	assert.Equal(t, api.URL, cfg["api_endpoint"], "scan calls go to the API, never to the login server")
	auth := cfg["auth"].(map[string]any)
	assert.Equal(t, login.issuer(), auth["issuer"], "revocation goes to the login server")
	assert.Equal(t, api.URL, auth["endpoint"])
}

// A login approved for an organization: there is no space, and the scope is
// the organization.
func TestLogin_ForAnOrganization(t *testing.T) {
	f := newFakeAS(t)
	f.orgLogin = true
	res, err := Login(context.Background(), testOptions(f, ModeDevice))
	require.NoError(t, err)

	assert.Equal(t, testOrgMrn, res.Credential.ScopeMrn)
	assert.Empty(t, res.Credential.SpaceMrn)
	assert.Equal(t, ScopeKindOrganization, res.Scope.Kind)

	cfg := res.ConfigValues()
	assert.Equal(t, testOrgMrn, cfg["scope_mrn"])
	assert.NotContains(t, cfg, "space_mrn")
	assert.Equal(t, ScopeKindOrganization, cfg["auth"].(map[string]any)["scope_kind"])
}

// A token response without a token, or that does not say what the login is
// for, is not a login.
func TestLogin_RefusesAnIncompleteTokenResponse(t *testing.T) {
	_, err := parseToken(tokenWith(map[string]any{"iss": "https://a.example.com", "mondoo_service_account": map[string]any{"mrn": testUserMrn}}, ""), "https://a.example.com", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "login token")

	_, err = parseToken(tokenWith(map[string]any{"iss": "https://a.example.com", "mondoo_service_account": map[string]any{"mrn": testUserMrn, "token": "t"}}, ""), "https://a.example.com", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "what the login is for")

	// the access_token stands in for a missing token field
	res, err := parseToken(tokenWith(map[string]any{"iss": "https://a.example.com", "mondoo_service_account": map[string]any{"mrn": testUserMrn, "scope_mrn": testSpaceMrn}}, "from-access-token"), "https://a.example.com", false)
	require.NoError(t, err)
	assert.Equal(t, "from-access-token", res.Credential.Token)
}
