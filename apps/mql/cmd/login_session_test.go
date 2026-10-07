// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"

	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/cli/oauthlogin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
)

// sessionConfig returns a config holding an interactive login session whose
// certificate expires at notAfter.
func sessionConfig(t *testing.T, notAfter time.Time) *config.Config {
	t.Helper()
	key, err := oauthlogin.GenerateKey()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "session"},
		NotBefore:    notAfter.Add(-2 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyPEM, err := oauthlogin.EncodePrivateKeyPEM(key)
	require.NoError(t, err)

	return &config.Config{CommonOpts: config.CommonOpts{
		ServiceAccountMrn: "//agents.api.mondoo.app/spaces/s1/serviceaccounts/session1",
		SpaceMrn:          "//captain.api.mondoo.app/spaces/s1",
		ScopeMrn:          "//captain.api.mondoo.app/spaces/s1",
		PrivateKey:        keyPEM,
		Certificate:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		APIEndpoint:       "http://localhost:8989",
		Authentication: &config.CliConfigAuthentication{
			Method:      config.AUTH_METHOD_OAUTH,
			Issuer:      "http://127.0.0.1:8989",
			AccessToken: "old-session",
			UserEmail:   "jane@example.com",
			SpaceName:   "prod",
			OrgName:     "acme",
		},
	}}
}

// fakePing records calls and answers with err.
type fakePing struct {
	calls     int
	endpoints []string
	err       error
}

func (f *fakePing) ping(_ context.Context, apiEndpoint string, _ *http.Client, cred *upstream.ServiceAccountCredentials) error {
	f.calls++
	f.endpoints = append(f.endpoints, apiEndpoint)
	if cred == nil {
		return errors.New("no credential")
	}
	return f.err
}

func TestExistingSession_ValidAndAccepted(t *testing.T) {
	now := time.Now()
	opts := sessionConfig(t, now.Add(time.Hour))
	p := &fakePing{}

	keep, err := existingSession(context.Background(), opts, "", false, now, nil, p.ping)
	require.NoError(t, err)
	assert.True(t, keep, "a valid session the server accepts is kept")
	assert.Equal(t, 1, p.calls)
	assert.Equal(t, []string{"http://localhost:8989"}, p.endpoints, "verified against the session's own server")

	// the same server named another way is still the same session
	keep, err = existingSession(context.Background(), opts, "http://127.0.0.1:8989/", false, now, nil, p.ping)
	require.NoError(t, err)
	assert.True(t, keep)

	msg := alreadyLoggedInMessage(opts, "cnspec", now)
	lines := strings.Split(msg, "\n")
	require.Len(t, lines, 2, msg)
	assert.True(t, strings.HasPrefix(lines[0], "✓ Already logged in as jane@example.com · space acme/prod · valid until "), lines[0])
	assert.True(t, strings.HasSuffix(lines[0], "(1h)"), lines[0])
	assert.Equal(t, `Run "cnspec logout" first, or "cnspec login --force" to log in again.`, lines[1])
}

func TestAlreadyLoggedInMessage_FallsBackToMrns(t *testing.T) {
	now := time.Now()
	opts := sessionConfig(t, now.Add(time.Hour))
	opts.Authentication.UserEmail = ""
	opts.Authentication.SpaceName = ""
	opts.Authentication.OrgName = ""

	msg := alreadyLoggedInMessage(opts, "", now)
	assert.True(t, strings.HasPrefix(msg, "✓ Already logged in · space //captain.api.mondoo.app/spaces/s1 · valid until "), msg)
	assert.Contains(t, msg, `"mql login --force"`)
}

func TestExistingSession_NewLogin(t *testing.T) {
	now := time.Now()
	tests := map[string]struct {
		notAfter  time.Time
		override  string
		force     bool
		pingErr   error
		wantPings int
	}{
		"expired":                {notAfter: now.Add(-time.Minute)},
		"expires within 5 min":   {notAfter: now.Add(4 * time.Minute)},
		"ping unauthenticated":   {notAfter: now.Add(time.Hour), pingErr: status.Error(codes.Unauthenticated, "unknown service account"), wantPings: 1},
		"ping permission denied": {notAfter: now.Add(time.Hour), pingErr: status.Error(codes.PermissionDenied, "revoked"), wantPings: 1},
		"force":                  {notAfter: now.Add(time.Hour), force: true},
		"different endpoint":     {notAfter: now.Add(time.Hour), override: "https://us.api.mondoo.com"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &fakePing{err: tc.pingErr}
			opts := sessionConfig(t, tc.notAfter)
			if tc.override != "" {
				// --api-endpoint is bound to api_endpoint, so the loaded
				// config carries the flag's value
				opts.APIEndpoint = tc.override
			}
			keep, err := existingSession(context.Background(), opts, tc.override, tc.force, now, nil, p.ping)
			require.NoError(t, err)
			assert.False(t, keep, "a new login starts")
			assert.Equal(t, tc.wantPings, p.calls)
		})
	}
}

func TestExistingSession_ServerUnreachable(t *testing.T) {
	now := time.Now()
	netErr := &url.Error{Op: "Post", URL: "http://localhost:8989", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}
	p := &fakePing{err: netErr}

	keep, err := existingSession(context.Background(), sessionConfig(t, now.Add(time.Hour)), "", false, now, nil, p.ping)
	require.Error(t, err, "no login flow against a server that cannot be reached")
	assert.False(t, keep)
	assert.ErrorIs(t, err, netErr)
	assert.Contains(t, err.Error(), "http://localhost:8989")
}

func TestExistingSession_NotASession(t *testing.T) {
	p := &fakePing{}
	keep, err := existingSession(context.Background(), &config.Config{}, "", false, time.Now(), nil, p.ping)
	require.NoError(t, err)
	assert.False(t, keep)
	assert.Zero(t, p.calls)
}

func TestForceRevokesReplacedSession(t *testing.T) {
	now := time.Now()
	opts := sessionConfig(t, now.Add(time.Hour))
	p := &fakePing{}

	keep, err := existingSession(context.Background(), opts, "", true, now, nil, p.ping)
	require.NoError(t, err)
	require.False(t, keep, "--force starts a new login")

	old := sessionToReplace(opts, now)
	require.NotNil(t, old)

	type revokeCall struct{ issuer, token, key string }
	var calls []revokeCall
	revoke := func(_ context.Context, _ *http.Client, issuer, token, key string) error {
		calls = append(calls, revokeCall{issuer, token, key})
		return nil
	}
	revokeReplaced(context.Background(), old, "new-session", nil, revoke)
	require.Len(t, calls, 1)
	assert.Equal(t, revokeCall{"http://127.0.0.1:8989", "old-session", opts.PrivateKey}, calls[0])

	// a failed revocation does not fail the login
	revokeReplaced(context.Background(), old, "new-session", nil, func(context.Context, *http.Client, string, string, string) error {
		return errors.New("unreachable")
	})
}

func TestSessionToReplace(t *testing.T) {
	now := time.Now()
	assert.Nil(t, sessionToReplace(sessionConfig(t, now.Add(-time.Minute)), now), "an expired session needs no revocation")
	assert.Nil(t, sessionToReplace(&config.Config{}, now))

	noToken := sessionConfig(t, now.Add(time.Hour))
	noToken.Authentication.AccessToken = ""
	assert.Nil(t, sessionToReplace(noToken, now))
}

func TestSameServer(t *testing.T) {
	assert.True(t, sameServer("http://127.0.0.1:8989", "http://localhost:8989"))
	assert.True(t, sameServer("https://us.api.mondoo.com/", "https://us.api.mondoo.com:443"))
	assert.True(t, sameServer("https://us.api.mondoo.com", "", "https://US.api.mondoo.com"))
	assert.False(t, sameServer("https://eu.api.mondoo.com", "https://us.api.mondoo.com"))
	assert.False(t, sameServer("http://127.0.0.1:8990", "http://localhost:8989"))
	assert.False(t, sameServer("https://us.api.mondoo.com"))
}

// Revoking a session needs https, or http to a loopback server, unless
// --insecure is set.
func TestRevokeSession_Transport(t *testing.T) {
	opts := sessionConfig(t, time.Now().Add(time.Hour))
	ctx := context.Background()

	err := revokeSession(false)(ctx, http.DefaultClient, "http://mondoo.invalid", "old-session", opts.PrivateKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unencrypted http")

	err = revokeSession(true)(ctx, http.DefaultClient, "http://mondoo.invalid", "old-session", opts.PrivateKey)
	require.Error(t, err, "nothing answers at mondoo.invalid")
	assert.NotContains(t, err.Error(), "unencrypted http", "--insecure allows http")

	// A loopback server needs no --insecure; the metadata lists its http
	// revocation endpoint.
	var revoked bool
	mux := http.NewServeMux()
	srv := httptestServer(t, mux)
	mux.HandleFunc(oauthlogin.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + srv + `","token_endpoint":"` + srv + `/oauth/token","revocation_endpoint":"` + srv + `/oauth/revoke"}`))
	})
	mux.HandleFunc("/oauth/revoke", func(w http.ResponseWriter, r *http.Request) { revoked = true })
	require.NoError(t, revokeSession(false)(ctx, http.DefaultClient, srv, "old-session", opts.PrivateKey))
	assert.True(t, revoked)

	// A remote server must not list an http revocation endpoint.
	revoked = false
	mux2 := http.NewServeMux()
	srv2 := httptestServer(t, mux2)
	mux2.HandleFunc(oauthlogin.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + srv2 + `","token_endpoint":"` + srv2 + `/oauth/token","revocation_endpoint":"http://revoke.example.com/oauth/revoke"}`))
	})
	err = revokeSession(false)(ctx, http.DefaultClient, srv2, "old-session", opts.PrivateKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unencrypted http")
}

// A registration token login over an interactive login session revokes the
// session once the registered client is saved.
func TestRegistrationRevokesReplacedSession(t *testing.T) {
	now := time.Now()
	opts := sessionConfig(t, now.Add(time.Hour))
	old := sessionToReplace(opts, now)
	require.NotNil(t, old)

	var tokens []string
	revokeReplaced(context.Background(), old, "", nil, func(_ context.Context, _ *http.Client, _, token, _ string) error {
		tokens = append(tokens, token)
		return nil
	})
	assert.Equal(t, []string{"old-session"}, tokens)
}

func httptestServer(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}
