// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func noEnv(string) string { return "" }

func testOptions(f *fakeAS, mode Mode) Options {
	return Options{
		Endpoint:        f.issuer(),
		Mode:            mode,
		ScopeMrn:        testSpaceMrn,
		DeviceName:      "build-host",
		DeviceInfo:      "cnspec 13.0.0 linux/amd64",
		HTTPClient:      f.srv.Client(),
		Out:             &bytes.Buffer{},
		In:              strings.NewReader(""),
		Getenv:          noEnv,
		GOOS:            "linux",
		LoopbackTimeout: 10 * time.Second,
		OpenBrowser:     func(string) error { return errors.New("no browser in tests") },
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"https://US.api.mondoo.com/":  "https://us.api.mondoo.com",
		"  http://127.0.0.1:8989 ":    "http://127.0.0.1:8989",
		"https://example.com/sts///":  "https://example.com/sts",
		"HTTPS://example.com:443/sts": "https://example.com:443/sts",
	} {
		got, err := NormalizeEndpoint(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, bad := range []string{"", "ftp://example.com", "https://", "https://example.com/?a=b", "https://u:p@example.com"} {
		_, err := NormalizeEndpoint(bad)
		assert.Error(t, err, bad)
	}
}

func TestCheckTransport(t *testing.T) {
	assert.NoError(t, checkTransport("https://example.com", false, false))
	assert.NoError(t, checkTransport("http://127.0.0.1:8989", false, false))
	assert.NoError(t, checkTransport("http://[::1]:8989", false, false))
	assert.NoError(t, checkTransport("http://localhost:8989", false, false))
	err := checkTransport("http://example.com", false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--insecure")
	assert.NoError(t, checkTransport("http://example.com", true, false))
}

func TestDiscover_RefusesHTTPToRemoteHost(t *testing.T) {
	called := false
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("must not be called")
	})}
	_, err := Discover(context.Background(), client, "http://sts.example.com", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unencrypted")
	assert.False(t, called, "no request may be sent over plain http to a remote host")
}

func TestDiscover_IssuerMismatch(t *testing.T) {
	f := newFakeAS(t)
	f.metadataIssuer = "https://evil.example.com"
	_, err := Discover(context.Background(), f.srv.Client(), f.issuer(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestDiscover_RemoteHTTPEndpointInMetadata(t *testing.T) {
	f := newFakeAS(t)
	f.tokenEndpoint = "http://sts.example.com/oauth/token"
	_, err := Discover(context.Background(), f.srv.Client(), f.issuer(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unencrypted")
}

func TestDiscover_NotEnabled(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	_, err := Discover(context.Background(), srv.Client(), srv.URL, false)
	assert.ErrorIs(t, err, ErrBrowserLoginDisabled)
}

func TestDiscover_TrailingSlashEndpoint(t *testing.T) {
	f := newFakeAS(t)
	md, err := Discover(context.Background(), f.srv.Client(), f.issuer()+"/", false)
	require.NoError(t, err)
	assert.Equal(t, f.issuer(), md.Issuer)
	assert.True(t, md.AuthorizationResponseIssParameterSupported)
}

func TestDetectMode(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	assert.Equal(t, ModeBrowser, DetectMode(noEnv, "darwin"))
	assert.Equal(t, ModeBrowser, DetectMode(noEnv, "windows"))
	assert.Equal(t, ModeDevice, DetectMode(noEnv, "linux"))
	assert.Equal(t, ModeBrowser, DetectMode(env(map[string]string{"DISPLAY": ":0"}), "linux"))
	assert.Equal(t, ModeBrowser, DetectMode(env(map[string]string{"WAYLAND_DISPLAY": "wayland-0"}), "linux"))
	assert.Equal(t, ModeDevice, DetectMode(env(map[string]string{"SSH_CONNECTION": "1 2 3 4"}), "darwin"))
	assert.Equal(t, ModeDevice, DetectMode(env(map[string]string{"SSH_TTY": "/dev/pts/0", "DISPLAY": ":0"}), "linux"))
}

func TestDeviceFlow(t *testing.T) {
	f := newFakeAS(t)
	f.devicePollReplies = []string{"authorization_pending", "slow_down"}
	opts := testOptions(f, ModeDevice)
	out := opts.Out.(*bytes.Buffer)

	res, err := Login(context.Background(), opts)
	require.NoError(t, err)

	assert.Contains(t, out.String(), "! First copy your one-time code: WDJB-MJHT")
	assert.Contains(t, out.String(), "https://console.example.com/activate")
	assert.NotContains(t, out.String(), "press Enter", "no prompt when not interactive")
	assert.Contains(t, out.String(), "Open https://console.example.com/activate in a browser and enter the code.\nWaiting for authorization...\n")
	assert.NotContains(t, out.String(), "\r", "no spinner when not interactive")

	// request parameters
	assert.Equal(t, ClientID, f.authForm.Get("client_id"))
	assert.Equal(t, Scope, f.authForm.Get("scope"))
	assert.Equal(t, testSpaceMrn, f.authForm.Get("mondoo_scope_mrn"))
	assert.Equal(t, "build-host", f.authForm.Get("mondoo_device_name"))
	assert.Equal(t, "cnspec 13.0.0 linux/amd64", f.authForm.Get("mondoo_device_info"))

	// polling: pending, slow_down, success; slow_down adds 5s to the interval
	require.Len(t, f.pollTimes, 3)
	assert.GreaterOrEqual(t, f.pollTimes[2].Sub(f.pollTimes[1]), 5*time.Second)
	// plain RFC 8628: the device code is the only proof, and no key is sent
	for _, form := range append([]url.Values{f.authForm}, f.tokenForms...) {
		assert.Empty(t, form.Get("mondoo_public_key"))
		assert.Empty(t, form.Get("mondoo_key_proof"))
	}

	assertResult(t, f, res)
}

func TestDeviceFlow_Denied(t *testing.T) {
	f := newFakeAS(t)
	f.devicePollReplies = []string{"access_denied"}
	_, err := Login(context.Background(), testOptions(f, ModeDevice))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied")
}

func TestLoopbackFlow(t *testing.T) {
	f := newFakeAS(t)
	opts := testOptions(f, ModeBrowser)
	var opened string
	opts.OpenBrowser = func(u string) error {
		opened = u
		return f.authorize(u, nil)
	}

	res, err := Login(context.Background(), opts)
	require.NoError(t, err)

	u, err := url.Parse(opened)
	require.NoError(t, err)
	assert.Equal(t, f.issuer()+"/oauth/authorize", u.Scheme+"://"+u.Host+u.Path)
	assert.True(t, strings.HasPrefix(f.redirectURI, "http://127.0.0.1:"), f.redirectURI)
	assert.True(t, strings.HasSuffix(f.redirectURI, "/callback"), f.redirectURI)
	assert.Equal(t, testSpaceMrn, f.authForm.Get("mondoo_scope_mrn"))
	assert.Equal(t, 1, f.tokenCalls)
	assert.NotEmpty(t, f.tokenForms[0].Get("code_verifier"))

	assertResult(t, f, res)
}

func TestLoopbackFlow_Output(t *testing.T) {
	f := newFakeAS(t)
	opts := testOptions(f, ModeBrowser)
	out := opts.Out.(*bytes.Buffer)
	opts.OpenBrowser = func(u string) error { return f.authorize(u, nil) }

	_, err := Login(context.Background(), opts)
	require.NoError(t, err)

	got := out.String()
	assert.Equal(t, "Opening your browser to log in…\nWaiting for authorization in the browser...\n", got)
	assert.NotContains(t, got, "/oauth/authorize", "the loopback URL only works on this machine")
	assert.NotContains(t, got, "127.0.0.1")
}

// Without a manual redirect URI in the metadata, a browser that cannot be
// opened switches the login to the device flow.
func TestLoopbackFlow_BrowserOpenFailsUsesDeviceFlow(t *testing.T) {
	f := newFakeAS(t)
	f.devicePollReplies = []string{"authorization_pending"}
	opts := testOptions(f, ModeBrowser)
	out := &syncBuffer{}
	opts.Out = out
	opts.Interactive = true
	opts.Getenv = func(k string) string {
		if k == "DISPLAY" {
			return ":0"
		}
		return ""
	}
	var redirectURI string
	opts.OpenBrowser = func(u string) error {
		parsed, err := url.Parse(u)
		if err != nil {
			return err
		}
		redirectURI = parsed.Query().Get("redirect_uri")
		return errors.New("no opener available")
	}

	res, err := Login(context.Background(), opts)
	require.NoError(t, err)
	assertResult(t, f, res)

	got := out.String()
	assert.Contains(t, got, "! First copy your one-time code: WDJB-MJHT")
	assert.Contains(t, got, "Open https://console.example.com/activate in a browser and enter the code.")
	assert.NotContains(t, got, "press Enter", "a browser could not be opened, so none is offered")
	assert.NotContains(t, got, "Opening your browser")
	assert.NotContains(t, got, "/oauth/authorize")
	assert.NotContains(t, got, "127.0.0.1")

	// The loopback listener is shut down.
	require.NotEmpty(t, redirectURI)
	resp, err := http.Get(redirectURI)
	if err == nil {
		resp.Body.Close()
	}
	assert.Error(t, err, "the loopback listener must be closed")
}

// A callback with another state, or a request to another path, gets an error
// response but does not end the login: it keeps waiting for the callback that
// belongs to it.
func TestLoopbackFlow_StateMismatchKeepsWaiting(t *testing.T) {
	f := newFakeAS(t)
	opts := testOptions(f, ModeBrowser)
	var otherState, otherPath int
	opts.OpenBrowser = func(u string) error {
		parsed, err := url.Parse(u)
		if err != nil {
			return err
		}
		redirectURI := parsed.Query().Get("redirect_uri")
		state := parsed.Query().Get("state")

		resp, err := http.Get(redirectURI + "?" + url.Values{"code": {"other-code"}, "state": {"other"}, "iss": {f.issuer()}}.Encode())
		if err != nil {
			return err
		}
		resp.Body.Close()
		otherState = resp.StatusCode

		base := strings.TrimSuffix(redirectURI, callbackPath)
		resp, err = http.Get(base + "/other?" + url.Values{"code": {"other-code"}, "state": {state}, "iss": {f.issuer()}}.Encode())
		if err != nil {
			return err
		}
		resp.Body.Close()
		otherPath = resp.StatusCode

		return f.authorize(u, nil)
	}
	res, err := Login(context.Background(), opts)
	require.NoError(t, err)
	assertResult(t, f, res)
	assert.Equal(t, http.StatusBadRequest, otherState)
	assert.Equal(t, http.StatusNotFound, otherPath)
	assert.Equal(t, 1, f.tokenCalls, "only the matching callback's code is redeemed")
}

// A callback with another state alone does not complete the login, which
// ends when it times out.
func TestLoopbackFlow_StateMismatchTimesOut(t *testing.T) {
	f := newFakeAS(t)
	opts := testOptions(f, ModeBrowser)
	opts.LoopbackTimeout = 500 * time.Millisecond
	opts.OpenBrowser = func(u string) error {
		return f.authorize(u, func(q url.Values) { q.Set("state", "other") })
	}
	_, err := Login(context.Background(), opts)
	require.ErrorIs(t, err, errLoopbackTimeout)
	assert.Equal(t, 0, f.tokenCalls)
}

func TestLoopbackFlow_IssuerMismatch(t *testing.T) {
	f := newFakeAS(t)
	opts := testOptions(f, ModeBrowser)
	opts.OpenBrowser = func(u string) error {
		return f.authorize(u, func(q url.Values) { q.Set("iss", "https://evil.example.com") })
	}
	_, err := Login(context.Background(), opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
	assert.Equal(t, 0, f.tokenCalls)
}

func TestLoopbackFlow_MissingIssuer(t *testing.T) {
	f := newFakeAS(t)
	opts := testOptions(f, ModeBrowser)
	opts.OpenBrowser = func(u string) error {
		return f.authorize(u, func(q url.Values) { q.Del("iss") })
	}
	_, err := Login(context.Background(), opts)
	require.Error(t, err)
	assert.Equal(t, 0, f.tokenCalls)
}

func TestLoopbackFlow_Denied(t *testing.T) {
	f := newFakeAS(t)
	opts := testOptions(f, ModeBrowser)
	opts.OpenBrowser = func(u string) error {
		return f.authorize(u, func(q url.Values) { q.Del("code"); q.Set("error", "access_denied") })
	}
	_, err := Login(context.Background(), opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied")
}

func TestLoopbackFlow_TokenIssuerMismatch(t *testing.T) {
	f := newFakeAS(t)
	f.tokenIssuer = "https://evil.example.com"
	opts := testOptions(f, ModeBrowser)
	opts.OpenBrowser = func(u string) error { return f.authorize(u, nil) }
	_, err := Login(context.Background(), opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestRevoke(t *testing.T) {
	f := newFakeAS(t)
	require.NoError(t, Revoke(context.Background(), f.srv.Client(), f.issuer(), "the-token", false))
	require.Len(t, f.revokeForms, 1)
	form := f.revokeForms[0]
	// RFC 7009 for a public client: the token and the client id, no proof.
	assert.Equal(t, "the-token", form.Get("token"))
	assert.Equal(t, ClientID, form.Get("client_id"))
	assert.Empty(t, form.Get("mondoo_key_proof"))
}

// Revocation starts from the issuer stored with the session. It reads the
// login server's metadata there and does not ask for a pointer: a login
// server that shares a host with an API answers that request with the API's
// document.
func TestRevoke_DoesNotFollowAPointer(t *testing.T) {
	f := newFakeAS(t)
	f.pointTo("https://elsewhere.example.com")
	require.NoError(t, Revoke(context.Background(), f.srv.Client(), f.issuer(), "the-token", false))
	require.Len(t, f.revokeForms, 1)
}

func TestSummary(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	r := &Result{
		User:       User{Email: "jane@example.com"},
		Scope:      LoginScope{Name: "prod", Kind: "space", OrgName: "acme"},
		ValidUntil: now.Add(time.Hour),
	}
	s := r.Summary(now)
	assert.True(t, strings.HasPrefix(s, "✓ Logged in as jane@example.com · space acme/prod · valid until "), s)
	assert.True(t, strings.HasSuffix(s, "(1h)"), s)

	// a login to an organization
	r.Scope = LoginScope{Name: "acme", Kind: ScopeKindOrganization, OrgName: "acme"}
	assert.True(t, strings.HasPrefix(r.Summary(now), "✓ Logged in as jane@example.com · organization acme · valid until "), r.Summary(now))

	// names the server did not send fall back to the MRN
	r.Scope = LoginScope{}
	r.Credential.ScopeMrn = testSpaceMrn
	assert.Contains(t, r.Summary(now), "space "+testSpaceMrn)
}

func assertResult(t *testing.T, f *fakeAS, res *Result) {
	t.Helper()
	// the login is the user: the user's MRN and a bearer token, no key
	assert.Equal(t, testUserMrn, res.Credential.Mrn)
	assert.Equal(t, testSpaceMrn, res.Credential.ScopeMrn)
	assert.Equal(t, testSpaceMrn, res.Credential.SpaceMrn)
	assert.Equal(t, f.token_, res.Credential.Token)
	assert.NotEmpty(t, res.Credential.Token)
	assert.Equal(t, "jane@example.com", res.User.Email)
	assert.Equal(t, "prod", res.Scope.Name)
	assert.Equal(t, "space", res.Scope.Kind)
	assert.Equal(t, "acme", res.Scope.OrgName)
	assert.Equal(t, f.issuer(), res.Issuer)
	assert.Equal(t, f.issuer(), res.Endpoint)
	assert.WithinDuration(t, time.Now().Add(time.Hour), res.ValidUntil, time.Minute)

	// what is written to the config: the token under the key the client
	// already sends as a bearer token, and nothing of a registered client
	cfg := res.ConfigValues()
	assert.Equal(t, f.token_, cfg["token"])
	assert.Equal(t, testUserMrn, cfg["mrn"])
	assert.Equal(t, testSpaceMrn, cfg["scope_mrn"])
	for _, absent := range []string{"private_key", "certificate", "agent_mrn", "space_mrn"} {
		assert.NotContains(t, cfg, absent)
	}
	auth := cfg["auth"].(map[string]any)
	assert.Equal(t, AuthMethod, auth["method"])
	assert.Equal(t, f.issuer(), auth["issuer"])
	assert.Equal(t, f.issuer(), auth["endpoint"])
	assert.Equal(t, res.ValidUntil.UTC().Format(time.RFC3339), auth["valid_until"])
	assert.NotContains(t, auth, "access_token", "the token is stored once, as the credential")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRevoke_NoContent(t *testing.T) {
	f := newFakeAS(t)
	f.revokeStatus = http.StatusNoContent
	require.NoError(t, Revoke(context.Background(), f.srv.Client(), f.issuer(), "the-token", false))
}

func TestRevoke_ErrorIncludesBodySnippet(t *testing.T) {
	f := newFakeAS(t)
	f.revokeStatus = http.StatusBadRequest
	f.revokeBody = "{\"error\":\"unsupported_token_type\"}\n" + strings.Repeat("x", 1000)
	err := Revoke(context.Background(), f.srv.Client(), f.issuer(), "the-token", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "unsupported_token_type")
	assert.NotContains(t, err.Error(), "\n")
	assert.Less(t, len(err.Error()), 300)
}

func TestLoopbackCallback_RejectsNonGET(t *testing.T) {
	f := newFakeAS(t)
	opts := testOptions(f, ModeBrowser)
	posted := make(chan int, 1)
	opts.OpenBrowser = func(u string) error {
		parsed, err := url.Parse(u)
		if err != nil {
			return err
		}
		q := parsed.Query()
		resp, err := http.Post(q.Get("redirect_uri"), "application/x-www-form-urlencoded",
			strings.NewReader(url.Values{"code": {"x"}, "state": {q.Get("state")}}.Encode()))
		if err != nil {
			return err
		}
		resp.Body.Close()
		posted <- resp.StatusCode
		return f.authorize(u, nil)
	}
	res, err := Login(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, http.StatusMethodNotAllowed, <-posted)
	assertResult(t, f, res)
}

func TestTruncateUTF8(t *testing.T) {
	assert.Equal(t, "abc", truncateUTF8("abc", 5))
	assert.Equal(t, "ab", truncateUTF8("abc", 2))
	// "é" is two bytes; cutting inside it drops the partial rune.
	assert.Equal(t, "a", truncateUTF8("aé", 2))
	assert.Equal(t, "aé", truncateUTF8("aéb", 3))
	// A three-byte rune cut after one or two bytes.
	assert.Equal(t, "a", truncateUTF8("a€", 2))
	assert.Equal(t, "a", truncateUTF8("a€", 3))
	// A U+FFFD already in the input is kept.
	assert.Equal(t, "a�", truncateUTF8("a�bc", 4))
	assert.Equal(t, "", truncateUTF8("€", 1))
}
