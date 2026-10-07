// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/ranger-rpc/plugins/rangerguard/crypto"
)

func noEnv(string) string { return "" }

func testOptions(f *fakeAS, mode Mode) Options {
	return Options{
		Endpoint:        f.issuer(),
		Mode:            mode,
		SpaceMrn:        "//captain.api.mondoo.app/spaces/test-space",
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

func TestKeyProof_VerifiesWithPublicKey(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	enc, err := EncodePublicKey(&key.PublicKey)
	require.NoError(t, err)
	der, err := base64.RawURLEncoding.DecodeString(enc)
	require.NoError(t, err)
	pub, err := x509.ParsePKIXPublicKey(der)
	require.NoError(t, err)

	now := time.Now()
	proof, err := NewKeyProof(key, "https://sts.example.com/oauth/token", "the-code", now, time.Hour)
	require.NoError(t, err)

	tok, err := jwt.Parse(proof, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"ES384"}), jwt.WithAudience("https://sts.example.com/oauth/token"), jwt.WithIssuer(ClientID))
	require.NoError(t, err)
	assert.Equal(t, KeyProofType, tok.Header["typ"])
	assert.Equal(t, "ES384", tok.Header["alg"])
	claims := tok.Claims.(jwt.MapClaims)
	assert.Equal(t, HashValue("the-code"), claims["code_hash"])
	assert.Equal(t, "https://sts.example.com/oauth/token", claims["aud"])
	assert.NotEmpty(t, claims["jti"])
	iat, _ := claims.GetIssuedAt()
	exp, _ := claims.GetExpirationTime()
	assert.Equal(t, MaxKeyProofLifetime, exp.Sub(iat.Time), "lifetime is capped at the server maximum")

	// a different key must not verify it
	other, err := GenerateKey()
	require.NoError(t, err)
	_, err = jwt.Parse(proof, func(*jwt.Token) (any, error) { return &other.PublicKey, nil }, jwt.WithValidMethods([]string{"ES384"}))
	assert.Error(t, err)
}

func TestPrivateKeyPEM_RoundTrip(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	pemStr, err := EncodePrivateKeyPEM(key)
	require.NoError(t, err)
	got, err := crypto.PrivateKeyFromBytes([]byte(pemStr))
	require.NoError(t, err)
	assert.True(t, got.Equal(key))
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
	assert.NotContains(t, out.String(), "Press Enter", "no prompt when not interactive")
	assert.Contains(t, out.String(), "Open https://console.example.com/activate in a browser and enter the code.\nWaiting for authorization...\n")
	assert.NotContains(t, out.String(), "\r", "no spinner when not interactive")

	// request parameters
	assert.Equal(t, ClientID, f.authForm.Get("client_id"))
	assert.Equal(t, Scope, f.authForm.Get("scope"))
	assert.Equal(t, "//captain.api.mondoo.app/spaces/test-space", f.authForm.Get("mondoo_space_mrn"))
	assert.Equal(t, "build-host", f.authForm.Get("mondoo_device_name"))
	assert.Equal(t, "cnspec 13.0.0 linux/amd64", f.authForm.Get("mondoo_device_info"))

	// polling: pending, slow_down, success; slow_down adds 5s to the interval
	require.Len(t, f.pollTimes, 3)
	assert.GreaterOrEqual(t, f.pollTimes[2].Sub(f.pollTimes[1]), 5*time.Second)
	// one proof for the whole poll window
	assert.Equal(t, f.tokenForms[0].Get("mondoo_key_proof"), f.tokenForms[2].Get("mondoo_key_proof"))

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
	assert.Equal(t, "//captain.api.mondoo.app/spaces/test-space", f.authForm.Get("mondoo_space_mrn"))
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
	assert.NotContains(t, got, "Press Enter", "a browser could not be opened, so none is offered")
	assert.NotContains(t, got, "Opening your browser")
	assert.NotContains(t, got, "/oauth/authorize")
	assert.NotContains(t, got, "127.0.0.1")
	assert.NotEmpty(t, f.authForm.Get("mondoo_public_key"), "the device flow sent the login's key")

	// The loopback listener is shut down.
	require.NotEmpty(t, redirectURI)
	resp, err := http.Get(redirectURI)
	if err == nil {
		resp.Body.Close()
	}
	assert.Error(t, err, "the loopback listener must be closed")
}

func TestLoopbackFlow_StateMismatch(t *testing.T) {
	f := newFakeAS(t)
	opts := testOptions(f, ModeBrowser)
	opts.OpenBrowser = func(u string) error {
		return f.authorize(u, func(q url.Values) { q.Set("state", "forged") })
	}
	_, err := Login(context.Background(), opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "state")
	assert.Equal(t, 0, f.tokenCalls, "a forged response must not be redeemed")
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
	key, err := GenerateKey()
	require.NoError(t, err)
	f.pubKey = &key.PublicKey
	pemStr, err := EncodePrivateKeyPEM(key)
	require.NoError(t, err)

	require.NoError(t, Revoke(context.Background(), f.srv.Client(), f.issuer(), "the-token", pemStr, false))
	require.Len(t, f.revokeForms, 1)
	form := f.revokeForms[0]
	assert.Equal(t, "the-token", form.Get("token"))
	require.NoError(t, f.verifyProof(form, f.issuer()+"/oauth/revoke", "the-token"))
}

func TestSummary(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	r := &Result{
		User:       User{Email: "jane@example.com"},
		Space:      Space{Name: "prod", OrgName: "acme"},
		ValidUntil: now.Add(time.Hour),
	}
	s := r.Summary(now)
	assert.True(t, strings.HasPrefix(s, "✓ Logged in as jane@example.com · space acme/prod · valid until "), s)
	assert.True(t, strings.HasSuffix(s, "(1h)"), s)
}

func assertResult(t *testing.T, f *fakeAS, res *Result) {
	t.Helper()
	assert.Equal(t, "//agents.api.mondoo.app/spaces/test-space/serviceaccounts/session1", res.ServiceAccount.Mrn)
	assert.Equal(t, "//captain.api.mondoo.app/spaces/test-space", res.ServiceAccount.ScopeMrn)
	assert.Equal(t, "jane@example.com", res.User.Email)
	assert.Equal(t, "acme", res.Space.OrgName)
	assert.Equal(t, f.issuer(), res.Issuer)
	assert.NotEmpty(t, res.AccessToken)
	assert.WithinDuration(t, time.Now().Add(time.Hour), res.ValidUntil, time.Minute)

	// the stored key loads with the existing loader and matches the certificate
	key, err := crypto.PrivateKeyFromBytes([]byte(res.PrivateKeyPEM))
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(res.ServiceAccount.Certificate))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey))
	assert.True(t, f.pubKey.Equal(&key.PublicKey), "the server saw this login's public key")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func revokeTestKey(t *testing.T, f *fakeAS) string {
	t.Helper()
	key, err := GenerateKey()
	require.NoError(t, err)
	f.pubKey = &key.PublicKey
	pemStr, err := EncodePrivateKeyPEM(key)
	require.NoError(t, err)
	return pemStr
}

func TestRevoke_NoContent(t *testing.T) {
	f := newFakeAS(t)
	f.revokeStatus = http.StatusNoContent
	pemStr := revokeTestKey(t, f)
	require.NoError(t, Revoke(context.Background(), f.srv.Client(), f.issuer(), "the-token", pemStr, false))
}

func TestRevoke_ErrorIncludesBodySnippet(t *testing.T) {
	f := newFakeAS(t)
	f.revokeStatus = http.StatusBadRequest
	f.revokeBody = "{\"error\":\"unsupported_token_type\"}\n" + strings.Repeat("x", 1000)
	pemStr := revokeTestKey(t, f)
	err := Revoke(context.Background(), f.srv.Client(), f.issuer(), "the-token", pemStr, false)
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

func TestDeviceProofWindow(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

	// The device code outlives the longest proof: the proof is capped and
	// polling stops a margin before it expires.
	lifetime, deadline := deviceProofWindow(now, now.Add(30*time.Minute))
	assert.Equal(t, MaxKeyProofLifetime, lifetime)
	assert.Equal(t, now.Add(MaxKeyProofLifetime-proofSafetyMargin), deadline)

	// The device code expires first: polling runs until it expires and the
	// proof stays valid a margin past that.
	expiry := now.Add(10 * time.Minute)
	lifetime, deadline = deviceProofWindow(now, expiry)
	assert.Equal(t, 10*time.Minute+proofSafetyMargin, lifetime)
	assert.Equal(t, expiry, deadline)
	assert.True(t, now.Add(lifetime).After(deadline))

	// Unknown expiry: the longest proof.
	lifetime, deadline = deviceProofWindow(now, time.Time{})
	assert.Equal(t, MaxKeyProofLifetime, lifetime)
	assert.Equal(t, now.Add(MaxKeyProofLifetime-proofSafetyMargin), deadline)

	// Already expired: a positive lifetime and no polling time left.
	lifetime, deadline = deviceProofWindow(now, now.Add(-time.Minute))
	assert.Equal(t, proofSafetyMargin, lifetime)
	assert.Equal(t, now, deadline)
}
