// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeAS is a minimal login server implementing the endpoints the client
// talks to. It verifies what a real server must verify (PKCE, redirect URI,
// the device code) and records what it saw.
//
// It is also the API endpoint, as a real server is today. By default it
// publishes no protected resource metadata, so the client takes the endpoint
// itself as the login server. See pointer.
type fakeAS struct {
	t   *testing.T
	srv *httptest.Server

	// knobs
	metadataIssuer    string // overrides the advertised issuer
	tokenEndpoint     string // overrides the advertised token endpoint
	tokenIssuer       string // overrides iss in the token response
	devicePollReplies []string
	manualRedirectURI string // advertised as mondoo_manual_redirect_uri when set
	verificationURI   string // overrides verification_uri in the device authorization response
	apiEndpoint       string // overrides api_endpoint in the token response
	orgLogin          bool   // the user approves the login for an organization
	noAPIEndpoint     bool   // the token response carries no api_endpoint
	// pointer answers the protected resource metadata request. Nil answers
	// 404.
	pointer http.HandlerFunc

	mu            sync.Mutex
	token_        string     // the login token issued last
	authForm      url.Values // device authorization or authorize query
	codeChallenge string
	redirectURI   string
	issuedCode    string
	deviceCode    string
	tokenCalls    int
	pollTimes     []time.Time
	tokenForms    []url.Values
	revokeForms   []url.Values
	revokeStatus  int    // 0: 200
	revokeBody    string // written with revokeStatus
}

func newFakeAS(t *testing.T) *fakeAS {
	f := &fakeAS{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc(WellKnownPath, f.metadata)
	mux.HandleFunc(ProtectedResourcePath, func(w http.ResponseWriter, r *http.Request) {
		if f.pointer == nil {
			http.NotFound(w, r)
			return
		}
		f.pointer(w, r)
	})
	mux.HandleFunc("/oauth/device_authorization", f.deviceAuthorization)
	mux.HandleFunc("/oauth/token", f.token)
	mux.HandleFunc("/oauth/revoke", f.revoke)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAS) issuer() string { return f.srv.URL }

func (f *fakeAS) tokenURL() string {
	if f.tokenEndpoint != "" {
		return f.tokenEndpoint
	}
	return f.issuer() + "/oauth/token"
}

func (f *fakeAS) metadata(w http.ResponseWriter, r *http.Request) {
	iss := f.issuer()
	if f.metadataIssuer != "" {
		iss = f.metadataIssuer
	}
	md := map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         f.issuer() + "/oauth/authorize",
		"token_endpoint":                                 f.tokenURL(),
		"device_authorization_endpoint":                  f.issuer() + "/oauth/device_authorization",
		"revocation_endpoint":                            f.issuer() + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"scopes_supported":                               []string{Scope},
		"authorization_response_iss_parameter_supported": true,
	}
	if f.manualRedirectURI != "" {
		md["mondoo_manual_redirect_uri"] = f.manualRedirectURI
	}
	writeJSON(w, http.StatusOK, md)
}

// consoleAuthorize plays a browser on another machine using the manual
// authorize URL: it validates the request and returns what the manual
// redirect page shows, "<code>#<state>".
func (f *fakeAS) consoleAuthorize(authURL string) (string, error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != ClientID || q.Get("response_type") != "code" {
		return "", fmt.Errorf("bad authorize request: %v", q)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authForm = q
	f.codeChallenge = q.Get("code_challenge")
	f.redirectURI = q.Get("redirect_uri")
	f.issuedCode = "code-" + randomString(16)
	return f.issuedCode + "#" + q.Get("state"), nil
}

func (f *fakeAS) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	require.NoError(f.t, r.ParseForm())
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authForm = r.PostForm
	f.deviceCode = "device-" + randomString(32)
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":      f.deviceCode,
		"user_code":        "WDJB-MJHT",
		"verification_uri": cmp.Or(f.verificationURI, "https://console.example.com/activate"),
		"expires_in":       600,
		"interval":         1,
	})
}

// authorize plays the browser: it validates the authorize URL, then calls the
// redirect URI with the given overrides.
func (f *fakeAS) authorize(authURL string, tamper func(q url.Values)) error {
	u, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	q := u.Query()
	f.mu.Lock()
	f.authForm = q
	f.codeChallenge = q.Get("code_challenge")
	f.redirectURI = q.Get("redirect_uri")
	f.issuedCode = "code-" + randomString(16)
	f.mu.Unlock()

	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != ClientID || q.Get("response_type") != "code" {
		return fmt.Errorf("bad authorize request: %v", q)
	}
	cb := url.Values{"code": {f.issuedCode}, "state": {q.Get("state")}, "iss": {f.issuer()}}
	if tamper != nil {
		tamper(cb)
	}
	go func() {
		resp, err := http.Get(f.redirectURI + "?" + cb.Encode())
		if err == nil {
			resp.Body.Close()
		}
	}()
	return nil
}

func (f *fakeAS) token(w http.ResponseWriter, r *http.Request) {
	require.NoError(f.t, r.ParseForm())
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenCalls++
	f.tokenForms = append(f.tokenForms, r.PostForm)
	form := r.PostForm
	if form.Get("client_id") != ClientID {
		oauthError(w, "invalid_client")
		return
	}

	switch form.Get("grant_type") {
	case "authorization_code":
		if form.Get("code") != f.issuedCode || form.Get("redirect_uri") != f.redirectURI {
			oauthError(w, "invalid_grant")
			return
		}
		sum := sha256.Sum256([]byte(form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != f.codeChallenge {
			oauthError(w, "invalid_grant")
			return
		}
	case "urn:ietf:params:oauth:grant-type:device_code":
		f.pollTimes = append(f.pollTimes, time.Now())
		if form.Get("device_code") != f.deviceCode {
			oauthError(w, "invalid_grant")
			return
		}
		if len(f.devicePollReplies) > 0 {
			reply := f.devicePollReplies[0]
			f.devicePollReplies = f.devicePollReplies[1:]
			oauthError(w, reply)
			return
		}
	default:
		oauthError(w, "unsupported_grant_type")
		return
	}

	f.writeTokenResponse(w)
}

const (
	testUserMrn  = "//captain.api.mondoo.app/users/u1"
	testSpaceMrn = "//captain.api.mondoo.app/spaces/test-space"
	testOrgMrn   = "//captain.api.mondoo.app/organizations/acme"
)

// writeTokenResponse answers as the real server does: a bearer token whose
// holder is the user. A login to a space names the space twice (space_mrn and
// scope_mrn); a login to an organization has no space_mrn.
func (f *fakeAS) writeTokenResponse(w http.ResponseWriter) {
	validUntil := time.Now().Add(time.Hour).Truncate(time.Second)
	f.token_ = "login-token-" + randomString(24)
	cred := map[string]any{
		"mrn":          testUserMrn,
		"space_mrn":    testSpaceMrn,
		"scope_mrn":    testSpaceMrn,
		"token":        f.token_,
		"api_endpoint": cmp.Or(f.apiEndpoint, f.issuer()),
		"valid_until":  validUntil.UTC().Format(time.RFC3339),
	}
	scope := map[string]any{"mrn": testSpaceMrn, "name": "prod", "kind": "space", "org_mrn": testOrgMrn, "org_name": "acme"}
	if f.noAPIEndpoint {
		delete(cred, "api_endpoint")
	}
	if f.orgLogin {
		delete(cred, "space_mrn")
		cred["scope_mrn"] = testOrgMrn
		scope = map[string]any{"mrn": testOrgMrn, "name": "acme", "kind": ScopeKindOrganization, "org_mrn": testOrgMrn, "org_name": "acme"}
	}
	iss := f.issuer()
	if f.tokenIssuer != "" {
		iss = f.tokenIssuer
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":           f.token_,
		"token_type":             "Bearer",
		"expires_in":             3600,
		"scope":                  Scope,
		"iss":                    iss,
		"mondoo_service_account": cred,
		"mondoo_user":            map[string]any{"mrn": testUserMrn, "email": "jane@example.com", "name": "Jane"},
		"mondoo_scope":           scope,
	})
}

// pointTo makes the server publish protected resource metadata that names
// loginServer as the login server of this API endpoint.
func (f *fakeAS) pointTo(loginServers ...string) {
	f.pointer = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"resource": f.issuer(), "authorization_servers": loginServers})
	}
}

func (f *fakeAS) revoke(w http.ResponseWriter, r *http.Request) {
	require.NoError(f.t, r.ParseForm())
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeForms = append(f.revokeForms, r.PostForm)
	status := f.revokeStatus
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(f.revokeBody))
}

func oauthError(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code, "error_description": code + " (test)"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
