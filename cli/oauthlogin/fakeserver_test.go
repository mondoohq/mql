// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// fakeAS is a minimal authorization server implementing the endpoints the
// client talks to. It verifies what a real server must verify (PKCE, key
// proof, redirect URI) and records what it saw.
type fakeAS struct {
	t   *testing.T
	srv *httptest.Server

	// knobs
	metadataIssuer    string // overrides the advertised issuer
	tokenEndpoint     string // overrides the advertised token endpoint
	tokenIssuer       string // overrides iss in the token response
	devicePollReplies []string

	mu             sync.Mutex
	pubKey         *ecdsa.PublicKey
	authForm       url.Values // device authorization or authorize query
	codeChallenge  string
	redirectURI    string
	issuedCode     string
	deviceCode     string
	tokenCalls     int
	pollTimes      []time.Time
	tokenForms     []url.Values
	revokeForms    []url.Values
	revokeStatus   int    // 0: 200
	revokeBody     string // written with revokeStatus
	lastProofClaim jwt.MapClaims
}

func newFakeAS(t *testing.T) *fakeAS {
	f := &fakeAS{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc(WellKnownPath, f.metadata)
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
	writeJSON(w, http.StatusOK, map[string]any{
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
	})
}

func (f *fakeAS) setPublicKey(enc string) {
	der, err := base64.RawURLEncoding.DecodeString(enc)
	require.NoError(f.t, err)
	pub, err := x509.ParsePKIXPublicKey(der)
	require.NoError(f.t, err)
	f.pubKey = pub.(*ecdsa.PublicKey)
}

func (f *fakeAS) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	require.NoError(f.t, r.ParseForm())
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authForm = r.PostForm
	f.setPublicKey(r.PostForm.Get("mondoo_public_key"))
	f.deviceCode = "device-" + randomString(32)
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":      f.deviceCode,
		"user_code":        "WDJB-MJHT",
		"verification_uri": "https://console.example.com/activate",
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
	f.setPublicKey(q.Get("mondoo_public_key"))
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

func (f *fakeAS) verifyProof(form url.Values, aud, bound string) error {
	tok, err := jwt.Parse(form.Get("mondoo_key_proof"), func(t *jwt.Token) (any, error) {
		return f.pubKey, nil
	}, jwt.WithValidMethods([]string{"ES384"}), jwt.WithAudience(aud), jwt.WithIssuer(ClientID), jwt.WithIssuedAt())
	if err != nil {
		return err
	}
	if tok.Header["typ"] != KeyProofType {
		return fmt.Errorf("bad typ %v", tok.Header["typ"])
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["code_hash"] != HashValue(bound) {
		return fmt.Errorf("code_hash mismatch")
	}
	if claims["jti"] == "" {
		return fmt.Errorf("missing jti")
	}
	iat, _ := claims.GetIssuedAt()
	exp, _ := claims.GetExpirationTime()
	if exp.Sub(iat.Time) > MaxKeyProofLifetime {
		return fmt.Errorf("proof lifetime %s exceeds %s", exp.Sub(iat.Time), MaxKeyProofLifetime)
	}
	if _, isString := claims["aud"].(string); !isString {
		return fmt.Errorf("aud must be a single string")
	}
	f.lastProofClaim = claims
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
		if err := f.verifyProof(form, f.tokenURL(), form.Get("code")); err != nil {
			f.t.Logf("proof rejected: %v", err)
			oauthError(w, "invalid_request")
			return
		}
	case "urn:ietf:params:oauth:grant-type:device_code":
		f.pollTimes = append(f.pollTimes, time.Now())
		if form.Get("device_code") != f.deviceCode {
			oauthError(w, "invalid_grant")
			return
		}
		if err := f.verifyProof(form, f.tokenURL(), form.Get("device_code")); err != nil {
			f.t.Logf("proof rejected: %v", err)
			oauthError(w, "invalid_request")
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

func (f *fakeAS) writeTokenResponse(w http.ResponseWriter) {
	validUntil := time.Now().Add(time.Hour).Truncate(time.Second)
	sa := map[string]any{
		"mrn":          "//agents.api.mondoo.app/spaces/test-space/serviceaccounts/session1",
		"space_mrn":    "//captain.api.mondoo.app/spaces/test-space",
		"scope_mrn":    "//captain.api.mondoo.app/spaces/test-space",
		"certificate":  issueCert(f.t, f.pubKey, validUntil),
		"api_endpoint": f.issuer(),
		"valid_until":  validUntil.UTC().Format(time.RFC3339),
	}
	raw, _ := json.Marshal(sa)
	iss := f.issuer()
	if f.tokenIssuer != "" {
		iss = f.tokenIssuer
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":           base64.RawURLEncoding.EncodeToString(raw),
		"token_type":             "N_A",
		"expires_in":             3600,
		"scope":                  Scope,
		"iss":                    iss,
		"mondoo_service_account": sa,
		"mondoo_user":            map[string]any{"mrn": "//captain.api.mondoo.app/users/u1", "email": "jane@example.com", "name": "Jane"},
		"mondoo_space":           map[string]any{"mrn": sa["space_mrn"], "name": "prod", "org_mrn": "//captain.api.mondoo.app/organizations/acme", "org_name": "acme"},
	})
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

// issueCert issues a certificate for pub, signed by a throwaway CA.
func issueCert(t *testing.T, pub *ecdsa.PublicKey, notAfter time.Time) string {
	caKey, err := GenerateKey()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "session"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, caKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
