// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// expirySkew is subtracted from a token's lifetime so a token that is about to
// expire is renewed before it is sent rather than after it fails.
const expirySkew = 30 * time.Second

// tokenResponse is the OpenID Connect token endpoint payload. Keycloak reports
// the refresh token lifetime in refresh_expires_in, which is 0 for an offline
// token that does not expire.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// tokenSource mints and renews the admin API access token. Keycloak access
// tokens are short lived, one minute on a stock install, so a scan outlives
// several of them.
type tokenSource struct {
	mu       sync.Mutex
	client   *http.Client
	tokenURL string
	// grant holds the credentials of the configured authentication method. It
	// is replayed whenever no usable refresh token is left.
	grant url.Values
	// now is swapped in tests so token expiry can be driven without waiting.
	now func() time.Time

	accessToken   string
	accessExpiry  time.Time
	refreshToken  string
	refreshExpiry time.Time
}

func newTokenSource(client *http.Client, tokenURL string, grant url.Values) *tokenSource {
	return &tokenSource{
		client:   client,
		tokenURL: tokenURL,
		grant:    grant,
		now:      time.Now,
	}
}

// Token returns a valid access token, renewing it when the cached one is spent.
// It prefers the refresh token, which does not replay the password or the
// client secret, and falls back to a full grant when the refresh is rejected.
func (t *tokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.token(ctx)
}

// Invalidate drops the cached access token so the next request mints a new one.
// It is called when the server rejects a token the cache still considered
// valid, which happens when a session is revoked or the clocks disagree.
func (t *tokenSource) Invalidate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.accessToken = ""
	t.accessExpiry = time.Time{}
}

func (t *tokenSource) token(ctx context.Context) (string, error) {
	now := t.now()
	if t.accessToken != "" && now.Before(t.accessExpiry) {
		return t.accessToken, nil
	}

	if t.refreshUsable(now) {
		refresh := url.Values{
			"grant_type":    []string{"refresh_token"},
			"refresh_token": []string{t.refreshToken},
			"client_id":     []string{t.grant.Get("client_id")},
		}
		if secret := t.grant.Get("client_secret"); secret != "" {
			refresh.Set("client_secret", secret)
		}
		if token, err := t.exchange(ctx, refresh); err == nil {
			return token, nil
		}
		// A refresh token can be revoked or expire earlier than announced, so a
		// rejected refresh falls back to the configured credentials rather than
		// failing the scan.
		t.refreshToken = ""
		t.refreshExpiry = time.Time{}
	}

	return t.exchange(ctx, t.grant)
}

// refreshUsable reports whether the stored refresh token is worth trying. A
// zero refresh expiry means the server announced no lifetime, which is the
// offline token case, so the token is tried and the failure path covers it.
func (t *tokenSource) refreshUsable(now time.Time) bool {
	if t.refreshToken == "" {
		return false
	}
	return t.refreshExpiry.IsZero() || now.Before(t.refreshExpiry)
}

func (t *tokenSource) exchange(ctx context.Context, form url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("keycloak token request: read response: %w", err)
	}

	var payload tokenResponse
	// A token endpoint behind a proxy can answer with HTML, so a decode failure
	// is reported together with the status rather than as a bare parse error.
	decodeErr := json.Unmarshal(body, &payload)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := payload.ErrorDescription
		if msg == "" {
			msg = payload.Error
		}
		return "", &APIError{StatusCode: resp.StatusCode, Path: "token", Message: msg}
	}
	if decodeErr != nil {
		return "", fmt.Errorf("keycloak token request: decode response: %w", decodeErr)
	}
	if payload.AccessToken == "" {
		return "", errors.New("keycloak token request: response carried no access token")
	}

	now := t.now()
	t.accessToken = payload.AccessToken
	t.accessExpiry = expiryFrom(now, payload.ExpiresIn)
	t.refreshToken = payload.RefreshToken
	t.refreshExpiry = time.Time{}
	if payload.RefreshExpiresIn > 0 {
		t.refreshExpiry = expiryFrom(now, payload.RefreshExpiresIn)
	}

	return t.accessToken, nil
}

// expiryFrom converts an announced lifetime into an absolute deadline, held
// back by the skew. A lifetime shorter than the skew keeps a usable window
// rather than expiring the token the moment it arrives.
func expiryFrom(now time.Time, seconds int64) time.Time {
	lifetime := time.Duration(seconds) * time.Second
	if lifetime <= expirySkew {
		return now.Add(lifetime / 2)
	}
	return now.Add(lifetime - expirySkew)
}
