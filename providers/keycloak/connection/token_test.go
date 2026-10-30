// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeToken answers a token request the way Keycloak does.
func writeToken(t *testing.T, w http.ResponseWriter, access string, expiresIn int64, refresh string, refreshExpiresIn int64) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
		"access_token":       access,
		"expires_in":         expiresIn,
		"refresh_token":      refresh,
		"refresh_expires_in": refreshExpiresIn,
		"token_type":         "Bearer",
	}))
}

func passwordGrant() url.Values {
	return url.Values{
		"grant_type": []string{"password"},
		"client_id":  []string{"admin-cli"},
		"username":   []string{"admin"},
		"password":   []string{"pw"},
	}
}

func TestExpiryFrom(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	// A normal lifetime is held back by the skew so a token is renewed before
	// it is sent rather than after it fails.
	assert.Equal(t, now.Add(270*time.Second), expiryFrom(now, 300))

	// A lifetime shorter than the skew must still leave a usable window,
	// otherwise every token expires the moment it arrives.
	assert.Equal(t, now.Add(15*time.Second), expiryFrom(now, 30))
	assert.Equal(t, now.Add(5*time.Second), expiryFrom(now, 10))
	assert.Equal(t, now, expiryFrom(now, 0))
}

func TestTokenIsCachedUntilItExpires(t *testing.T) {
	minted := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		minted++
		writeToken(t, w, "access-1", 300, "", 0)
	}))
	defer srv.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	ts := newTokenSource(srv.Client(), srv.URL, passwordGrant())
	ts.now = func() time.Time { return now }

	for range 3 {
		token, err := ts.Token(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "access-1", token)
	}
	assert.Equal(t, 1, minted)
}

func TestTokenRefreshesWithTheRefreshToken(t *testing.T) {
	var grants []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		grants = append(grants, r.Form.Get("grant_type"))

		if r.Form.Get("grant_type") == "refresh_token" {
			assert.Equal(t, "refresh-1", r.Form.Get("refresh_token"))
			writeToken(t, w, "access-2", 300, "refresh-2", 1800)
			return
		}
		writeToken(t, w, "access-1", 300, "refresh-1", 1800)
	}))
	defer srv.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	ts := newTokenSource(srv.Client(), srv.URL, passwordGrant())
	ts.now = func() time.Time { return now }

	token, err := ts.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "access-1", token)

	// Move past the access token's deadline but stay within the refresh
	// token's, which is the ordinary case during a longer scan.
	now = now.Add(280 * time.Second)

	token, err = ts.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "access-2", token)
	assert.Equal(t, []string{"password", "refresh_token"}, grants)
}

func TestTokenFallsBackToTheGrantWhenTheRefreshIsRejected(t *testing.T) {
	var grants []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		grants = append(grants, r.Form.Get("grant_type"))

		if r.Form.Get("grant_type") == "refresh_token" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Session not active"}`))
			return
		}
		writeToken(t, w, "access-fresh", 300, "refresh-1", 1800)
	}))
	defer srv.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	ts := newTokenSource(srv.Client(), srv.URL, passwordGrant())
	ts.now = func() time.Time { return now }

	_, err := ts.Token(context.Background())
	require.NoError(t, err)

	now = now.Add(280 * time.Second)

	token, err := ts.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "access-fresh", token)
	assert.Equal(t, []string{"password", "refresh_token", "password"}, grants)
}

func TestTokenSkipsAnExpiredRefreshToken(t *testing.T) {
	var grants []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		grants = append(grants, r.Form.Get("grant_type"))
		writeToken(t, w, "access", 300, "refresh-1", 600)
	}))
	defer srv.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	ts := newTokenSource(srv.Client(), srv.URL, passwordGrant())
	ts.now = func() time.Time { return now }

	_, err := ts.Token(context.Background())
	require.NoError(t, err)

	// Past both deadlines, so the refresh token is not worth trying.
	now = now.Add(700 * time.Second)

	_, err = ts.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"password", "password"}, grants)
}

func TestTokenSkipsRefreshWhenTheGrantReturnedNone(t *testing.T) {
	var grants []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		grants = append(grants, r.Form.Get("grant_type"))
		// A client credentials grant commonly answers without a refresh token.
		writeToken(t, w, "access", 60, "", 0)
	}))
	defer srv.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	ts := newTokenSource(srv.Client(), srv.URL, url.Values{
		"grant_type":    []string{"client_credentials"},
		"client_id":     []string{"scanner"},
		"client_secret": []string{"topsecret"},
	})
	ts.now = func() time.Time { return now }

	_, err := ts.Token(context.Background())
	require.NoError(t, err)

	now = now.Add(60 * time.Second)

	_, err = ts.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"client_credentials", "client_credentials"}, grants)
}

func TestTokenRefreshCarriesTheClientSecret(t *testing.T) {
	var refreshSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		if r.Form.Get("grant_type") == "refresh_token" {
			refreshSecret = r.Form.Get("client_secret")
			writeToken(t, w, "access-2", 300, "refresh-2", 1800)
			return
		}
		writeToken(t, w, "access-1", 300, "refresh-1", 1800)
	}))
	defer srv.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	grant := passwordGrant()
	grant.Set("client_id", "scanner")
	grant.Set("client_secret", "topsecret")

	ts := newTokenSource(srv.Client(), srv.URL, grant)
	ts.now = func() time.Time { return now }

	_, err := ts.Token(context.Background())
	require.NoError(t, err)

	now = now.Add(280 * time.Second)
	_, err = ts.Token(context.Background())
	require.NoError(t, err)

	// A confidential client must authenticate on the refresh as well, or the
	// refresh is rejected and every renewal replays the password.
	assert.Equal(t, "topsecret", refreshSecret)
}

func TestInvalidateForcesANewToken(t *testing.T) {
	minted := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		minted++
		// No refresh token, so an invalidated token is minted from the grant.
		writeToken(t, w, "access", 300, "", 0)
	}))
	defer srv.Close()

	ts := newTokenSource(srv.Client(), srv.URL, passwordGrant())

	_, err := ts.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, minted)

	ts.Invalidate()

	_, err = ts.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, minted)
}

func TestTokenReportsAFailedGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"Invalid client credentials"}`))
	}))
	defer srv.Close()

	ts := newTokenSource(srv.Client(), srv.URL, passwordGrant())

	_, err := ts.Token(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid client credentials")
}

func TestTokenRejectsAResponseWithoutAToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"expires_in":300}`))
	}))
	defer srv.Close()

	ts := newTokenSource(srv.Client(), srv.URL, passwordGrant())

	_, err := ts.Token(context.Background())
	require.Error(t, err)
}

func TestTokenReportsAnUnparseableBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A proxy in front of Keycloak can answer with HTML on a 200.
		_, _ = w.Write([]byte(`<html>gateway</html>`))
	}))
	defer srv.Close()

	ts := newTokenSource(srv.Client(), srv.URL, passwordGrant())

	_, err := ts.Token(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode response")
}
