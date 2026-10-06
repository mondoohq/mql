// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// fakeTokenCredential hands out numbered tokens that live for lifetime. With
// empty set it answers with an empty token and no error.
type fakeTokenCredential struct {
	mu       sync.Mutex
	clock    *fakeClock
	lifetime time.Duration
	calls    int
	scopes   [][]string
	err      error
	empty    bool
}

func (f *fakeTokenCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.scopes = append(f.scopes, opts.Scopes)
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	if f.empty {
		return azcore.AccessToken{ExpiresOn: f.clock.now.Add(f.lifetime)}, nil
	}
	return azcore.AccessToken{
		Token:     fmt.Sprintf("entra-token-%d", f.calls),
		ExpiresOn: f.clock.now.Add(f.lifetime),
	}, nil
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func newEntraAuth(t *testing.T, lifetime time.Duration) (*Authenticator, *fakeTokenCredential, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	cred := &fakeTokenCredential{clock: clock, lifetime: lifetime}
	auth, err := NewAuthenticator(AuthOptions{
		TenantID:        "11111111-2222-3333-4444-555555555555",
		ClientID:        "66666666-7777-8888-9999-000000000000",
		TokenCredential: cred,
		Now:             clock.Now,
	})
	require.NoError(t, err)
	return auth, cred, clock
}

func TestEntraRequestsTheAzureDevOpsScope(t *testing.T) {
	auth, cred, _ := newEntraAuth(t, time.Hour)

	_, err := auth.Token(context.Background())
	require.NoError(t, err)

	require.Len(t, cred.scopes, 1)
	assert.Equal(t, []string{"499b84ac-1321-427f-aa17-267ca6975798/.default"}, cred.scopes[0])
}

func TestEntraTokenRefreshesAtEightyPercentOfItsLifetime(t *testing.T) {
	auth, cred, clock := newEntraAuth(t, time.Hour)
	ctx := context.Background()

	first, err := auth.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "entra-token-1", first)

	// 47m59s is before 80% of the hour: the cached token is reused.
	clock.now = clock.now.Add(47*time.Minute + 59*time.Second)
	again, err := auth.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "entra-token-1", again)
	assert.Equal(t, 1, cred.calls)

	// 48m is exactly 80%: the next call mints a new token.
	clock.now = clock.now.Add(time.Second)
	refreshed, err := auth.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "entra-token-2", refreshed)
	assert.Equal(t, 2, cred.calls)
}

func TestEntraHeaderIsABearerToken(t *testing.T) {
	auth, _, _ := newEntraAuth(t, time.Hour)

	header, err := auth.AuthorizationHeader(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer entra-token-1", header)
	assert.Equal(t, AuthEntra, auth.Mode())
}

func TestEntraMintFailureIsReported(t *testing.T) {
	auth, cred, _ := newEntraAuth(t, time.Hour)
	cred.err = errors.New("invalid_client")

	_, err := auth.AuthorizationHeader(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot mint an Entra token")
	assert.Contains(t, err.Error(), "invalid_client")
}

// captureLogs collects what the package logs for the rest of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prev })
	return &buf
}

// A refresh that fails while the current token has time left keeps that token
// in use. The failure reaches the caller only once no valid token remains.
func TestAFailedRefreshKeepsAnUnexpiredToken(t *testing.T) {
	logs := captureLogs(t)
	auth, cred, clock := newEntraAuth(t, time.Hour)
	ctx := context.Background()

	_, err := auth.Token(ctx)
	require.NoError(t, err)

	// past the refresh point at 48m, before the expiry at 60m
	clock.now = clock.now.Add(50 * time.Minute)
	cred.err = errors.New("AADSTS7000222: the client secret expired")
	tok, err := auth.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "entra-token-1", tok)
	assert.Equal(t, 2, cred.calls, "the refresh was tried")
	assert.Contains(t, logs.String(), "cannot refresh the Entra token")
	assert.NotContains(t, logs.String(), "entra-token-1")

	// an empty answer is a failed refresh as well
	cred.err = nil
	cred.empty = true
	tok, err = auth.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "entra-token-1", tok)
	assert.Equal(t, 1, strings.Count(logs.String(), "cannot refresh the Entra token"), "the warning is logged once per token")

	// at the expiry no valid token is left
	clock.now = clock.now.Add(10 * time.Minute)
	cred.empty = false
	cred.err = errors.New("AADSTS7000222: the client secret expired")
	_, err = auth.Token(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot mint an Entra token")

	// a refresh that works again replaces the token
	cred.err = nil
	tok, err = auth.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "entra-token-5", tok)
}

func TestPATHeaderIsBasicWithAnEmptyUser(t *testing.T) {
	auth, err := NewAuthenticator(AuthOptions{Credential: vault.NewPasswordCredential("", "fake-pat-value")})
	require.NoError(t, err)

	header, err := auth.AuthorizationHeader(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte(":fake-pat-value")), header)
	assert.Equal(t, AuthPAT, auth.Mode())
}

func TestGitCredentialUsesANonEmptyUser(t *testing.T) {
	pat, err := NewAuthenticator(AuthOptions{Credential: vault.NewPasswordCredential("", "fake-pat-value")})
	require.NoError(t, err)
	got, err := pat.GitCredential(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "oauth2", got.User)
	assert.Equal(t, "fake-pat-value", string(got.Secret))

	entra, _, _ := newEntraAuth(t, time.Hour)
	got, err = entra.GitCredential(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "oauth2", got.User)
	assert.Equal(t, "entra-token-1", string(got.Secret))
}

func TestAuthSelection(t *testing.T) {
	password := vault.NewPasswordCredential("", "fake-secret")
	cases := []struct {
		name    string
		opts    AuthOptions
		mode    AuthMode
		wantErr string
	}{
		{name: "tenant and client select Entra", opts: AuthOptions{
			TenantID: "11111111-2222-3333-4444-555555555555", ClientID: "66666666-7777-8888-9999-000000000000", Credential: password}, mode: AuthEntra},
		{name: "a password alone is a PAT", opts: AuthOptions{Credential: password}, mode: AuthPAT},
		{name: "a tenant without a client", opts: AuthOptions{TenantID: "11111111-2222-3333-4444-555555555555", Credential: password},
			wantErr: "tenant-id and client-id must be set together"},
		{name: "a client without a tenant", opts: AuthOptions{ClientID: "66666666-7777-8888-9999-000000000000", Credential: password},
			wantErr: "tenant-id and client-id must be set together"},
		{name: "no credential at all", opts: AuthOptions{}, wantErr: "no credentials"},
		{name: "an empty PAT", opts: AuthOptions{Credential: vault.NewPasswordCredential("", "")}, wantErr: "no credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth, err := NewAuthenticator(tc.opts)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.mode, auth.Mode())
		})
	}
}

func TestEachAuthenticatorMintsItsOwnToken(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	cred := &fakeTokenCredential{clock: clock, lifetime: time.Hour}
	build := func() *Authenticator {
		auth, err := NewAuthenticator(AuthOptions{
			TenantID:        "11111111-2222-3333-4444-555555555555",
			ClientID:        "66666666-7777-8888-9999-000000000000",
			TokenCredential: cred,
			Now:             clock.Now,
		})
		require.NoError(t, err)
		return auth
	}
	first, second := build(), build()

	one, err := first.Token(context.Background())
	require.NoError(t, err)
	two, err := second.Token(context.Background())
	require.NoError(t, err)

	// Two jobs for two repositories do not share a token, so one job running
	// past the token's lifetime cannot break the other.
	assert.Equal(t, 2, cred.calls)
	assert.NotEqual(t, one, two)
}

func TestConcurrentCallersShareOneMintedToken(t *testing.T) {
	// The jobs of one scan ask for the token at the same time. Run with -race.
	auth, cred, _ := newEntraAuth(t, time.Hour)

	const callers = 32
	var wg sync.WaitGroup
	tokens := make([]string, callers)
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tokens[i], errs[i] = auth.Token(context.Background())
		}()
	}
	wg.Wait()

	for i := range callers {
		require.NoError(t, errs[i])
		assert.Equal(t, "entra-token-1", tokens[i])
	}
	cred.mu.Lock()
	defer cred.mu.Unlock()
	assert.Equal(t, 1, cred.calls, "one mint serves every caller")
}

func TestAnEmptyFirstTokenIsAnError(t *testing.T) {
	// With no token cached there is nothing to fall back on, so an empty answer
	// fails the call instead of sending an empty bearer token.
	auth, cred, _ := newEntraAuth(t, time.Hour)
	cred.empty = true

	tok, err := auth.Token(context.Background())
	require.Error(t, err)
	assert.Empty(t, tok)
	assert.Contains(t, err.Error(), "Entra returned an empty token")

	cred.empty = false
	tok, err = auth.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "entra-token-2", tok, "the next call mints again")
}

func TestEachAuthenticatorBuildsItsOwnEntraCredential(t *testing.T) {
	build := func() *Authenticator {
		auth, err := NewAuthenticator(AuthOptions{
			TenantID:   "11111111-2222-3333-4444-555555555555",
			ClientID:   "66666666-7777-8888-9999-000000000000",
			Credential: vault.NewPasswordCredential("", "fake-client-secret"),
		})
		require.NoError(t, err)
		return auth
	}
	first, second := build(), build()

	assert.Equal(t, AuthEntra, first.Mode())
	require.NotNil(t, first.cred)
	require.NotNil(t, second.cred)
	assert.NotSame(t, first.cred, second.cred, "no credential, and so no token cache, is shared")
}

func TestErrorsNeverCarryTheSecretOrTheToken(t *testing.T) {
	const secret = "fake-secret-that-must-stay-hidden"
	const tenant = "11111111-2222-3333-4444-555555555555"
	const client = "66666666-7777-8888-9999-000000000000"

	build := []struct {
		name    string
		opts    AuthOptions
		wantErr string
	}{
		{
			name:    "a tenant without a client",
			opts:    AuthOptions{TenantID: tenant, Credential: vault.NewPasswordCredential("", secret)},
			wantErr: "tenant-id and client-id must be set together",
		},
		{
			name: "a certificate that does not parse",
			opts: AuthOptions{TenantID: tenant, ClientID: client, Credential: &vault.Credential{
				Type: vault.CredentialType_pkcs12, Secret: []byte(secret)}},
			wantErr: "cannot build the Entra credential",
		},
		{
			name: "a service principal with an unsupported credential",
			opts: AuthOptions{TenantID: tenant, ClientID: client, Credential: &vault.Credential{
				Type: vault.CredentialType_private_key, Secret: []byte(secret)}},
			wantErr: "cannot build the Entra credential",
		},
		{
			name: "a token of an unsupported type",
			opts: AuthOptions{Credential: &vault.Credential{
				Type: vault.CredentialType_private_key, Secret: []byte(secret)}},
			wantErr: "is not supported",
		},
	}
	for _, tc := range build {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAuthenticator(tc.opts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.NotContains(t, err.Error(), secret)
		})
	}

	t.Run("a mint that fails after the token expired", func(t *testing.T) {
		logs := captureLogs(t)
		auth, cred, clock := newEntraAuth(t, time.Hour)
		old, err := auth.Token(context.Background())
		require.NoError(t, err)

		cred.err = errors.New("invalid_client")
		clock.now = clock.now.Add(50 * time.Minute)
		_, err = auth.Token(context.Background())
		require.NoError(t, err, "the unexpired token is kept")
		clock.now = clock.now.Add(11 * time.Minute)
		_, err = auth.Token(context.Background())
		require.Error(t, err)

		assert.NotContains(t, err.Error(), old)
		assert.NotContains(t, logs.String(), old)
	})
}
