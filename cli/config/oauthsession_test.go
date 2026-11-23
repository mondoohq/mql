// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	subject "go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/cli/oauthlogin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
)

const (
	sessionUser  = "//captain.api.mondoo.app/users/jane"
	sessionSpace = "//captain.api.mondoo.app/spaces/s1"
)

// sessionResult is a completed login for a space that ends at validUntil.
func sessionResult(validUntil time.Time) *oauthlogin.Result {
	return &oauthlogin.Result{
		Credential: oauthlogin.Credential{
			Mrn:         sessionUser,
			SpaceMrn:    sessionSpace,
			ScopeMrn:    sessionSpace,
			Token:       "the-login-token",
			ApiEndpoint: "https://api.example.com",
		},
		Endpoint:   "https://api.example.com",
		Issuer:     "https://login.example.com",
		ValidUntil: validUntil,
	}
}

// writeAndLoad persists the login result the way the login command does (viper
// with the CLI's key delimiter) and decodes it back into the config struct.
func writeAndLoad(t *testing.T, res *oauthlogin.Result) *subject.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mondoo.yml")

	w := viper.NewWithOptions(viper.KeyDelimiter("\\"))
	w.SetConfigFile(path)
	w.Set("agent_mrn", nil)
	for k, v := range res.ConfigValues() {
		w.Set(k, v)
	}
	require.NoError(t, w.WriteConfigAs(path))

	r := viper.NewWithOptions(viper.KeyDelimiter("\\"))
	r.SetConfigFile(path)
	require.NoError(t, r.ReadInConfig())
	var cfg subject.Config
	require.NoError(t, r.Unmarshal(&cfg))
	return &cfg
}

// A stored login session loads as a credential the existing client code
// accepts: the user's MRN and a token that is sent as a bearer token. It holds
// no key and no certificate, and is not a registered client.
func TestOAuthSessionConfig_LoadsAsBearerToken(t *testing.T) {
	res := sessionResult(time.Now().Add(time.Hour))
	cfg := writeAndLoad(t, res)

	assert.True(t, cfg.IsOAuthSession())
	assert.True(t, cfg.HasCredentials())
	assert.Empty(t, cfg.AgentMrn, "a session is not a registered client")
	assert.Empty(t, cfg.PrivateKey)
	assert.Empty(t, cfg.Certificate)
	assert.Equal(t, "https://login.example.com", cfg.Authentication.Issuer, "where the session is revoked")
	assert.Equal(t, "https://api.example.com", cfg.Authentication.Endpoint, "the server the session is for")

	cred := cfg.GetServiceCredential()
	require.NotNil(t, cred)
	assert.Equal(t, sessionUser, cred.Mrn)
	assert.Equal(t, sessionSpace, cred.ScopeMrn)
	assert.Equal(t, "https://api.example.com", cred.ApiEndpoint)
	assert.Equal(t, "the-login-token", cred.Token)
	assert.Empty(t, cred.PrivateKey)

	// the existing client authentication takes the token
	plugin, err := upstream.NewServiceAccountRangerPlugin(cred)
	require.NoError(t, err)
	assert.NotNil(t, plugin)

	validUntil, ok := cfg.SessionExpiry()
	require.True(t, ok)
	assert.WithinDuration(t, res.ValidUntil, validUntil, time.Second)
}

func TestOAuthSessionConfig_Expired(t *testing.T) {
	cfg := writeAndLoad(t, sessionResult(time.Now().Add(-time.Minute)))
	validUntil, ok := cfg.SessionExpiry()
	require.True(t, ok)
	assert.True(t, validUntil.Before(time.Now()))
	// still returned, so the caller's request fails with the server's error
	// after the expiry hint
	assert.NotNil(t, cfg.GetServiceCredential())
}

// A session whose end the server did not name has no known expiry.
func TestOAuthSessionConfig_NoExpiryRecorded(t *testing.T) {
	cfg := writeAndLoad(t, sessionResult(time.Time{}))
	_, ok := cfg.SessionExpiry()
	assert.False(t, ok)
	assert.NotNil(t, cfg.GetServiceCredential())
}

// A login to an organization stores the organization as its scope and no
// space.
func TestOAuthSessionConfig_ForAnOrganization(t *testing.T) {
	const org = "//captain.api.mondoo.app/organizations/acme"
	res := sessionResult(time.Now().Add(time.Hour))
	res.Credential.SpaceMrn = ""
	res.Credential.ScopeMrn = org
	res.Scope = oauthlogin.LoginScope{Mrn: org, Name: "acme", Kind: oauthlogin.ScopeKindOrganization, OrgName: "acme"}
	cfg := writeAndLoad(t, res)

	assert.Equal(t, org, cfg.GetScopeMrn())
	assert.Equal(t, org, cfg.GetServiceCredential().ScopeMrn)
	assert.Equal(t, oauthlogin.ScopeKindOrganization, cfg.Authentication.ScopeKind)
	assert.Equal(t, "acme", cfg.Authentication.ScopeName)
}

func TestHasCredentials(t *testing.T) {
	assert.False(t, (&subject.CommonOpts{}).HasCredentials())
	assert.True(t, (&subject.CommonOpts{ServiceAccountMrn: "x"}).HasCredentials())
	assert.True(t, (&subject.CommonOpts{Token: "x"}).HasCredentials())
	assert.True(t, (&subject.CommonOpts{Authentication: &subject.CliConfigAuthentication{Method: subject.AUTH_METHOD_WIF}}).HasCredentials())
	assert.False(t, (&subject.CommonOpts{ServiceAccountMrn: "x"}).IsOAuthSession())
	_, ok := (&subject.CommonOpts{ServiceAccountMrn: "x"}).SessionExpiry()
	assert.False(t, ok)
}

func TestOAuthSessionConfig_StoresNames(t *testing.T) {
	res := sessionResult(time.Now().Add(time.Hour))
	res.User = oauthlogin.User{Mrn: sessionUser, Email: "jane@example.com", Name: "Jane"}
	res.Scope = oauthlogin.LoginScope{Name: "prod", Kind: "space", OrgName: "acme"}
	cfg := writeAndLoad(t, res)

	require.NotNil(t, cfg.Authentication)
	assert.Equal(t, "jane@example.com", cfg.Authentication.UserEmail)
	assert.Equal(t, "Jane", cfg.Authentication.UserName)
	assert.Equal(t, sessionUser, cfg.Authentication.UserMrn)
	assert.Equal(t, "prod", cfg.Authentication.ScopeName)
	assert.Equal(t, "space", cfg.Authentication.ScopeKind)
	assert.Equal(t, "acme", cfg.Authentication.OrgName)
}
