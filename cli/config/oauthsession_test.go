// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

func sessionResult(t *testing.T, notAfter time.Time) *oauthlogin.Result {
	t.Helper()
	key, err := oauthlogin.GenerateKey()
	require.NoError(t, err)
	caKey, err := oauthlogin.GenerateKey()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "session"},
		NotBefore:    notAfter.Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, caKey)
	require.NoError(t, err)
	keyPEM, err := oauthlogin.EncodePrivateKeyPEM(key)
	require.NoError(t, err)

	return &oauthlogin.Result{
		ServiceAccount: oauthlogin.ServiceAccount{
			Mrn:         "//agents.api.mondoo.app/spaces/s1/serviceaccounts/session1",
			SpaceMrn:    "//captain.api.mondoo.app/spaces/s1",
			ScopeMrn:    "//captain.api.mondoo.app/spaces/s1",
			Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			ApiEndpoint: "https://api.example.com",
		},
		PrivateKeyPEM: keyPEM,
		Issuer:        "https://api.example.com",
		AccessToken:   "opaque-session-id",
		ValidUntil:    notAfter,
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

func TestOAuthSessionConfig_LoadsAsServiceAccount(t *testing.T) {
	res := sessionResult(t, time.Now().Add(time.Hour))
	cfg := writeAndLoad(t, res)

	assert.True(t, cfg.IsOAuthSession())
	assert.True(t, cfg.HasCredentials())
	assert.Empty(t, cfg.AgentMrn, "a session is not a registered client")
	assert.Equal(t, res.Issuer, cfg.Authentication.Issuer)
	assert.Equal(t, res.AccessToken, cfg.Authentication.AccessToken)

	cred := cfg.GetServiceCredential()
	require.NotNil(t, cred)
	assert.Equal(t, res.ServiceAccount.Mrn, cred.Mrn)
	assert.Equal(t, res.ServiceAccount.ScopeMrn, cred.ScopeMrn)
	assert.Equal(t, "https://api.example.com", cred.ApiEndpoint)
	assert.Equal(t, res.PrivateKeyPEM, cred.PrivateKey)

	// the existing certificate authentication accepts the stored key
	plugin, err := upstream.NewServiceAccountRangerPlugin(cred)
	require.NoError(t, err)
	assert.NotNil(t, plugin)

	notAfter, ok := cfg.SessionExpiry()
	require.True(t, ok)
	assert.WithinDuration(t, res.ValidUntil, notAfter, time.Second)
}

func TestOAuthSessionConfig_Expired(t *testing.T) {
	cfg := writeAndLoad(t, sessionResult(t, time.Now().Add(-time.Minute)))
	notAfter, ok := cfg.SessionExpiry()
	require.True(t, ok)
	assert.True(t, notAfter.Before(time.Now()))
	// still returned, so the caller's request fails with the server's error
	// after the expiry hint
	assert.NotNil(t, cfg.GetServiceCredential())
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
