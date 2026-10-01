// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	azcore "github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/util/azauth"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// resetCredentialCache drops every cached credential. Tests need it because the
// cache outlives any one of them.
func resetCredentialCache() {
	credentialMu.Lock()
	defer credentialMu.Unlock()
	clear(credentialCache)
}

func cachedCredentialCount() int {
	credentialMu.Lock()
	defer credentialMu.Unlock()
	return len(credentialCache)
}

func secretConf(tenant, client, secret string) *inventory.Config {
	return &inventory.Config{
		Options:     map[string]string{OptionTenantID: tenant, OptionClientID: client},
		Credentials: []*vault.Credential{{Type: vault.CredentialType_password, Secret: []byte(secret)}},
	}
}

// selfSignedPEM returns a PEM bundle with a throwaway certificate and its key,
// in the shape azidentity.ParseCertificates accepts.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ms365-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})...)
}

// The credential is built once per identity and shared: a scan opens a
// connection per asset, and one credential per connection is a token request per
// asset for a tenant that already had a token.
func TestSelectMs365Credential_CachesAcrossConnections(t *testing.T) {
	resetCredentialCache()
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	first, _, err := selectMs365Credential(&inventory.Config{
		Options: map[string]string{OptionTenantID: "tid", OptionClientID: "cid"},
	})
	require.NoError(t, err)

	second, _, err := selectMs365Credential(&inventory.Config{
		Options: map[string]string{OptionTenantID: "tid", OptionClientID: "cid", OptionOrganization: "org"},
	})
	require.NoError(t, err)
	require.Same(t, first, second, "a connection under the same identity must reuse the credential")
}

// Handing tenant A's token to tenant B would not fail cleanly -- it would read
// the wrong tenant -- so each identity gets its own entry, and each is reused.
func TestSelectMs365Credential_CachesPerIdentity(t *testing.T) {
	resetCredentialCache()
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	first, _, err := selectMs365Credential(&inventory.Config{
		Options: map[string]string{OptionTenantID: "tenant-a", OptionClientID: "cid"},
	})
	require.NoError(t, err)

	second, _, err := selectMs365Credential(&inventory.Config{
		Options: map[string]string{OptionTenantID: "tenant-b", OptionClientID: "cid"},
	})
	require.NoError(t, err)
	require.NotSame(t, first, second, "a different tenant must get its own credential")

	againA, _, err := selectMs365Credential(&inventory.Config{
		Options: map[string]string{OptionTenantID: "tenant-a", OptionClientID: "cid"},
	})
	require.NoError(t, err)
	require.Same(t, first, againA)
}

// An unusable auth-method belongs to the connection that named it. Consulting
// the cache first would let a typo through on every connection after the one
// that built the credential.
func TestSelectMs365Credential_RejectsBadAuthMethodEvenWhenCached(t *testing.T) {
	resetCredentialCache()
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	_, _, err := selectMs365Credential(&inventory.Config{
		Options: map[string]string{OptionTenantID: "tid", OptionClientID: "cid"},
	})
	require.NoError(t, err)

	_, _, err = selectMs365Credential(&inventory.Config{
		Options: map[string]string{
			OptionTenantID:   "tid",
			OptionClientID:   "cid",
			OptionAuthMethod: "service-principal",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "service-principal")
}

// A rotated or corrected secret for the same app must build a new credential;
// reusing the cached one keeps signing in with the old secret until restart.
// The same secret again is still served from the cache.
func TestSelectMs365Credential_DifferentSecretsGetDifferentCredentials(t *testing.T) {
	resetCredentialCache()

	old, _, err := selectMs365Credential(secretConf("tid", "cid", "old-secret"))
	require.NoError(t, err)
	rotated, _, err := selectMs365Credential(secretConf("tid", "cid", "new-secret"))
	require.NoError(t, err)
	require.NotSame(t, old, rotated, "a different secret must not reuse the cached credential")

	again, _, err := selectMs365Credential(secretConf("tid", "cid", "new-secret"))
	require.NoError(t, err)
	require.Same(t, rotated, again, "the same secret must reuse the cached credential")
}

// A certificate and a secret for the same app are different credentials (some
// workloads, like SharePoint, accept only the certificate), and a keyless
// connection is a third.
func TestSelectMs365Credential_DifferentTypesGetDifferentCredentials(t *testing.T) {
	resetCredentialCache()
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	bySecret, _, err := selectMs365Credential(secretConf("tid", "cid", "s3cret"))
	require.NoError(t, err)

	byCert, _, err := selectMs365Credential(&inventory.Config{
		Options:     map[string]string{OptionTenantID: "tid", OptionClientID: "cid"},
		Credentials: []*vault.Credential{{Type: vault.CredentialType_pkcs12, Secret: selfSignedPEM(t)}},
	})
	require.NoError(t, err)
	require.NotSame(t, bySecret, byCert, "a certificate must not reuse the secret's credential")

	keyless, _, err := selectMs365Credential(&inventory.Config{
		Options: map[string]string{OptionTenantID: "tid", OptionClientID: "cid"},
	})
	require.NoError(t, err)
	require.NotSame(t, bySecret, keyless)
	require.NotSame(t, byCert, keyless)
}

// Keyless connections that name different sign-in methods get different chains.
func TestSelectMs365Credential_DifferentAuthMethodsGetDifferentChains(t *testing.T) {
	resetCredentialCache()
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	cli, _, err := selectMs365Credential(&inventory.Config{
		Options: map[string]string{OptionTenantID: "tid", OptionClientID: "cid", OptionAuthMethod: "cli"},
	})
	require.NoError(t, err)
	workload, _, err := selectMs365Credential(&inventory.Config{
		Options: map[string]string{OptionTenantID: "tid", OptionClientID: "cid", OptionAuthMethod: "workload-identity"},
	})
	require.NoError(t, err)
	require.NotSame(t, cli, workload)
}

func TestCredentialCacheKey(t *testing.T) {
	pw := func(secret, password string) *vault.Credential {
		return &vault.Credential{Type: vault.CredentialType_pkcs12, Secret: []byte(secret), Password: password}
	}

	// the certificate password is part of what decides the credential
	require.NotEqual(t,
		credentialCacheKey("tid", "cid", pw("cert", "a"), nil),
		credentialCacheKey("tid", "cid", pw("cert", "b"), nil))

	// length prefixes keep the secret/password boundary from being shifted
	require.NotEqual(t,
		credentialCacheKey("tid", "cid", pw("ab", "c"), nil),
		credentialCacheKey("tid", "cid", pw("a", "bc"), nil))

	// an empty auth-method is the default chain, spelled out or not
	require.Equal(t,
		credentialCacheKey("tid", "cid", nil, nil),
		credentialCacheKey("tid", "cid", nil, azauth.DefaultCredentialMethods))

	// the key never carries the secret itself
	key := credentialCacheKey("tid", "cid", &vault.Credential{Type: vault.CredentialType_password, Secret: []byte("hunter2-supersecret")}, nil)
	require.False(t, strings.Contains(key, "hunter2"), "cache key must not contain the secret: %s", key)
}

// Building a credential contacts nothing, so a wrong secret is only caught by
// the connection test. A credential that fails it must not stay cached, or a
// long-running process keeps handing it out after the secret is fixed.
func TestConnectMs365Credential_FailedVerifyEvicts(t *testing.T) {
	resetCredentialCache()
	conf := secretConf("tid", "cid", "wrong-secret")

	var failed azcore.TokenCredential
	_, err := connectMs365Credential(conf, func(tok azcore.TokenCredential) error {
		failed = tok
		return errors.New("AADSTS7000215: invalid client secret")
	})
	require.ErrorContains(t, err, "authentication failed")
	require.Equal(t, 0, cachedCredentialCount(), "a credential that failed to sign in must be evicted")

	var retried azcore.TokenCredential
	_, err = connectMs365Credential(conf, func(tok azcore.TokenCredential) error {
		retried = tok
		return nil
	})
	require.NoError(t, err)
	require.NotSame(t, failed, retried, "the retry must build a fresh credential")
	require.Equal(t, 1, cachedCredentialCount())
}

// A credential that signs in stays cached for the next connection.
func TestConnectMs365Credential_SuccessfulVerifyKeeps(t *testing.T) {
	resetCredentialCache()
	conf := secretConf("tid", "cid", "good-secret")
	ok := func(azcore.TokenCredential) error { return nil }

	first, err := connectMs365Credential(conf, ok)
	require.NoError(t, err)
	second, err := connectMs365Credential(conf, ok)
	require.NoError(t, err)
	require.Same(t, first, second)
}
