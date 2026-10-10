// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	subscriptions "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestSelectAzureCredential_WorkloadIdentity(t *testing.T) {
	resetCredentialCache()
	// Set up an env var pointing to a (non-existent) token file.
	// Construction of WorkloadIdentityCredential does not read the file —
	// it is read lazily at GetToken time — so the file need not exist.
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	conf := &inventory.Config{
		Options: map[string]string{
			"tenant-id":       "tid",
			"client-id":       "cid",
			"subscription-id": "sub",
		},
		Credentials: nil,
	}

	cred, err := selectAzureCredential(conf)
	require.NoError(t, err)
	require.NotNil(t, cred)
}

func TestSelectAzureCredential_WorkloadIdentity_ViaOption(t *testing.T) {
	resetCredentialCache()
	// Ensure env var is not set so we test the option path exclusively.
	// Save and restore to avoid permanently clobbering the env for later tests.
	prev, ok := os.LookupEnv("AZURE_FEDERATED_TOKEN_FILE")
	os.Unsetenv("AZURE_FEDERATED_TOKEN_FILE")
	t.Cleanup(func() {
		if ok {
			os.Setenv("AZURE_FEDERATED_TOKEN_FILE", prev)
		} else {
			os.Unsetenv("AZURE_FEDERATED_TOKEN_FILE")
		}
	})

	conf := &inventory.Config{
		Options: map[string]string{
			"tenant-id":                  "tid",
			"client-id":                  "cid",
			"subscription-id":            "sub",
			"azure-federated-token-file": "/tmp/x.jwt",
		},
		Credentials: nil,
	}

	cred, err := selectAzureCredential(conf)
	require.NoError(t, err)
	require.NotNil(t, cred)
}

// TestSelectAzureCredential_VaultCredWins asserts that an explicit vault
// credential takes precedence over a federated token file env var. Even when
// AZURE_FEDERATED_TOKEN_FILE is set, the vault credential path must be taken,
// so the returned credential must not be a WorkloadIdentityCredential.
func TestSelectAzureCredential_VaultCredWins(t *testing.T) {
	resetCredentialCache()
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	conf := &inventory.Config{
		Options: map[string]string{
			"tenant-id": "tid",
			"client-id": "cid",
		},
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, Secret: []byte("secret")},
		},
	}

	cred, err := selectAzureCredential(conf)
	require.NoError(t, err)
	require.NotNil(t, cred)
	_, isWIF := cred.(*azidentity.WorkloadIdentityCredential)
	require.False(t, isWIF, "vault credential must win over federated token file env var")
}

// TestSelectAzureCredential_DefaultChain asserts that when neither a vault
// credential nor a federated token file is present, selectAzureCredential
// falls through to the default credential chain — which must not be a
// WorkloadIdentityCredential.
func TestSelectAzureCredential_DefaultChain(t *testing.T) {
	resetCredentialCache()
	// Unset the env var and restore it after the test.
	prev, ok := os.LookupEnv("AZURE_FEDERATED_TOKEN_FILE")
	os.Unsetenv("AZURE_FEDERATED_TOKEN_FILE")
	t.Cleanup(func() {
		if ok {
			os.Setenv("AZURE_FEDERATED_TOKEN_FILE", prev)
		} else {
			os.Unsetenv("AZURE_FEDERATED_TOKEN_FILE")
		}
	})

	conf := &inventory.Config{
		Options: map[string]string{
			"tenant-id": "tid",
			"client-id": "cid",
		},
		Credentials: nil,
	}

	cred, err := selectAzureCredential(conf)
	require.NoError(t, err)
	require.NotNil(t, cred)
	_, isWIF := cred.(*azidentity.WorkloadIdentityCredential)
	require.False(t, isWIF, "no vault cred + no token file must fall through to the default chain, not WorkloadIdentityCredential")
}

// resetCredentialCache drops every cached credential. Tests need it because the
// cache outlives any one of them.
func resetCredentialCache() {
	credentialMu.Lock()
	defer credentialMu.Unlock()
	clear(credentialCache)
}

// unsetFederatedTokenFile clears AZURE_FEDERATED_TOKEN_FILE for the duration of
// the test and restores whatever was there before.
func unsetFederatedTokenFile(t *testing.T) {
	t.Helper()
	prev, ok := os.LookupEnv("AZURE_FEDERATED_TOKEN_FILE")
	os.Unsetenv("AZURE_FEDERATED_TOKEN_FILE")
	t.Cleanup(func() {
		if ok {
			os.Setenv("AZURE_FEDERATED_TOKEN_FILE", prev)
		} else {
			os.Unsetenv("AZURE_FEDERATED_TOKEN_FILE")
		}
	})
}

// TestSelectAzureCredential_AuthMethodRestrictsChain asserts that naming an
// auth method really does narrow the chain rather than just reordering it.
// Nothing here can build a WorkloadIdentityCredential (no token file anywhere),
// so a chain restricted to workload identity has to come back empty and error.
// A chain that had quietly kept the CLI and managed identity probes would have
// succeeded instead — and gone on to burn ~15s per asset probing them.
func TestSelectAzureCredential_AuthMethodRestrictsChain(t *testing.T) {
	resetCredentialCache()
	unsetFederatedTokenFile(t)

	conf := &inventory.Config{
		Options: map[string]string{
			"tenant-id":   "tid",
			"client-id":   "cid",
			"auth-method": "workload-identity",
		},
		Credentials: nil,
	}

	_, err := selectAzureCredential(conf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no Azure credential source could be configured")
}

// TestSelectAzureCredential_AuthMethodWorkloadIdentity covers the deployment
// this option exists for: the inventory names workload identity, the pod's
// webhook supplies the token file, and no client secret is in play.
func TestSelectAzureCredential_AuthMethodWorkloadIdentity(t *testing.T) {
	resetCredentialCache()
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	conf := &inventory.Config{
		Options: map[string]string{
			"tenant-id":   "aba673d8-12f8-4315-90c1-848f09d747f1",
			"client-id":   "f424bc0b-7f95-4270-8ffc-694a52e60b9f",
			"auth-method": "workload-identity",
		},
		Credentials: nil,
	}

	cred, err := selectAzureCredential(conf)
	require.NoError(t, err)
	require.NotNil(t, cred)
}

// TestSelectAzureCredential_AuthMethodWorkloadIdentity_TokenFileFromOption is
// the version of the test above that actually proves the plumbing. With
// AZURE_FEDERATED_TOKEN_FILE unset, the only way to build the credential is for
// the option to be forwarded as ChainedTokenOptions.FederatedTokenFile: drop
// that and the chain comes back empty. The env-var version passes either way,
// because azidentity reads that variable itself.
func TestSelectAzureCredential_AuthMethodWorkloadIdentity_TokenFileFromOption(t *testing.T) {
	resetCredentialCache()
	unsetFederatedTokenFile(t)

	conf := &inventory.Config{
		Options: map[string]string{
			"tenant-id":                  "tid",
			"client-id":                  "cid",
			"azure-federated-token-file": "/tmp/x.jwt",
			"auth-method":                "workload-identity",
		},
		Credentials: nil,
	}

	cred, err := selectAzureCredential(conf)
	require.NoError(t, err)
	require.NotNil(t, cred)
}

// TestSelectAzureCredential_AuthMethodBeatsTokenFile asserts that an explicit
// method selection wins over a federated token file. The file can be a leftover
// env var from the pod spec, so it must not silently override what the
// inventory asked for.
func TestSelectAzureCredential_AuthMethodBeatsTokenFile(t *testing.T) {
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	conf := &inventory.Config{
		Options: map[string]string{
			"tenant-id":   "tid",
			"client-id":   "cid",
			"auth-method": "cli",
		},
		Credentials: nil,
	}

	cred, err := selectAzureCredential(conf)
	require.NoError(t, err)
	require.NotNil(t, cred)
	_, isWIF := cred.(*azidentity.WorkloadIdentityCredential)
	require.False(t, isWIF, "an explicit auth-method must win over a federated token file")
}

func TestSelectAzureCredential_InvalidAuthMethod(t *testing.T) {
	conf := &inventory.Config{
		Options: map[string]string{"auth-method": "service-principal"},
	}

	_, err := selectAzureCredential(conf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "service-principal")
}

// The credential is built once and shared: every discovered asset gets its own
// connection, and one credential per connection means one token request per
// asset for an identity that already had a token.
func TestSelectAzureCredential_CachesAcrossConnections(t *testing.T) {
	resetCredentialCache()
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	conf := &inventory.Config{
		Options: map[string]string{"tenant-id": "tid", "client-id": "cid"},
	}
	first, err := selectAzureCredential(conf)
	require.NoError(t, err)

	// a discovered asset: same identity, its own config
	child := &inventory.Config{
		Options: map[string]string{"tenant-id": "tid", "client-id": "cid", "subscription-id": "sub"},
	}
	second, err := selectAzureCredential(child)
	require.NoError(t, err)
	require.Same(t, first, second, "an asset under the same identity must reuse the credential")
}

// An inventory can hold Azure assets under different tenants. Reusing the first
// tenant's credential for the second would not fail -- it would quietly scan as
// the wrong principal -- so each identity gets its own entry, and each of those
// is reused the same way.
func TestSelectAzureCredential_CachesPerIdentity(t *testing.T) {
	resetCredentialCache()
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	first, err := selectAzureCredential(&inventory.Config{
		Options: map[string]string{"tenant-id": "tenant-a", "client-id": "cid"},
	})
	require.NoError(t, err)

	second, err := selectAzureCredential(&inventory.Config{
		Options: map[string]string{"tenant-id": "tenant-b", "client-id": "cid"},
	})
	require.NoError(t, err)
	require.NotSame(t, first, second, "a different tenant must get its own credential")

	// both entries survive each other, and both are reused
	againA, err := selectAzureCredential(&inventory.Config{
		Options: map[string]string{"tenant-id": "tenant-a", "client-id": "cid"},
	})
	require.NoError(t, err)
	require.Same(t, first, againA)

	againB, err := selectAzureCredential(&inventory.Config{
		Options: map[string]string{"tenant-id": "tenant-b", "client-id": "cid"},
	})
	require.NoError(t, err)
	require.Same(t, second, againB)
}

// A build that fails must not be remembered as the answer for that identity.
func TestSelectAzureCredential_DoesNotCacheFailures(t *testing.T) {
	resetCredentialCache()
	unsetFederatedTokenFile(t)

	conf := &inventory.Config{
		Options: map[string]string{
			"tenant-id":   "tid",
			"client-id":   "cid",
			"auth-method": "workload-identity",
		},
	}
	_, err := selectAzureCredential(conf)
	require.Error(t, err)

	// with a token file in place the same identity builds fine, which it could
	// not do if the failure had been cached
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")
	cred, err := selectAzureCredential(conf)
	require.NoError(t, err)
	require.NotNil(t, cred)
}

// An unusable auth-method belongs to the connection that named it. Consulting
// the cache first would let a typo through on every connection after the one
// that built the credential.
func TestSelectAzureCredential_RejectsBadAuthMethodEvenWhenCached(t *testing.T) {
	resetCredentialCache()
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	_, err := selectAzureCredential(&inventory.Config{
		Options: map[string]string{"tenant-id": "tid", "client-id": "cid"},
	})
	require.NoError(t, err)

	_, err = selectAzureCredential(&inventory.Config{
		Options: map[string]string{
			"tenant-id":   "tid",
			"client-id":   "cid",
			"auth-method": "service-principal",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "service-principal")
}

// A connection with no subscription has no record to fetch: the caller named
// several subscriptions or none, and discovery enumerates them instead.
func TestSubscriptionRequiresAScopedConnection(t *testing.T) {
	conn := &AzureConnection{}
	_, err := conn.Subscription()
	require.Error(t, err)
	require.Contains(t, err.Error(), "not scoped to a subscription")
}

// A cached record is served without a client round-trip: a pre-seeded record
// comes straight back even though the connection has no credentials to fetch
// anything with.
func TestSubscriptionServesTheCachedRecord(t *testing.T) {
	name := "Production"
	conn := &AzureConnection{
		subscriptionId: "sub",
		subRecord:      &subscriptions.Subscription{DisplayName: &name},
	}
	record, err := conn.Subscription()
	require.NoError(t, err)
	require.Equal(t, "Production", *record.DisplayName)
}

// Without a tenant option, the Azure CLI signs in for each connection's
// subscription, which can belong to another account and tenant, so a
// subscription gets its own credential; the same subscription reuses it.
func TestSelectAzureCredential_CachesPerSubscriptionWithoutTenant(t *testing.T) {
	resetCredentialCache()
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/x.jwt")

	first, err := selectAzureCredential(&inventory.Config{
		Options: map[string]string{"subscription-id": "sub-a"},
	})
	require.NoError(t, err)

	second, err := selectAzureCredential(&inventory.Config{
		Options: map[string]string{"subscription-id": "sub-b"},
	})
	require.NoError(t, err)
	require.NotSame(t, first, second, "a subscription without a tenant option must get its own credential")

	againA, err := selectAzureCredential(&inventory.Config{
		Options: map[string]string{"subscription-id": "sub-a"},
	})
	require.NoError(t, err)
	require.Same(t, first, againA)
}
