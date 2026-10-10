// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package azauth

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetWorkloadIdentityToken(t *testing.T) {
	cred, err := GetWorkloadIdentityToken("tid", "cid", "/tmp/x.jwt")
	require.NoError(t, err)
	require.NotNil(t, cred)
}

type fakeCredential struct {
	err error
}

func (f *fakeCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: "token"}, nil
}

func TestParseCredentialMethods(t *testing.T) {
	t.Run("empty means every method", func(t *testing.T) {
		methods, err := ParseCredentialMethods("")
		require.NoError(t, err)
		assert.Nil(t, methods)
		assert.True(t, methods.Allows(CredentialMethodManagedIdentity))
	})

	t.Run("default and auto also mean every method", func(t *testing.T) {
		for _, in := range []string{"default", "auto", " , "} {
			methods, err := ParseCredentialMethods(in)
			require.NoError(t, err, in)
			assert.Nil(t, methods, in)
		}
	})

	t.Run("single method", func(t *testing.T) {
		methods, err := ParseCredentialMethods("workload-identity")
		require.NoError(t, err)
		assert.Equal(t, CredentialMethods{CredentialMethodWorkloadIdentity}, methods)
		assert.False(t, methods.Allows(CredentialMethodManagedIdentity))
	})

	t.Run("list keeps the caller's order", func(t *testing.T) {
		methods, err := ParseCredentialMethods("workload-identity,cli")
		require.NoError(t, err)
		assert.Equal(t, CredentialMethods{CredentialMethodWorkloadIdentity, CredentialMethodCLI}, methods)
	})

	t.Run("normalizes case, spacing, underscores, and duplicates", func(t *testing.T) {
		methods, err := ParseCredentialMethods(" Workload_Identity , workload-identity ")
		require.NoError(t, err)
		assert.Equal(t, CredentialMethods{CredentialMethodWorkloadIdentity}, methods)
	})

	// a real Azure auth concept that is simply not one of ours, which is the
	// likelier mistake than a misspelling
	t.Run("unknown method is an error, not a silent full chain", func(t *testing.T) {
		_, err := ParseCredentialMethods("service-principal")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service-principal")
		assert.Contains(t, err.Error(), "workload-identity")
	})
}

func TestGetDefaultChainedToken_RestrictsChain(t *testing.T) {
	t.Run("workload identity uses the configured client id", func(t *testing.T) {
		// NewWorkloadIdentityCredential errors without a client id, so a
		// credential coming back at all proves ClientID was passed through
		// rather than left to AZURE_CLIENT_ID.
		cred, err := GetDefaultChainedToken(&ChainedTokenOptions{
			TenantID:           "aba673d8-12f8-4315-90c1-848f09d747f1",
			ClientID:           "f424bc0b-7f95-4270-8ffc-694a52e60b9f",
			FederatedTokenFile: "/var/run/secrets/azure/tokens/azure-identity-token",
			Methods:            CredentialMethods{CredentialMethodWorkloadIdentity},
		})
		require.NoError(t, err)
		require.NotNil(t, cred)
	})

	t.Run("an unbuildable sole method surfaces why", func(t *testing.T) {
		// nothing to build the credential from, so the chain comes back empty
		// and we report the constructor error instead of the SDK's bare
		// "at least one credential required"
		_, err := GetDefaultChainedToken(&ChainedTokenOptions{
			Methods: CredentialMethods{CredentialMethodWorkloadIdentity},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no Azure credential source could be configured")
		assert.Contains(t, err.Error(), "specified")
	})

	t.Run("unknown method is rejected", func(t *testing.T) {
		_, err := GetDefaultChainedToken(&ChainedTokenOptions{Methods: CredentialMethods{"nope"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nope")
	})
}

// Managed identity is the only method that cannot fail fast: the others drop
// out of the chain at construction (env, workload identity) or in milliseconds
// (cli), while this one asks the instance metadata endpoint and waits 5s a try,
// three tries. Anywhere but last, a connection that had a working credential
// further down the chain still pays those 15 seconds -- once per asset, all
// scan long.
func TestDefaultCredentialMethods_ManagedIdentityIsLast(t *testing.T) {
	require.NotEmpty(t, DefaultCredentialMethods)
	assert.Equal(t, CredentialMethodManagedIdentity, DefaultCredentialMethods[len(DefaultCredentialMethods)-1])
	assert.ElementsMatch(t,
		CredentialMethods{
			CredentialMethodCLI, CredentialMethodEnv,
			CredentialMethodWorkloadIdentity, CredentialMethodManagedIdentity,
		},
		DefaultCredentialMethods,
		"every method still has to be in the default chain, only the order changed")
}

func TestCredentialSource(t *testing.T) {
	assert.Equal(t, "azure-connection", credentialSource("azure-connection"))
	assert.Equal(t, "unknown", credentialSource(""))
}

func TestHasFederatedTokenFile(t *testing.T) {
	t.Run("from the options", func(t *testing.T) {
		t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
		assert.True(t, hasFederatedTokenFile(&ChainedTokenOptions{FederatedTokenFile: "/tmp/x.jwt"}))
		assert.False(t, hasFederatedTokenFile(&ChainedTokenOptions{}))
		assert.False(t, hasFederatedTokenFile(nil))
	})

	t.Run("from the environment azidentity reads", func(t *testing.T) {
		t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/azure/tokens/azure-identity-token")
		assert.True(t, hasFederatedTokenFile(&ChainedTokenOptions{}))
	})
}

func TestCredentialMethods_Effective(t *testing.T) {
	assert.Equal(t, DefaultCredentialMethods, CredentialMethods(nil).Effective())
	assert.Equal(t, DefaultCredentialMethods, CredentialMethods{}.Effective())
	assert.Equal(t,
		CredentialMethods{CredentialMethodWorkloadIdentity},
		CredentialMethods{CredentialMethodWorkloadIdentity}.Effective())
}

func TestCredentialMethods_Allows(t *testing.T) {
	// an empty selection is not yet resolved, so it permits everything
	assert.True(t, CredentialMethods(nil).Allows(CredentialMethodManagedIdentity))
	assert.True(t, DefaultCredentialMethods.Allows(CredentialMethodCLI))
	assert.False(t, CredentialMethods{CredentialMethodWorkloadIdentity}.Allows(CredentialMethodCLI))
}

func TestCredentialMethods_Names(t *testing.T) {
	assert.Equal(t, "workload-identity", CredentialMethods{CredentialMethodWorkloadIdentity}.Names())
	assert.Equal(t, "cli, env, workload-identity, managed-identity", DefaultCredentialMethods.Names())
	// it renders what it is given: resolving an empty selection is the caller's
	// job, done once, rather than something this quietly repeats
	assert.Equal(t, "", CredentialMethods(nil).Names())
}

func TestGuidedCredential_EnrichesErrors(t *testing.T) {
	// the raw error azidentity's Azure CLI credential returns when the CLI
	// hands back something other than a token
	cliErr := errors.New("invalid character 'N' looking for beginning of value")

	t.Run("default chain with CLI JSON failure", func(t *testing.T) {
		cred := &guidedCredential{inner: &fakeCredential{err: cliErr}, usedDefaultChain: true}
		_, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "az login")
		assert.Contains(t, err.Error(), "Azure CLI returned something other than a sign-in token")
		// original error is preserved
		assert.Contains(t, err.Error(), "invalid character 'N'")
	})

	t.Run("default chain with generic failure", func(t *testing.T) {
		cred := &guidedCredential{inner: &fakeCredential{err: errors.New("boom")}, usedDefaultChain: true}
		_, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "No credentials were provided")
		assert.NotContains(t, err.Error(), "Azure CLI returned something other than")
		assert.Contains(t, err.Error(), "boom")
	})

	t.Run("restricted chain only names what was tried", func(t *testing.T) {
		cred := &guidedCredential{
			inner:            &fakeCredential{err: errors.New("boom")},
			usedDefaultChain: true,
			methods:          CredentialMethods{CredentialMethodWorkloadIdentity},
		}
		_, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "workload-identity")
		// no CLI in the chain, so no point telling anyone to run az login
		assert.NotContains(t, err.Error(), "az login")
		assert.NotContains(t, err.Error(), "managed-identity")
	})

	t.Run("explicit credentials failure", func(t *testing.T) {
		cred := &guidedCredential{inner: &fakeCredential{err: errors.New("boom")}, usedDefaultChain: false}
		_, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "double-check the tenant ID, client ID")
		assert.Contains(t, err.Error(), "boom")
	})

	t.Run("success passes through untouched", func(t *testing.T) {
		cred := &guidedCredential{inner: &fakeCredential{}, usedDefaultChain: true}
		tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{})
		require.NoError(t, err)
		assert.Equal(t, "token", tk.Token)
	})
}

func TestCliCredentialOptions(t *testing.T) {
	tenant := "00000000-0000-0000-0000-000000000001"
	sub := "00000000-0000-0000-0000-000000000002"

	opts := cliCredentialOptions(&ChainedTokenOptions{TenantID: tenant})
	assert.Equal(t, tenant, opts.TenantID, "--tenant-id reaches the CLI")
	assert.Empty(t, opts.Subscription)
	assert.Equal(t, []string{"*"}, opts.AdditionallyAllowedTenants)

	opts = cliCredentialOptions(&ChainedTokenOptions{TenantID: tenant, Subscription: sub})
	assert.Equal(t, sub, opts.Subscription, "the subscription selects the CLI account")
	assert.Empty(t, opts.TenantID, "az does not accept --tenant with --subscription")

	opts = cliCredentialOptions(&ChainedTokenOptions{})
	assert.Empty(t, opts.TenantID, "nothing set keeps the CLI's defaults")
	assert.Empty(t, opts.Subscription)
}
