// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func assetFor(options map[string]string, creds ...*vault.Credential) *inventory.Asset {
	return &inventory.Asset{
		Connections: []*inventory.Config{{
			Type:        "azuredevops",
			Options:     options,
			Credentials: creds,
		}},
	}
}

func patAsset(endpoint, pat string, extra map[string]string) *inventory.Asset {
	opts := map[string]string{
		OPTION_ORGANIZATION: fakeado.Org,
		OPTION_API_ENDPOINT: endpoint,
	}
	for k, v := range extra {
		opts[k] = v
	}
	return assetFor(opts, vault.NewPasswordCredential("", pat))
}

func TestVerifyWithAPersonalAccessToken(t *testing.T) {
	srv := fakeado.New(t)
	conn, err := NewAzuredevopsConnection(1, patAsset(srv.URL, fakeado.PAT, nil))
	require.NoError(t, err)

	assert.Equal(t, AuthPAT, conn.AuthMode())
	require.NoError(t, conn.Verify(context.Background()))

	data, err := conn.ConnectionData(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "hosted", data.DeploymentType)
	assert.Equal(t, "5e000000-0000-4000-8000-000000000001", data.InstanceID)
}

func TestVerifyWithEntra(t *testing.T) {
	srv := fakeado.New(t)
	asset := assetFor(map[string]string{
		OPTION_ORGANIZATION: fakeado.Org,
		OPTION_API_ENDPOINT: srv.URL,
	})
	conn, err := NewAzuredevopsConnection(1, asset, WithAuthenticator(entraAuth(t, fakeado.BearerToken)))
	require.NoError(t, err)

	assert.Equal(t, AuthEntra, conn.AuthMode())
	require.NoError(t, conn.Verify(context.Background()))
}

func TestVerifyExplainsARejectedCredential(t *testing.T) {
	srv := fakeado.New(t)

	t.Run("pat", func(t *testing.T) {
		conn, err := NewAzuredevopsConnection(1, patAsset(srv.URL, "a-token-the-server-refuses", nil))
		require.NoError(t, err)
		err = conn.Verify(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "personal access token")
		assert.Contains(t, err.Error(), "AZURE_DEVOPS_TOKEN")
		assert.NotContains(t, err.Error(), "a-token-the-server-refuses", "the error never echoes the secret")
		assert.True(t, IsUnauthorized(err), "the cause stays inspectable")
	})

	t.Run("entra", func(t *testing.T) {
		asset := assetFor(map[string]string{OPTION_ORGANIZATION: fakeado.Org, OPTION_API_ENDPOINT: srv.URL})
		conn, err := NewAzuredevopsConnection(1, asset, WithAuthenticator(entraAuth(t, "a-token-the-server-refuses")))
		require.NoError(t, err)
		err = conn.Verify(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Add it to the organization")
		assert.NotContains(t, err.Error(), "a-token-the-server-refuses", "the error never echoes the token")
		assert.True(t, IsUnauthorized(err))
	})
}

func TestVerifyExplainsAnUnknownOrganization(t *testing.T) {
	srv := fakeado.New(t)
	asset := patAsset(srv.URL, fakeado.PAT, map[string]string{OPTION_ORGANIZATION: "no-such-org"})
	conn, err := NewAzuredevopsConnection(1, asset)
	require.NoError(t, err)

	err = conn.Verify(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `organization "no-such-org" was not found`)
	assert.True(t, IsNotFound(err), "the cause stays inspectable")
}

func TestVerifyExplainsACredentialThatMayNotReadTheOrganization(t *testing.T) {
	// A 403 on connectionData is a cannot-read answer, told apart from a
	// rejected credential (401) and from an unknown organization (404) by its
	// status code, never by its message.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"some words that name no known status"}`))
	}))
	t.Cleanup(srv.Close)

	conn, err := NewAzuredevopsConnection(1, patAsset(srv.URL, fakeado.PAT, nil))
	require.NoError(t, err)
	err = conn.Verify(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "may not read organization")
	assert.True(t, IsNoAccess(err))
	assert.False(t, IsUnauthorized(err))
}

func TestVerifyRejectsAServerThatIsNotHosted(t *testing.T) {
	// Azure DevOps Server answers connectionData with another deployment type.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"instanceId":"5e000000-0000-4000-8000-0000000000ff","deploymentType":"onPremises"}`))
	}))
	t.Cleanup(srv.Close)

	conn, err := NewAzuredevopsConnection(1, patAsset(srv.URL, fakeado.PAT, nil))
	require.NoError(t, err)
	err = conn.Verify(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"onPremises"`)
	assert.Contains(t, err.Error(), "only Azure DevOps Services")
}

func TestConnectionOptions(t *testing.T) {
	cred := vault.NewPasswordCredential("", fakeado.PAT)

	cases := []struct {
		name    string
		options map[string]string
		wantErr string
	}{
		{name: "missing organization", options: map[string]string{}, wantErr: "is empty"},
		{name: "organization url", options: map[string]string{OPTION_ORGANIZATION: "https://dev.azure.com/" + fakeado.Org}},
		{name: "foreign host", options: map[string]string{OPTION_ORGANIZATION: "https://example.com/" + fakeado.Org}, wantErr: "not an Azure DevOps Services address"},
		{name: "repository without project", options: map[string]string{OPTION_ORGANIZATION: fakeado.Org, OPTION_REPOSITORY: "r"}, wantErr: "needs its project"},
		{name: "project without repository", options: map[string]string{OPTION_ORGANIZATION: fakeado.Org, OPTION_PROJECT: "p"}, wantErr: "project connection is not supported"},
		{name: "bad filter", options: map[string]string{OPTION_ORGANIZATION: fakeado.Org, OPTION_REPOS: "p/["}, wantErr: OPTION_REPOS},
		{name: "repository", options: map[string]string{OPTION_ORGANIZATION: fakeado.Org, OPTION_PROJECT: "scan test", OPTION_REPOSITORY: "ado-scan-test-iac"}},
		{name: "remote api endpoint", options: map[string]string{OPTION_ORGANIZATION: fakeado.Org, OPTION_API_ENDPOINT: "https://example.com"}, wantErr: "loopback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAzuredevopsConnection(1, assetFor(tc.options, cred))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	_, err := NewAzuredevopsConnection(1, nil)
	require.Error(t, err)
	_, err = NewAzuredevopsConnection(1, &inventory.Asset{})
	require.Error(t, err)
}

func TestConnectionPlatformAndShape(t *testing.T) {
	cred := vault.NewPasswordCredential("", fakeado.PAT)

	org, err := NewAzuredevopsConnection(1, assetFor(map[string]string{OPTION_ORGANIZATION: fakeado.Org}, cred))
	require.NoError(t, err)
	assert.False(t, org.IsRepository())
	assert.Equal(t, PlatformOrg, org.PlatformInfo().Name)
	assert.Equal(t, fakeado.Org, org.Organization())
	assert.Empty(t, org.Project())

	repo, err := NewAzuredevopsConnection(2, assetFor(map[string]string{
		OPTION_ORGANIZATION: fakeado.Org,
		OPTION_PROJECT:      "scan test",
		OPTION_REPOSITORY:   "ado-scan-test-iac",
	}, cred))
	require.NoError(t, err)
	assert.True(t, repo.IsRepository())
	assert.Equal(t, PlatformRepo, repo.PlatformInfo().Name)
	assert.Equal(t, "scan test", repo.Project())
	assert.Equal(t, "ado-scan-test-iac", repo.Repository())
	assert.Equal(t, uint32(2), repo.ID())
	assert.Equal(t, "azuredevops", repo.Name())
}

func TestOptionsHash(t *testing.T) {
	hashOf := func(org, secret string) uint64 {
		t.Helper()
		conn, err := NewAzuredevopsConnection(1, assetFor(
			map[string]string{OPTION_ORGANIZATION: org},
			vault.NewPasswordCredential("", secret)))
		require.NoError(t, err)
		return conn.OptionsHash
	}
	base := hashOf(fakeado.Org, "one")
	assert.Equal(t, base, hashOf(fakeado.Org, "one"), "the same options hash alike")
	assert.NotEqual(t, base, hashOf(fakeado.Org, "two"), "another secret needs another client")
	assert.NotEqual(t, base, hashOf("another-org", "one"), "another organization needs another client")
}

func TestHashDoesNotChangeWithTheProject(t *testing.T) {
	// A repository connection shares the verified client of its organization,
	// so the repository and the project are not part of the hash.
	cred := vault.NewPasswordCredential("", fakeado.PAT)
	org, err := NewAzuredevopsConnection(1, assetFor(map[string]string{OPTION_ORGANIZATION: fakeado.Org}, cred))
	require.NoError(t, err)
	repo, err := NewAzuredevopsConnection(2, assetFor(map[string]string{
		OPTION_ORGANIZATION: fakeado.Org,
		OPTION_PROJECT:      "scan test",
		OPTION_REPOSITORY:   "ado-scan-test-iac",
	}, cred))
	require.NoError(t, err)
	assert.Equal(t, org.OptionsHash, repo.OptionsHash)
}

func TestListingIsFetchedOnce(t *testing.T) {
	srv := fakeado.New(t)
	conn, err := NewAzuredevopsConnection(1, patAsset(srv.URL, fakeado.PAT, nil))
	require.NoError(t, err)

	first, err := conn.Listing(context.Background())
	require.NoError(t, err)
	before := len(srv.Requests())
	second, err := conn.Listing(context.Background())
	require.NoError(t, err)

	assert.Same(t, first, second)
	assert.Equal(t, before, len(srv.Requests()), "the second call must not touch the server")

	var projectCalls int
	for _, r := range srv.Requests() {
		if strings.HasPrefix(r, "/"+fakeado.Org+"/_apis/projects") {
			projectCalls++
		}
	}
	assert.Equal(t, 2, projectCalls, "two pages of projects, once")
}

func TestListingKeepsAnOrganizationWhoseProjectsAreSomeUnreadable(t *testing.T) {
	// The fixture organization has one project the credential cannot read. The
	// others still list, so the connection is usable.
	srv := fakeado.New(t)
	conn, err := NewAzuredevopsConnection(1, patAsset(srv.URL, fakeado.PAT, nil))
	require.NoError(t, err)

	listing, err := conn.Listing(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"locked-down"}, listing.Unreadable())
	assert.NotEmpty(t, listing.Repos())
}

func TestListingFailsWhenNoProjectIsReadable(t *testing.T) {
	srv := fakeado.New(t)
	conn, err := NewAzuredevopsConnection(1, patAsset(srv.URL, fakeado.PAT, nil))
	require.NoError(t, err)

	// Hide the repository list of every project: each answers 404, which is how
	// Azure DevOps says "not yours" for a project the principal cannot see.
	projects, err := conn.Client().Projects(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	for _, p := range projects {
		srv.HideRepositories(p.Name)
	}

	listing, err := conn.Listing(context.Background())
	require.Error(t, err, "a credential that reads nothing must not look like an empty organization")
	assert.Nil(t, listing)

	msg := err.Error()
	assert.Contains(t, msg, `organization "`+fakeado.Org+`"`)
	assert.Contains(t, msg, "any of its 4 projects")
	assert.NotContains(t, msg, fakeado.PAT, "the error never echoes the secret")

	// The verdict is kept, like the listing: the second call neither asks the
	// server again nor changes its mind.
	before := len(srv.Requests())
	_, again := conn.Listing(context.Background())
	require.Error(t, again)
	assert.Equal(t, before, len(srv.Requests()))
}

// Azure DevOps leaves the projects a credential cannot read out of the list,
// so a service principal in no project sees an empty organization. That must
// fail discovery, not report zero repositories.
func TestListingWithNoVisibleProjectIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"count":0,"value":[]}`))
	}))
	t.Cleanup(srv.Close)

	conn, err := NewAzuredevopsConnection(1, patAsset(srv.URL, fakeado.PAT, nil))
	require.NoError(t, err)

	_, err = conn.Listing(context.Background())
	require.Error(t, err, "no visible project must not look like an empty organization")
	assert.Contains(t, err.Error(), "sees no projects")
	assert.NotContains(t, err.Error(), fakeado.PAT, "the error never echoes the secret")
}

func TestGitCredentialForAPAT(t *testing.T) {
	srv := fakeado.New(t)
	conn, err := NewAzuredevopsConnection(1, patAsset(srv.URL, fakeado.PAT, nil))
	require.NoError(t, err)

	cred, err := conn.GitCredential(context.Background())
	require.NoError(t, err)
	assert.Equal(t, GitCredentialUser, cred.User)
	assert.Equal(t, fakeado.PAT, string(cred.Secret))
}

func TestTheSecretOfTheAssetIsTheOneThatAuthenticates(t *testing.T) {
	srv := fakeado.New(t)
	opts := map[string]string{OPTION_ORGANIZATION: fakeado.Org, OPTION_API_ENDPOINT: srv.URL}

	// The secret is not the first entry of the credential list: an empty slot
	// and a credential of another kind come before it.
	bearer := &vault.Credential{Type: vault.CredentialType_bearer, Secret: []byte("not-a-pat")}
	good, err := NewAzuredevopsConnection(1, assetFor(opts, nil, bearer, vault.NewPasswordCredential("", fakeado.PAT)))
	require.NoError(t, err)
	require.NoError(t, good.Verify(context.Background()), "the server only accepts the PAT the asset carries")

	// The same shape with another secret is turned away, so the value that
	// authenticated above came from the asset and from nowhere else.
	bad, err := NewAzuredevopsConnection(2, assetFor(opts, nil, bearer, vault.NewPasswordCredential("", "another-secret")))
	require.NoError(t, err)
	err = bad.Verify(context.Background())
	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))
}

func TestEntraReceivesTheCredentialOfTheAsset(t *testing.T) {
	// A nil credential makes the Azure sign-in chain fall back to whatever login
	// the machine has. So when the asset carries a credential, the constructor
	// must hand it to the authenticator. The proof is that a credential that
	// cannot be used fails the constructor, where a dropped one would have
	// quietly signed in some other way.
	entraOpts := map[string]string{
		OPTION_ORGANIZATION: fakeado.Org,
		OPTION_TENANT_ID:    "11111111-2222-3333-4444-555555555555",
		OPTION_CLIENT_ID:    "66666666-7777-8888-9999-000000000000",
	}

	t.Run("a certificate that cannot be read", func(t *testing.T) {
		bad := &vault.Credential{Type: vault.CredentialType_pkcs12, Secret: []byte("this is not a certificate")}
		_, err := NewAzuredevopsConnection(1, assetFor(entraOpts, bad))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot build the Entra credential")
		assert.NotContains(t, err.Error(), "this is not a certificate")
	})

	t.Run("a credential of a kind that cannot sign in", func(t *testing.T) {
		bearer := &vault.Credential{Type: vault.CredentialType_bearer, Secret: []byte("not-a-client-secret")}
		_, err := NewAzuredevopsConnection(1, assetFor(entraOpts, bearer))
		require.Error(t, err, "a credential the asset carries is never silently dropped")
		assert.Contains(t, err.Error(), "cannot build the Entra credential")
		assert.NotContains(t, err.Error(), "not-a-client-secret")
	})

	t.Run("a client secret", func(t *testing.T) {
		conn, err := NewAzuredevopsConnection(1, assetFor(entraOpts, vault.NewPasswordCredential("", "a-client-secret")))
		require.NoError(t, err)
		assert.Equal(t, AuthEntra, conn.AuthMode())
	})
}

func TestEntraWithoutACredentialKeepsTheDefaultSignIn(t *testing.T) {
	// An asset with a tenant and a client and no credential is deliberate: a
	// person who ran az login on the machine signs in with that session.
	// Building the chain logs which sign-in methods it will try. This test does
	// not need that line.
	prev := log.Logger
	log.Logger = zerolog.Nop()
	t.Cleanup(func() { log.Logger = prev })

	conn, err := NewAzuredevopsConnection(1, assetFor(map[string]string{
		OPTION_ORGANIZATION: fakeado.Org,
		OPTION_TENANT_ID:    "11111111-2222-3333-4444-555555555555",
		OPTION_CLIENT_ID:    "66666666-7777-8888-9999-000000000000",
	}))
	require.NoError(t, err)
	assert.Equal(t, AuthEntra, conn.AuthMode())
}

func TestNoCredentialAndNoServicePrincipalIsAnError(t *testing.T) {
	_, err := NewAzuredevopsConnection(1, assetFor(map[string]string{OPTION_ORGANIZATION: fakeado.Org}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credentials")
}

// A credential that is present but of a kind the personal access token path
// cannot use must be named by its type. Saying "no credentials" sends the user
// looking for a credential they already supplied.
func TestAnUnusableCredentialTypeIsNamedAndNeverEchoed(t *testing.T) {
	const secret = "fake-secret-that-must-never-be-printed"
	cases := []struct {
		name string
		cred *vault.Credential
		kind string
	}{
		{name: "bearer", cred: &vault.Credential{Type: vault.CredentialType_bearer, Secret: []byte(secret)}, kind: "bearer"},
		{name: "pkcs12", cred: &vault.Credential{Type: vault.CredentialType_pkcs12, Secret: []byte(secret)}, kind: "pkcs12"},
		{name: "bearer without a secret", cred: &vault.Credential{Type: vault.CredentialType_bearer}, kind: "bearer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAzuredevopsConnection(1, assetFor(map[string]string{OPTION_ORGANIZATION: fakeado.Org}, tc.cred))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "credential type "+tc.kind+" is not supported")
			assert.Contains(t, err.Error(), "personal access token")
			assert.NotContains(t, err.Error(), "no credentials")
			assert.NotContains(t, err.Error(), secret)
		})
	}

	t.Run("the authenticator reports the same", func(t *testing.T) {
		_, err := NewAuthenticator(AuthOptions{Credential: &vault.Credential{Type: vault.CredentialType_bearer, Secret: []byte(secret)}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential type bearer is not supported")
		assert.NotContains(t, err.Error(), secret)
	})
}
