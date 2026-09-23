// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestGithubNoConnection(t *testing.T) {
	os.Setenv("GITHUB_TOKEN", "")
	_, err := NewGithubConnection(0, &inventory.Asset{})
	require.Error(t, err)
}

func TestGithubValidConnection_Private_Key(t *testing.T) {
	// Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // 2048-bit key size
	require.NoError(t, err)
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	pemData := pem.EncodeToMemory(privateKeyPEM)

	_, err = NewGithubConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Options: map[string]string{
					OPTION_APP_ID:              "123",
					OPTION_APP_INSTALLATION_ID: "890",
				},
				Credentials: []*vault.Credential{
					{
						Type:   vault.CredentialType_private_key,
						Secret: pemData,
					},
				},
			},
		},
	})
	require.NoError(t, err)
}

func TestGithubValidConnection_Password(t *testing.T) {
	_, err := NewGithubConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Credentials: []*vault.Credential{
					{
						Type:   vault.CredentialType_password,
						Secret: []byte("super_secret"),
					},
				},
			},
		},
	})
	require.NoError(t, err)
}

func TestGithubRetryableClientSetsRequestTimeout(t *testing.T) {
	hc := &http.Client{}
	newGithubRetryableClient(hc)
	require.Equal(t, githubRequestTimeout, hc.Timeout)
}

func TestGithubRetryableClientKeepsExistingTimeout(t *testing.T) {
	hc := &http.Client{Timeout: time.Second}
	newGithubRetryableClient(hc)
	require.Equal(t, time.Second, hc.Timeout)
}

func TestGithubRetryableClientDoesNotMutateDefaultClient(t *testing.T) {
	newGithubRetryableClient(nil)
	require.Zero(t, http.DefaultClient.Timeout)
}

func TestGithubNeedsFix(t *testing.T) {
	t.Skip()
	p, err := NewGithubConnection(0, &inventory.Asset{})
	orgName := "mondoohq"
	client := p.Client()
	ctx := context.Background()
	org, _, err := client.Organizations.Get(ctx, orgName)
	require.NoError(t, err)
	require.NotNil(t, org)

	owners, _, err := client.Organizations.ListMembers(context.Background(), orgName, &github.ListMembersOptions{
		Role: "admin",
	})
	require.NoError(t, err)
	require.NotNil(t, owners)

	members, _, err := client.Organizations.ListMembers(context.Background(), orgName, nil)
	require.NoError(t, err)
	require.NotNil(t, members)

	// list public repositories for org "github"
	opt := &github.RepositoryListByOrgOptions{Type: "all"}
	repos, _, err := client.Repositories.ListByOrg(context.Background(), orgName, opt)
	require.NoError(t, err)
	require.NotNil(t, repos)

	apps, _, err := client.Organizations.ListInstallations(context.Background(), orgName, &github.ListOptions{})
	require.NoError(t, err)
	require.NotNil(t, apps)
}
