// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestGetToken_FromOptions(t *testing.T) {
	conf := &inventory.Config{
		Options: map[string]string{OPTION_TOKEN: "api-token"},
	}
	token, ok := GetToken(conf)
	assert.True(t, ok)
	assert.Equal(t, "api-token", token)
}

func TestGetToken_FromPasswordCredential(t *testing.T) {
	conf := &inventory.Config{
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, Secret: []byte("api-token")},
		},
	}
	token, ok := GetToken(conf)
	assert.True(t, ok)
	assert.Equal(t, "api-token", token)
}

func TestGetToken_IgnoresCredentialInOAuthMode(t *testing.T) {
	conf := &inventory.Config{
		Options: map[string]string{OPTION_CLIENT_ID: "oauth-client-id"},
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, Secret: []byte("oauth-client-secret")},
		},
	}
	token, ok := GetToken(conf)
	assert.False(t, ok)
	assert.Empty(t, token)
}

func TestGetClientSecret_FromOptions(t *testing.T) {
	conf := &inventory.Config{
		Options: map[string]string{
			OPTION_CLIENT_ID:     "oauth-client-id",
			OPTION_CLIENT_SECRET: "oauth-client-secret",
		},
	}
	secret, ok := GetClientSecret(conf)
	assert.True(t, ok)
	assert.Equal(t, "oauth-client-secret", secret)
}

func TestGetClientSecret_FromPasswordCredentialInOAuthMode(t *testing.T) {
	conf := &inventory.Config{
		Options: map[string]string{OPTION_CLIENT_ID: "oauth-client-id"},
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, Secret: []byte("oauth-client-secret")},
		},
	}
	secret, ok := GetClientSecret(conf)
	assert.True(t, ok)
	assert.Equal(t, "oauth-client-secret", secret)
}

func TestGetClientSecret_IgnoresCredentialWithoutClientID(t *testing.T) {
	conf := &inventory.Config{
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, Secret: []byte("api-token")},
		},
	}
	secret, ok := GetClientSecret(conf)
	assert.False(t, ok)
	assert.Empty(t, secret)
}

func TestAuthenticationMethod_OAuthFromCredentials(t *testing.T) {
	conf := &inventory.Config{
		Options: map[string]string{OPTION_CLIENT_ID: "oauth-client-id"},
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, Secret: []byte("oauth-client-secret")},
		},
	}
	assert.Equal(t, OAuthMethod, AuthenticationMethod(conf))
}

func TestAuthenticationMethod_TokenFromCredential(t *testing.T) {
	conf := &inventory.Config{
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, Secret: []byte("api-token")},
		},
	}
	assert.Equal(t, TokenAuthMethod, AuthenticationMethod(conf))
}
