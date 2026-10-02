// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// The connection has to read an Access Token whether it arrives as the
// bearer credential ParseCLI now emits or as the bare password credential
// older inventories carry, and an App Password only when a username rides
// on the credential. A dropped branch here fails auth with a misleading
// "credentials required" or, worse, sends the token as an app password.
func TestNewBitbucketConnectionCredentialForms(t *testing.T) {
	for _, v := range []string{BITBUCKET_WORKSPACE_VAR, BITBUCKET_USERNAME_VAR, BITBUCKET_TOKEN_VAR, BITBUCKET_APP_PASSWORD_VAR} {
		t.Setenv(v, "")
	}
	cases := []struct {
		name         string
		cred         *vault.Credential
		wantToken    string
		wantUser     string
		wantPassword string
	}{
		{"bearer token", &vault.Credential{Type: vault.CredentialType_bearer, Secret: []byte("tok-bearer")}, "tok-bearer", "", ""},
		{"password credential without user is a token", vault.NewPasswordCredential("", "tok-legacy"), "tok-legacy", "", ""},
		{"password credential with user is an app password", vault.NewPasswordCredential("alice", "app-pw"), "", "alice", "app-pw"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := NewBitbucketConnection(1, &inventory.Asset{}, &inventory.Config{
				Options:     map[string]string{OPTION_WORKSPACE: "ws"},
				Credentials: []*vault.Credential{tc.cred},
			})
			if err != nil {
				t.Fatalf("NewBitbucketConnection: %v", err)
			}
			tr, ok := conn.client.httpClient.Transport.(*bitbucketAuthTransport)
			if !ok {
				t.Fatalf("transport is %T", conn.client.httpClient.Transport)
			}
			if tr.token != tc.wantToken || tr.username != tc.wantUser || tr.appPassword != tc.wantPassword {
				t.Fatalf("got token=%q user=%q appPassword=%q, want token=%q user=%q appPassword=%q",
					tr.token, tr.username, tr.appPassword, tc.wantToken, tc.wantUser, tc.wantPassword)
			}
		})
	}

	t.Run("no credential is an error", func(t *testing.T) {
		if _, err := NewBitbucketConnection(1, &inventory.Asset{}, &inventory.Config{Options: map[string]string{OPTION_WORKSPACE: "ws"}}); err == nil {
			t.Fatal("expected an error without credentials")
		}
	})
}
