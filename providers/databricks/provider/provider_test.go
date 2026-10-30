// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/databricks/connection"
)

// clearEnv unsets the Databricks env vars so ParseCLI's fallbacks don't pick up
// ambient credentials during the test.
func clearEnv(t *testing.T) {
	for _, k := range []string{
		"DATABRICKS_ACCOUNT_ID", "DATABRICKS_HOST",
		"DATABRICKS_CLIENT_ID", "DATABRICKS_CLIENT_SECRET", "DATABRICKS_TOKEN",
	} {
		t.Setenv(k, "")
	}
}

func credByUser(creds []*vault.Credential, user string) *vault.Credential {
	for _, c := range creds {
		if c.User == user {
			return c
		}
	}
	return nil
}

func TestParseCLI_AccountPlane(t *testing.T) {
	clearEnv(t)
	s := &Service{Service: plugin.NewService()}

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "databricks",
		Flags: map[string]*llx.Primitive{
			"account-id":    llx.StringPrimitive("acc-123"),
			"client-id":     llx.StringPrimitive("client-abc"),
			"client-secret": llx.StringPrimitive("secret-xyz"),
		},
	})
	require.NoError(t, err)
	require.Len(t, res.Asset.Connections, 1)
	conf := res.Asset.Connections[0]

	assert.Equal(t, connection.PlaneAccount, conf.Options[connection.OptionPlane])
	assert.Equal(t, "acc-123", conf.Options[connection.OptionAccountID])
	assert.Equal(t, "client-abc", conf.Options[connection.OptionClientID])

	secret := credByUser(conf.Credentials, connection.CredentialClientSecret)
	require.NotNil(t, secret, "client secret credential should be present")
	assert.Equal(t, "secret-xyz", string(secret.Secret))
	assert.Nil(t, credByUser(conf.Credentials, connection.CredentialToken))
}

func TestParseCLI_WorkspacePlane(t *testing.T) {
	clearEnv(t)
	s := &Service{Service: plugin.NewService()}

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "databricks",
		Flags: map[string]*llx.Primitive{
			"host":  llx.StringPrimitive("https://myworkspace.cloud.databricks.com"),
			"token": llx.StringPrimitive("dapi-token"),
		},
	})
	require.NoError(t, err)
	conf := res.Asset.Connections[0]

	// No account id means a direct single-workspace connect.
	assert.Equal(t, connection.PlaneWorkspace, conf.Options[connection.OptionPlane])
	assert.Equal(t, "https://myworkspace.cloud.databricks.com", conf.Options[connection.OptionHost])
	assert.Empty(t, conf.Options[connection.OptionAccountID])

	token := credByUser(conf.Credentials, connection.CredentialToken)
	require.NotNil(t, token, "token credential should be present")
	assert.Equal(t, "dapi-token", string(token.Secret))
}
