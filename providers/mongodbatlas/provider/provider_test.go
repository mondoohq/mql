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
	"go.mondoo.com/mql/providers/mongodbatlas/connection"
)

func clearEnv(t *testing.T) {
	for _, k := range []string{
		"MONGODB_ATLAS_ORG_ID", "MONGODB_ATLAS_PROJECT_ID",
		"MONGODB_ATLAS_PUBLIC_KEY", "MONGODB_ATLAS_PRIVATE_KEY",
		"MONGODB_ATLAS_CLIENT_ID", "MONGODB_ATLAS_CLIENT_SECRET",
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

func TestParseCLI_OrgPlaneWithApiKey(t *testing.T) {
	clearEnv(t)
	s := &Service{Service: plugin.NewService()}

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "mongodbatlas",
		Flags: map[string]*llx.Primitive{
			"org-id":      llx.StringPrimitive("org-123"),
			"public-key":  llx.StringPrimitive("pub-abc"),
			"private-key": llx.StringPrimitive("priv-xyz"),
		},
	})
	require.NoError(t, err)
	conf := res.Asset.Connections[0]

	assert.Equal(t, connection.PlaneOrg, conf.Options[connection.OptionPlane])
	assert.Equal(t, "org-123", conf.Options[connection.OptionOrgID])
	assert.Equal(t, "pub-abc", conf.Options[connection.OptionPublicKey])

	priv := credByUser(conf.Credentials, connection.CredentialPrivateKey)
	require.NotNil(t, priv, "private key credential should be present")
	assert.Equal(t, "priv-xyz", string(priv.Secret))
}

func TestParseCLI_ProjectPlaneWithServiceAccount(t *testing.T) {
	clearEnv(t)
	s := &Service{Service: plugin.NewService()}

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "mongodbatlas",
		Flags: map[string]*llx.Primitive{
			"project-id":    llx.StringPrimitive("proj-456"),
			"client-id":     llx.StringPrimitive("client-abc"),
			"client-secret": llx.StringPrimitive("secret-xyz"),
		},
	})
	require.NoError(t, err)
	conf := res.Asset.Connections[0]

	// A project id scopes to a single project.
	assert.Equal(t, connection.PlaneProject, conf.Options[connection.OptionPlane])
	assert.Equal(t, "proj-456", conf.Options[connection.OptionProjectID])

	secret := credByUser(conf.Credentials, connection.CredentialClientSecret)
	require.NotNil(t, secret, "client secret credential should be present")
	assert.Equal(t, "secret-xyz", string(secret.Secret))
}
