// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/github/connection"
)

const testPEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"

func appFlags(extra map[string]*llx.Primitive) map[string]*llx.Primitive {
	flags := map[string]*llx.Primitive{
		connection.OPTION_APP_ID:              llx.StringPrimitive("123"),
		connection.OPTION_APP_INSTALLATION_ID: llx.StringPrimitive("456"),
	}
	maps.Copy(flags, extra)
	return flags
}

func TestParseCLI_AppPrivateKeyContentFlag(t *testing.T) {
	s := Init()
	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: ConnectionType,
		Args:      []string{"org", "my-org"},
		Flags: appFlags(map[string]*llx.Primitive{
			connection.OPTION_APP_PRIVATE_KEY_CONTENT: llx.StringPrimitive(testPEM),
		}),
	})
	require.NoError(t, err)

	conf := res.Asset.Connections[0]
	// content must not leak into the path option
	assert.Empty(t, conf.Options[connection.OPTION_APP_PRIVATE_KEY])

	require.Len(t, conf.Credentials, 1)
	cred := conf.Credentials[0]
	assert.Equal(t, vault.CredentialType_private_key, cred.Type)
	assert.Equal(t, testPEM, string(cred.Secret))
}

func TestParseCLI_AppPrivateKeyContentEnv(t *testing.T) {
	t.Setenv("GITHUB_APP_PRIVATE_KEY", testPEM)

	s := Init()
	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: ConnectionType,
		Args:      []string{"org", "my-org"},
		Flags:     appFlags(nil),
	})
	require.NoError(t, err)

	conf := res.Asset.Connections[0]
	assert.Empty(t, conf.Options[connection.OPTION_APP_PRIVATE_KEY])
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, vault.CredentialType_private_key, conf.Credentials[0].Type)
	assert.Equal(t, testPEM, string(conf.Credentials[0].Secret))
}

func TestParseCLI_AppPrivateKeyContentFlagBeatsEnv(t *testing.T) {
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "env-key")

	s := Init()
	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: ConnectionType,
		Args:      []string{"org", "my-org"},
		Flags: appFlags(map[string]*llx.Primitive{
			connection.OPTION_APP_PRIVATE_KEY_CONTENT: llx.StringPrimitive(testPEM),
		}),
	})
	require.NoError(t, err)

	conf := res.Asset.Connections[0]
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, testPEM, string(conf.Credentials[0].Secret))
}

func TestParseCLI_AppPrivateKeyPathStillWorks(t *testing.T) {
	s := Init()
	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: ConnectionType,
		Args:      []string{"org", "my-org"},
		Flags: appFlags(map[string]*llx.Primitive{
			connection.OPTION_APP_PRIVATE_KEY: llx.StringPrimitive("/path/to/key.pem"),
		}),
	})
	require.NoError(t, err)

	conf := res.Asset.Connections[0]
	assert.Equal(t, "/path/to/key.pem", conf.Options[connection.OPTION_APP_PRIVATE_KEY])
	assert.Empty(t, conf.Credentials)
}
