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
)

func parseCLI(t *testing.T, flags map[string]*llx.Primitive) (*plugin.ParseCLIRes, error) {
	t.Helper()
	return Init().ParseCLI(&plugin.ParseCLIReq{Connector: "snowflake", Flags: flags})
}

func TestParseCLI_TokenExcludesPassword(t *testing.T) {
	_, err := parseCLI(t, map[string]*llx.Primitive{
		"user":     llx.StringPrimitive("CHRIS"),
		"token":    llx.StringPrimitive("pat-abc"),
		"password": llx.StringPrimitive("hunter2"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot combine --token")
}

func TestParseCLI_TokenExcludesAskPass(t *testing.T) {
	_, err := parseCLI(t, map[string]*llx.Primitive{
		"user":     llx.StringPrimitive("CHRIS"),
		"token":    llx.StringPrimitive("pat-abc"),
		"ask-pass": llx.BoolPrimitive(true),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot combine --token")
}

// ask-pass explicitly false must not trip the mutual-exclusion check.
func TestParseCLI_TokenWithAskPassFalse(t *testing.T) {
	res, err := parseCLI(t, map[string]*llx.Primitive{
		"user":     llx.StringPrimitive("CHRIS"),
		"token":    llx.StringPrimitive("pat-abc"),
		"ask-pass": llx.BoolPrimitive(false),
	})
	require.NoError(t, err)
	require.Len(t, res.Asset.Connections[0].Credentials, 1)
	assert.Equal(t, vault.CredentialType_bearer, res.Asset.Connections[0].Credentials[0].Type)
}

func TestParseCLI_TokenAloneIsBearerCredential(t *testing.T) {
	res, err := parseCLI(t, map[string]*llx.Primitive{
		"user":  llx.StringPrimitive("CHRIS"),
		"token": llx.StringPrimitive("pat-abc"),
	})
	require.NoError(t, err)
	require.Len(t, res.Asset.Connections[0].Credentials, 1)
	cred := res.Asset.Connections[0].Credentials[0]
	assert.Equal(t, vault.CredentialType_bearer, cred.Type)
	assert.Equal(t, "CHRIS", cred.User)
	assert.Equal(t, "pat-abc", string(cred.Secret))
}

func TestParseCLI_PasswordAloneIsAllowed(t *testing.T) {
	res, err := parseCLI(t, map[string]*llx.Primitive{
		"user":     llx.StringPrimitive("CHRIS"),
		"password": llx.StringPrimitive("hunter2"),
	})
	require.NoError(t, err)
	require.Len(t, res.Asset.Connections[0].Credentials, 1)
	assert.Equal(t, vault.CredentialType_password, res.Asset.Connections[0].Credentials[0].Type)
}
