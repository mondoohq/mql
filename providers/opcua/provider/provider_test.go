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

func parseCLI(t *testing.T, flags map[string]*llx.Primitive) *plugin.ParseCLIRes {
	t.Helper()
	res, err := Init().ParseCLI(&plugin.ParseCLIReq{Connector: "opcua", Flags: flags})
	require.NoError(t, err)
	require.NotNil(t, res.Asset)
	require.Len(t, res.Asset.Connections, 1)
	return res
}

// Every connection flag has to survive the trip from the CLI into the
// connection config. A flag that ParseCLI never copies is accepted on the
// command line and then silently does nothing.
func TestParseCLI_SecurityFlagsReachTheConnection(t *testing.T) {
	res := parseCLI(t, map[string]*llx.Primitive{
		"endpoint":        llx.StringPrimitive("opc.tcp://server:4840"),
		"security-policy": llx.StringPrimitive("Basic256Sha256"),
		"security-mode":   llx.StringPrimitive("SignAndEncrypt"),
		"cert-file":       llx.StringPrimitive("/tmp/client.der"),
		"key-file":        llx.StringPrimitive("/tmp/client.key"),
	})

	conf := res.Asset.Connections[0]
	assert.Equal(t, map[string]string{
		"endpoint":        "opc.tcp://server:4840",
		"security-policy": "Basic256Sha256",
		"security-mode":   "SignAndEncrypt",
		"cert-file":       "/tmp/client.der",
		"key-file":        "/tmp/client.key",
	}, conf.Options)
}

func TestParseCLI_UsernameAndPasswordBecomeACredential(t *testing.T) {
	res := parseCLI(t, map[string]*llx.Primitive{
		"endpoint": llx.StringPrimitive("opc.tcp://server:4840"),
		"username": llx.StringPrimitive("operator"),
		"password": llx.StringPrimitive("secret"),
	})

	conf := res.Asset.Connections[0]
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, vault.CredentialType_password, conf.Credentials[0].Type)
	assert.Equal(t, "operator", conf.Credentials[0].User)
	assert.Equal(t, "secret", string(conf.Credentials[0].Secret))
}

// The unauthenticated, unencrypted case has to keep working untouched.
func TestParseCLI_EndpointOnly(t *testing.T) {
	res := parseCLI(t, map[string]*llx.Primitive{
		"endpoint": llx.StringPrimitive("opc.tcp://server:4840"),
	})

	conf := res.Asset.Connections[0]
	assert.Equal(t, map[string]string{"endpoint": "opc.tcp://server:4840"}, conf.Options)
	assert.Empty(t, conf.Credentials)
}

func TestParseCLI_NoFlags(t *testing.T) {
	res := parseCLI(t, nil)
	assert.Empty(t, res.Asset.Connections[0].Options)
}
