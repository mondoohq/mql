// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestParseCLI_WithFlags(t *testing.T) {
	s := Init()

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "jamf",
		Flags: map[string]*llx.Primitive{
			"client-id":       {Value: []byte("my-client-id")},
			"client-secret":   {Value: []byte("my-client-secret")},
			"instance-domain": {Value: []byte("https://example.jamfcloud.com")},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res.Asset)

	conf := res.Asset.Connections[0]
	assert.Equal(t, "jamf", conf.Type)
	assert.Equal(t, "https://example.jamfcloud.com", conf.Options["instance_domain"])

	// Credentials should be set
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, "my-client-id", conf.Credentials[0].User)
	assert.Equal(t, "my-client-secret", string(conf.Credentials[0].Secret))

	// Secrets should NOT be in Options
	_, hasClientId := conf.Options["client_id"]
	_, hasClientSecret := conf.Options["client_secret"]
	assert.False(t, hasClientId, "client_id should not be in Options")
	assert.False(t, hasClientSecret, "client_secret should not be in Options")
}

func TestParseCLI_EmptyFlags(t *testing.T) {
	s := Init()

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "jamf",
		Flags:     nil,
	})
	require.NoError(t, err)
	require.NotNil(t, res.Asset)

	conf := res.Asset.Connections[0]
	assert.Equal(t, "jamf", conf.Type)
	assert.Empty(t, conf.Credentials)
}

func TestParseCLI_PartialFlags(t *testing.T) {
	s := Init()

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "jamf",
		Flags: map[string]*llx.Primitive{
			"instance-domain": {Value: []byte("https://example.jamfcloud.com")},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res.Asset)

	conf := res.Asset.Connections[0]
	assert.Equal(t, "https://example.jamfcloud.com", conf.Options["instance_domain"])
	assert.Empty(t, conf.Credentials, "no credentials when only domain is provided")
}

func TestParseCLI_EnvVarFallback(t *testing.T) {
	t.Setenv("JAMF_CLIENT_ID", "env-client-id")
	t.Setenv("JAMF_CLIENT_SECRET", "env-client-secret")
	t.Setenv("JAMF_INSTANCE_DOMAIN", "https://env.jamfcloud.com")

	s := Init()

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "jamf",
		Flags:     map[string]*llx.Primitive{},
	})
	require.NoError(t, err)
	require.NotNil(t, res.Asset)

	conf := res.Asset.Connections[0]
	assert.Equal(t, "https://env.jamfcloud.com", conf.Options["instance_domain"])
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, "env-client-id", conf.Credentials[0].User)
	assert.Equal(t, "env-client-secret", string(conf.Credentials[0].Secret))
}

func TestParseCLI_FlagsTakePrecedenceOverEnv(t *testing.T) {
	t.Setenv("JAMF_CLIENT_ID", "env-client-id")
	t.Setenv("JAMF_CLIENT_SECRET", "env-client-secret")
	t.Setenv("JAMF_INSTANCE_DOMAIN", "https://env.jamfcloud.com")

	s := Init()

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "jamf",
		Flags: map[string]*llx.Primitive{
			"client-id":       {Value: []byte("flag-client-id")},
			"instance-domain": {Value: []byte("https://flag.jamfcloud.com")},
		},
	})
	require.NoError(t, err)

	conf := res.Asset.Connections[0]
	assert.Equal(t, "https://flag.jamfcloud.com", conf.Options["instance_domain"])
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, "flag-client-id", conf.Credentials[0].User)
}
