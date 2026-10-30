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

func TestParseCLI_FullTarget(t *testing.T) {
	s := &Service{Service: plugin.NewService()}

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "mikrotik",
		Args:      []string{"admin@192.168.88.1:8728"},
		Flags: map[string]*llx.Primitive{
			"password": llx.StringPrimitive("secret"),
			"tls":      llx.BoolPrimitive(true),
			"insecure": llx.BoolPrimitive(true),
		},
	})
	require.NoError(t, err)
	require.Len(t, res.Asset.Connections, 1)

	conf := res.Asset.Connections[0]
	assert.Equal(t, "mikrotik", conf.Type)
	assert.Equal(t, "192.168.88.1", conf.Host)
	assert.Equal(t, int32(8728), conf.Port)
	assert.Equal(t, "true", conf.Options["tls"])
	assert.True(t, conf.Insecure)

	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, "admin", conf.Credentials[0].User)
	assert.Equal(t, "secret", string(conf.Credentials[0].Secret))
}

func TestParseCLI_Defaults(t *testing.T) {
	s := &Service{Service: plugin.NewService()}

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "mikrotik",
		Args:      []string{"admin@router.example.com"},
	})
	require.NoError(t, err)

	conf := res.Asset.Connections[0]
	assert.Equal(t, "router.example.com", conf.Host)
	assert.Equal(t, int32(0), conf.Port, "port is left unset so the connection can pick the protocol default")
	assert.False(t, conf.Insecure)
	assert.NotContains(t, conf.Options, "tls")

	// the user is preserved as a credential even without a password
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, "admin", conf.Credentials[0].User)
	assert.Empty(t, conf.Credentials[0].Secret)
}

func TestParseCLI_PortFlag(t *testing.T) {
	s := &Service{Service: plugin.NewService()}

	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "mikrotik",
		Args:      []string{"admin@192.168.88.1"},
		Flags: map[string]*llx.Primitive{
			"port": llx.StringPrimitive("8729"),
		},
	})
	require.NoError(t, err)

	conf := res.Asset.Connections[0]
	assert.Equal(t, "8729", conf.Options["port"])
}
