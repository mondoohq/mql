// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/grafana/provider"
)

func TestParseCLI_Success(t *testing.T) {
	svc := provider.Init()
	req := &plugin.ParseCLIReq{
		Connector: "grafana",
		Flags: map[string]*llx.Primitive{
			"token": llx.StringPrimitive("test-token"),
			"url":   llx.StringPrimitive("https://example.grafana.net"),
		},
	}

	res, err := svc.ParseCLI(req)
	require.NoError(t, err)
	require.NotNil(t, res.Asset)

	assert.Equal(t, "Grafana", res.Asset.Name)
	require.Len(t, res.Asset.Connections, 1)

	conn := res.Asset.Connections[0]
	assert.Equal(t, "https://example.grafana.net", conn.Options["url"])
	require.Len(t, conn.Credentials, 1)
	assert.Equal(t, vault.CredentialType_password, conn.Credentials[0].Type)
	assert.Equal(t, "test-token", string(conn.Credentials[0].Secret))
}

func TestParseCLI_MissingToken(t *testing.T) {
	t.Setenv("GRAFANA_TOKEN", "")

	svc := provider.Init()
	req := &plugin.ParseCLIReq{
		Connector: "grafana",
		Flags: map[string]*llx.Primitive{
			"url": llx.StringPrimitive("https://example.grafana.net"),
		},
	}

	_, err := svc.ParseCLI(req)
	require.Error(t, err)
	assert.True(t, strings.Contains(strings.ToLower(err.Error()), "token"),
		"error should mention 'token', got: %s", err.Error())
}

func TestParseCLI_MissingURL(t *testing.T) {
	t.Setenv("GRAFANA_URL", "")

	svc := provider.Init()
	req := &plugin.ParseCLIReq{
		Connector: "grafana",
		Flags: map[string]*llx.Primitive{
			"token": llx.StringPrimitive("test-token"),
		},
	}

	_, err := svc.ParseCLI(req)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "URL"),
		"error should mention 'URL', got: %s", err.Error())
}

func TestParseCLI_EnvFallback(t *testing.T) {
	t.Setenv("GRAFANA_TOKEN", "env-token")
	t.Setenv("GRAFANA_URL", "https://env.grafana.net")

	svc := provider.Init()
	req := &plugin.ParseCLIReq{
		Connector: "grafana",
		Flags:     map[string]*llx.Primitive{},
	}

	res, err := svc.ParseCLI(req)
	require.NoError(t, err)
	require.NotNil(t, res.Asset)

	assert.Equal(t, "Grafana", res.Asset.Name)
	require.Len(t, res.Asset.Connections, 1)

	conn := res.Asset.Connections[0]
	assert.Equal(t, "https://env.grafana.net", conn.Options["url"])
	require.Len(t, conn.Credentials, 1)
	assert.Equal(t, vault.CredentialType_password, conn.Credentials[0].Type)
	assert.Equal(t, "env-token", string(conn.Credentials[0].Secret))
}
