// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// connectWithName connects an asset the way a caller hands it over:
// optionally pre-named (--asset-name, or an inventory file), with the token as
// a password credential. No Discover block, so nothing reaches the Shodan API.
func connectWithName(t *testing.T, host, search, name string) *inventory.Asset {
	t.Helper()
	conf := &inventory.Config{
		Type:        DefaultConnectionType,
		Host:        host,
		Credentials: []*vault.Credential{{Type: vault.CredentialType_password, Secret: []byte("test-token")}},
	}
	if search != "" {
		conf.Options = map[string]string{"search": search}
	}
	resp, err := Init().Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{Name: name, Connections: []*inventory.Config{conf}},
	}, nil)
	require.NoError(t, err)
	return resp.Asset
}

// The account-level asset (`cnspec scan shodan --token …`) has no connection
// host, so naming the asset after the host left it blank. A caller who already
// named the asset must keep that name; an unnamed account asset gets a
// readable default.
func TestDetect_AssetName(t *testing.T) {
	t.Run("names an unnamed account asset Shodan", func(t *testing.T) {
		asset := connectWithName(t, "", "", "")
		assert.Equal(t, "Shodan", asset.Name)
		assert.Equal(t, "shodan-org", asset.Platform.Name)
	})

	t.Run("keeps a caller-supplied name on the account asset", func(t *testing.T) {
		asset := connectWithName(t, "", "", "Shodan prod")
		assert.Equal(t, "Shodan prod", asset.Name)
		// The name is display only; identity still comes from detection.
		assert.Equal(t, []string{"//platformid.api.mondoo.app/runtime/shodan"}, asset.PlatformIds)
	})

	t.Run("names an unnamed host asset after its host", func(t *testing.T) {
		asset := connectWithName(t, "192.0.2.10", "host", "")
		assert.Equal(t, "192.0.2.10", asset.Name)
		assert.Equal(t, "shodan-host", asset.Platform.Name)
	})

	t.Run("keeps a caller-supplied name on a domain asset", func(t *testing.T) {
		asset := connectWithName(t, "example.com", "domain", "edge estate")
		assert.Equal(t, "edge estate", asset.Name)
		assert.Equal(t, "shodan-domain", asset.Platform.Name)
	})
}
