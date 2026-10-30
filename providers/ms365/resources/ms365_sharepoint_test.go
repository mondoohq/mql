// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func TestSpoTenantConfigSharingFields(t *testing.T) {
	t.Run("reported by the tenant", func(t *testing.T) {
		cfg := &SpoTenantConfig{}
		err := json.Unmarshal([]byte(`{
			"EnableAzureADB2BIntegration": true,
			"OneDriveSharingCapability": "Disabled",
			"WhoCanShareAuthenticatedGuestAllowList": ["a1b2c3d4-0000-0000-0000-000000000001"]
		}`), cfg)
		require.NoError(t, err)

		require.NotNil(t, cfg.EnableAzureADB2BIntegration)
		assert.True(t, *cfg.EnableAzureADB2BIntegration)
		require.NotNil(t, cfg.OneDriveSharingCapability)
		assert.Equal(t, "Disabled", *cfg.OneDriveSharingCapability)
		assert.Equal(t, []string{"a1b2c3d4-0000-0000-0000-000000000001"},
			cfg.WhoCanShareAuthenticatedGuestAllowList)
	})

	// a tenant that omits the properties must not read as "B2B off, OneDrive
	// unrestricted" -- the pointers stay nil so the fields resolve to null
	t.Run("omitted by the tenant", func(t *testing.T) {
		cfg := &SpoTenantConfig{}
		err := json.Unmarshal([]byte(`{"SharingCapability": "Disabled"}`), cfg)
		require.NoError(t, err)

		assert.Nil(t, cfg.EnableAzureADB2BIntegration)
		assert.Nil(t, cfg.OneDriveSharingCapability)
		assert.Nil(t, cfg.WhoCanShareAuthenticatedGuestAllowList)
	})

	t.Run("reported as null", func(t *testing.T) {
		cfg := &SpoTenantConfig{}
		err := json.Unmarshal([]byte(`{
			"EnableAzureADB2BIntegration": null,
			"OneDriveSharingCapability": null,
			"WhoCanShareAuthenticatedGuestAllowList": null
		}`), cfg)
		require.NoError(t, err)

		assert.Nil(t, cfg.EnableAzureADB2BIntegration)
		assert.Nil(t, cfg.OneDriveSharingCapability)
		assert.Nil(t, cfg.WhoCanShareAuthenticatedGuestAllowList)
	})

	// no security group restricts guest sharing
	t.Run("empty allow list", func(t *testing.T) {
		cfg := &SpoTenantConfig{}
		err := json.Unmarshal([]byte(`{"WhoCanShareAuthenticatedGuestAllowList": []}`), cfg)
		require.NoError(t, err)

		assert.Empty(t, cfg.WhoCanShareAuthenticatedGuestAllowList)
	})
}

func TestStringListData(t *testing.T) {
	// the distinction that matters: a tenant that never reported the setting
	// must not read as one that reported no groups
	t.Run("nil is null", func(t *testing.T) {
		assert.Equal(t, llx.NilData, stringListData(nil))
	})

	t.Run("empty is an empty array", func(t *testing.T) {
		got := stringListData([]string{})
		assert.Equal(t, types.Array(types.String), got.Type)
		assert.Equal(t, []any{}, got.Value)
	})

	t.Run("values are preserved", func(t *testing.T) {
		got := stringListData([]string{"group-a", "group-b"})
		assert.Equal(t, types.Array(types.String), got.Type)
		assert.Equal(t, []any{"group-a", "group-b"}, got.Value)
	})
}

func TestExtractSharepointTenant(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"bare onmicrosoft", "contoso.onmicrosoft.com", "contoso", false},
		{"bare sharepoint", "contoso.sharepoint.com", "contoso", false},
		{"https scheme", "https://contoso.sharepoint.com", "contoso", false},
		{"http scheme", "http://contoso.sharepoint.com", "contoso", false},
		{"https with trailing slash", "https://contoso.sharepoint.com/", "contoso", false},
		{"https with path", "https://contoso.sharepoint.com/sites/foo", "contoso", false},
		{"empty", "", "", true},
		{"single label", "contoso", "", true},
		{"leading dot", ".contoso.com", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractSharepointTenant(tc.in)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
