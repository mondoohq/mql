// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	networksecurity "google.golang.org/api/networksecurity/v1"
)

func TestWildfireAnalysisProfileDict(t *testing.T) {
	t.Run("absent profile is nil", func(t *testing.T) {
		got, err := wildfireAnalysisProfileDict(nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("maps the profile and drops the deprecated inline ML settings list", func(t *testing.T) {
		got, err := wildfireAnalysisProfileDict(&networksecurity.WildfireAnalysisProfile{
			WildfireRealtimeLookup: true,
			WildfireOverrides: []*networksecurity.WildfireOverride{
				{Protocol: "SMTP", Action: "DENY"},
			},
			WildfireThreatOverrides: []*networksecurity.WildfireThreatOverride{
				{ThreatId: "1234", Action: "ALLOW"},
			},
			WildfireInlineMlSetting: &networksecurity.WildfireInlineMlSettings{},
			WildfireInlineMlSettings: []*networksecurity.WildfireInlineMlSettings{
				{},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, true, got["wildfireRealtimeLookup"])
		assert.Equal(t, []any{map[string]any{"protocol": "SMTP", "action": "DENY"}}, got["wildfireOverrides"])
		assert.Equal(t, []any{map[string]any{"threatId": "1234", "action": "ALLOW"}}, got["wildfireThreatOverrides"])
		assert.Contains(t, got, "wildfireInlineMlSetting")
		assert.NotContains(t, got, "wildfireInlineMlSettings")
	})

	t.Run("does not mutate the SDK struct", func(t *testing.T) {
		p := &networksecurity.WildfireAnalysisProfile{
			WildfireInlineMlSettings: []*networksecurity.WildfireInlineMlSettings{{}},
		}
		_, err := wildfireAnalysisProfileDict(p)
		require.NoError(t, err)
		assert.Len(t, p.WildfireInlineMlSettings, 1)
	})
}

func TestFindNetworkSecurityProfile(t *testing.T) {
	profile := func(name string) *mqlGcpOrganizationNetworkSecurityProfile {
		return &mqlGcpOrganizationNetworkSecurityProfile{Name: plugin.TValue[string]{Data: name, State: plugin.StateIsSet}}
	}
	wildfire := profile("organizations/1/locations/global/securityProfiles/wf")
	urlf := profile("organizations/1/locations/global/securityProfiles/url")
	profiles := []any{nil, urlf, wildfire}

	assert.Same(t, wildfire, findNetworkSecurityProfile(profiles, "organizations/1/locations/global/securityProfiles/wf"))
	assert.Same(t, urlf, findNetworkSecurityProfile(profiles, "organizations/1/locations/global/securityProfiles/url"))
	assert.Nil(t, findNetworkSecurityProfile(profiles, "organizations/2/locations/global/securityProfiles/wf"))
	assert.Nil(t, findNetworkSecurityProfile(profiles, ""))
	assert.Nil(t, findNetworkSecurityProfile([]any{profile("")}, ""))
}
