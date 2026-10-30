// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZoneSettings(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/settings", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("zone_settings"))
	})

	s, err := zone.settings()
	require.NoError(t, err)
	require.NotNil(t, s)

	// String settings extracted from the heterogeneous settings array
	assert.Equal(t, "strict", s.Ssl.Data)
	assert.Equal(t, "on", s.AlwaysUseHttps.Data)
	assert.Equal(t, "1.2", s.MinTlsVersion.Data)
	assert.Equal(t, "on", s.Tls13.Data)
	assert.Equal(t, "on", s.AutomaticHttpsRewrites.Data)
	assert.Equal(t, "high", s.SecurityLevel.Data)
	assert.Equal(t, "on", s.Waf.Data)
	assert.Equal(t, "on", s.BrowserCheck.Data)
	assert.Equal(t, "on", s.OpportunisticEncryption.Data)
	assert.Equal(t, "on", s.EmailObfuscation.Data)
	assert.Equal(t, "off", s.HotlinkProtection.Data)
	assert.Equal(t, "on", s.ServerSideExcludes.Data)

	// HSTS sub-fields extracted from the nested security_header.strict_transport_security struct
	assert.True(t, s.HstsEnabled.Data)
	assert.Equal(t, int64(15552000), s.HstsMaxAge.Data)
	assert.True(t, s.HstsIncludeSubdomains.Data)
	assert.True(t, s.HstsPreload.Data)
	assert.True(t, s.HstsNoSniff.Data)
}

func TestBotManagement(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/bot_management", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("bot_management"))
	})

	result, err := zone.botManagement()
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.EnableJs.Data)
	assert.True(t, result.FightMode.Data)
	assert.Equal(t, "block", result.SbfmDefinitelyAutomated.Data)
	assert.Equal(t, "managed_challenge", result.SbfmLikelyAutomated.Data)
	assert.Equal(t, "allow", result.SbfmVerifiedBots.Data)
	assert.False(t, result.SbfmStaticResourceProtection.Data)
	assert.True(t, result.AutoUpdateModel.Data)
	assert.True(t, result.UsingLatestModel.Data)
	assert.Equal(t, "block", result.AiBotsProtection.Data)
}

func TestBotManagement_unavailable(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/bot_management", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
	})

	result, err := zone.botManagement()
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestZoneSettings_alreadyFetchedExtras(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	calls := 0
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/settings", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		calls++
		jsonResponse(w, loadFixture("zone_settings"))
	})

	s, err := zone.settings()
	require.NoError(t, err)
	require.NotNil(t, s)

	// An explicit cipher allowlist overrides the plan default set, so a weak
	// suite listed here is negotiable regardless of minTlsVersion.
	assert.Equal(t, []any{"ECDHE-ECDSA-AES128-GCM-SHA256", "AES128-SHA"}, s.Ciphers.Data)
	assert.Equal(t, "on", s.DevelopmentMode.Data)
	assert.True(t, s.NelEnabled.Data)
	assert.Equal(t, "off", s.ReplaceInsecureJs.Data)

	// These come out of the bulk settings response the resource already reads.
	assert.Equal(t, 1, calls, "the extra settings must not cost another API call")
}

func TestExtractSettingStrList(t *testing.T) {
	tests := []struct {
		name     string
		settings []zoneSetting
		want     []string
	}{
		{"absent setting", []zoneSetting{{ID: "ssl", Value: "strict"}}, nil},
		{"empty allowlist means the plan default set", []zoneSetting{{ID: "ciphers", Value: []any{}}}, []string{}},
		{"string list", []zoneSetting{{ID: "ciphers", Value: []any{"AES128-SHA", "AES256-SHA"}}}, []string{"AES128-SHA", "AES256-SHA"}},
		{"non-string entries are dropped", []zoneSetting{{ID: "ciphers", Value: []any{"AES128-SHA", 7.0}}}, []string{"AES128-SHA"}},
		{"wrong value type", []zoneSetting{{ID: "ciphers", Value: "AES128-SHA"}}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, extractSettingStrList(tc.settings, "ciphers"))
		})
	}
}

func TestExtractSettingNestedBool(t *testing.T) {
	tests := []struct {
		name     string
		settings []zoneSetting
		want     *bool
	}{
		{"absent setting stays null", []zoneSetting{{ID: "ssl", Value: "strict"}}, nil},
		{"object without the key stays null", []zoneSetting{{ID: "nel", Value: map[string]any{}}}, nil},
		{"enabled", []zoneSetting{{ID: "nel", Value: map[string]any{"enabled": true}}}, new(true)},
		{"disabled", []zoneSetting{{ID: "nel", Value: map[string]any{"enabled": false}}}, new(false)},
		{"wrong value type stays null", []zoneSetting{{ID: "nel", Value: "on"}}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractSettingNestedBool(tc.settings, "nel", "enabled")
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tc.want, *got)
		})
	}
}
