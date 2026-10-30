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

func TestGatewayRules(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/gateway/rules", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("gateway_rules"))
	})

	result, err := one.gatewayRules()
	require.NoError(t, err)
	require.Len(t, result, 1)

	rule := result[0].(*mqlCloudflareOneGatewayRule)
	assert.Equal(t, "gw-rule-001", rule.Id.Data)
	assert.Equal(t, "Block Malware Domains", rule.Name.Data)
	assert.Equal(t, "block", rule.Action.Data)
	assert.True(t, rule.Enabled.Data)
	assert.Equal(t, int64(1), rule.Precedence.Data)
	assert.Equal(t, "dns.fqdn in $malware_domains", rule.Traffic.Data)
	assert.Equal(t, int64(2), rule.Version.Data)
	assert.Len(t, rule.Filters.Data, 1)
}

func TestLists(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/gateway/lists", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("teams_lists"))
	})

	result, err := one.lists()
	require.NoError(t, err)
	require.Len(t, result, 1)

	list := result[0].(*mqlCloudflareOneList)
	assert.Equal(t, "list-001", list.Id.Data)
	assert.Equal(t, "Blocked IPs", list.Name.Data)
	assert.Equal(t, "IP", list.Type.Data)
	assert.Equal(t, int64(150), list.Count.Data)
}

func TestLocations(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/gateway/locations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("teams_locations"))
	})

	result, err := one.locations()
	require.NoError(t, err)
	require.Len(t, result, 1)

	loc := result[0].(*mqlCloudflareOneLocation)
	assert.Equal(t, "loc-001", loc.Id.Data)
	assert.Equal(t, "Office HQ", loc.Name.Data)
	assert.Equal(t, "office-hq", loc.DohSubdomain.Data)
	assert.Equal(t, "203.0.113.1", loc.Ip.Data)
	assert.True(t, loc.ClientDefault.Data)
	assert.True(t, loc.EcsSupport.Data)
}

func TestDlpProfiles(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/dlp/profiles", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("dlp_profiles"))
	})

	result, err := one.dlpProfiles()
	require.NoError(t, err)
	require.Len(t, result, 1)

	profile := result[0].(*mqlCloudflareOneDlpProfile)
	assert.Equal(t, "dlp-001", profile.Id.Data)
	assert.Equal(t, "Credit Card Detection", profile.Name.Data)
	assert.Equal(t, "predefined", profile.Type.Data)
	assert.True(t, profile.OcrEnabled.Data)
	assert.Equal(t, int64(0), profile.AllowedMatchCount.Data)
}

func TestGatewayConfiguration_defangedAccount(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/gateway/configuration", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("gateway_configuration"))
	})

	cfg, err := one.gatewayConfiguration()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// The two settings that decide whether any Gateway rule enforces or records
	// anything at all.
	assert.False(t, cfg.TlsDecryptEnabled.Data)
	assert.False(t, cfg.ActivityLogEnabled.Data)

	assert.True(t, cfg.AntivirusDownloadEnabled.Data)
	assert.False(t, cfg.AntivirusUploadEnabled.Data)
	assert.False(t, cfg.AntivirusFailClosed.Data)
	assert.Equal(t, "shallow", cfg.BodyScanningInspectionMode.Data)
	assert.True(t, cfg.UrlBrowserIsolationEnabled.Data)
	assert.False(t, cfg.NonIdentityBrowserIsolationEnabled.Data)
	assert.False(t, cfg.ProtocolDetectionEnabled.Data)
	assert.True(t, cfg.SandboxEnabled.Data)
	assert.Equal(t, "allow", cfg.SandboxFallbackAction.Data)
	assert.False(t, cfg.FipsTls.Data)
	assert.Equal(t, "static", cfg.InspectionMode.Data)
	assert.False(t, cfg.HostSelectorEnabled.Data)
	assert.True(t, cfg.ExtendedEmailMatchingEnabled.Data)

	// A nil-UUID certificate means the Cloudflare Root CA intercepts, so there
	// is no customer certificate to report.
	assert.Equal(t, "", cfg.InterceptionCertificateId.Data)
	// No max_ttl_secs in the response means no cap, not a cap of zero seconds.
	assert.True(t, cfg.MaxTtlSeconds.IsNull())
}

func TestGatewayConfiguration_fullyEnforcingAccount(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/gateway/configuration", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("gateway_configuration_full"))
	})

	cfg, err := one.gatewayConfiguration()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.True(t, cfg.TlsDecryptEnabled.Data)
	assert.True(t, cfg.ActivityLogEnabled.Data)
	assert.True(t, cfg.AntivirusFailClosed.Data)
	assert.Equal(t, "deep", cfg.BodyScanningInspectionMode.Data)
	assert.True(t, cfg.ProtocolDetectionEnabled.Data)
	assert.Equal(t, "block", cfg.SandboxFallbackAction.Data)
	assert.True(t, cfg.FipsTls.Data)
	assert.Equal(t, "dynamic", cfg.InspectionMode.Data)
	assert.Equal(t, int64(300), cfg.MaxTtlSeconds.Data)
	assert.Equal(t, "d4c5e6f7-1234-4321-abcd-0123456789ab", cfg.InterceptionCertificateId.Data)
}

func TestGatewayConfiguration_unreadableIsNullNotAllDisabled(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/gateway/configuration", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Zero Trust is not enabled"}]}`)
	})

	cfg, err := one.gatewayConfiguration()
	require.NoError(t, err)
	assert.Nil(t, cfg, "an unreadable configuration must be null, not a resource reading all-false")
	assert.True(t, one.GatewayConfiguration.IsNull())
}
