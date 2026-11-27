// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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
	assert.True(t, loc.Dns64Enabled.Data)
}

// Synthetic: a location payload without dns64_enabled reports null, not false.
func TestLocationsDns64Absent(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/gateway/locations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[{"id":"loc-002","name":"Branch"}],"result_info":{"page":1,"total_pages":1}}`)
	})

	result, err := one.locations()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.True(t, result[0].(*mqlCloudflareOneLocation).Dns64Enabled.IsNull())
}

// Synthetic: one location reporting all four resolver endpoints, one reporting
// only a DoH block without networks, and one without endpoints; no live
// account was checked.
func TestLocationEndpoints(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/gateway/locations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[
			{"id":"loc-full","name":"HQ","endpoints":{
				"doh":{"enabled":true,"require_token":true,"networks":[{"network":"203.0.113.0/24"}]},
				"dot":{"enabled":false,"networks":[]},
				"ipv4":{"enabled":true},
				"ipv6":{"enabled":true,"networks":[{"network":"2001:db8::/32"}]}}},
			{"id":"loc-doh","name":"Branch","endpoints":{"doh":{"enabled":true,"require_token":false}}},
			{"id":"loc-none","name":"Legacy"}
		],"result_info":{"page":1,"total_pages":1}}`)
	})

	result, err := one.locations()
	require.NoError(t, err)
	require.Len(t, result, 3)

	full := result[0].(*mqlCloudflareOneLocation)
	assert.True(t, full.DohEnabled.Data)
	assert.True(t, full.DohRequireToken.Data)
	assert.Equal(t, []any{"203.0.113.0/24"}, full.DohNetworks.Data)
	assert.False(t, full.DotEnabled.IsNull())
	assert.False(t, full.DotEnabled.Data)
	assert.False(t, full.DotNetworks.IsNull(), "an empty network list means any source, not unknown")
	assert.Equal(t, []any{}, full.DotNetworks.Data)
	assert.True(t, full.Ipv4Enabled.Data)
	assert.True(t, full.Ipv6Enabled.Data)
	assert.Equal(t, []any{"2001:db8::/32"}, full.Ipv6Networks.Data)

	doh := result[1].(*mqlCloudflareOneLocation)
	assert.False(t, doh.DohRequireToken.IsNull())
	assert.False(t, doh.DohRequireToken.Data)
	assert.True(t, doh.DohNetworks.IsNull())
	assert.True(t, doh.DotEnabled.IsNull())
	assert.True(t, doh.Ipv4Enabled.IsNull())
	assert.True(t, doh.Ipv6Networks.IsNull())

	none := result[2].(*mqlCloudflareOneLocation)
	assert.True(t, none.DohEnabled.IsNull())
	assert.True(t, none.DohRequireToken.IsNull())
	assert.True(t, none.DotEnabled.IsNull())
	assert.True(t, none.Ipv4Enabled.IsNull())
	assert.True(t, none.Ipv6Enabled.IsNull())
}

func serveGatewayRules(env *testEnv, body string) {
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/gateway/rules", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[`+body+`]}`)
	})
}

// Synthetic: a block rule with settings, a warning and a source account the
// token can list, and a rule from an account it cannot; no live account was
// checked.
func TestGatewayRuleSettingsAndSourceAccount(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	serveGatewayRules(env, `
		{"id":"r1","name":"Block","action":"block","enabled":true,
		 "rule_settings":{"block_page_enabled":true,"block_reason":"policy","check_session":{"enforce":true,"duration":"24h"}},
		 "warning_status":"rule uses a deprecated selector","source_account":"`+testAccountID+`"},
		{"id":"r2","name":"Shared","action":"allow","enabled":true,"source_account":"foreign-account"}`)
	env.Mux.HandleFunc("/accounts", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[{"id":"`+testAccountID+`","name":"Test Account","type":"standard"}],
			"result_info":{"page":1,"total_pages":1}}`)
	})

	result, err := one.gatewayRules()
	require.NoError(t, err)
	require.Len(t, result, 2)

	r1 := result[0].(*mqlCloudflareOneGatewayRule)
	assert.Equal(t, map[string]any{
		"block_page_enabled": true,
		"block_reason":       "policy",
		"check_session":      map[string]any{"enforce": true, "duration": "24h"},
	}, r1.RuleSettings.Data)
	assert.Equal(t, "rule uses a deprecated selector", r1.WarningStatus.Data)
	acc, err := r1.sourceAccount()
	require.NoError(t, err)
	require.NotNil(t, acc)
	assert.Equal(t, testAccountID, acc.Id.Data)
	assert.Equal(t, "Test Account", acc.Name.Data)

	r2 := result[1].(*mqlCloudflareOneGatewayRule)
	foreign, err := r2.sourceAccount()
	require.NoError(t, err)
	require.NotNil(t, foreign)
	assert.Equal(t, "foreign-account", foreign.Id.Data)
	assert.True(t, foreign.Name.IsNull(), "an account the token cannot list keeps only its id")
}

// Synthetic: a rule with no settings, warning or source account, and one
// whose warning is explicitly null; no live account was checked.
func TestGatewayRuleSettingsAbsent(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	serveGatewayRules(env, `
		{"id":"r3","name":"Plain","action":"allow","enabled":true},
		{"id":"r4","name":"NullWarning","action":"allow","enabled":true,"warning_status":null,"rule_settings":null}`)
	env.Mux.HandleFunc("/accounts", func(w http.ResponseWriter, r *http.Request) {
		t.Error("no account list request expected for a rule without a source account")
	})

	result, err := one.gatewayRules()
	require.NoError(t, err)
	require.Len(t, result, 2)

	for _, entry := range result {
		rule := entry.(*mqlCloudflareOneGatewayRule)
		assert.True(t, rule.RuleSettings.IsNull(), rule.Id.Data)
		assert.True(t, rule.WarningStatus.IsNull(), rule.Id.Data)
		acc, err := rule.sourceAccount()
		require.NoError(t, err)
		assert.Nil(t, acc)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, rule.SourceAccount.State)
	}
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
