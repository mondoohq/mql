// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

// zoneSetting is the shape of a single entry returned by the bulk zone-settings
// endpoint (`/zones/{id}/settings`). cloudflare-go only exposes a typed
// per-setting Get, so we read the full set in one call via the client's generic
// Get and pick out the settings we surface.
type zoneSetting struct {
	ID    string `json:"id"`
	Value any    `json:"value"`
}

func extractSettingStr(settings []zoneSetting, id string) string {
	for _, s := range settings {
		if s.ID == id {
			if v, ok := s.Value.(string); ok {
				return v
			}
		}
	}
	return ""
}

func extractSettingValue(settings []zoneSetting, id string) any {
	for _, s := range settings {
		if s.ID == id {
			return s.Value
		}
	}
	return nil
}

// extractSettingInt pulls a numeric zone setting. Cloudflare returns these as
// JSON numbers, which decode to float64.
func extractSettingInt(settings []zoneSetting, id string) int64 {
	if v, ok := extractSettingValue(settings, id).(float64); ok {
		return int64(v)
	}
	return 0
}

// extractSettingStrList pulls a zone setting whose value is a JSON array of
// strings, such as the `ciphers` allowlist. An absent setting and one set to an
// empty array both yield an empty slice: Cloudflare represents "use the plan
// default set" as an empty array, so the two mean the same thing here.
func extractSettingStrList(settings []zoneSetting, id string) []string {
	raw, ok := extractSettingValue(settings, id).([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if str, ok := v.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

// extractSettingNestedBool pulls a boolean out of a zone setting whose value is
// an object, such as `nel` with its `{enabled: bool}` shape. It returns nil when
// the setting is absent from the response or does not carry the key, so a
// setting that was never reported is not reported as switched off.
func extractSettingNestedBool(settings []zoneSetting, id, key string) *bool {
	m, ok := extractSettingValue(settings, id).(map[string]any)
	if !ok {
		return nil
	}
	b, ok := m[key].(bool)
	if !ok {
		return nil
	}
	return &b
}

// extractHSTS pulls HSTS subfields from the `security_header` zone setting.
// The setting value is `{strict_transport_security: {enabled, max_age, include_subdomains, preload, nosniff}}`.
func extractHSTS(settings []zoneSetting) (enabled bool, maxAge int64, includeSubdomains bool, preload bool, nosniff bool) {
	v := extractSettingValue(settings, "security_header")
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	sts, ok := m["strict_transport_security"].(map[string]any)
	if !ok {
		return
	}
	if e, ok := sts["enabled"].(bool); ok {
		enabled = e
	}
	if a, ok := sts["max_age"].(float64); ok {
		maxAge = int64(a)
	}
	if i, ok := sts["include_subdomains"].(bool); ok {
		includeSubdomains = i
	}
	if p, ok := sts["preload"].(bool); ok {
		preload = p
	}
	if n, ok := sts["nosniff"].(bool); ok {
		nosniff = n
	}
	return
}

func (c *mqlCloudflareZone) settings() (*mqlCloudflareZoneSettings, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result []zoneSetting `json:"result"`
	}
	uri := fmt.Sprintf("zones/%s/settings", c.Id.Data)
	if err := conn.Cf.Get(context.Background(), uri, nil, &env); err != nil {
		// A token that can read the zone but not its settings (403), or a plan
		// without this endpoint (404), degrades to null rather than failing the
		// whole zone traversal — matching botManagement() below.
		if isUnavailable(err) {
			c.Settings.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	settings := env.Result

	hstsEnabled, hstsMaxAge, hstsIncludeSubdomains, hstsPreload, hstsNoSniff := extractHSTS(settings)

	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.settings", map[string]*llx.RawData{
		"__id":                    llx.StringData("cloudflare.zone.settings@" + c.Id.Data),
		"ssl":                     llx.StringData(extractSettingStr(settings, "ssl")),
		"alwaysUseHttps":          llx.StringData(extractSettingStr(settings, "always_use_https")),
		"minTlsVersion":           llx.StringData(extractSettingStr(settings, "min_tls_version")),
		"tls13":                   llx.StringData(extractSettingStr(settings, "tls_1_3")),
		"automaticHttpsRewrites":  llx.StringData(extractSettingStr(settings, "automatic_https_rewrites")),
		"securityLevel":           llx.StringData(extractSettingStr(settings, "security_level")),
		"waf":                     llx.StringData(extractSettingStr(settings, "waf")),
		"browserCheck":            llx.StringData(extractSettingStr(settings, "browser_check")),
		"opportunisticEncryption": llx.StringData(extractSettingStr(settings, "opportunistic_encryption")),
		"emailObfuscation":        llx.StringData(extractSettingStr(settings, "email_obfuscation")),
		"hotlinkProtection":       llx.StringData(extractSettingStr(settings, "hotlink_protection")),
		"serverSideExcludes":      llx.StringData(extractSettingStr(settings, "server_side_exclude")),
		"http3":                   llx.StringData(extractSettingStr(settings, "http3")),
		"zeroRtt":                 llx.StringData(extractSettingStr(settings, "0rtt")),
		"websockets":              llx.StringData(extractSettingStr(settings, "websockets")),
		"ipGeolocation":           llx.StringData(extractSettingStr(settings, "ip_geolocation")),
		"trueClientIpHeader":      llx.StringData(extractSettingStr(settings, "true_client_ip_header")),
		"challengeTtl":            llx.IntData(extractSettingInt(settings, "challenge_ttl")),
		"hstsEnabled":             llx.BoolData(hstsEnabled),
		"hstsMaxAge":              llx.IntData(hstsMaxAge),
		"hstsIncludeSubdomains":   llx.BoolData(hstsIncludeSubdomains),
		"hstsPreload":             llx.BoolData(hstsPreload),
		"hstsNoSniff":             llx.BoolData(hstsNoSniff),

		"ciphers":           llx.ArrayData(convert.SliceAnyToInterface(extractSettingStrList(settings, "ciphers")), types.String),
		"developmentMode":   llx.StringData(extractSettingStr(settings, "development_mode")),
		"nelEnabled":        llx.BoolDataPtr(extractSettingNestedBool(settings, "nel", "enabled")),
		"replaceInsecureJs": llx.StringData(extractSettingStr(settings, "replace_insecure_js")),
	})
	if err != nil {
		return nil, err
	}

	return res.(*mqlCloudflareZoneSettings), nil
}

// botManagementSettings mirrors the zone bot-management response. cloudflare-go
// models this endpoint as a polymorphic union (each bot-management plan is a
// separate variant), so decoding into a single typed struct only populates one
// variant's fields. We read the endpoint via the client's generic Get and decode
// the full payload to keep every field the MQL schema exposes.
type botManagementSettings struct {
	EnableJS                     *bool   `json:"enable_js"`
	FightMode                    *bool   `json:"fight_mode"`
	SBFMDefinitelyAutomated      *string `json:"sbfm_definitely_automated"`
	SBFMLikelyAutomated          *string `json:"sbfm_likely_automated"`
	SBFMVerifiedBots             *string `json:"sbfm_verified_bots"`
	SBFMStaticResourceProtection *bool   `json:"sbfm_static_resource_protection"`
	OptimizeWordpress            *bool   `json:"optimize_wordpress"`
	AutoUpdateModel              *bool   `json:"auto_update_model"`
	UsingLatestModel             *bool   `json:"using_latest_model"`
	AIBotsProtection             *string `json:"ai_bots_protection"`
}

func (c *mqlCloudflareZone) botManagement() (*mqlCloudflareZoneBotManagement, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result botManagementSettings `json:"result"`
	}
	uri := fmt.Sprintf("zones/%s/bot_management", c.Id.Data)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		// Bot management may not be available on all plans (403/404)
		if isUnavailable(err) {
			c.BotManagement.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	bm := env.Result

	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.botManagement", map[string]*llx.RawData{
		"__id":                         llx.StringData("cloudflare.zone.botManagement@" + c.Id.Data),
		"enableJs":                     llx.BoolDataPtr(bm.EnableJS),
		"fightMode":                    llx.BoolDataPtr(bm.FightMode),
		"sbfmDefinitelyAutomated":      llx.StringDataPtr(bm.SBFMDefinitelyAutomated),
		"sbfmLikelyAutomated":          llx.StringDataPtr(bm.SBFMLikelyAutomated),
		"sbfmVerifiedBots":             llx.StringDataPtr(bm.SBFMVerifiedBots),
		"sbfmStaticResourceProtection": llx.BoolDataPtr(bm.SBFMStaticResourceProtection),
		"optimizeWordpress":            llx.BoolDataPtr(bm.OptimizeWordpress),
		"autoUpdateModel":              llx.BoolDataPtr(bm.AutoUpdateModel),
		"usingLatestModel":             llx.BoolDataPtr(bm.UsingLatestModel),
		"aiBotsProtection":             llx.StringDataPtr(bm.AIBotsProtection),
	})
	if err != nil {
		return nil, err
	}

	return res.(*mqlCloudflareZoneBotManagement), nil
}
