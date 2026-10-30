// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// grafanaSsoSettingsJSON mirrors one element of /api/v1/sso-settings.
// Settings is provider-specific; Grafana redacts secret fields server-side.
type grafanaSsoSettingsJSON struct {
	ID       string         `json:"id"`
	Provider string         `json:"provider"`
	Source   string         `json:"source"`
	Settings map[string]any `json:"settings"`
}

// ssoSettings queries /api/v1/sso-settings, listing all configured identity
// providers. The endpoint is available on Grafana 10.4+ Enterprise and Cloud;
// on older versions or OSS it returns 404 and we surface an empty list.
func (g *mqlGrafana) ssoSettings() ([]any, error) {
	conn, err := grafanaConnection(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	resp, err := conn.Get(context.Background(), "/api/v1/sso-settings")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return []any{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grafana: GET /api/v1/sso-settings returned status %d", resp.StatusCode)
	}

	var raw []grafanaSsoSettingsJSON
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("grafana: decoding /api/v1/sso-settings response: %w", err)
	}

	list := make([]any, 0, len(raw))
	for _, s := range raw {
		res, err := buildSsoSettingsResource(g.MqlRuntime, s)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// buildSsoSettingsResource converts a single grafanaSsoSettingsJSON to an
// MQL grafana.ssoSettings resource.
func buildSsoSettingsResource(runtime *plugin.Runtime, s grafanaSsoSettingsJSON) (plugin.Resource, error) {
	settingsDict, err := convert.JsonToDict(s.Settings)
	if err != nil {
		return nil, fmt.Errorf("grafana: converting sso settings for %s: %w", s.Provider, err)
	}

	enabled := boolFromAny(s.Settings["enabled"])
	allowSignUp := boolFromAny(s.Settings["allow_sign_up"])

	// hasDomainRestriction: any of allowed_domains, allowed_organizations,
	// allowed_groups limit who can sign in.
	hasRestriction := strings.TrimSpace(stringFromAny(s.Settings["allowed_domains"])) != "" ||
		strings.TrimSpace(stringFromAny(s.Settings["allowed_organizations"])) != "" ||
		strings.TrimSpace(stringFromAny(s.Settings["allowed_groups"])) != ""

	return CreateResource(runtime, "grafana.ssoSettings", map[string]*llx.RawData{
		"provider":             llx.StringData(s.Provider),
		"source":               llx.StringData(s.Source),
		"enabled":              llx.BoolData(enabled),
		"settings":             llx.DictData(settingsDict),
		"allowSignUp":          llx.BoolData(allowSignUp),
		"hasDomainRestriction": llx.BoolData(hasRestriction),
	})
}

func (s *mqlGrafanaSsoSettings) id() (string, error) {
	return "grafana-sso/" + s.Provider.Data, nil
}

// initGrafanaSamlSettings delegates to the parent grafana resource when the
// SAML settings are accessed directly (e.g. grafana.samlSettings.enabled).
func initGrafanaSamlSettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	grafanaRes, err := NewResource(runtime, "grafana", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	saml := grafanaRes.(*mqlGrafana).GetSamlSettings()
	if saml.Error != nil {
		return nil, nil, saml.Error
	}
	return nil, saml.Data, nil
}

// samlSettings fetches /api/v1/sso-settings/saml directly and surfaces the
// security-relevant fields (signing, encryption, logout, signup policy).
// Returns an empty resource (enabled=false) on instances without SAML.
func (g *mqlGrafana) samlSettings() (*mqlGrafanaSamlSettings, error) {
	conn, err := grafanaConnection(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	resp, err := conn.Get(context.Background(), "/api/v1/sso-settings/saml")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	args := map[string]*llx.RawData{
		"enabled":              llx.BoolData(false),
		"source":               llx.StringData(""),
		"signatureAlgorithm":   llx.StringData(""),
		"signRequests":         llx.BoolData(false),
		"singleLogoutEnabled":  llx.BoolData(false),
		"allowIdpInitiated":    llx.BoolData(false),
		"allowSignUp":          llx.BoolData(false),
		"allowedOrganizations": llx.StringData(""),
		"skipOrgRoleSync":      llx.BoolData(false),
		"settings":             llx.DictData(nil),
	}

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		res, err := CreateResource(g.MqlRuntime, "grafana.samlSettings", args)
		if err != nil {
			return nil, err
		}
		return res.(*mqlGrafanaSamlSettings), nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grafana: GET /api/v1/sso-settings/saml returned status %d", resp.StatusCode)
	}

	var saml grafanaSsoSettingsJSON
	if err := json.NewDecoder(resp.Body).Decode(&saml); err != nil {
		return nil, fmt.Errorf("grafana: decoding /api/v1/sso-settings/saml response: %w", err)
	}

	settingsDict, err := convert.JsonToDict(saml.Settings)
	if err != nil {
		return nil, fmt.Errorf("grafana: converting saml settings: %w", err)
	}

	args["enabled"] = llx.BoolData(boolFromAny(saml.Settings["enabled"]))
	args["source"] = llx.StringData(saml.Source)
	args["signatureAlgorithm"] = llx.StringData(stringFromAny(saml.Settings["signature_algorithm"]))
	args["signRequests"] = llx.BoolData(boolFromAny(saml.Settings["signed_requests"]))
	args["singleLogoutEnabled"] = llx.BoolData(boolFromAny(saml.Settings["single_logout"]))
	args["allowIdpInitiated"] = llx.BoolData(boolFromAny(saml.Settings["allow_idp_initiated"]))
	args["allowSignUp"] = llx.BoolData(boolFromAny(saml.Settings["allow_sign_up"]))
	args["allowedOrganizations"] = llx.StringData(stringFromAny(saml.Settings["allowed_organizations"]))
	args["skipOrgRoleSync"] = llx.BoolData(boolFromAny(saml.Settings["skip_org_role_sync"]))
	args["settings"] = llx.DictData(settingsDict)

	res, err := CreateResource(g.MqlRuntime, "grafana.samlSettings", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlGrafanaSamlSettings), nil
}

func (s *mqlGrafanaSamlSettings) id() (string, error) {
	return "grafana-sso/saml", nil
}

// boolFromAny extracts a bool from a JSON-decoded value. Grafana settings are
// often stored as strings even for boolean keys, so accept both.
func boolFromAny(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		b, _ := strconv.ParseBool(strings.TrimSpace(x))
		return b
	}
	return false
}

func stringFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
