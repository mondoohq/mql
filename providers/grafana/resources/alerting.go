// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// grafanaContactPointJSON mirrors one element of the
// /api/v1/provisioning/contact-points response.
type grafanaContactPointJSON struct {
	UID                   string          `json:"uid"`
	Name                  string          `json:"name"`
	Type                  string          `json:"type"`
	DisableResolveMessage bool            `json:"disableResolveMessage"`
	Settings              json.RawMessage `json:"settings"`
}

// grafanaNotificationPolicyJSON mirrors the /api/v1/provisioning/policies response.
type grafanaNotificationPolicyJSON struct {
	Receiver string          `json:"receiver"`
	GroupBy  []string        `json:"group_by"`
	Routes   json.RawMessage `json:"routes"`
}

func (g *mqlGrafana) contactPoints() ([]any, error) {
	conn, err := grafanaConnection(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	resp, err := conn.Get(context.Background(), "/api/v1/provisioning/contact-points")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grafana: GET /api/v1/provisioning/contact-points returned status %d", resp.StatusCode)
	}

	var raw []grafanaContactPointJSON
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("grafana: decoding /api/v1/provisioning/contact-points response: %w", err)
	}

	list := make([]any, 0, len(raw))
	for _, cp := range raw {
		var settingsDict any
		if len(cp.Settings) > 0 && string(cp.Settings) != "null" {
			var parsed any
			if err := json.Unmarshal(cp.Settings, &parsed); err != nil {
				return nil, fmt.Errorf("grafana: parsing settings for contact point %s: %w", cp.UID, err)
			}
			settingsDict, err = convert.JsonToDict(parsed)
			if err != nil {
				return nil, fmt.Errorf("grafana: converting settings for contact point %s: %w", cp.UID, err)
			}
		}

		res, err := CreateResource(g.MqlRuntime, "grafana.contactPoint", map[string]*llx.RawData{
			"uid":                   llx.StringData(cp.UID),
			"name":                  llx.StringData(cp.Name),
			"type":                  llx.StringData(cp.Type),
			"disableResolveMessage": llx.BoolData(cp.DisableResolveMessage),
			"settings":              llx.DictData(settingsDict),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (c *mqlGrafanaContactPoint) id() (string, error) {
	return "grafana-cp/" + c.Uid.Data, nil
}

// contactPointSettings returns the parsed settings dict, or nil if absent.
func (c *mqlGrafanaContactPoint) contactPointSettings() map[string]any {
	v := c.Settings
	if v.Error != nil || v.Data == nil {
		return nil
	}
	m, ok := v.Data.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

// contactPointURL returns the URL configured on the contact point. Different
// contact-point types use different keys (slack=url, webhook=url,
// pagerduty=integrationKey not URL, etc.).
func contactPointURL(cpType string, settings map[string]any) string {
	if settings == nil {
		return ""
	}
	candidates := []string{"url", "endpointUrl", "apiUrl", "webhook", "webhookUrl"}
	for _, k := range candidates {
		if v, ok := settings[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func (c *mqlGrafanaContactPoint) url() (string, error) {
	return contactPointURL(c.Type.Data, c.contactPointSettings()), nil
}

// isHttps reports whether the configured URL uses HTTPS. For contact-point
// types that have no URL (e.g., email, sms, prometheus alertmanager via
// internal addressing), this returns true so the field is not falsely flagged.
func (c *mqlGrafanaContactPoint) isHttps() (bool, error) {
	u := contactPointURL(c.Type.Data, c.contactPointSettings())
	if u == "" {
		return true, nil
	}
	return strings.HasPrefix(strings.ToLower(u), "https://"), nil
}

// contactPointTLSSkipVerify reports whether the contact-point settings disable
// TLS server-certificate verification. httpConfig.tlsConfig is the standard
// Alertmanager-style nested key; a top-level tlsConfig is the flatter
// Grafana-managed key.
func contactPointTLSSkipVerify(settings map[string]any) bool {
	if settings == nil {
		return false
	}
	if hc, ok := settings["httpConfig"].(map[string]any); ok {
		if tls, ok := hc["tlsConfig"].(map[string]any); ok {
			if v, ok := tls["insecureSkipVerify"].(bool); ok && v {
				return true
			}
		}
	}
	if tls, ok := settings["tlsConfig"].(map[string]any); ok {
		if v, ok := tls["insecureSkipVerify"].(bool); ok && v {
			return true
		}
	}
	return false
}

func (c *mqlGrafanaContactPoint) tlsSkipVerify() (bool, error) {
	return contactPointTLSSkipVerify(c.contactPointSettings()), nil
}

// contactPointHasHTTPAuth reports whether basic-auth or bearer-token auth is
// configured on the contact point, indicating the alert receiver requires
// authentication.
func contactPointHasHTTPAuth(settings map[string]any) bool {
	if settings == nil {
		return false
	}
	if _, ok := settings["username"]; ok {
		return true
	}
	if _, ok := settings["authorizationCredentials"]; ok {
		return true
	}
	if hc, ok := settings["httpConfig"].(map[string]any); ok {
		if _, ok := hc["basicAuth"]; ok {
			return true
		}
		if _, ok := hc["bearerToken"]; ok {
			return true
		}
		if _, ok := hc["authorization"]; ok {
			return true
		}
	}
	return false
}

func (c *mqlGrafanaContactPoint) hasHttpAuth() (bool, error) {
	return contactPointHasHTTPAuth(c.contactPointSettings()), nil
}

// initGrafanaNotificationPolicy delegates to the parent grafana resource when
// the notification policy is accessed directly (e.g. grafana.notificationPolicy.receiver).
// Without this, NewResource creates an empty stub with no field data.
func initGrafanaNotificationPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	grafanaRes, err := NewResource(runtime, "grafana", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	np := grafanaRes.(*mqlGrafana).GetNotificationPolicy()
	if np.Error != nil {
		return nil, nil, np.Error
	}
	return nil, np.Data, nil
}

func (g *mqlGrafana) notificationPolicy() (*mqlGrafanaNotificationPolicy, error) {
	conn, err := grafanaConnection(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	resp, err := conn.Get(context.Background(), "/api/v1/provisioning/policies")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grafana: GET /api/v1/provisioning/policies returned status %d", resp.StatusCode)
	}

	var policy grafanaNotificationPolicyJSON
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return nil, fmt.Errorf("grafana: decoding /api/v1/provisioning/policies response: %w", err)
	}

	// Convert groupBy string slice to []interface{} for the MQL array.
	groupByAny := make([]any, len(policy.GroupBy))
	for i, v := range policy.GroupBy {
		groupByAny[i] = v
	}

	// Decode routes to []interface{} and convert each element to a dict.
	var rawRoutes []any
	if len(policy.Routes) > 0 && string(policy.Routes) != "null" {
		if err := json.Unmarshal(policy.Routes, &rawRoutes); err != nil {
			return nil, fmt.Errorf("grafana: parsing routes in notification policy: %w", err)
		}
	}
	routeDicts := make([]any, 0, len(rawRoutes))
	for _, r := range rawRoutes {
		d, err := convert.JsonToDict(r)
		if err != nil {
			return nil, fmt.Errorf("grafana: converting notification policy route: %w", err)
		}
		routeDicts = append(routeDicts, d)
	}

	res, err := CreateResource(g.MqlRuntime, "grafana.notificationPolicy", map[string]*llx.RawData{
		"receiver": llx.StringData(policy.Receiver),
		"groupBy":  llx.ArrayData(groupByAny, types.String),
		"routes":   llx.ArrayData(routeDicts, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGrafanaNotificationPolicy), nil
}

func (n *mqlGrafanaNotificationPolicy) id() (string, error) {
	return "grafana-notification-policy", nil
}
