// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"fmt"
	"strings"
	"time"
)

// AuthMethod marks a config whose credential came from this login flow.
const AuthMethod = "oauth"

// ConfigValues returns the config keys to persist for this login. agent_mrn is
// deliberately absent: a session credential is not a registered client.
func (r *Result) ConfigValues() map[string]any {
	apiEndpoint := r.ServiceAccount.ApiEndpoint
	if apiEndpoint == "" {
		apiEndpoint = r.Issuer
	}
	return map[string]any{
		"mrn":          r.ServiceAccount.Mrn,
		"space_mrn":    r.ServiceAccount.SpaceMrn,
		"scope_mrn":    r.ServiceAccount.ScopeMrn,
		"certificate":  r.ServiceAccount.Certificate,
		"private_key":  r.PrivateKeyPEM,
		"api_endpoint": apiEndpoint,
		"auth": map[string]any{
			"method":       AuthMethod,
			"issuer":       r.Issuer,
			"access_token": r.AccessToken,
		},
	}
}

// Summary is the one-line confirmation printed after a login.
func (r *Result) Summary(now time.Time) string {
	who := r.User.Email
	if who == "" {
		who = r.User.Name
	}
	if who == "" {
		who = r.User.Mrn
	}
	parts := []string{"✓ Logged in"}
	if who != "" {
		parts[0] += " as " + who
	}

	space := r.Space.Name
	if space == "" {
		space = r.ServiceAccount.SpaceMrn
	}
	if r.Space.OrgName != "" && r.Space.Name != "" {
		space = r.Space.OrgName + "/" + r.Space.Name
	}
	if space != "" {
		parts = append(parts, "space "+space)
	}
	if !r.ValidUntil.IsZero() {
		parts = append(parts, fmt.Sprintf("valid until %s (%s)",
			r.ValidUntil.Local().Format("2006-01-02 15:04 MST"), humanDuration(r.ValidUntil.Sub(now))))
	}
	return strings.Join(parts, " · ")
}

func humanDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	if d <= 0 {
		return "expired"
	}
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case h > 0:
		return fmt.Sprintf("%dh", h)
	default:
		return fmt.Sprintf("%dm", m)
	}
}
