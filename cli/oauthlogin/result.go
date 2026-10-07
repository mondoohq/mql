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
	auth := map[string]any{
		"method":       AuthMethod,
		"issuer":       r.Issuer,
		"access_token": r.AccessToken,
	}
	// Names shown when login finds this session still valid. Absent ones are
	// left out, and the confirmation falls back to MRNs.
	for key, value := range map[string]string{
		"user_email": r.User.Email,
		"user_name":  r.User.Name,
		"user_mrn":   r.User.Mrn,
		"space_name": r.Space.Name,
		"org_name":   r.Space.OrgName,
	} {
		if value != "" {
			auth[key] = value
		}
	}
	return map[string]any{
		"mrn":          r.ServiceAccount.Mrn,
		"space_mrn":    r.ServiceAccount.SpaceMrn,
		"scope_mrn":    r.ServiceAccount.ScopeMrn,
		"certificate":  r.ServiceAccount.Certificate,
		"private_key":  r.PrivateKeyPEM,
		"api_endpoint": apiEndpoint,
		"auth":         auth,
	}
}

// Info returns what the login confirmation shows about this session.
func (r *Result) Info() SessionInfo {
	return SessionInfo{
		UserEmail:  r.User.Email,
		UserName:   r.User.Name,
		UserMrn:    r.User.Mrn,
		SpaceName:  r.Space.Name,
		OrgName:    r.Space.OrgName,
		SpaceMrn:   r.ServiceAccount.SpaceMrn,
		ValidUntil: r.ValidUntil,
	}
}

// Summary is the one-line confirmation printed after a login.
func (r *Result) Summary(now time.Time) string {
	return r.Info().Summary("✓ Logged in", now)
}

// SessionInfo describes a login session for the confirmation line. Names
// that are not known fall back to MRNs.
type SessionInfo struct {
	UserEmail  string
	UserName   string
	UserMrn    string
	SpaceName  string
	OrgName    string
	SpaceMrn   string
	ValidUntil time.Time
}

// Summary formats the session as one line that starts with headline, for
// example "✓ Logged in as jane@example.com · space acme/prod · valid until
// 2026-10-06 13:00 CEST (1h)".
func (s SessionInfo) Summary(headline string, now time.Time) string {
	// The names come from the server.
	for _, f := range []*string{&s.UserEmail, &s.UserName, &s.UserMrn, &s.SpaceName, &s.OrgName, &s.SpaceMrn} {
		*f = DisplayText(*f)
	}
	who := s.UserEmail
	if who == "" {
		who = s.UserName
	}
	if who == "" {
		who = s.UserMrn
	}
	parts := []string{headline}
	if who != "" {
		parts[0] += " as " + who
	}

	space := s.SpaceName
	if space == "" {
		space = s.SpaceMrn
	}
	if s.OrgName != "" && s.SpaceName != "" {
		space = s.OrgName + "/" + s.SpaceName
	}
	if space != "" {
		parts = append(parts, "space "+space)
	}
	if !s.ValidUntil.IsZero() {
		parts = append(parts, fmt.Sprintf("valid until %s (%s)",
			s.ValidUntil.Local().Format("2006-01-02 15:04 MST"), humanDuration(s.ValidUntil.Sub(now))))
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
