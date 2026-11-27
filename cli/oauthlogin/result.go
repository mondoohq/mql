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

// ConfigValues returns the config keys to persist for this login.
//
// The token is stored under "token", the key the client already sends as a
// bearer token. agent_mrn, private_key and certificate are deliberately
// absent: a login is not a registered client and holds no key. "mrn" is the
// user's MRN.
func (r *Result) ConfigValues() map[string]any {
	// The API endpoint is the one the user logged in to, unless the server
	// names another. The issuer is never used for it: the login server may
	// be a different host than the API.
	apiEndpoint := r.Credential.ApiEndpoint
	if apiEndpoint == "" {
		apiEndpoint = r.Endpoint
	}
	auth := map[string]any{
		"method":   AuthMethod,
		"issuer":   r.Issuer,
		"endpoint": r.Endpoint,
	}
	if !r.ValidUntil.IsZero() {
		auth["valid_until"] = r.ValidUntil.UTC().Format(time.RFC3339)
	}
	// Names shown when login finds this session still valid. Absent ones are
	// left out, and the confirmation falls back to MRNs.
	for key, value := range map[string]string{
		"user_email": r.User.Email,
		"user_name":  r.User.Name,
		"user_mrn":   r.User.Mrn,
		"scope_name": r.Scope.Name,
		"scope_kind": r.Scope.Kind,
		"org_name":   r.Scope.OrgName,
	} {
		if value != "" {
			auth[key] = value
		}
	}
	return map[string]any{
		"mrn":          r.Credential.Mrn,
		"scope_mrn":    r.Credential.ScopeMrn,
		"token":        r.Credential.Token,
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
		ScopeName:  r.Scope.Name,
		ScopeKind:  r.Scope.Kind,
		OrgName:    r.Scope.OrgName,
		ScopeMrn:   r.Credential.ScopeMrn,
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
	UserEmail string
	UserName  string
	UserMrn   string
	// ScopeName, ScopeKind and ScopeMrn describe what the login is for: a
	// space or an organization.
	ScopeName string
	ScopeKind string
	ScopeMrn  string
	// OrgName is the space's organization, or the organization itself.
	OrgName    string
	ValidUntil time.Time
}

// Summary formats the session as one line that starts with headline, for
// example "✓ Logged in as jane@example.com · space acme/prod · valid until
// 2026-10-06 13:00 CEST (1h)". A login to an organization reads
// "organization acme".
func (s SessionInfo) Summary(headline string, now time.Time) string {
	// The names come from the server.
	for _, f := range []*string{&s.UserEmail, &s.UserName, &s.UserMrn, &s.ScopeName, &s.OrgName, &s.ScopeMrn} {
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

	kind := "space"
	scope := s.ScopeName
	if s.ScopeKind == ScopeKindOrganization {
		kind = "organization"
	} else if s.OrgName != "" && s.ScopeName != "" {
		scope = s.OrgName + "/" + s.ScopeName
	}
	if scope == "" {
		scope = s.ScopeMrn
	}
	if scope != "" {
		parts = append(parts, kind+" "+scope)
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
