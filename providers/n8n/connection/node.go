// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/url"
	"strings"
)

// Node types whose security settings are read.
const (
	NodeTypeWebhook     = "n8n-nodes-base.webhook"
	NodeTypeFormTrigger = "n8n-nodes-base.formTrigger"
	NodeTypeChatTrigger = "@n8n/n8n-nodes-langchain.chatTrigger"
	NodeTypeHTTPRequest = "n8n-nodes-base.httpRequest"
)

// nodeSecurity holds the security settings of a node as they take effect.
//
// The n8n editor stores only the parameters a user changed from their
// default, so an unset parameter means the node's default applies. A Webhook
// left on its default authentication carries no `authentication` key at all
// (25 of 28 UI-built webhooks in n8n's public templates, 2026-10-25). The
// defaults below are the ones the node definitions declare in n8n 2.44.6, for
// every version of each node: `authentication` is "none" on all four node
// types, a Chat Trigger is not public and allows every origin, a Webhook has
// no IP allowlist, and an HTTP Request verifies certificates.
//
// Fields that do not apply to a node's type stay empty (nil for pointers and
// lists) and surface as null.
type nodeSecurity struct {
	Authentication         string
	Path                   string
	Public                 *bool
	AllowedOrigins         []string
	IPAllowlist            []string
	AllowUnauthorizedCerts *bool
	RequestHost            string
}

func readNodeSecurity(nodeType string, typeVersion float64, params map[string]any) nodeSecurity {
	var s nodeSecurity
	options, _ := params["options"].(map[string]any)

	switch nodeType {
	case NodeTypeWebhook:
		s.Authentication = stringParam(params, "authentication", "none")
		s.Path = stringParam(params, "path", "")
		s.IPAllowlist = listParam(options, "ipWhitelist", "")
	case NodeTypeFormTrigger:
		s.Authentication = stringParam(params, "authentication", "none")
		s.Path = stringParam(params, "path", "")
	case NodeTypeChatTrigger:
		s.Public = boolParam(params, "public", false)
		// A chat that is not public opens only inside the n8n editor, where
		// the editor login protects it; authentication and origins apply to
		// the public chat. When an expression decides whether the chat is
		// public, it may be, so they are read too.
		if s.Public == nil || *s.Public {
			s.Authentication = stringParam(params, "authentication", "none")
			s.AllowedOrigins = listParam(options, "allowedOrigins", "*")
		}
	case NodeTypeHTTPRequest:
		s.Authentication = stringParam(params, "authentication", "none")
		// Versions 1 and 2 keep the flag at the top level, 3 and later
		// under options.
		if typeVersion < 3 {
			s.AllowUnauthorizedCerts = boolParam(params, "allowUnauthorizedCerts", false)
		} else {
			s.AllowUnauthorizedCerts = boolParam(options, "allowUnauthorizedCerts", false)
		}
		s.RequestHost = literalURLHost(stringParam(params, "url", ""))
	}
	return s
}

// stringParam reads a string parameter, or the default when it is unset.
// Expressions (values starting with "=") are computed per execution and have
// no value to report, so they read as empty.
func stringParam(params map[string]any, key, def string) string {
	v, ok := params[key]
	if !ok || v == nil {
		return def
	}
	s, ok := v.(string)
	if !ok || strings.HasPrefix(s, "=") {
		return ""
	}
	return s
}

// boolParam reads a boolean parameter, or the default when it is unset. A
// value that is set but is not a boolean, such as an expression, is decided
// per execution and reads as nil (unknown) rather than as the default, which
// would claim the safe setting.
func boolParam(params map[string]any, key string, def bool) *bool {
	v, ok := params[key]
	if !ok || v == nil {
		return &def
	}
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	return &b
}

// listParam reads a comma-separated list parameter, or the default list when
// it is unset. The result is never nil, so a node the setting applies to
// reports an empty list rather than null.
func listParam(params map[string]any, key, def string) []string {
	out := splitList(stringParam(params, key, def))
	if out == nil {
		out = []string{}
	}
	return out
}

// literalURLHost returns the host (with port, when one is given) of a request
// URL written as a literal. A URL built from an expression is resolved per
// execution and reads as empty, as does one that does not parse. User info
// is never returned.
func literalURLHost(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}
