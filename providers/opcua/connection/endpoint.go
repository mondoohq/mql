// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
)

// securityModes maps the message security mode names accepted on the command
// line to their protocol values.
var securityModes = map[string]ua.MessageSecurityMode{
	"None":           ua.MessageSecurityModeNone,
	"Sign":           ua.MessageSecurityModeSign,
	"SignAndEncrypt": ua.MessageSecurityModeSignAndEncrypt,
}

// endpointStrength ranks how much protection an endpoint provides. It defers to
// the ranking the OPC UA stack keeps for every policy and mode combination, so
// a deprecated policy that encrypts does not outrank a modern policy that only
// signs. A policy the stack cannot negotiate ranks at zero and is therefore
// only reached as a last-resort fallback.
func endpointStrength(ep *ua.EndpointDescription) int {
	return int(uapolicy.SecurityLevel(ep.SecurityPolicyURI, ep.SecurityMode))
}

// parseSecurityPolicy turns a security policy name into its canonical URI. An
// empty name means "whatever the server offers" and yields an empty URI.
func parseSecurityPolicy(policy string) (string, error) {
	if policy == "" {
		return "", nil
	}
	uri := ua.FormatSecurityPolicyURI(policy)
	for _, known := range ua.SecurityPolicyURIs {
		if known == uri {
			return uri, nil
		}
	}
	return "", fmt.Errorf("unsupported security policy %q, expected one of %s", policy, strings.Join(securityPolicyNames(), ", "))
}

// parseSecurityMode turns a message security mode name into its protocol
// value. An empty name means "whatever the server offers" and yields
// MessageSecurityModeInvalid.
func parseSecurityMode(mode string) (ua.MessageSecurityMode, error) {
	if mode == "" {
		return ua.MessageSecurityModeInvalid, nil
	}
	value, ok := securityModes[mode]
	if !ok {
		return ua.MessageSecurityModeInvalid, fmt.Errorf("unsupported security mode %q, expected one of None, Sign, SignAndEncrypt", mode)
	}
	return value, nil
}

func securityPolicyNames() []string {
	names := make([]string, 0, len(ua.SecurityPolicyURIs))
	for name := range ua.SecurityPolicyURIs {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return uapolicy.SecurityLevel(ua.SecurityPolicyURIs[names[i]], ua.MessageSecurityModeSignAndEncrypt) <
			uapolicy.SecurityLevel(ua.SecurityPolicyURIs[names[j]], ua.MessageSecurityModeSignAndEncrypt)
	})
	return names
}

// supportsTokenType reports whether an endpoint accepts the given user token
// type. Servers that advertise no user identity tokens at all are treated as
// compatible: rejecting them would drop endpoints that are in fact usable.
func supportsTokenType(ep *ua.EndpointDescription, tokenType ua.UserTokenType) bool {
	if len(ep.UserIdentityTokens) == 0 {
		return true
	}
	for _, token := range ep.UserIdentityTokens {
		if token != nil && token.TokenType == tokenType {
			return true
		}
	}
	return false
}

// selectEndpoints returns the endpoints worth attempting, strongest security
// first. Callers walk the result in order and fall back to the next entry when
// a connection cannot be established, so a server that advertises an endpoint
// it cannot actually serve still connects on a weaker one.
//
// policy and mode narrow the candidates to an exact match when set. They are
// the escape hatch for a server whose advertised endpoints do not reflect what
// it accepts; left empty, selection is automatic.
func selectEndpoints(endpoints []*ua.EndpointDescription, policy string, mode string, tokenType ua.UserTokenType) ([]*ua.EndpointDescription, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("the OPC UA server did not advertise any endpoints")
	}

	wantPolicy, err := parseSecurityPolicy(policy)
	if err != nil {
		return nil, err
	}
	wantMode, err := parseSecurityMode(mode)
	if err != nil {
		return nil, err
	}

	candidates := make([]*ua.EndpointDescription, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep == nil {
			continue
		}
		if wantPolicy != "" && ep.SecurityPolicyURI != wantPolicy {
			continue
		}
		if wantMode != ua.MessageSecurityModeInvalid && ep.SecurityMode != wantMode {
			continue
		}
		if !supportsTokenType(ep, tokenType) {
			continue
		}
		candidates = append(candidates, ep)
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf(
			"no endpoint supports %s authentication with the requested security settings, the server offers security %s and authentication %s",
			tokenTypeName(tokenType), describeEndpoints(endpoints), describeTokenTypes(endpoints),
		)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if endpointStrength(a) != endpointStrength(b) {
			return endpointStrength(a) > endpointStrength(b)
		}
		// equally strong on paper, so fall back to the ranking the server
		// itself publishes
		return a.SecurityLevel > b.SecurityLevel
	})

	return candidates, nil
}

// modeName renders a message security mode with the short name used on the
// command line. The generated String() prefixes every value with the type name,
// which reads badly in a message that already says "security".
func modeName(mode ua.MessageSecurityMode) string {
	for name, value := range securityModes {
		if value == mode {
			return name
		}
	}
	return "Invalid"
}

// describeEndpoint renders an endpoint's security settings for log and error
// messages.
func describeEndpoint(ep *ua.EndpointDescription) string {
	policy := strings.TrimPrefix(ep.SecurityPolicyURI, ua.SecurityPolicyURIPrefix)
	if policy == "" {
		policy = "unknown"
	}
	return policy + "/" + modeName(ep.SecurityMode)
}

// tokenTypeName renders a user token type the way a user would name it.
func tokenTypeName(tokenType ua.UserTokenType) string {
	switch tokenType {
	case ua.UserTokenTypeUserName:
		return "username and password"
	case ua.UserTokenTypeCertificate:
		return "certificate"
	case ua.UserTokenTypeIssuedToken:
		return "issued token"
	default:
		return "anonymous"
	}
}

// describeTokenTypes lists the authentication methods the server advertises.
func describeTokenTypes(endpoints []*ua.EndpointDescription) string {
	seen := map[string]struct{}{}
	names := []string{}
	for _, ep := range endpoints {
		if ep == nil {
			continue
		}
		for _, token := range ep.UserIdentityTokens {
			if token == nil {
				continue
			}
			name := tokenTypeName(token.TokenType)
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

func describeEndpoints(endpoints []*ua.EndpointDescription) string {
	seen := map[string]struct{}{}
	descriptions := []string{}
	for _, ep := range endpoints {
		if ep == nil {
			continue
		}
		description := describeEndpoint(ep)
		if _, ok := seen[description]; ok {
			continue
		}
		seen[description] = struct{}{}
		descriptions = append(descriptions, description)
	}
	if len(descriptions) == 0 {
		return "none"
	}
	return strings.Join(descriptions, ", ")
}
