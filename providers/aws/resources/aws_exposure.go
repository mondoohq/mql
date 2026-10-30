// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "strings"

// viewerPolicyEnforcesHttps reports whether a CloudFront viewer protocol policy
// requires HTTPS. "allow-all" permits plaintext HTTP; "https-only" and
// "redirect-to-https" enforce TLS. An empty policy is treated as not enforcing.
func viewerPolicyEnforcesHttps(policy string) bool {
	return policy != "" && !strings.EqualFold(policy, "allow-all")
}

// listenerProtocolIsPlaintext reports whether a load balancer listener protocol
// carries traffic without transport encryption.
//
// The encrypted protocols are the closed set, so they are what gets listed:
// HTTPS and TLS on ALB and NLB, SSL on a classic load balancer. Everything else
// is plaintext, which is the safe direction for a value this predicate has not
// seen before. Listing the plaintext names instead would have reported GENEVE -
// the unencrypted Gateway Load Balancer tunnel - as encrypted, along with any
// protocol AWS adds later and any value the description did not parse.
func listenerProtocolIsPlaintext(protocol string) bool {
	switch strings.ToUpper(protocol) {
	case "HTTPS", "TLS", "SSL":
		return false
	default:
		return true
	}
}

// listenerDescriptionProtocol extracts the protocol from a load balancer
// listener-description dict, handling both shapes: ALB/NLB listeners (from
// DescribeListeners) carry "Protocol" at the top level, while classic ELB
// listener descriptions nest it under "Listener".
func listenerDescriptionProtocol(desc map[string]any) string {
	if p, ok := desc["Protocol"].(string); ok && p != "" {
		return p
	}
	if listener, ok := desc["Listener"].(map[string]any); ok {
		if p, ok := listener["Protocol"].(string); ok {
			return p
		}
	}
	return ""
}
