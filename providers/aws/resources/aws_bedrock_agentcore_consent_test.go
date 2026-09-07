// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// AgentCore accepts either a bare gateway id or a full gateway ARN when a
// consent portal source is configured, and reports back whichever was used.
// Comparing whole strings resolves only the ARN-configured half of real
// portals; because a failed resolution is logged and skipped, the id-configured
// half would surface as a silently null gateway rather than an error.
func TestMatchesAgentCoreIdentifier(t *testing.T) {
	const gatewayArn = "arn:aws:bedrock-agentcore:us-east-1:555555555555:gateway/gw-abc123"

	tests := []struct {
		name       string
		arn        string
		identifier string
		want       bool
	}{
		{"exact arn", gatewayArn, gatewayArn, true},
		{"bare id matches last segment", gatewayArn, "gw-abc123", true},
		{"bare id of a different gateway", gatewayArn, "gw-xyz789", false},
		{"different arn must not match by suffix", gatewayArn, "arn:aws:bedrock-agentcore:eu-west-1:555555555555:gateway/gw-abc123", false},
		{"empty identifier", gatewayArn, "", false},
		{"empty arn", "", "gw-abc123", false},
		{"arn without a path separator", "gw-abc123", "gw-abc123", true},
		{"partial id must not match", gatewayArn, "abc123", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, matchesAgentCoreIdentifier(tc.arn, tc.identifier))
		})
	}
}

// Two portals may serve the same source, and one portal may serve the same
// identifier under two source types. A key that drops either dimension
// collapses those into one row, so CreateResource returns the cached first
// source and the second one is never reported.
func TestConsentPortalSourceCacheID_Distinct(t *testing.T) {
	const portal = "arn:aws:bedrock-agentcore:us-east-1:555555555555:consent-portal/cp-1"

	base := consentPortalSourceCacheID(portal, "agentcore-gateway", "gw-abc123")

	assert.NotEqual(t, base, consentPortalSourceCacheID(portal, "agentcore-gateway", "gw-xyz789"))
	assert.NotEqual(t, base, consentPortalSourceCacheID(portal, "some-other-type", "gw-abc123"))
	assert.NotEqual(t, base, consentPortalSourceCacheID(
		"arn:aws:bedrock-agentcore:us-east-1:555555555555:consent-portal/cp-2",
		"agentcore-gateway", "gw-abc123"))
}
