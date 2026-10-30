// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestViewerPolicyEnforcesHttps(t *testing.T) {
	assert.True(t, viewerPolicyEnforcesHttps("https-only"))
	assert.True(t, viewerPolicyEnforcesHttps("redirect-to-https"))
	assert.False(t, viewerPolicyEnforcesHttps("allow-all"))
	assert.False(t, viewerPolicyEnforcesHttps("Allow-All"))
	assert.False(t, viewerPolicyEnforcesHttps(""))
}

func TestListenerProtocolIsPlaintext(t *testing.T) {
	// The encrypted protocols are the closed set: HTTPS and TLS on ALB and NLB,
	// SSL on a classic load balancer.
	for _, p := range []string{"HTTPS", "TLS", "SSL", "https", "tls", "ssl"} {
		assert.False(t, listenerProtocolIsPlaintext(p), p)
	}

	for _, p := range []string{"HTTP", "TCP", "UDP", "TCP_UDP", "http", "tcp"} {
		assert.True(t, listenerProtocolIsPlaintext(p), p)
	}

	// GENEVE is the Gateway Load Balancer tunnel and carries traffic in the
	// clear. The schema enumerates it, so it is not a hypothetical value.
	assert.True(t, listenerProtocolIsPlaintext("GENEVE"))

	// A protocol this predicate has not seen, and a listener whose description
	// did not parse, both have to fail toward plaintext. Reporting an unread
	// listener as encrypted is the answer that lets a finding through.
	assert.True(t, listenerProtocolIsPlaintext("QUIC"))
	assert.True(t, listenerProtocolIsPlaintext(""))
}

func TestListenerDescriptionProtocol(t *testing.T) {
	// ALB/NLB shape: protocol at the top level.
	assert.Equal(t, "HTTPS", listenerDescriptionProtocol(map[string]any{"Protocol": "HTTPS"}))
	// Classic ELB shape: protocol nested under "Listener".
	assert.Equal(t, "HTTP", listenerDescriptionProtocol(map[string]any{"Listener": map[string]any{"Protocol": "HTTP"}}))
	// Neither shape present.
	assert.Equal(t, "", listenerDescriptionProtocol(map[string]any{"PolicyNames": []any{}}))
	assert.Equal(t, "", listenerDescriptionProtocol(map[string]any{}))
}
