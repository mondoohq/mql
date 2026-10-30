// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeSecurity(t *testing.T) {
	// Measured: workflows-nodes.json, a local n8n 2.44.6 on 2026-10-25. Each
	// node type appears once with parameters left at their defaults, which is
	// how the editor stores them, and once with explicit settings.
	c := fixtureServer(t, map[string]served{"/api/v1/workflows": {200, "workflows-nodes.json"}})
	workflows, err := c.Workflows(context.Background())
	require.NoError(t, err)
	require.Len(t, workflows, 1)

	nodes := map[string]Node{}
	for _, n := range workflows[0].Nodes {
		nodes[n.Name] = n
	}
	require.Len(t, nodes, 9)

	f, tr := false, true

	// A webhook with no authentication parameter is open: the default is none.
	assert.Equal(t, nodeSecurity{Authentication: "none", Path: "default-hook", IPAllowlist: []string{}}, nodes["Webhook default"].nodeSecurity)
	assert.Equal(t, nodeSecurity{Authentication: "headerAuth", Path: "locked-hook", IPAllowlist: []string{"10.0.0.1", "192.168.1.0/24"}}, nodes["Webhook locked"].nodeSecurity)
	assert.Equal(t, nodeSecurity{Authentication: "none"}, nodes["Form default"].nodeSecurity)

	// A chat that is not public reports neither authentication nor origins.
	assert.Equal(t, nodeSecurity{Public: &f}, nodes["Chat private"].nodeSecurity)
	assert.Equal(t, nodeSecurity{Public: &tr, Authentication: "none", AllowedOrigins: []string{"*"}}, nodes["Chat public open"].nodeSecurity)
	assert.Equal(t, nodeSecurity{Public: &tr, Authentication: "basicAuth", AllowedOrigins: []string{"https://app.example.com"}}, nodes["Chat public locked"].nodeSecurity)

	// Only the host of a literal URL is read; the query token is not.
	assert.Equal(t, nodeSecurity{Authentication: "none", AllowUnauthorizedCerts: &f, RequestHost: "api.example.com:8443"}, nodes["HTTP default"].nodeSecurity)
	assert.Equal(t, nodeSecurity{Authentication: "none", AllowUnauthorizedCerts: &tr}, nodes["HTTP insecure"].nodeSecurity)
	// Version 1 keeps allowUnauthorizedCerts at the top level.
	assert.Equal(t, nodeSecurity{Authentication: "none", AllowUnauthorizedCerts: &tr, RequestHost: "legacy.example.com"}, nodes["HTTP v1 insecure"].nodeSecurity)
}

func TestNodeSecurityOtherTypes(t *testing.T) {
	// Measured: a Code node from workflows.json carries jsCode only. Nothing
	// applies, so every setting stays null.
	assert.Equal(t, nodeSecurity{}, readNodeSecurity("n8n-nodes-base.code", 2, map[string]any{"jsCode": "return [];"}))
}

func TestNodeSecurityExpressions(t *testing.T) {
	// Synthetic: settings an expression decides are unknown, never the safe
	// default. A chat whose visibility is an expression may be public, so its
	// authentication and origins are still read.
	chat := readNodeSecurity(NodeTypeChatTrigger, 1.1, map[string]any{"public": "={{ $env.PUBLIC_CHAT }}"})
	assert.Nil(t, chat.Public)
	assert.Equal(t, "none", chat.Authentication)
	assert.Equal(t, []string{"*"}, chat.AllowedOrigins)

	http := readNodeSecurity(NodeTypeHTTPRequest, 4.2, map[string]any{"options": map[string]any{"allowUnauthorizedCerts": "={{ $json.insecure }}"}})
	assert.Nil(t, http.AllowUnauthorizedCerts)

	legacy := readNodeSecurity(NodeTypeHTTPRequest, 1, map[string]any{"allowUnauthorizedCerts": "={{ true }}"})
	assert.Nil(t, legacy.AllowUnauthorizedCerts)
}

func TestStringParam(t *testing.T) {
	// Synthetic: values the editor can store besides plain strings.
	params := map[string]any{"a": "basicAuth", "expr": "={{ $json.auth }}", "num": 3.0, "null": nil}
	assert.Equal(t, "basicAuth", stringParam(params, "a", "none"))
	assert.Equal(t, "none", stringParam(params, "missing", "none"))
	assert.Equal(t, "none", stringParam(params, "null", "none"))
	assert.Empty(t, stringParam(params, "expr", "none"))
	assert.Empty(t, stringParam(params, "num", "none"))
}

func TestLiteralURLHost(t *testing.T) {
	// Synthetic: user info and paths never come through.
	assert.Equal(t, "api.example.com", literalURLHost("https://user:pass@api.example.com/path?key=1"))
	assert.Equal(t, "10.0.0.5:8080", literalURLHost("http://10.0.0.5:8080"))
	assert.Empty(t, literalURLHost("not a url"))
	assert.Empty(t, literalURLHost(""))
}
