// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	agentregistry "google.golang.org/api/agentregistry/v1"
	"google.golang.org/api/googleapi"
)

func TestAgentRegistryAgentDecode(t *testing.T) {
	// Synthetic: an A2A agent shaped after the v1 discovery document; no
	// target showed this.
	body := `{
		"name": "projects/p/locations/us-central1/agents/a1",
		"agentId": "a1",
		"version": "1.2.0",
		"protocols": [
			{"type": "A2A_AGENT", "interfaces": [{"url": "https://agent.example.com/a2a", "protocolBinding": "JSONRPC"}, {"url": "https://agent.example.com/grpc", "protocolBinding": "GRPC"}]},
			{"type": "A2A_AGENT", "interfaces": [{"url": "https://agent.example.com/a2a", "protocolBinding": "HTTP_JSON"}]},
			{"type": "CUSTOM"}
		],
		"skills": [{"id": "s1", "name": "search tickets"}],
		"attributes": {"agentregistry.googleapis.com/system/Framework": {"framework": "google-adk"}}
	}`
	var a agentregistry.Agent
	require.NoError(t, json.Unmarshal([]byte(body), &a))

	protocols, urls := agentRegistryAgentProtocols(a.Protocols)
	assert.Equal(t, []string{"A2A_AGENT", "CUSTOM"}, protocols)
	assert.Equal(t, []string{"https://agent.example.com/a2a", "https://agent.example.com/grpc"}, urls)
	require.Len(t, a.Skills, 1)
	assert.Equal(t, "search tickets", a.Skills[0].Name)
	assert.Equal(t, map[string]any{
		"agentregistry.googleapis.com/system/Framework": map[string]any{"framework": "google-adk"},
	}, rawAttributesToDict(a.Attributes))
}

func TestAgentRegistryAgentProtocolsEmpty(t *testing.T) {
	// Synthetic: no protocols, and a nil entry.
	protocols, urls := agentRegistryAgentProtocols([]*agentregistry.Protocol{nil})
	assert.Equal(t, []string{}, protocols)
	assert.Equal(t, []string{}, urls)
}

func TestRawAttributesToDict(t *testing.T) {
	// Synthetic: an attribute that is not valid JSON is kept as its text.
	got := rawAttributesToDict(map[string]googleapi.RawMessage{
		"ok":  googleapi.RawMessage(`{"principal":"principal://x"}`),
		"bad": googleapi.RawMessage(`{not json`),
	})
	assert.Equal(t, map[string]any{"principal": "principal://x"}, got["ok"])
	assert.Equal(t, "{not json", got["bad"])
	assert.Equal(t, map[string]any{}, rawAttributesToDict(nil))
}

func TestAgentRegistryInterfaces(t *testing.T) {
	// Synthetic: an MCP server with two interfaces, one without a URL.
	got := agentRegistryInterfaces([]*agentregistry.Interface{
		{Url: "https://mcp.example.com/mcp", ProtocolBinding: "JSONRPC"},
		{ProtocolBinding: "GRPC"},
		nil,
	})
	assert.Equal(t, map[string]any{"https://mcp.example.com/mcp": "JSONRPC"}, got)
}

func TestListAcrossAgentLocations(t *testing.T) {
	locations := []string{"projects/p/locations/global", "projects/p/locations/us-central1"}

	// Synthetic: one location fails, the other still reports.
	got, err := listAcrossAgentLocations("agents", locations, func(l string) ([]any, error) {
		if l == locations[0] {
			return nil, errors.New("unavailable")
		}
		return []any{"a1"}, nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []any{"a1"}, got)

	// Synthetic: every location fails.
	_, err = listAcrossAgentLocations("agents", locations, func(string) ([]any, error) {
		return nil, errors.New("denied")
	})
	assert.EqualError(t, err, "denied")

	// Synthetic: no locations reported is an empty answer.
	got, err = listAcrossAgentLocations("agents", nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, []any{}, got)
}
