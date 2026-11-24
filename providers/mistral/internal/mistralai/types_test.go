// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mistralai

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func boolPtr(b bool) *bool { return &b }

func strPtr(s string) *string { return &s }

// Synthetic: every combination of per-level raw-HTTP switches; no live account was checked.
func TestConnectorHTTPProxyEnabled(t *testing.T) {
	tests := []struct {
		name  string
		prefs []ConnectionPreference
		want  *bool
	}{
		{"no preferences", nil, nil},
		{"no level states an opinion", []ConnectionPreference{{}, {}}, nil},
		{"one level allows", []ConnectionPreference{{}, {HTTPProxyEnabled: boolPtr(true)}}, boolPtr(true)},
		{"one level turns it off", []ConnectionPreference{{HTTPProxyEnabled: boolPtr(false)}}, boolPtr(false)},
		{"off wins over on, in either order", []ConnectionPreference{
			{HTTPProxyEnabled: boolPtr(true)}, {HTTPProxyEnabled: boolPtr(false)}, {HTTPProxyEnabled: boolPtr(true)},
		}, boolPtr(false)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Connector{ConnectionPreferences: tc.prefs}.HTTPProxyEnabled()
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			if assert.NotNil(t, got) {
				assert.Equal(t, *tc.want, *got)
			}
		})
	}
}

// Synthetic: guardrail lists with and without block_on_error; no live account was checked.
func TestAgentGuardrailsBlockOnError(t *testing.T) {
	assert.Nil(t, Agent{}.GuardrailsBlockOnError(), "no guardrails is null, not false")

	all := Agent{Guardrails: []GuardrailConfig{{BlockOnError: true}, {BlockOnError: true}}}
	if got := all.GuardrailsBlockOnError(); assert.NotNil(t, got) {
		assert.True(t, *got)
	}

	// One guardrail that lets a failed check through means the agent does not
	// fail closed, whatever the others say.
	mixed := Agent{Guardrails: []GuardrailConfig{{BlockOnError: true}, {BlockOnError: false}}}
	if got := mixed.GuardrailsBlockOnError(); assert.NotNil(t, got) {
		assert.False(t, *got)
	}
}

// Synthetic: tools naming the same connector twice, an empty id, and no id; no live account was checked.
func TestAgentConnectorIDs(t *testing.T) {
	a := Agent{Tools: []AgentTool{
		{Type: "connector", ConnectorID: strPtr("c2")},
		{Type: "web_search"},
		{Type: "connector", ConnectorID: strPtr("")},
		{Type: "connector", ConnectorID: strPtr("c1")},
		{Type: "connector", ConnectorID: strPtr("c2")},
	}}
	assert.Equal(t, []string{"c2", "c1"}, a.ConnectorIDs())
}

// Synthetic: library ids spread across tools with a repeat and an empty id; no live account was checked.
func TestAgentLibraryIDs(t *testing.T) {
	a := Agent{Tools: []AgentTool{
		{Type: "document_library", LibraryIDs: []string{"l1", ""}},
		{Type: "document_library", LibraryIDs: []string{"l2", "l1"}},
	}}
	assert.Equal(t, []string{"l1", "l2"}, a.LibraryIDs())
}
