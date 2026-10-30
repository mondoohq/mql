// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ollama

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realConfigJSON is a ~/.ollama/config.json written by ollama 0.32.14, copied
// verbatim from a host where Claude Code was pointed at a local model. Note what
// it does not contain: no "aliases", no "onboarded", no "last_model". The absent
// fields are the normal case, not the exception.
const realConfigJSON = `{
  "integrations": {
    "claude": {
      "models": [
        "qwen3-coder:30b"
      ]
    }
  }
}`

func TestParseIntegrations_RealFile(t *testing.T) {
	got, err := ParseIntegrations([]byte(realConfigJSON))
	require.NoError(t, err)

	require.Len(t, got, 1)
	assert.Equal(t, "claude", got[0].Name)
	assert.Equal(t, []string{"qwen3-coder:30b"}, got[0].Models)
	assert.Empty(t, got[0].Aliases)
	assert.False(t, got[0].Onboarded)
}

func TestParseIntegrations_FullShape(t *testing.T) {
	got, err := ParseIntegrations([]byte(`{
	  "last_model": "qwen3-coder:30b",
	  "integrations": {
	    "opencode": {"models": ["gpt-oss:20b"], "onboarded": true},
	    "claude":   {"models": ["qwen3-coder:30b", "gpt-oss:20b"],
	                 "aliases": {"sonnet": "qwen3-coder:30b"}},
	    "codex":    null
	  }
	}`))
	require.NoError(t, err)

	// Sorted by name so the output does not depend on Go's map iteration order.
	require.Len(t, got, 3)
	assert.Equal(t, []string{"claude", "codex", "opencode"},
		[]string{got[0].Name, got[1].Name, got[2].Name})

	assert.Equal(t, []string{"qwen3-coder:30b", "gpt-oss:20b"}, got[0].Models)
	assert.Equal(t, map[string]string{"sonnet": "qwen3-coder:30b"}, got[0].Aliases)
	assert.False(t, got[0].Onboarded)

	// A null entry is a tool Ollama knows about with nothing configured. It must
	// still be reported, or a wired-up tool disappears from the audit.
	assert.Equal(t, "codex", got[1].Name)
	assert.Empty(t, got[1].Models)

	assert.True(t, got[2].Onboarded)
}

func TestParseIntegrations_Empty(t *testing.T) {
	for _, in := range []string{`{}`, `{"integrations":{}}`, `{"integrations":null}`} {
		got, err := ParseIntegrations([]byte(in))
		require.NoError(t, err, in)
		assert.Empty(t, got, in)
	}
}

func TestParseIntegrations_Malformed(t *testing.T) {
	_, err := ParseIntegrations([]byte(`{"integrations": [`))
	assert.Error(t, err)
}

func TestParseServerSettings(t *testing.T) {
	s, err := ParseServerSettings([]byte(`{"disable_ollama_cloud": true}`))
	require.NoError(t, err)
	assert.True(t, s.DisableOllamaCloud)

	// Absent means not disabled, which is the permissive reading and the one
	// Ollama itself takes.
	s, err = ParseServerSettings([]byte(`{}`))
	require.NoError(t, err)
	assert.False(t, s.DisableOllamaCloud)

	_, err = ParseServerSettings([]byte(`not json`))
	assert.Error(t, err)
}
