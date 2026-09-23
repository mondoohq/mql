// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAiderConfig(t *testing.T) {
	cfg, err := parseAiderConfig([]byte("# aider settings\nmodel: ollama/qwen2.5-coder:0.5b\nopenai-api-key: sk-not-a-real-key\n"), ".aider.conf.yml")
	require.NoError(t, err)
	assert.Equal(t, "ollama/qwen2.5-coder:0.5b", cfg.Model)
	assert.True(t, cfg.hasAPIKeys())
}

func TestAiderHasAPIKeys(t *testing.T) {
	cases := map[string]bool{
		"model: sonnet\n":                                  false,
		"anthropic-api-key: sk-ant-not-real\n":             true,
		"openai-api-key: \"\"\n":                           false,
		"api-key: gemini=not-real\n":                       true,
		"api-key:\n  - gemini=\n  - openrouter=not-real\n": true,
		"api-key:\n  - gemini=\n  - openrouter=\n":         false,
		"api-key: []\n":                                    false,
	}
	for in, want := range cases {
		cfg, err := parseAiderConfig([]byte(in), ".aider.conf.yml")
		require.NoError(t, err, in)
		assert.Equal(t, want, cfg.hasAPIKeys(), "input %q", in)
	}
}

func TestParseAiderConfigMalformed(t *testing.T) {
	_, err := parseAiderConfig([]byte("model: [unterminated\n"), ".aider.conf.yml")
	assert.Error(t, err)
}
