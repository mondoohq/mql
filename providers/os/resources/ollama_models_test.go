// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Ollama treats an untagged model name as implicitly :latest, but the model
// store reports the fully qualified name. An integration recording the bare
// name matched nothing, so ollama.config.integration.models came back empty on
// a host that had the model pulled.
func TestMatchOllamaModel(t *testing.T) {
	store := map[string]any{
		"qwen3.5:latest": "tagged",
		"llama3.2:1b":    "pinned",
		"mistral":        "bare",
	}

	for _, tc := range []struct {
		name  string
		query string
		want  any
		found bool
	}{
		{"bare name matches the :latest entry", "qwen3.5", "tagged", true},
		{"exact tagged name still matches", "qwen3.5:latest", "tagged", true},
		{"a non-latest tag matches exactly", "llama3.2:1b", "pinned", true},
		{"a bare name does not match a differently tagged entry", "llama3.2", nil, false},
		{":latest matches a store entry reported bare", "mistral:latest", "bare", true},
		{"an unknown model resolves to nothing", "gemma3", nil, false},
		{"an empty name resolves to nothing", "", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := matchOllamaModel(store, tc.query)
			assert.Equal(t, tc.found, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}
