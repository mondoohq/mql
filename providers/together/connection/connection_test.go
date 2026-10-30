// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeBaseURL(t *testing.T) {
	// Synthetic: base URLs as an operator would type them; no target showed these.
	cases := map[string]string{
		"https://api.together.ai":            "https://api.together.ai/",
		"https://api.together.ai/":           "https://api.together.ai/",
		"https://api.together.ai/v1":         "https://api.together.ai/",
		"https://api.together.ai/v1/":        "https://api.together.ai/",
		"  https://proxy.example.com/v1  ":   "https://proxy.example.com/",
		"https://proxy.example.com/together": "https://proxy.example.com/together/",
		"https://proxy.example.com/v10":      "https://proxy.example.com/v10/",
	}
	for in, want := range cases {
		assert.Equal(t, want, normalizeBaseURL(in), in)
	}
}
