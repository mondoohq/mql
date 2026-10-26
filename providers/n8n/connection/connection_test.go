// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeInstanceURL(t *testing.T) {
	// Synthetic: forms a user may type or paste.
	tests := map[string]string{
		"http://localhost:5678":               "http://localhost:5678",
		"http://localhost:5678/":              "http://localhost:5678",
		"n8n.example.com":                     "https://n8n.example.com",
		"https://n8n.example.com/api/v1":      "https://n8n.example.com",
		"https://n8n.example.com/api/v1/":     "https://n8n.example.com",
		"https://example.com/n8n/":            "https://example.com/n8n",
		"https://example.com/n8n/api/v1?x=1":  "https://example.com/n8n",
		"  https://n8n.example.com  ":         "https://n8n.example.com",
		"https://n8n.example.com/#/workflows": "https://n8n.example.com",
	}
	for in, want := range tests {
		got, err := normalizeInstanceURL(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	// Synthetic: no scheme n8n serves, no host, and credentials in the URL,
	// which would surface in the url field and the asset id.
	for _, bad := range []string{"", "ftp://n8n.example.com", "https://", "https://admin:secret@n8n.example.com", "https://admin@n8n.example.com"} {
		_, err := normalizeInstanceURL(bad)
		assert.Error(t, err, bad)
	}
}

func TestInstanceHost(t *testing.T) {
	// Synthetic: the host keys the asset, so a path-prefixed instance keeps its path.
	assert.Equal(t, "localhost:5678", InstanceHost("http://localhost:5678"))
	assert.Equal(t, "n8n.example.com", InstanceHost("https://n8n.example.com"))
	assert.Equal(t, "example.com/n8n", InstanceHost("https://example.com/n8n"))
}
