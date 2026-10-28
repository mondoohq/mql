// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveMcpTransport(t *testing.T) {
	tests := []struct {
		name         string
		explicitType string
		command      string
		url          string
		want         string
	}{
		{name: "explicit wins over inference", explicitType: "sse", command: "npx", url: "https://x", want: "sse"},
		{name: "command implies stdio", command: "npx", want: mcpTransportStdio},
		{name: "url implies http", url: "https://mcp.example.com/mcp", want: mcpTransportHTTP},
		{name: "command preferred when both present", command: "npx", url: "https://x", want: mcpTransportStdio},
		{name: "nothing set", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, deriveMcpTransport(tt.explicitType, tt.command, tt.url))
		})
	}
}

func TestMcpArgsData(t *testing.T) {
	rd := mcpArgsData([]string{"-y", "server", "/tmp"})
	arr, ok := rd.Value.([]any)
	assert.True(t, ok)
	assert.Equal(t, []any{"-y", "server", "/tmp"}, arr)

	// Synthetic: a secret passed on the command line is redacted.
	rd = mcpArgsData([]string{"server", "--api-key", "abc123"})
	assert.Equal(t, []any{"server", "--api-key", redactedValue}, rd.Value)

	// nil slice yields an empty, non-nil array
	empty := mcpArgsData(nil)
	emptyArr, ok := empty.Value.([]any)
	assert.True(t, ok)
	assert.Empty(t, emptyArr)
}
