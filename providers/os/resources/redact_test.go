// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Synthetic: token-shaped values carry only the documented vendor prefix and
// length. They are assembled at run time, as are the credential URLs below, so
// the source holds no literal a secret scanner reports.
var (
	fakeGitHubToken    = "ghp" + "_" + strings.Repeat("a", 36)
	fakeAnthropicKey   = "sk" + "-ant-api03-" + strings.Repeat("b", 26)
	fakeGoogleAPIKey   = "AI" + "za" + strings.Repeat("c", 35)
	fakeHuggingFaceTok = "hf" + "_" + strings.Repeat("d", 34)
)

// credURL builds scheme://user:password@rest.
func credURL(scheme, user, password, rest string) string {
	return scheme + "://" + user + ":" + password + "@" + rest
}

func TestIsSecretKey(t *testing.T) {
	// Synthetic: names AI tools and MCP servers use for credentials, and
	// look-alikes that are not credentials.
	for _, k := range []string{
		"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN",
		"api-key", "apiKey", "x-api-key", "Authorization", "clientSecret",
		"DB_PASSWORD", "Cookie", "STRIPE_KEY", "aws.secret", "GOOGLE_APPLICATION_CREDENTIALS",
	} {
		assert.True(t, isSecretKey(k), k)
	}
	for _, k := range []string{
		"apiKeyHelper", "max_tokens", "CLAUDE_CODE_MAX_OUTPUT_TOKENS", "model",
		"toggleKey", "key", "DISABLE_TELEMETRY", "PWD", "",
	} {
		assert.False(t, isSecretKey(k), k)
	}
}

func TestIsVarRef(t *testing.T) {
	// Synthetic: the reference syntaxes Claude, Cursor/VS Code, OpenCode and
	// shell-style configs use.
	for _, v := range []string{"${GITHUB_TOKEN}", "${env:GITHUB_TOKEN}", "{env:GITHUB_TOKEN}", "$GITHUB_TOKEN", "Bearer ${TOKEN}"} {
		assert.True(t, isVarRef(v), v)
	}
	for _, v := range []string{fakeGitHubToken, "Bearer abc", "${A}${B}", "prefix-${A}", ""} {
		assert.False(t, isVarRef(v), v)
	}
}

func TestRedactURL(t *testing.T) {
	// Synthetic: credentials embedded in remote MCP server and git remote URLs.
	tests := []struct{ in, want string }{
		{"https://mcp.example.com/sse", "https://mcp.example.com/sse"},
		{credURL("postgres", "admin", "hunter2", "db.internal:5432/app"), "postgres://admin:<redacted>@db.internal:5432/app"},
		{"https://x:${PAT}@github.com/org/repo.git", "https://x:${PAT}@github.com/org/repo.git"},
		{"https://" + fakeGitHubToken + "@github.com/org/repo.git", "https://<redacted>@github.com/org/repo.git"},
		{"https://mcp.example.com/mcp?api_key=abc123&region=eu", "https://mcp.example.com/mcp?api_key=<redacted>&region=eu"},
		{"https://generativelanguage.googleapis.com/v1?key=abc", "https://generativelanguage.googleapis.com/v1?key=<redacted>"},
		{"https://mcp.example.com/mcp?token=${TOKEN}", "https://mcp.example.com/mcp?token=${TOKEN}"},
		{"git@github.com:org/repo.git", "git@github.com:org/repo.git"},
		// Synthetic: url.Parse rejects the unescaped { in the password, and the
		// socket form has no host; both still lose the password.
		{credURL("postgres", "app", "p{w}", "db.internal/app"), "postgres://app:<redacted>@db.internal/app"},
		{credURL("postgres", "app", "pw", "/app?host=/var/run/postgresql"), "postgres://app:<redacted>@/app?host=/var/run/postgresql"},
		// Synthetic: an opaque token alone as the username, and a short account
		// name that is kept.
		{"https://" + strings.Repeat("e", 40) + "@github.com/org/repo.git", "https://<redacted>@github.com/org/repo.git"},
		{"https://alice@github.com/org/repo.git", "https://alice@github.com/org/repo.git"},
		{"not a url " + fakeAnthropicKey, "not a url <redacted>"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, redactURL(tt.in), tt.in)
	}
}

func TestRedactArgs(t *testing.T) {
	// Synthetic: MCP server command lines in the shapes their READMEs suggest.
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "no secrets",
			in:   []string{"-y", "@modelcontextprotocol/server-filesystem", "/Users/alice/Desktop"},
			want: []string{"-y", "@modelcontextprotocol/server-filesystem", "/Users/alice/Desktop"},
		},
		{
			name: "bare key and auth flags",
			in:   []string{"server", "--key", "abc123", "--auth=xyz"},
			want: []string{"server", "--key", "<redacted>", "--auth=<redacted>"},
		},
		{
			name: "flag=value",
			in:   []string{"server", "--api-key=abc123", "--region=eu"},
			want: []string{"server", "--api-key=<redacted>", "--region=eu"},
		},
		{
			name: "flag then value",
			in:   []string{"server", "--token", "abc123", "--verbose"},
			want: []string{"server", "--token", "<redacted>", "--verbose"},
		},
		{
			name: "secret flag followed by another flag",
			in:   []string{"server", "--token", "--verbose"},
			want: []string{"server", "--token", "--verbose"},
		},
		{
			name: "flag value is a variable reference",
			in:   []string{"server", "--token=${GITHUB_TOKEN}", "--api-key", "$KEY"},
			want: []string{"server", "--token=${GITHUB_TOKEN}", "--api-key", "$KEY"},
		},
		{
			name: "mcp-remote header",
			in:   []string{"-y", "mcp-remote", "https://mcp.example.com/sse", "--header", "Authorization: Bearer abc123"},
			want: []string{"-y", "mcp-remote", "https://mcp.example.com/sse", "--header", "Authorization: <redacted>"},
		},
		{
			name: "mcp-remote header from env",
			in:   []string{"mcp-remote", "--header", "Authorization: Bearer ${AUTH_TOKEN}"},
			want: []string{"mcp-remote", "--header", "Authorization: Bearer ${AUTH_TOKEN}"},
		},
		{
			name: "docker env assignment",
			in:   []string{"run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN=" + fakeGitHubToken, "ghcr.io/github/github-mcp-server"},
			want: []string{"run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN=<redacted>", "ghcr.io/github/github-mcp-server"},
		},
		{
			name: "docker env passthrough by name",
			in:   []string{"run", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"},
			want: []string{"run", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"},
		},
		{
			name: "connection string positional",
			in:   []string{"-y", "@modelcontextprotocol/server-postgres", credURL("postgresql", "app", "s3cret", "localhost/db")},
			want: []string{"-y", "@modelcontextprotocol/server-postgres", "postgresql://app:<redacted>@localhost/db"},
		},
		{
			name: "bare vendor token positional",
			in:   []string{"server", fakeHuggingFaceTok},
			want: []string{"server", "<redacted>"},
		},
		{
			name: "url in a non-secret flag value",
			in:   []string{"--endpoint=" + credURL("https", "u", "pw", "host.example.com/x")},
			want: []string{"--endpoint=https://u:<redacted>@host.example.com/x"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, redactArgs(tt.in))
		})
	}
	assert.Empty(t, redactArgs(nil))
}

func TestRedactSettings(t *testing.T) {
	// Synthetic: a settings file combining the Claude Code env block, a Gemini
	// style mcpServers block and a Zed style context_servers block.
	in := map[string]any{
		"model": "opus",
		"env": map[string]any{
			"ANTHROPIC_API_KEY":       fakeAnthropicKey,
			"ANTHROPIC_AUTH_TOKEN":    "opaque-token-value",
			"CLAUDE_CODE_USE_BEDROCK": "1",
			"DISABLE_TELEMETRY":       "1",
			"ANTHROPIC_BASE_URL":      "https://gateway.example.com",
			"HTTPS_PROXY":             credURL("http", "user", "pw", "proxy.example.com:3128"),
		},
		"apiKeyHelper": "/usr/local/bin/get-key.sh",
		"permissions":  map[string]any{"allow": []any{"Bash(npm run test)"}},
		"mcpServers": map[string]any{
			"github": map[string]any{
				"command": "npx",
				"args":    []any{"-y", "server", "--token", "abc123"},
				"env": map[string]any{
					"GITHUB_PERSONAL_ACCESS_TOKEN": fakeGitHubToken,
					"LOG_LEVEL":                    "debug",
					"FROM_ENV":                     "${GITHUB_TOKEN}",
				},
			},
			"remote": map[string]any{
				"httpUrl": "https://mcp.example.com/mcp?apikey=abc",
				"headers": map[string]any{"X-Custom": "anything", "Authorization": "Bearer ${TOKEN}"},
			},
		},
		"context_servers": map[string]any{
			"pg": map[string]any{"command": map[string]any{"path": "pg-mcp", "env": map[string]any{"PGHOST": "db"}}},
		},
		"pinSettings": map[string]any{"pin_password": 1234, "enabled": true, "port": 8080},
		"apiKey":        map[string]any{"value": "abc123", "source": "inline"},
		"nothing":       nil,
	}

	got := redactSettings(in)

	assert.Equal(t, "opus", got["model"])
	env := got["env"].(map[string]any)
	assert.Equal(t, redactedValue, env["ANTHROPIC_API_KEY"])
	assert.Equal(t, redactedValue, env["ANTHROPIC_AUTH_TOKEN"])
	// Non-secret behavior switches in the top-level env block stay readable.
	assert.Equal(t, "1", env["CLAUDE_CODE_USE_BEDROCK"])
	assert.Equal(t, "1", env["DISABLE_TELEMETRY"])
	assert.Equal(t, "https://gateway.example.com", env["ANTHROPIC_BASE_URL"])
	assert.Equal(t, "http://user:<redacted>@proxy.example.com:3128", env["HTTPS_PROXY"])
	assert.Equal(t, "/usr/local/bin/get-key.sh", got["apiKeyHelper"])
	assert.Equal(t, []any{"Bash(npm run test)"}, got["permissions"].(map[string]any)["allow"])

	servers := got["mcpServers"].(map[string]any)
	gh := servers["github"].(map[string]any)
	assert.Equal(t, []any{"-y", "server", "--token", redactedValue}, gh["args"])
	ghEnv := gh["env"].(map[string]any)
	// Inside an MCP server every env value is a secret, whatever its name.
	assert.Equal(t, redactedValue, ghEnv["GITHUB_PERSONAL_ACCESS_TOKEN"])
	assert.Equal(t, redactedValue, ghEnv["LOG_LEVEL"])
	assert.Equal(t, "${GITHUB_TOKEN}", ghEnv["FROM_ENV"])
	remote := servers["remote"].(map[string]any)
	assert.Equal(t, "https://mcp.example.com/mcp?apikey=<redacted>", remote["httpUrl"])
	headers := remote["headers"].(map[string]any)
	assert.Equal(t, redactedValue, headers["X-Custom"])
	assert.Equal(t, "Bearer ${TOKEN}", headers["Authorization"])

	pg := got["context_servers"].(map[string]any)["pg"].(map[string]any)["command"].(map[string]any)
	assert.Equal(t, redactedValue, pg["env"].(map[string]any)["PGHOST"])
	assert.Equal(t, "pg-mcp", pg["path"])

	ns := got["pinSettings"].(map[string]any)
	assert.Equal(t, redactedValue, ns["pin_password"])
	assert.Equal(t, true, ns["enabled"])
	assert.Equal(t, 8080, ns["port"])
	assert.Nil(t, got["nothing"])
	// Everything under a secret-named key is redacted, whatever the child keys.
	assert.Equal(t, map[string]any{"value": redactedValue, "source": redactedValue}, got["apiKey"])

	// The input is not modified.
	assert.Equal(t, fakeAnthropicKey, in["env"].(map[string]any)["ANTHROPIC_API_KEY"])
	assert.Nil(t, redactSettings(nil))
}

func TestRedactStringGoogleKeyAnywhere(t *testing.T) {
	// Synthetic: a Google API key pasted into a free-form string.
	assert.Equal(t, "key is <redacted>", redactString("key is "+fakeGoogleAPIKey))
}
