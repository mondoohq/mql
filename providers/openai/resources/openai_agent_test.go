// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func decodeJSON[T any](t *testing.T, payload string) T {
	t.Helper()
	var out T
	require.NoError(t, json.Unmarshal([]byte(payload), &out))
	return out
}

// assertNullFields checks that each named field reads as null. A union member
// that is not present has to stay null: reporting "" or an empty list there
// claims a setting the record does not carry.
func assertNullFields(t *testing.T, args map[string]*llx.RawData, names ...string) {
	t.Helper()
	for _, name := range names {
		raw, ok := args[name]
		require.True(t, ok, "%s has to be set, or the runtime has no resolver for it", name)
		assert.Nil(t, raw.Value, "%s belongs to another variant and has to read null", name)
	}
}

// timeValue reads a time field, which the runtime carries as a pointer so an
// absent timestamp can stay null.
func timeValue(t *testing.T, args map[string]*llx.RawData, name string) time.Time {
	t.Helper()
	raw, ok := args[name]
	require.True(t, ok, "%s has to be set", name)
	ts, ok := raw.Value.(*time.Time)
	require.True(t, ok, "%s has to be a time", name)
	require.NotNil(t, ts)
	return *ts
}

// assertAbsent checks that a value the API returned appears in none of the
// mapped fields. Used to prove that secret material stays out of the schema.
func assertAbsent(t *testing.T, args map[string]*llx.RawData, needle string) {
	t.Helper()
	for name, raw := range args {
		if raw == nil {
			continue
		}
		assert.NotContains(t, fmt.Sprintf("%v", raw.Value), needle,
			"%s carries a value the API returned but the schema must not report", name)
	}
}

// openai.agent.tool

func TestAgentToolArgsMcp(t *testing.T) {
	tool := decodeJSON[openai.PersistedAgentToolUnion](t, `{
		"type": "mcp",
		"server_label": "issue-tracker",
		"connection_origin": "environment",
		"credential_id": "cred_0001",
		"allowed_tools": ["list_issues", "create_issue"],
		"required": true,
		"request_metadata": {"x-tenant": "acme", "x-secret-header": "sentinel-request-metadata"},
		"transport": {
			"type": "http",
			"server_url": "https://mcp.example.com/sse",
			"headers": {
				"x-trace": "on",
				"authorization": "sentinel-header-value",
				"x-api-version": "2026-01-01",
				"accept": "application/json"
			}
		}
	}`)

	args, credentialID := agentToolArgs("agent_0001", 3, tool)

	assert.Equal(t, "agent_0001/tool/3", args["__id"].Value)
	assert.Equal(t, "mcp", args["type"].Value)
	assert.Equal(t, "issue-tracker", args["serverLabel"].Value)
	assert.Equal(t, "environment", args["connectionOrigin"].Value)
	assert.Equal(t, true, args["required"].Value)
	assert.Equal(t, []any{"list_issues", "create_issue"}, args["allowedTools"].Value)
	assert.Equal(t, "http", args["transportType"].Value)
	assert.Equal(t, "https://mcp.example.com/sse", args["transportServerUrl"].Value)

	// the credential is resolved through the vault collection, so the mapper
	// hands the id back rather than putting it in the schema
	assert.Equal(t, "cred_0001", credentialID)

	// header names only, in a stable order: Go randomizes map iteration, so an
	// unsorted list reads differently on every scan
	assert.Equal(t, []any{"accept", "authorization", "x-api-version", "x-trace"},
		args["transportHeaderNames"].Value)

	// a header value is where an API key hides, and request_metadata travels
	// with every call the agent makes, so neither reaches the schema
	assertAbsent(t, args, "sentinel-header-value")
	assertAbsent(t, args, "sentinel-request-metadata")

	assertNullFields(t, args, "name", "description", "parameters", "deferLoading", "enabled",
		"transportCommand", "transportArgs", "transportCwd", "transportEnvVars",
		"allowedDomains", "mode", "contextSize")
}

func TestAgentToolArgsMcpWithNoAllowlist(t *testing.T) {
	tool := decodeJSON[openai.PersistedAgentToolUnion](t, `{
		"type": "mcp",
		"server_label": "issue-tracker",
		"connection_origin": "service",
		"credential_id": "",
		"allowed_tools": null,
		"required": false,
		"transport": {"type": "http", "server_url": "https://mcp.example.com/sse", "headers": {}}
	}`)

	args, credentialID := agentToolArgs("agent_0001", 0, tool)

	// an agent that may call every tool the server publishes is the finding, so
	// it reports an empty list. Null here would make a check that counts the
	// entries read as "nothing was measured" and pass.
	assert.Equal(t, []any{}, args["allowedTools"].Value)
	assert.NotNil(t, args["allowedTools"].Value)
	assert.Equal(t, []any{}, args["transportHeaderNames"].Value)
	assert.Empty(t, credentialID, "a server with no stored credential names none")
}

func TestAgentToolArgsWebSearch(t *testing.T) {
	tool := decodeJSON[openai.PersistedAgentToolUnion](t, `{
		"type": "web_search",
		"allowed_domains": ["docs.example.com"],
		"context_size": "high",
		"mode": "live",
		"location": {"city": "Berlin", "country": "DE", "region": "Berlin", "timezone": "Europe/Berlin"}
	}`)

	args, credentialID := agentToolArgs("agent_0001", 1, tool)

	assert.Equal(t, "web_search", args["type"].Value)
	assert.Equal(t, []any{"docs.example.com"}, args["allowedDomains"].Value)
	assert.Equal(t, "live", args["mode"].Value)
	assert.Equal(t, "high", args["contextSize"].Value)
	assert.Empty(t, credentialID)

	assertNullFields(t, args, "serverLabel", "connectionOrigin", "allowedTools", "required",
		"transportType", "transportServerUrl", "name", "parameters")
}

func TestAgentToolArgsWebSearchUnrestricted(t *testing.T) {
	tool := decodeJSON[openai.PersistedAgentToolUnion](t, `{
		"type": "web_search",
		"allowed_domains": null,
		"context_size": "medium",
		"mode": "live"
	}`)

	args, _ := agentToolArgs("agent_0001", 0, tool)
	assert.Equal(t, []any{}, args["allowedDomains"].Value,
		"unrestricted search is an empty allowlist, not an absence of measurement")
}

func TestAgentToolArgsFunction(t *testing.T) {
	tool := decodeJSON[openai.PersistedAgentToolUnion](t, `{
		"type": "function",
		"name": "lookup_order",
		"description": "Look up an order by number",
		"defer_loading": true,
		"parameters": {"type": "object", "properties": {"order": {"type": "string"}}}
	}`)

	args, credentialID := agentToolArgs("agent_0001", 0, tool)

	assert.Equal(t, "function", args["type"].Value)
	assert.Equal(t, "lookup_order", args["name"].Value)
	assert.Equal(t, "Look up an order by number", args["description"].Value)
	assert.Equal(t, true, args["deferLoading"].Value)
	params, ok := args["parameters"].Value.(map[string]any)
	require.True(t, ok, "the parameter schema has to survive as a dict")
	assert.Equal(t, "object", params["type"])
	assert.Empty(t, credentialID)

	assertNullFields(t, args, "serverLabel", "connectionOrigin", "allowedTools", "required",
		"transportType", "mode", "contextSize", "allowedDomains")
}

func TestAgentToolArgsStdioTransport(t *testing.T) {
	tool := decodeJSON[openai.PersistedAgentToolUnion](t, `{
		"type": "mcp",
		"server_label": "local-fs",
		"connection_origin": "environment",
		"credential_id": "",
		"allowed_tools": ["read_file"],
		"required": false,
		"transport": {
			"type": "stdio",
			"command": "/usr/local/bin/fs-mcp",
			"args": ["--root", "/workspace"],
			"cwd": "/workspace",
			"env_vars": ["HOME", "PATH"]
		}
	}`)

	args, _ := agentToolArgs("agent_0001", 0, tool)

	assert.Equal(t, "stdio", args["transportType"].Value)
	assert.Equal(t, "/usr/local/bin/fs-mcp", args["transportCommand"].Value)
	assert.Equal(t, []any{"--root", "/workspace"}, args["transportArgs"].Value)
	assert.Equal(t, "/workspace", args["transportCwd"].Value)
	assert.Equal(t, []any{"HOME", "PATH"}, args["transportEnvVars"].Value)

	assertNullFields(t, args, "transportServerUrl", "transportHeaderNames")
}

func TestAgentToolArgsUnknownVariantKeepsEveryFieldNull(t *testing.T) {
	// A tool type the SDK does not model yet still has to produce a complete
	// resource: a field left out of the args has no resolver behind it and
	// fails at access time with no attribution.
	tool := decodeJSON[openai.PersistedAgentToolUnion](t, `{"type": "image_generation"}`)

	args, credentialID := agentToolArgs("agent_0001", 7, tool)

	assert.Equal(t, "image_generation", args["type"].Value)
	assert.Empty(t, credentialID)
	assertNullFields(t, args, "name", "description", "parameters", "deferLoading", "enabled",
		"serverLabel", "connectionOrigin", "allowedTools", "required", "transportType",
		"transportServerUrl", "transportHeaderNames", "transportCommand", "transportArgs",
		"transportCwd", "transportEnvVars", "allowedDomains", "mode", "contextSize")
}

func TestAgentToolIdsAreDistinctForRepeatedTypes(t *testing.T) {
	// Two MCP tools on one agent are two rows. Keying them by anything they
	// share hands the second one the first one's cached values, and the query
	// reports one server where there are two.
	first := decodeJSON[openai.PersistedAgentToolUnion](t, `{"type": "mcp", "server_label": "a"}`)
	second := decodeJSON[openai.PersistedAgentToolUnion](t, `{"type": "mcp", "server_label": "a"}`)

	firstArgs, _ := agentToolArgs("agent_0001", 0, first)
	secondArgs, _ := agentToolArgs("agent_0001", 1, second)

	assert.NotEqual(t, firstArgs["__id"].Value, secondArgs["__id"].Value)
}

// The tool list is a union whose variant accessors read the raw document the
// SDK keeps beside each decoded item. Items inside a list response are decoded
// by the pager rather than individually, so this pins that the raw document
// survives that path: if it did not, every MCP server label and credential
// would silently read null while the build and the decode tests stayed green.
func TestAgentToolUnionSurvivesTheListDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/agents", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"object": "list",
			"has_more": false,
			"data": [{
				"id": "agent_0001",
				"object": "agent",
				"created_at": 1711471533,
				"updated_at": 1711471533,
				"instructions": "be helpful",
				"metadata": {},
				"model": "gpt-5",
				"name": "support",
				"service_tier": "auto",
				"multi_agent": {"enabled": true, "max_concurrent_subagents": 4},
				"reasoning": {"effort": "high", "summary": "auto"},
				"text": {"verbosity": "medium"},
				"tools": [{
					"type": "mcp",
					"server_label": "issue-tracker",
					"connection_origin": "service",
					"credential_id": "cred_0001",
					"allowed_tools": null,
					"required": true,
					"transport": {"type": "http", "server_url": "https://mcp.example.com/sse", "headers": {}}
				}]
			}]
		}`))
	}))
	defer srv.Close()

	client := testClient(srv.URL)
	iter := client.Beta.Agents.ListAutoPaging(context.Background(), openai.BetaAgentListParams{})
	require.True(t, iter.Next())
	agent := iter.Current()
	require.NoError(t, iter.Err())
	require.Len(t, agent.Tools, 1)

	args, credentialID := agentToolArgs(agent.ID, 0, agent.Tools[0])
	assert.Equal(t, "issue-tracker", args["serverLabel"].Value)
	assert.Equal(t, "https://mcp.example.com/sse", args["transportServerUrl"].Value)
	assert.Equal(t, "cred_0001", credentialID)
}

// openai.agent

func TestAgentArgs(t *testing.T) {
	a := decodeJSON[openai.Agent](t, `{
		"id": "agent_0001",
		"object": "agent",
		"created_at": 1711471533,
		"updated_at": 1711471999,
		"instructions": "answer support questions",
		"metadata": {"team": "support"},
		"model": "gpt-5",
		"name": "support",
		"service_tier": "priority",
		"multi_agent": {"enabled": true, "max_concurrent_subagents": 4},
		"reasoning": {"effort": "xhigh", "summary": "detailed"},
		"text": {"verbosity": "low"},
		"tools": []
	}`)

	args := agentArgs(a)
	assert.Equal(t, "agent_0001", args["__id"].Value)
	assert.Equal(t, "agent_0001", args["id"].Value)
	assert.Equal(t, "support", args["name"].Value)
	assert.Equal(t, "gpt-5", args["model"].Value)
	assert.Equal(t, "answer support questions", args["instructions"].Value)
	assert.Equal(t, "priority", args["serviceTier"].Value)
	assert.Equal(t, map[string]any{"team": "support"}, args["metadata"].Value)
	assert.Equal(t, true, args["multiAgentEnabled"].Value)
	assert.Equal(t, int64(4), args["maxConcurrentSubagents"].Value)
	assert.Equal(t, "xhigh", args["reasoningEffort"].Value)
	assert.Equal(t, "detailed", args["reasoningSummary"].Value)
	assert.Equal(t, "low", args["textVerbosity"].Value)
	assert.Equal(t, time.Unix(1711471533, 0), timeValue(t, args, "createdAt"))
	assert.Equal(t, time.Unix(1711471999, 0), timeValue(t, args, "updatedAt"))
}

func TestAgentArgsWithoutSubagents(t *testing.T) {
	a := decodeJSON[openai.Agent](t, `{
		"id": "agent_0002",
		"object": "agent",
		"created_at": 1711471533,
		"updated_at": 1711471533,
		"instructions": "",
		"model": "gpt-5",
		"name": null,
		"multi_agent": {"enabled": false, "max_concurrent_subagents": null},
		"reasoning": {},
		"text": {},
		"tools": []
	}`)

	args := agentArgs(a)
	assert.Equal(t, false, args["multiAgentEnabled"].Value)
	// null decodes to 0, and reporting 0 concurrent subagents states a limit
	// where the API stated there is nothing to limit
	assert.Nil(t, args["maxConcurrentSubagents"].Value)
	assertNullFields(t, args, "name", "serviceTier", "reasoningEffort", "reasoningSummary",
		"textVerbosity", "metadata")
}

// openai.vault

func TestMapVault(t *testing.T) {
	v := decodeJSON[openai.Vault](t, `{
		"id": "vault_0001",
		"object": "vault",
		"created_at": 1711471533,
		"metadata": {"team": "platform"},
		"name": "mcp credentials"
	}`)

	args := mapVault(v)
	assert.Equal(t, "vault_0001", args["__id"].Value)
	assert.Equal(t, "vault_0001", args["id"].Value)
	assert.Equal(t, "mcp credentials", args["name"].Value)
	assert.Equal(t, map[string]any{"team": "platform"}, args["metadata"].Value)
	assert.Equal(t, time.Unix(1711471533, 0), timeValue(t, args, "createdAt"))
}

func TestMapVaultWithoutNameOrMetadata(t *testing.T) {
	v := decodeJSON[openai.Vault](t, `{
		"id": "vault_0002",
		"object": "vault",
		"created_at": 1711471533,
		"metadata": null,
		"name": null
	}`)

	args := mapVault(v)
	assertNullFields(t, args, "name", "metadata")
}

// openai.vault.credential

func TestMapCredentialStaticBearer(t *testing.T) {
	// The API documents that it never returns the token itself. The extra key
	// here stands in for the API sending one anyway: nothing in the mapper
	// copies a raw response body, so it cannot reach a scan result.
	c := decodeJSON[openai.Credential](t, `{
		"id": "cred_0001",
		"object": "vault.credential",
		"vault_id": "vault_0001",
		"name": "issue tracker",
		"created_at": 1711471533,
		"updated_at": 1711471533,
		"auth": {
			"type": "static_bearer",
			"mcp_server_url": "https://mcp.example.com/sse",
			"token": "sentinel-bearer-value"
		}
	}`)

	args := mapCredential(c)
	assert.Equal(t, "vault_0001/cred_0001", args["__id"].Value,
		"a credential is only reachable through its vault, so the key carries it")
	assert.Equal(t, "cred_0001", args["id"].Value)
	assert.Equal(t, "issue tracker", args["name"].Value)
	assert.Equal(t, "static_bearer", args["authType"].Value)
	assert.Equal(t, "https://mcp.example.com/sse", args["mcpServerUrl"].Value)

	assertAbsent(t, args, "sentinel-bearer-value")

	// a static bearer has no expiry and nothing to renew it with, which is the
	// finding: it stays valid until someone rotates it by hand
	assertNullFields(t, args, "expiresAt", "refreshClientId", "refreshTokenEndpoint",
		"refreshScope", "refreshResource", "refreshTokenEndpointAuthType")
}

func TestMapCredentialMcpOAuth(t *testing.T) {
	c := decodeJSON[openai.Credential](t, `{
		"id": "cred_0002",
		"object": "vault.credential",
		"vault_id": "vault_0001",
		"name": "calendar",
		"created_at": 1711471533,
		"updated_at": 1711471999,
		"auth": {
			"type": "mcp_oauth",
			"mcp_server_url": "https://calendar.example.com/mcp",
			"expires_at": "2026-03-26T18:05:33Z",
			"refresh": {
				"client_id": "client-0001",
				"resource": "https://calendar.example.com/",
				"scope": "calendar.read calendar.write",
				"token_endpoint": "https://auth.example.com/oauth/token",
				"token_endpoint_auth": {"type": "client_secret_post"}
			}
		}
	}`)

	args := mapCredential(c)
	assert.Equal(t, "mcp_oauth", args["authType"].Value)
	assert.Equal(t, "https://calendar.example.com/mcp", args["mcpServerUrl"].Value)
	assert.Equal(t, time.Date(2026, 3, 26, 18, 5, 33, 0, time.UTC), timeValue(t, args, "expiresAt").UTC())
	assert.Equal(t, "client-0001", args["refreshClientId"].Value)
	assert.Equal(t, "https://auth.example.com/oauth/token", args["refreshTokenEndpoint"].Value)
	assert.Equal(t, "calendar.read calendar.write", args["refreshScope"].Value)
	assert.Equal(t, "https://calendar.example.com/", args["refreshResource"].Value)
	// the nested union carries only its discriminator; the client secret is
	// never part of a response
	assert.Equal(t, "client_secret_post", args["refreshTokenEndpointAuthType"].Value)
}

func TestMapCredentialWithUnknownExpiry(t *testing.T) {
	c := decodeJSON[openai.Credential](t, `{
		"id": "cred_0003",
		"object": "vault.credential",
		"vault_id": "vault_0001",
		"name": "calendar",
		"created_at": 1711471533,
		"updated_at": 1711471533,
		"auth": {
			"type": "mcp_oauth",
			"mcp_server_url": "https://calendar.example.com/mcp",
			"expires_at": "",
			"refresh": {"client_id": "client-0001", "resource": "", "scope": "",
				"token_endpoint": "https://auth.example.com/oauth/token",
				"token_endpoint_auth": {"type": "none"}}
		}
	}`)

	args := mapCredential(c)
	// an unreported expiry has to stay null. A zero time would put the
	// expiration in year 1 and read as long expired.
	assert.Nil(t, args["expiresAt"].Value)
	// the settings the refresh block leaves out stay null rather than ""
	assertNullFields(t, args, "refreshScope", "refreshResource")
	assert.Equal(t, "none", args["refreshTokenEndpointAuthType"].Value)
}

func TestParseRFC3339(t *testing.T) {
	require.NotNil(t, parseRFC3339("2026-03-26T18:05:33Z"))
	assert.Equal(t, time.Date(2026, 3, 26, 18, 5, 33, 0, time.UTC), *parseRFC3339("2026-03-26T18:05:33Z"))
	assert.Nil(t, parseRFC3339(""))
	assert.Nil(t, parseRFC3339("Thu, 26 Mar 2026 18:05:33 UTC"),
		"a timestamp in another format is not a time at the start of the epoch")
}

// openai.environmentTemplate

func TestEnvironmentTemplateArgs(t *testing.T) {
	tpl := decodeJSON[openai.EnvironmentTemplate](t, `{
		"id": "envtpl_0001",
		"object": "agent.environment.template",
		"created_at": 1711471533,
		"updated_at": 1711471999,
		"name": "build sandbox",
		"capability_directories": ["/opt/capabilities"],
		"network": {"access": "restricted", "allowed_domains": ["registry.npmjs.org"]},
		"packages": {"npm": ["typescript"], "python": ["requests", "boto3"], "system": ["git"]},
		"plugins": [{"type": "inline", "name": "linter", "description": "runs the linter"}],
		"skills": [],
		"files": []
	}`)

	args := environmentTemplateArgs(tpl)
	assert.Equal(t, "envtpl_0001", args["__id"].Value)
	assert.Equal(t, "build sandbox", args["name"].Value)
	assert.Equal(t, "restricted", args["networkPolicyType"].Value)
	assert.Equal(t, []any{"registry.npmjs.org"}, args["networkPolicyAllowedDomains"].Value)
	assert.Equal(t, []any{"/opt/capabilities"}, args["capabilityDirectories"].Value)
	// each package manager reads from its own list: crossing two of them
	// reports packages the sandbox does not have and hides the ones it does
	assert.Equal(t, []any{"typescript"}, args["npmPackages"].Value)
	assert.Equal(t, []any{"requests", "boto3"}, args["pythonPackages"].Value)
	assert.Equal(t, []any{"git"}, args["systemPackages"].Value)
	assert.Equal(t, map[string]any{"linter": "runs the linter"}, args["plugins"].Value)
}

func TestEnvironmentTemplateArgsWithoutANetworkBlock(t *testing.T) {
	tpl := decodeJSON[openai.EnvironmentTemplate](t, `{
		"id": "envtpl_0002",
		"object": "agent.environment.template",
		"created_at": 1711471533,
		"updated_at": 1711471533,
		"name": null,
		"capability_directories": [],
		"packages": {"npm": [], "python": [], "system": []},
		"plugins": [],
		"skills": [],
		"files": []
	}`)

	args := environmentTemplateArgs(tpl)
	// a template that reports no network policy has none to report. An empty
	// allowlist here would read as "restricted to nothing", which is the
	// opposite of what an unset policy means.
	assertNullFields(t, args, "networkPolicyType", "networkPolicyAllowedDomains", "name")
}

func TestEnvironmentTemplateSkillArgs(t *testing.T) {
	ref := decodeJSON[openai.EnvironmentTemplateSkillUnion](t,
		`{"type": "skill_reference", "skill_id": "skill_0001", "version": "latest"}`)
	refArgs, skillID := environmentTemplateSkillArgs("envtpl_0001", 0, ref)
	assert.Equal(t, "envtpl_0001/skill/0", refArgs["__id"].Value)
	assert.Equal(t, "skill_reference", refArgs["type"].Value)
	assert.Equal(t, "latest", refArgs["version"].Value)
	assert.Equal(t, "skill_0001", skillID)
	assertNullFields(t, refArgs, "name", "description")

	inline := decodeJSON[openai.EnvironmentTemplateSkillUnion](t,
		`{"type": "inline", "name": "release notes", "description": "writes release notes"}`)
	inlineArgs, inlineSkillID := environmentTemplateSkillArgs("envtpl_0001", 1, inline)
	assert.Equal(t, "envtpl_0001/skill/1", inlineArgs["__id"].Value)
	assert.Equal(t, "release notes", inlineArgs["name"].Value)
	assert.Equal(t, "writes release notes", inlineArgs["description"].Value)
	// an inline skill is not registered in the project, so it names no skill
	// for the reference to resolve against
	assert.Empty(t, inlineSkillID)
	assertNullFields(t, inlineArgs, "version")
}

func TestEnvironmentTemplateFileArgs(t *testing.T) {
	byID := decodeJSON[openai.EnvironmentTemplateFileUnion](t,
		`{"type": "file_id", "file_id": "file-0001", "path": "/workspace/seed.csv"}`)
	byIDArgs, fileID := environmentTemplateFileArgs("envtpl_0001", 0, byID)
	assert.Equal(t, "envtpl_0001/file/0", byIDArgs["__id"].Value)
	assert.Equal(t, "/workspace/seed.csv", byIDArgs["path"].Value)
	assert.Equal(t, "file_id", byIDArgs["type"].Value)
	assert.Equal(t, "file-0001", fileID)
	// the size of an uploaded file is reported on the upload, not here
	assertNullFields(t, byIDArgs, "sizeBytes")

	inline := decodeJSON[openai.EnvironmentTemplateFileUnion](t,
		`{"type": "inline", "path": "/workspace/config.toml", "size_bytes": 812}`)
	inlineArgs, inlineFileID := environmentTemplateFileArgs("envtpl_0001", 1, inline)
	assert.Equal(t, "/workspace/config.toml", inlineArgs["path"].Value)
	assert.Equal(t, int64(812), inlineArgs["sizeBytes"].Value)
	assert.Empty(t, inlineFileID, "an inline file names no uploaded file")
}

func TestEnvironmentTemplateFileIdsAreDistinctForARepeatedPath(t *testing.T) {
	// Two entries writing to one path is a broken template, not a reason to
	// report one of them: a shared key hands the second entry the first one's
	// values and the collection silently loses a row.
	first := decodeJSON[openai.EnvironmentTemplateFileUnion](t,
		`{"type": "inline", "path": "/workspace/config.toml", "size_bytes": 1}`)
	second := decodeJSON[openai.EnvironmentTemplateFileUnion](t,
		`{"type": "inline", "path": "/workspace/config.toml", "size_bytes": 2}`)

	firstArgs, _ := environmentTemplateFileArgs("envtpl_0001", 0, first)
	secondArgs, _ := environmentTemplateFileArgs("envtpl_0001", 1, second)
	assert.NotEqual(t, firstArgs["__id"].Value, secondArgs["__id"].Value)
}

func TestStringArg(t *testing.T) {
	id, ok := stringArg(map[string]*llx.RawData{"id": llx.StringData("agent_0001")}, "id")
	assert.True(t, ok)
	assert.Equal(t, "agent_0001", id)

	_, ok = stringArg(map[string]*llx.RawData{}, "id")
	assert.False(t, ok)

	// an empty id must not reach a get: the API answers for the collection
	// path instead and the init builds a resource for the wrong thing
	_, ok = stringArg(map[string]*llx.RawData{"id": llx.StringData("")}, "id")
	assert.False(t, ok)

	_, ok = stringArg(map[string]*llx.RawData{"id": llx.NilData}, "id")
	assert.False(t, ok)

	_, ok = stringArg(map[string]*llx.RawData{"id": llx.IntData(7)}, "id")
	assert.False(t, ok)
}
