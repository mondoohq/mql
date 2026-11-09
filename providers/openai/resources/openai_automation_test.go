// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// No account with access to the beta Automations API was available, so every
// fixture below is Synthetic: built from the JSON tags and field documentation
// of openai-go v3.97.0 (betaagentautomation.go), not captured from a live
// response.

// Synthetic: periodic automation a developer created, running a saved agent in
// an openai_hosted environment that overrides every block of its template.
func TestAutomationArgsPeriodicSavedAgentHosted(t *testing.T) {
	a := decodeJSON[openai.AutomationUnion](t, `{
		"id": "auto_0001",
		"object": "agent.automation",
		"type": "periodic",
		"name": "nightly triage",
		"status": "paused",
		"expression": "0 3 * * *",
		"timezone": "Europe/Berlin",
		"metadata": {"team": "sre"},
		"created_at": 1767225600,
		"created_by": {"type": "developer"},
		"target": {
			"type": "new_session",
			"agent": null,
			"agent_id": "agent_0001",
			"vault_ids": ["vault_0001", "vault_0002"],
			"input": [],
			"metadata": {},
			"environment": {
				"type": "openai_hosted",
				"environment_id": null,
				"environment_template_id": "envtpl_0001",
				"container_size": "large",
				"capability_directories": ["/opt/caps"],
				"desktop": {"enabled": true},
				"network": {"access": "restricted", "allowed_domains": ["api.github.com", "pypi.org"]},
				"packages": {"npm": ["typescript"], "python": ["requests"], "system": []},
				"plugins": [{"type": "inline", "name": "linter", "description": "runs the linter"}],
				"skills": [],
				"files": []
			}
		}
	}`)

	args, refs := automationArgs(a)

	assert.Equal(t, "auto_0001", args["__id"].Value)
	assert.Equal(t, "auto_0001", args["id"].Value)
	assert.Equal(t, "nightly triage", args["name"].Value)
	assert.Equal(t, "periodic", args["type"].Value)
	assert.Equal(t, "paused", args["status"].Value)
	assert.Equal(t, "0 3 * * *", args["expression"].Value)
	assert.Equal(t, "Europe/Berlin", args["timezone"].Value)
	assert.Equal(t, map[string]any{"team": "sre"}, args["metadata"].Value)
	assert.Equal(t, time.Unix(1767225600, 0), timeValue(t, args, "createdAt"))
	assert.Equal(t, "developer", args["createdByType"].Value)
	assert.Equal(t, "new_session", args["targetType"].Value)

	assert.Equal(t, "openai_hosted", args["environmentType"].Value)
	assert.Equal(t, "large", args["containerSize"].Value)
	assert.Equal(t, "restricted", args["networkPolicyType"].Value)
	assert.Equal(t, []any{"api.github.com", "pypi.org"}, args["networkPolicyAllowedDomains"].Value)
	assert.Equal(t, true, args["desktopEnabled"].Value)
	assert.Equal(t, []any{"/opt/caps"}, args["capabilityDirectories"].Value)
	assert.Equal(t, []any{"typescript"}, args["npmPackages"].Value)
	assert.Equal(t, []any{"requests"}, args["pythonPackages"].Value)
	// an empty override is a setting (no system packages), not an absence
	assert.Equal(t, []any{}, args["systemPackages"].Value)
	assert.Equal(t, map[string]any{"linter": "runs the linter"}, args["plugins"].Value)

	assert.Equal(t, "agent_0001", refs.agentID)
	assert.Equal(t, []string{"vault_0001", "vault_0002"}, refs.vaultIDs)
	assert.Equal(t, "envtpl_0001", refs.templateID)

	assertNullFields(t, args, "runAt", "createdBySessionId", "createdByToolCallId",
		"targetSessionId", "targetInstructions", "inlineAgentModel",
		"inlineAgentInstructions", "environmentId", "workspaceDirectory")
}

// Synthetic: once automation an agent created from inside a session, sending
// instructions back into an existing session.
func TestAutomationArgsOnceAgentCreatedExistingSession(t *testing.T) {
	a := decodeJSON[openai.AutomationUnion](t, `{
		"id": "auto_0002",
		"object": "agent.automation",
		"type": "once",
		"name": "follow up",
		"status": "completed",
		"run_at": 1767312000,
		"metadata": {},
		"created_at": 0,
		"created_by": {"type": "agent", "session_id": "sess_0001", "tool_call_id": "call_0001"},
		"target": {
			"type": "existing_session",
			"session_id": "sess_0001",
			"instructions": "check whether the deploy finished"
		}
	}`)

	args, refs := automationArgs(a)

	assert.Equal(t, "once", args["type"].Value)
	assert.Equal(t, "completed", args["status"].Value)
	assert.Equal(t, time.Unix(1767312000, 0), timeValue(t, args, "runAt"))
	assert.Equal(t, "agent", args["createdByType"].Value)
	assert.Equal(t, "sess_0001", args["createdBySessionId"].Value)
	assert.Equal(t, "call_0001", args["createdByToolCallId"].Value)
	assert.Equal(t, "existing_session", args["targetType"].Value)
	assert.Equal(t, "sess_0001", args["targetSessionId"].Value)
	assert.Equal(t, "check whether the deploy finished", args["targetInstructions"].Value)

	// an existing session names no agent, vault or template
	assert.Empty(t, refs.agentID)
	assert.Nil(t, refs.vaultIDs)
	assert.Empty(t, refs.templateID)

	// created_at 0 is an absent timestamp, not 1970
	assertNullFields(t, args, "createdAt", "expression", "timezone",
		"inlineAgentModel", "inlineAgentInstructions",
		"environmentType", "environmentId", "networkPolicyType",
		"networkPolicyAllowedDomains", "desktopEnabled", "containerSize",
		"capabilityDirectories", "npmPackages", "pythonPackages",
		"systemPackages", "plugins", "workspaceDirectory")
}

// Synthetic: openai_hosted environment that overrides nothing, so every block
// is null and the template's settings apply.
func TestAutomationArgsHostedInheritsTemplate(t *testing.T) {
	a := decodeJSON[openai.AutomationUnion](t, `{
		"id": "auto_0003",
		"type": "periodic",
		"status": "active",
		"expression": "*/15 * * * *",
		"timezone": "UTC",
		"created_by": {"type": "developer"},
		"target": {
			"type": "new_session",
			"agent": null,
			"agent_id": "agent_0002",
			"vault_ids": [],
			"environment": {
				"type": "openai_hosted",
				"environment_id": null,
				"environment_template_id": "envtpl_0002",
				"container_size": null,
				"capability_directories": null,
				"desktop": null,
				"network": null,
				"packages": null,
				"plugins": null,
				"skills": null,
				"files": null
			}
		}
	}`)

	args, refs := automationArgs(a)

	assert.Equal(t, "openai_hosted", args["environmentType"].Value)
	assert.Equal(t, "envtpl_0002", refs.templateID)
	// reporting an empty allowlist here would read as "restricted to nothing"
	// when the template may allow everything
	assertNullFields(t, args, "networkPolicyType", "networkPolicyAllowedDomains",
		"desktopEnabled", "containerSize", "capabilityDirectories",
		"npmPackages", "pythonPackages", "systemPackages", "plugins")
}

// Synthetic: restricted network with an empty allowlist, the strictest
// override there is.
func TestAutomationArgsRestrictedToNothing(t *testing.T) {
	a := decodeJSON[openai.AutomationUnion](t, `{
		"id": "auto_0004",
		"type": "periodic",
		"target": {
			"type": "new_session",
			"agent_id": "agent_0002",
			"environment": {
				"type": "openai_hosted",
				"network": {"access": "restricted", "allowed_domains": []}
			}
		}
	}`)

	args, _ := automationArgs(a)

	assert.Equal(t, "restricted", args["networkPolicyType"].Value)
	assert.Equal(t, []any{}, args["networkPolicyAllowedDomains"].Value)
}

// Synthetic: self_hosted environment, which carries a workspace directory and
// none of the hosted blocks.
func TestAutomationArgsSelfHosted(t *testing.T) {
	a := decodeJSON[openai.AutomationUnion](t, `{
		"id": "auto_0005",
		"type": "periodic",
		"target": {
			"type": "new_session",
			"agent_id": "agent_0003",
			"environment": {
				"type": "self_hosted",
				"environment_id": "env_0001",
				"capability_directories": ["/srv/caps"],
				"workspace_directory": "/srv/work"
			}
		}
	}`)

	args, refs := automationArgs(a)

	assert.Equal(t, "self_hosted", args["environmentType"].Value)
	assert.Equal(t, "env_0001", args["environmentId"].Value)
	assert.Equal(t, []any{"/srv/caps"}, args["capabilityDirectories"].Value)
	assert.Equal(t, "/srv/work", args["workspaceDirectory"].Value)
	// a self-hosted environment has no template to resolve
	assert.Empty(t, refs.templateID)
	assertNullFields(t, args, "networkPolicyType", "networkPolicyAllowedDomains",
		"desktopEnabled", "containerSize", "npmPackages", "pythonPackages",
		"systemPackages", "plugins")
}

// Synthetic: inline agent configuration in place of a saved agent, with an mcp
// tool whose header value has to stay out of the schema.
func TestAutomationArgsInlineAgent(t *testing.T) {
	a := decodeJSON[openai.AutomationUnion](t, `{
		"id": "auto_0006",
		"type": "periodic",
		"target": {
			"type": "new_session",
			"agent_id": null,
			"agent": {
				"model": "gpt-5",
				"instructions": "summarize open incidents",
				"tools": [{
					"type": "mcp",
					"server_label": "pager",
					"credential_id": "cred_0009",
					"allowed_tools": [],
					"transport": {
						"type": "http",
						"server_url": "https://mcp.example.com",
						"headers": {"authorization": "sentinel-inline-header"}
					}
				}]
			},
			"environment": {"type": "none"}
		}
	}`)

	args, refs := automationArgs(a)

	assert.Equal(t, "gpt-5", args["inlineAgentModel"].Value)
	assert.Equal(t, "summarize open incidents", args["inlineAgentInstructions"].Value)
	assert.Empty(t, refs.agentID, "an inline agent names no saved agent")
	assert.Equal(t, "none", args["environmentType"].Value)

	require.Len(t, a.Target.Agent.Tools, 1)
	toolArgs, credentialID := agentToolArgs(a.ID, 0, persistedAgentTool(a.Target.Agent.Tools[0]))
	assert.Equal(t, "auto_0006/tool/0", toolArgs["__id"].Value)
	assert.Equal(t, "mcp", toolArgs["type"].Value)
	assert.Equal(t, "pager", toolArgs["serverLabel"].Value)
	assert.Equal(t, "https://mcp.example.com", toolArgs["transportServerUrl"].Value)
	assert.Equal(t, []any{"authorization"}, toolArgs["transportHeaderNames"].Value)
	assert.Equal(t, "cred_0009", credentialID)
	assertAbsent(t, toolArgs, "sentinel-inline-header")
}

// Synthetic: a tool built in code has no raw JSON to read again, and keeps
// only its type rather than failing.
func TestPersistedAgentToolWithoutRawJSON(t *testing.T) {
	p := persistedAgentTool(openai.AgentToolUnion{Type: "web_search"})
	assert.Equal(t, "web_search", p.Type)
}

// Synthetic: the skill and file lists of an automation's environment decode
// into the same args a template's lists produce.
func TestAutomationSandboxSkillAndFileArgs(t *testing.T) {
	a := decodeJSON[openai.AutomationUnion](t, `{
		"id": "auto_0007",
		"type": "once",
		"target": {
			"type": "new_session",
			"agent_id": "agent_0001",
			"environment": {
				"type": "openai_hosted",
				"skills": [
					{"type": "skill_reference", "skill_id": "skill_0001", "version": "latest"},
					{"type": "inline", "name": "triage", "description": "sorts tickets"}
				],
				"files": [
					{"type": "file_id", "file_id": "file-0001", "path": "/data/input.csv"},
					{"type": "inline", "path": "/data/config.json", "size_bytes": 42}
				]
			}
		}
	}`)
	env := a.Target.Environment
	require.Len(t, env.Skills, 2)
	require.Len(t, env.Files, 2)

	ref, skillID := sandboxSkillArgs(a.ID, 0, env.Skills[0].Type, env.Skills[0].SkillID, env.Skills[0].Version, env.Skills[0].Name, env.Skills[0].Description)
	assert.Equal(t, "auto_0007/skill/0", ref["__id"].Value)
	assert.Equal(t, "skill_0001", skillID)
	assert.Equal(t, "latest", ref["version"].Value)
	assertNullFields(t, ref, "name", "description")

	inline, inlineID := sandboxSkillArgs(a.ID, 1, env.Skills[1].Type, env.Skills[1].SkillID, env.Skills[1].Version, env.Skills[1].Name, env.Skills[1].Description)
	assert.Empty(t, inlineID)
	assert.Equal(t, "triage", inline["name"].Value)
	assertNullFields(t, inline, "version")

	fileRef, fileID := sandboxFileArgs(a.ID, 0, env.Files[0].Type, env.Files[0].Path, env.Files[0].FileID, env.Files[0].SizeBytes)
	assert.Equal(t, "file-0001", fileID)
	assert.Equal(t, "/data/input.csv", fileRef["path"].Value)
	assertNullFields(t, fileRef, "sizeBytes")

	fileInline, inlineFileID := sandboxFileArgs(a.ID, 1, env.Files[1].Type, env.Files[1].Path, env.Files[1].FileID, env.Files[1].SizeBytes)
	assert.Empty(t, inlineFileID)
	assert.Equal(t, int64(42), fileInline["sizeBytes"].Value)
}
