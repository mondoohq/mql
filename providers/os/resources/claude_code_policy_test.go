// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/llx"
)

// Measured: the shape of ~/.claude/settings.json of a Claude Code 2.1.312
// install on macOS (2026-10-28), trimmed to the keys this file reads: allow
// rules, defaultMode "auto", and additionalDirectories. No sandbox block and
// no managed source on that host.
const measuredClaudeUserSettings = `{
  "permissions": {
    "allow": ["Bash(grep:*)", "Bash(go run:*)", "Bash(ls:*)"],
    "defaultMode": "auto",
    "additionalDirectories": ["/tmp"]
  },
  "model": "opus",
  "skipDangerousModePermissionPrompt": true
}`

func noRegistry(string, string) (string, bool, error) { return "", false, nil }

func TestLoadClaudePolicyUserOnly(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{
		"/Users/u/.claude/settings.json": measuredClaudeUserSettings,
		// Measured: an account with no server-managed settings caches `{}`.
		"/Users/u/.claude/remote-settings.json": `{}`,
	})
	p, err := loadClaudePolicy(&afero.Afero{Fs: fs}, "darwin", "/Users/u/.claude", noRegistry)
	require.NoError(t, err)

	assert.Empty(t, p.sources, "an empty server-managed cache is not a policy")
	assert.Nil(t, p.managed)
	assert.Equal(t, "auto", *p.effectiveString("permissions", "defaultMode"))
	assert.Equal(t, []string{"Bash(grep:*)", "Bash(go run:*)", "Bash(ls:*)"}, p.combinedList(false, "permissions", "allow"))
	assert.Nil(t, p.effectiveBool("sandbox", "enabled"), "unset sandbox is null, not false")
	assert.Nil(t, p.disableSwitch([]string{"permissions", "disableBypassPermissionsMode"}))
	assert.Nil(t, p.managedLock("allowManagedPermissionRulesOnly"))
	assert.Nil(t, p.allowedMcpRules(), "no allowlist is null, not an empty allowlist")
	assert.Empty(t, p.deniedMcpRules())
	assert.Nil(t, p.mcp)
}

func TestLoadClaudePolicyManagedFiles(t *testing.T) {
	// Synthetic: no target had managed settings. The policy follows the
	// examples in code.claude.com/docs/en/managed-settings and
	// settings-reference.
	fs := afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{
		"/home/u/.claude/settings.json": `{
		  "permissions": {"allow": ["Bash(ls:*)"], "deny": ["Read(./.env)"], "defaultMode": "bypassPermissions"},
		  "sandbox": {"enabled": false, "network": {"allowedDomains": ["user.example.com"]}},
		  "enableAllProjectMcpServers": true,
		  "allowedMcpServers": [{"serverName": "user-srv"}],
		  "deniedMcpServers": [{"serverName": "user-blocked"}]
		}`,
		"/etc/claude-code/managed-settings.json": `{
		  "permissions": {"disableBypassPermissionsMode": "disable", "deny": ["Bash(curl *)"], "defaultMode": "default"},
		  "allowManagedPermissionRulesOnly": true,
		  "sandbox": {"enabled": true, "allowUnsandboxedCommands": false, "network": {"allowedDomains": ["github.com"]}},
		  "apiKeyHelper": "/opt/corp/key.sh",
		  "forceLoginOrgUUID": "11111111-2222-3333-4444-555555555555"
		}`,
		// a later drop-in replaces a single value and adds list entries
		"/etc/claude-code/managed-settings.d/20-mcp.json": `{
		  "sandbox": {"network": {"allowedDomains": ["*.npmjs.org", "github.com"]}},
		  "allowManagedMcpServersOnly": true,
		  "allowedMcpServers": [{"serverName": "github"}, {"serverUrl": "https://mcp.example.com/*"}],
		  "deniedMcpServers": [{"serverCommand": ["npx", "-y", "bad-server"]}],
		  "managedMcpServers": {"search": {"type": "http", "url": "https://search.example.com/mcp"}}
		}`,
		"/etc/claude-code/managed-mcp.json": `{"mcpServers": {"corp": {"command": "/opt/corp/mcp", "args": ["--stdio"]}}}`,
	})
	p, err := loadClaudePolicy(&afero.Afero{Fs: fs}, "debian", "/home/u/.claude", noRegistry)
	require.NoError(t, err)

	require.Len(t, p.sources, 1)
	assert.Equal(t, []string{"/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-settings.d/20-mcp.json"}, p.sources[0].locations)

	// the managed value wins over the user's
	assert.Equal(t, "default", *p.effectiveString("permissions", "defaultMode"))
	assert.True(t, *p.effectiveBool("sandbox", "enabled"))
	assert.False(t, *p.effectiveBool("sandbox", "allowUnsandboxedCommands"))
	// a key only the user sets still applies
	assert.True(t, *p.effectiveBool("enableAllProjectMcpServers"))
	assert.True(t, *p.disableSwitch([]string{"permissions", "disableBypassPermissionsMode"}))
	assert.True(t, *p.managedLock("allowManagedPermissionRulesOnly"))

	// allowManagedPermissionRulesOnly drops the user's rules
	assert.Equal(t, []string{"Bash(curl *)"}, p.combinedList(true, "permissions", "deny"))
	assert.Equal(t, []string{"Bash(curl *)", "Read(./.env)"}, p.combinedList(false, "permissions", "deny"))
	// drop-in lists union with the base file, without duplicates
	assert.Equal(t, []string{"github.com", "*.npmjs.org", "user.example.com"}, p.combinedList(false, "sandbox", "network", "allowedDomains"))

	// allowManagedMcpServersOnly: only the managed allowlist
	allowed := p.allowedMcpRules()
	require.Len(t, allowed, 2)
	assert.Equal(t, "github", allowed[0].ServerName)
	assert.Equal(t, "https://mcp.example.com/*", allowed[1].ServerURL)
	assert.True(t, allowed[0].managed)

	denied := p.deniedMcpRules()
	require.Len(t, denied, 2)
	assert.Equal(t, []string{"npx", "-y", "bad-server"}, denied[0].ServerCommand)
	assert.True(t, denied[0].managed)
	assert.Equal(t, "user-blocked", denied[1].ServerName)
	assert.False(t, denied[1].managed)

	require.NotNil(t, p.mcp)
	servers := p.managedMcpServers()
	require.Len(t, servers, 2)
	assert.Equal(t, "corp", servers[0].name)
	assert.Equal(t, "/etc/claude-code/managed-mcp.json", servers[0].source)
	assert.Equal(t, "search", servers[1].name)
	assert.Equal(t, "https://search.example.com/mcp", servers[1].entry.URL)
	assert.Equal(t, "/etc/claude-code/managed-settings.d/20-mcp.json", servers[1].source, "the drop-in that declares it")

	assert.Equal(t, "11111111-2222-3333-4444-555555555555", p.effective("forceLoginOrgUUID"))
}

func TestClaudePolicySourcePrecedence(t *testing.T) {
	// Synthetic: the server-managed cache, a device-level configuration
	// profile, and the managed settings file, all present. The plist uses
	// the documented com.anthropic.claudecode domain.
	fs := afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{
		"/Users/u/.claude/remote-settings.json": `{"permissions": {"defaultMode": "plan"}}`,
		"/Library/Managed Preferences/com.anthropic.claudecode.plist": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>allowManagedHooksOnly</key><true/>
  <key>sandbox</key><dict><key>network</key><dict><key>allowManagedDomainsOnly</key><true/>
    <key>allowedDomains</key><array><string>mdm.example.com</string></array></dict></dict>
</dict></plist>`,
		"/Library/Application Support/ClaudeCode/managed-settings.json": `{"permissions": {"defaultMode": "acceptEdits"}, "allowManagedHooksOnly": false,
		  "sandbox": {"network": {"allowedDomains": ["file.example.com"]}}}`,
		"/Users/u/.claude/settings.json": `{"sandbox": {"network": {"allowedDomains": ["user.example.com"]}}}`,
	})
	p, err := loadClaudePolicy(&afero.Afero{Fs: fs}, "darwin", "/Users/u/.claude", noRegistry)
	require.NoError(t, err)

	require.Len(t, p.sources, 3)
	assert.Equal(t, "/Users/u/.claude/remote-settings.json", p.sources[0].locations[0])
	assert.Equal(t, "/Library/Managed Preferences/com.anthropic.claudecode.plist", p.sources[1].locations[0])
	assert.Equal(t, "/Library/Application Support/ClaudeCode/managed-settings.json", p.sources[2].locations[0])

	// first-wins: only the server-managed cache supplies ordinary keys
	assert.Equal(t, "plan", *p.effectiveString("permissions", "defaultMode"))
	assert.Nil(t, p.managedLock("allowManagedHooksOnly"), "unselected sources do not supply ordinary keys")
	// the domain lock is read from every admin source, and unions their lists
	assert.True(t, *p.anyPolicyTrue("sandbox", "network", "allowManagedDomainsOnly"))
	assert.ElementsMatch(t, []any{"mdm.example.com", "file.example.com"}, p.policyList("sandbox", "network", "allowedDomains"))
}

func TestClaudePolicyMergeBehavior(t *testing.T) {
	// Synthetic: managedSourcesBehavior "merge" in the highest source.
	p := resolveClaudePolicy([]claudeSettingsSource{
		{locations: []string{"remote"}, admin: true, settings: map[string]any{
			"managedSourcesBehavior": "merge",
			"allowManagedHooksOnly":  false,
			"permissions":            map[string]any{"allow": []any{"Read"}, "defaultMode": "plan"},
		}},
		{locations: []string{"file"}, admin: true, settings: map[string]any{
			"allowManagedHooksOnly": true,
			"permissions":           map[string]any{"allow": []any{"Bash(ls:*)"}, "defaultMode": "acceptEdits"},
		}},
	})
	assert.True(t, p.merge)
	assert.Equal(t, "plan", *p.effectiveString("permissions", "defaultMode"), "higher source wins single values")
	assert.Equal(t, []string{"Bash(ls:*)", "Read"}, p.combinedList(true, "permissions", "allow"))
	assert.True(t, *p.managedLock("allowManagedHooksOnly"), "locks take the strictest value under merge")
}

func TestClaudePolicyRegistry(t *testing.T) {
	// Synthetic: the documented Settings value under the Policies keys.
	reg := map[string]string{
		claudePolicyHKCU: `{"permissions": {"defaultMode": "bypassPermissions"}}`,
	}
	read := func(key, name string) (string, bool, error) {
		assert.Equal(t, "Settings", name)
		v, ok := reg[key]
		return v, ok, nil
	}
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	// HKCU alone applies
	p, err := loadClaudePolicy(afs, "windows", `C:\Users\u\.claude`, read)
	require.NoError(t, err)
	require.Len(t, p.sources, 1)
	assert.Equal(t, `HKCU\SOFTWARE\Policies\ClaudeCode`, p.sources[0].locations[0])
	assert.Equal(t, "bypassPermissions", *p.effectiveString("permissions", "defaultMode"))

	// HKCU never applies beneath an admin source
	reg[claudePolicyHKLM] = `{"permissions": {"disableBypassPermissionsMode": "disable"}}`
	p, err = loadClaudePolicy(afs, "windows", `C:\Users\u\.claude`, read)
	require.NoError(t, err)
	require.Len(t, p.sources, 2)
	assert.Equal(t, `HKLM\SOFTWARE\Policies\ClaudeCode`, p.sources[0].locations[0])
	assert.Nil(t, p.effectiveString("permissions", "defaultMode"))
	assert.True(t, *p.disableSwitch([]string{"permissions", "disableBypassPermissionsMode"}))

	// a malformed HKLM value is an error, as Claude Code refuses to start
	reg[claudePolicyHKLM] = `not json`
	_, err = loadClaudePolicy(afs, "windows", `C:\Users\u\.claude`, read)
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrMalformedData))
}

func TestClaudePolicyControlKeysOnly(t *testing.T) {
	// Synthetic: a managed file with only control keys is not a policy, so
	// the lower HKCU source applies.
	p := resolveClaudePolicy([]claudeSettingsSource{
		{locations: []string{"file"}, admin: true, settings: map[string]any{"managedSourcesBehavior": "first-wins"}},
		{locations: []string{"hkcu"}, settings: map[string]any{"disableAllHooks": true}},
	})
	require.Len(t, p.sources, 1)
	assert.Equal(t, "hkcu", p.sources[0].locations[0])
	assert.True(t, *p.effectiveBool("disableAllHooks"))
}

func TestClaudeMdmPlists(t *testing.T) {
	// Synthetic: Claude Code reads the per-user profile before the device
	// profile.
	assert.Equal(t, []string{
		"/Library/Managed Preferences/alice/com.anthropic.claudecode.plist",
		"/Library/Managed Preferences/com.anthropic.claudecode.plist",
	}, claudeMdmPlists("/Users/alice/.claude"))
	assert.Equal(t, []string{"/Library/Managed Preferences/com.anthropic.claudecode.plist"}, claudeMdmPlists("/opt/claude-config"))
}

func TestClaudeDisableSwitch(t *testing.T) {
	// Synthetic: disableAutoMode in either accepted location; a value other
	// than "disable" does not turn the mode off.
	p := &claudePolicy{user: map[string]any{"permissions": map[string]any{"disableAutoMode": "disable"}}}
	assert.True(t, *p.disableSwitch([]string{"disableAutoMode"}, []string{"permissions", "disableAutoMode"}))
	p = &claudePolicy{user: map[string]any{"disableAutoMode": "enable"}}
	assert.False(t, *p.disableSwitch([]string{"disableAutoMode"}, []string{"permissions", "disableAutoMode"}))
}

func TestMergeClaudeSettingsEntryKeys(t *testing.T) {
	// Synthetic: a later managedMcpServers entry with the same name replaces
	// the earlier one whole instead of merging its fields.
	base := map[string]any{"managedMcpServers": map[string]any{
		"a": map[string]any{"url": "https://a", "headers": map[string]any{"X": "1"}},
		"b": map[string]any{"url": "https://b"},
	}, "fallbackModel": []any{"opus", "sonnet"}}
	over := map[string]any{"managedMcpServers": map[string]any{
		"a": map[string]any{"url": "https://a2"},
	}, "fallbackModel": []any{"haiku"}}
	got := mergeClaudeSettings(base, over)
	servers := got["managedMcpServers"].(map[string]any)
	assert.Equal(t, map[string]any{"url": "https://a2"}, servers["a"])
	assert.Equal(t, map[string]any{"url": "https://b"}, servers["b"])
	assert.Equal(t, []any{"haiku"}, got["fallbackModel"])
}

func TestReadClaudeSettingsFileMalformed(t *testing.T) {
	// Synthetic: a managed file that is not JSON fails the read.
	fs := afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{"/etc/claude-code/managed-settings.json": `{"permissions":`})
	_, err := loadClaudePolicy(&afero.Afero{Fs: fs}, "debian", "/home/u/.claude", noRegistry)
	require.Error(t, err)
}

func TestReadClaudeManagedMcpUnparsable(t *testing.T) {
	// Synthetic: a managed-mcp.json Claude Code cannot parse does not take
	// control, and an empty server map does.
	fs := afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{"/etc/claude-code/managed-mcp.json": `{"mcpServers": [}`})
	assert.Nil(t, readClaudeManagedMcp(&afero.Afero{Fs: fs}, "debian"))
	writeTestFiles(t, fs, map[string]string{"/etc/claude-code/managed-mcp.json": `{"mcpServers": {}}`})
	m := readClaudeManagedMcp(&afero.Afero{Fs: fs}, "debian")
	require.NotNil(t, m)
	assert.Empty(t, m.servers)
}

func TestClaudeCodePolicyFields(t *testing.T) {
	// Synthetic: a managed file that locks the sandbox and an MCP denylist,
	// read through the resource on a filesystem connection.
	mockFS := afero.NewMemMapFs()
	writeTestFiles(t, mockFS, map[string]string{
		"/home/u/.claude/settings.json": measuredClaudeUserSettings,
	})
	runtime := memFSRuntime(t, mockFS)
	raw, err := CreateResource(runtime, "claude.code", map[string]*llx.RawData{"configPath": llx.StringData("/home/u/.claude")})
	require.NoError(t, err)
	r := raw.(*mqlClaudeCode)

	// nothing managed: unset settings are null, not false
	present, err := r.managedSettingsPresent()
	require.NoError(t, err)
	assert.False(t, present)
	_, err = r.sandboxEnabled()
	require.NoError(t, err)
	assert.True(t, r.SandboxEnabled.IsNull())
	_, err = r.allowedMcpServers()
	require.NoError(t, err)
	assert.True(t, r.AllowedMcpServers.IsNull())
	_, err = r.managedSettings()
	require.NoError(t, err)
	assert.True(t, r.ManagedSettings.IsNull())
	mode, err := r.defaultPermissionMode()
	require.NoError(t, err)
	assert.Equal(t, "auto", mode)
	helper, err := r.hasApiKeyHelper()
	require.NoError(t, err)
	assert.False(t, helper)

	writeTestFiles(t, mockFS, map[string]string{
		"/etc/claude-code/managed-settings.json": `{"sandbox": {"enabled": true}, "apiKeyHelper": "/opt/key.sh",
		  "deniedMcpServers": [{"serverName": "filesystem"}], "env": {"ANTHROPIC_API_KEY": "placeholder-value"}}`,
	})
	raw, err = CreateResource(runtime, "claude.code", map[string]*llx.RawData{"configPath": llx.StringData("/home/u/.claude"), "__id": llx.StringData("second")})
	require.NoError(t, err)
	r = raw.(*mqlClaudeCode)

	sources, err := r.managedSources()
	require.NoError(t, err)
	assert.Equal(t, []any{"/etc/claude-code/managed-settings.json"}, sources)
	enabled, err := r.sandboxEnabled()
	require.NoError(t, err)
	assert.True(t, enabled)
	helper, err = r.hasApiKeyHelper()
	require.NoError(t, err)
	assert.True(t, helper)
	denied, err := r.deniedMcpServers()
	require.NoError(t, err)
	require.Len(t, denied, 1)
	assert.Equal(t, "filesystem", denied[0].(*mqlClaudeCodeMcpServerRule).ServerName.Data)
	settings, err := r.managedSettings()
	require.NoError(t, err)
	env := settings.(map[string]any)["env"].(map[string]any)
	assert.NotContains(t, env["ANTHROPIC_API_KEY"], "placeholder", "managed settings are redacted")
}
