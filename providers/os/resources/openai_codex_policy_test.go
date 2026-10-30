// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/base64"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func codexPolicyFs(t *testing.T, files map[string]string) *afero.Afero {
	t.Helper()
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for p, content := range files {
		require.NoError(t, afs.WriteFile(p, []byte(content), 0o644))
	}
	return afs
}

func codexPolicyFor(t *testing.T, afs *afero.Afero, osFamily string, prefs map[string]any) *codexPolicy {
	t.Helper()
	in, err := readCodexPolicyInputs(afs, "/home/dev/.codex", osFamily, prefs)
	require.NoError(t, err)
	return computeCodexPolicy(in)
}

// Synthetic: no Codex configuration on the host; no target showed this.
func TestCodexPolicyUnconfigured(t *testing.T) {
	p := codexPolicyFor(t, codexPolicyFs(t, nil), "linux", nil)
	assert.Nil(t, p.approvalPolicy)
	assert.Nil(t, p.sandboxMode)
	assert.Nil(t, p.defaultPermissions)
	assert.Nil(t, p.sandboxNetworkAccess)
	assert.Nil(t, p.writableRoots)
	assert.Nil(t, p.allowedApprovalPolicies)
	assert.Nil(t, p.allowedSandboxModes)
	assert.Empty(t, p.trustedProjects)
	assert.Empty(t, p.managedConfigSources)
	assert.Empty(t, p.requirementsSources)
}

// Synthetic: user config.toml keys from the Codex config reference
// (approval_policy, sandbox_mode, [sandbox_workspace_write], projects).
func TestCodexPolicyUserConfig(t *testing.T) {
	afs := codexPolicyFs(t, map[string]string{
		"/home/dev/.codex/config.toml": `
approval_policy = "never"
sandbox_mode = "workspace-write"

[sandbox_workspace_write]
network_access = true
writable_roots = ["/home/dev/.cache", "/var/tmp"]

[projects."/home/dev/src/app"]
trust_level = "trusted"

[projects."/home/dev/src/zeta"]
trust_level = "trusted"

[projects."/home/dev/Downloads/repo"]
trust_level = "untrusted"
`,
	})
	p := codexPolicyFor(t, afs, "linux", nil)
	require.NotNil(t, p.approvalPolicy)
	assert.Equal(t, "never", *p.approvalPolicy)
	require.NotNil(t, p.sandboxMode)
	assert.Equal(t, "workspace-write", *p.sandboxMode)
	require.NotNil(t, p.sandboxNetworkAccess)
	assert.True(t, *p.sandboxNetworkAccess)
	assert.Equal(t, []string{"/home/dev/.cache", "/var/tmp"}, p.writableRoots)
	assert.Equal(t, []string{"/home/dev/src/app", "/home/dev/src/zeta"}, p.trustedProjects)
	assert.Empty(t, p.requirementsSources)
}

// Synthetic: granular approval table and permission profile from the config
// reference.
func TestCodexPolicyGranularAndPermissions(t *testing.T) {
	afs := codexPolicyFs(t, map[string]string{
		"/home/dev/.codex/config.toml": `
default_permissions = ":workspace"

[approval_policy.granular]
sandbox_approval = true
rules = false

[sandbox_workspace_write]
network_access = false
`,
	})
	p := codexPolicyFor(t, afs, "linux", nil)
	require.NotNil(t, p.approvalPolicy)
	assert.Equal(t, "granular", *p.approvalPolicy)
	require.NotNil(t, p.defaultPermissions)
	assert.Equal(t, ":workspace", *p.defaultPermissions)
	assert.Nil(t, p.sandboxMode)
	require.NotNil(t, p.sandboxNetworkAccess, "an explicit false is not null")
	assert.False(t, *p.sandboxNetworkAccess)
	assert.Nil(t, p.writableRoots)
}

// Synthetic: layering per codex-rs/config/src/loader (system config.toml <
// user config.toml < managed_config.toml), tables merged key by key.
func TestCodexPolicyLayering(t *testing.T) {
	afs := codexPolicyFs(t, map[string]string{
		"/etc/codex/config.toml": `
approval_policy = "on-request"
sandbox_mode = "read-only"
[sandbox_workspace_write]
writable_roots = ["/srv"]
`,
		"/home/dev/.codex/config.toml": `
approval_policy = "never"
sandbox_mode = "danger-full-access"
[sandbox_workspace_write]
network_access = true
`,
		"/etc/codex/managed_config.toml": `
sandbox_mode = "workspace-write"
`,
	})
	p := codexPolicyFor(t, afs, "linux", nil)
	assert.Equal(t, "never", *p.approvalPolicy, "user overrides system")
	assert.Equal(t, "workspace-write", *p.sandboxMode, "managed overrides user")
	assert.True(t, *p.sandboxNetworkAccess)
	assert.Equal(t, []string{"/srv"}, p.writableRoots, "system key kept when user sets a sibling key")
	assert.Equal(t, []string{"/etc/codex/managed_config.toml"}, p.managedConfigSources)

	// The legacy managed config caps the sandbox mode it sets, with read-only.
	assert.Equal(t, []string{"/etc/codex/managed_config.toml"}, p.requirementsSources)
	assert.Equal(t, []string{"read-only", "workspace-write"}, p.allowedSandboxModes)
	assert.Nil(t, p.allowedApprovalPolicies)
}

// Synthetic: requirements.toml keys from the managed configuration docs; MDM
// values encoded as the docs describe (base64 TOML in com.openai.codex).
func TestCodexPolicyRequirements(t *testing.T) {
	afs := codexPolicyFs(t, map[string]string{
		"/etc/codex/requirements.toml": `
allowed_approval_policies = ["untrusted", "on-request"]
allowed_sandbox_modes = ["read-only", "workspace-write"]
`,
		"/home/dev/.codex/config.toml": `approval_policy = "never"`,
	})
	p := codexPolicyFor(t, afs, "darwin", nil)
	assert.Equal(t, []string{"/etc/codex/requirements.toml"}, p.requirementsSources)
	assert.Equal(t, []string{"untrusted", "on-request"}, p.allowedApprovalPolicies)
	assert.Equal(t, []string{"read-only", "workspace-write"}, p.allowedSandboxModes)
	assert.Equal(t, "never", *p.approvalPolicy, "the configured value is reported even when disallowed")

	// MDM requirements replace the lists of lower layers.
	prefs := map[string]any{
		codexMdmRequirementsKey: "  " + base64.StdEncoding.EncodeToString([]byte(`allowed_sandbox_modes = ["read-only"]`)) + "\n",
		codexMdmConfigKey:       base64.StdEncoding.EncodeToString([]byte(`approval_policy = "on-request"`)),
	}
	p = codexPolicyFor(t, afs, "darwin", prefs)
	mdmConfig := "/Library/Managed Preferences/com.openai.codex.plist#config_toml_base64"
	mdmReq := "/Library/Managed Preferences/com.openai.codex.plist#requirements_toml_base64"
	assert.Equal(t, []string{mdmConfig}, p.managedConfigSources)
	assert.Equal(t, []string{"/etc/codex/requirements.toml", mdmConfig, mdmReq}, p.requirementsSources)
	assert.Equal(t, "on-request", *p.approvalPolicy, "MDM config overrides the user")
	assert.Equal(t, []string{"on-request"}, p.allowedApprovalPolicies, "MDM config approval_policy becomes the only allowed policy")
	assert.Equal(t, []string{"read-only"}, p.allowedSandboxModes)
}

// Measured: node:22-bookworm-slim container with Codex CLI 0.165.0, 2026-10-28.
// With these files `codex exec` reported "approval: untrusted" and "sandbox:
// read-only": the user's never/danger-full-access is outside the allowed
// lists, so Codex fell back. Expected values are what the live mql scan of
// the same files returned.
func TestCodexPolicyMeasuredRequirementsCap(t *testing.T) {
	afs := codexPolicyFs(t, map[string]string{
		"/etc/codex/requirements.toml": "allowed_approval_policies = [\"untrusted\", \"on-request\"]\nallowed_sandbox_modes = [\"read-only\", \"workspace-write\"]\n",
		"/home/dev/.codex/config.toml": "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n",
	})
	p := codexPolicyFor(t, afs, "linux", nil)
	assert.Equal(t, "never", *p.approvalPolicy)
	assert.Equal(t, "danger-full-access", *p.sandboxMode)
	assert.Equal(t, []string{"untrusted", "on-request"}, p.allowedApprovalPolicies)
	assert.Equal(t, []string{"read-only", "workspace-write"}, p.allowedSandboxModes)
	assert.Equal(t, []string{"/etc/codex/requirements.toml"}, p.requirementsSources)
	assert.Empty(t, p.managedConfigSources)
}

// Measured: same Codex CLI 0.165.0 container. /etc/codex/managed_config.toml
// with approval_policy = "on-request" made `codex exec` report "approval:
// on-request" over the user's "never", and /etc/codex/config.toml's
// sandbox_mode = "workspace-write" applied while the user set none.
func TestCodexPolicyMeasuredManagedApproval(t *testing.T) {
	afs := codexPolicyFs(t, map[string]string{
		"/etc/codex/config.toml":         "sandbox_mode = \"workspace-write\"\n",
		"/etc/codex/managed_config.toml": "approval_policy = \"on-request\"\n",
		"/home/dev/.codex/config.toml":   "approval_policy = \"never\"\n",
	})
	p := codexPolicyFor(t, afs, "linux", nil)
	assert.Equal(t, "on-request", *p.approvalPolicy)
	assert.Equal(t, "workspace-write", *p.sandboxMode)
	assert.Equal(t, []string{"on-request"}, p.allowedApprovalPolicies)
	assert.Nil(t, p.allowedSandboxModes)
}

// Synthetic: a managed_config.toml without approval or sandbox settings is a
// managed config layer but adds no requirements.
func TestCodexPolicyManagedConfigWithoutRequirements(t *testing.T) {
	afs := codexPolicyFs(t, map[string]string{
		"/etc/codex/managed_config.toml": `model = "gpt-5"`,
	})
	p := codexPolicyFor(t, afs, "linux", nil)
	assert.Equal(t, []string{"/etc/codex/managed_config.toml"}, p.managedConfigSources)
	assert.Empty(t, p.requirementsSources)
}

// Synthetic: Windows paths from the managed configuration docs; Codex ignores
// managed_config.toml on Windows.
func TestCodexPolicyWindows(t *testing.T) {
	afs := codexPolicyFs(t, map[string]string{
		`C:\ProgramData\OpenAI\Codex\requirements.toml`: `allowed_approval_policies = ["on-request"]`,
		"/etc/codex/managed_config.toml":                `approval_policy = "never"`,
	})
	p := codexPolicyFor(t, afs, "windows", nil)
	assert.Equal(t, []string{`C:\ProgramData\OpenAI\Codex\requirements.toml`}, p.requirementsSources)
	assert.Equal(t, []string{"on-request"}, p.allowedApprovalPolicies)
	assert.Empty(t, p.managedConfigSources)
	assert.Nil(t, p.approvalPolicy)
}

// Synthetic: malformed inputs Codex itself refuses to load.
func TestCodexPolicyMalformed(t *testing.T) {
	afs := codexPolicyFs(t, map[string]string{"/etc/codex/requirements.toml": `allowed_sandbox_modes = [`})
	_, err := readCodexPolicyInputs(afs, "/home/dev/.codex", "linux", nil)
	assert.Error(t, err)

	_, err = readCodexPolicyInputs(codexPolicyFs(t, nil), "/home/dev/.codex", "darwin",
		map[string]any{codexMdmRequirementsKey: "not base64!"})
	assert.Error(t, err)

	_, err = readCodexPolicyInputs(codexPolicyFs(t, nil), "/home/dev/.codex", "darwin",
		map[string]any{codexMdmConfigKey: 42})
	assert.Error(t, err)

	in, err := readCodexPolicyInputs(codexPolicyFs(t, nil), "/home/dev/.codex", "darwin",
		map[string]any{codexMdmConfigKey: "   "})
	require.NoError(t, err)
	assert.False(t, in.mdmConfig.present(), "a blank value is no layer")
}
