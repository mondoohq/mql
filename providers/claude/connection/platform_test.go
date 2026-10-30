// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClaudeOrgPlatform(t *testing.T) {
	p := NewClaudeOrgPlatform("org_123")
	require.NotNil(t, p)

	// catalog metadata is applied
	assert.Equal(t, "claude-organization", p.Name)
	assert.Equal(t, "Claude Organization", p.Title)
	assert.Contains(t, p.Family, "claude")

	// the org id must land in the technology URL segments
	assert.Equal(t, []string{"ai", "claude", "organization", "org_123"}, p.TechnologyUrlSegments)
}

func TestNewClaudeWorkspacePlatform(t *testing.T) {
	p := NewClaudeWorkspacePlatform("org_123", "wrkspc_1")
	require.NotNil(t, p)

	assert.Equal(t, "claude-workspace", p.Name)
	assert.Equal(t, "Claude Workspace", p.Title)

	// both the org and workspace ids must be preserved, in order
	assert.Equal(t,
		[]string{"ai", "claude", "organization", "org_123", "workspace", "wrkspc_1"},
		p.TechnologyUrlSegments)
}

func TestNewClaudeAPIPlatform(t *testing.T) {
	p := NewClaudeAPIPlatform("https://api.anthropic.com")
	require.NotNil(t, p)

	assert.Equal(t, "claude", p.Name)
	assert.Equal(t, "Claude", p.Title)
	assert.Equal(t, []string{"ai", "claude", "https://api.anthropic.com"}, p.TechnologyUrlSegments)
}

func TestClaudeIdentifiers(t *testing.T) {
	// The identifiers are keyed by a single id each; a workspace identifier is
	// keyed by the workspace id alone (not the org id), which is what asset
	// detection and discovery both rely on to match.
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/claude/organization/org_123",
		NewClaudeOrgIdentifier("org_123"))
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/claude/workspace/wrkspc_1",
		NewClaudeWorkspaceIdentifier("wrkspc_1"))
}
