// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/claude/connection"
)

func TestClaudeAssetIdentity(t *testing.T) {
	tests := []struct {
		name        string
		orgID       string
		orgName     string
		workspaceID string
		host        string

		wantName     string
		wantPlatform string
		wantID       string
	}{
		{
			name:        "workspace scope wins over org",
			orgID:       "org_123",
			orgName:     "Acme",
			workspaceID: "wrkspc_1",
			host:        "https://api.anthropic.com",
			wantName:    "Claude Workspace wrkspc_1",
			// asserts the workspace-id, not the org-id, keys the identifier
			wantPlatform: "claude-workspace",
			wantID:       connection.PlatformIdWorkspace + "wrkspc_1",
		},
		{
			name:        "default workspace falls through to org",
			orgID:       "org_123",
			orgName:     "Acme",
			workspaceID: "default",
			host:        "https://api.anthropic.com",
			// "default" must not mint a workspace-scoped identity
			wantName:     "Claude Organization Acme",
			wantPlatform: "claude-organization",
			wantID:       connection.PlatformIdOrg + "org_123",
		},
		{
			name:         "org without name omits the trailing name",
			orgID:        "org_123",
			workspaceID:  "",
			host:         "https://api.anthropic.com",
			wantName:     "Claude Organization",
			wantPlatform: "claude-organization",
			wantID:       connection.PlatformIdOrg + "org_123",
		},
		{
			name:         "no org falls back to bare host",
			host:         "https://api.anthropic.com",
			wantName:     "Claude (https://api.anthropic.com)",
			wantPlatform: "claude",
			wantID:       "//platformid.api.mondoo.app/runtime/claude/host/https://api.anthropic.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, platform, ids := claudeAssetIdentity(tt.orgID, tt.orgName, tt.workspaceID, tt.host)

			assert.Equal(t, tt.wantName, name)
			require.NotNil(t, platform)
			assert.Equal(t, tt.wantPlatform, platform.Name)
			require.Equal(t, []string{tt.wantID}, ids)
		})
	}
}
