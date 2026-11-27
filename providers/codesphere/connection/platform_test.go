// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Synthetic: platform IDs carry the installation host so integer IDs from two
// installations never collide; no live Codesphere account was available.
func TestPlatformIDs(t *testing.T) {
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/codesphere/host/cloud.codesphere.com", InstallationID("cloud.codesphere.com"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/codesphere/host/a.example.com/resource-group/1", ResourceGroupID("a.example.com", 1))
	assert.NotEqual(t, ResourceGroupID("a.example.com", 1), ResourceGroupID("b.example.com", 1))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/codesphere/host/a.example.com/workspace/7", WorkspaceID("a.example.com", 7))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/codesphere/host/a.example.com/organization/org-1", OrganizationID("a.example.com", "org-1"))

	pf := NewWorkspacePlatform("a.example.com", 1, 7)
	assert.Equal(t, PlatformWorkspace, pf.Name)
	assert.Equal(t, "Codesphere Workspace", pf.Title)
	assert.Equal(t, []string{"saas", "codesphere", "a.example.com", "resource-group", "1", "workspace", "7"}, pf.TechnologyUrlSegments)
}
