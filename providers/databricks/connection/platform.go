// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	DiscoveryAll        = "all"
	DiscoveryAuto       = "auto"
	DiscoveryWorkspaces = "workspaces"
)

var (
	PlatformIdDatabricksAccount   = "//platformid.api.mondoo.app/runtime/databricks/account/"
	PlatformIdDatabricksWorkspace = "//platformid.api.mondoo.app/runtime/databricks/workspace/"
)

// PlatformInfo returns the platform for this connection's asset based on its plane.
func (c *DatabricksConnection) PlatformInfo() (*inventory.Platform, error) {
	switch c.plane {
	case PlaneAccount:
		return NewDatabricksAccountPlatform(c.accountID), nil
	case PlaneWorkspace:
		return NewDatabricksWorkspacePlatform(c.workspaceID), nil
	}
	return nil, errors.New("could not detect Databricks asset type")
}

func NewDatabricksAccountPlatform(accountID string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "databricks", "account", accountID},
	}
	PlatformByName("databricks-account").Apply(pf)
	return pf
}

func NewDatabricksWorkspacePlatform(workspaceID string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "databricks", "workspace", workspaceID},
	}
	PlatformByName("databricks-workspace").Apply(pf)
	return pf
}

func NewDatabricksAccountIdentifier(accountID string) string {
	return PlatformIdDatabricksAccount + accountID
}

func NewDatabricksWorkspaceIdentifier(workspaceID string) string {
	return PlatformIdDatabricksWorkspace + workspaceID
}
