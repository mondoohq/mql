// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// Scope identifies which kind of HCP asset a connection targets. The root
// connection is an organization; discovery clones it into project- and
// resource-scoped children.
const (
	ScopeOrg                 = "org"
	ScopeProject             = "project"
	ScopeVaultCluster        = "vault-cluster"
	ScopeConsulCluster       = "consul-cluster"
	ScopeBoundaryCluster     = "boundary-cluster"
	ScopePackerRegistry      = "packer-registry"
	ScopeWaypointApplication = "waypoint-application"
)

const platformIDPrefix = "//platformid.api.mondoo.app/runtime/hcp/"

// scopePlatform maps a scope to its platform catalog name.
var scopePlatform = map[string]string{
	ScopeOrg:                 "hcp-organization",
	ScopeProject:             "hcp-project",
	ScopeVaultCluster:        "hcp-vault-cluster",
	ScopeConsulCluster:       "hcp-consul-cluster",
	ScopeBoundaryCluster:     "hcp-boundary-cluster",
	ScopePackerRegistry:      "hcp-packer-registry",
	ScopeWaypointApplication: "hcp-waypoint-application",
}

// NewPlatform builds the platform for a scoped asset. The id segments uniquely
// identify the asset within its scope (for example the project id and cluster
// id for a cluster). They also feed the technology URL tree that groups assets
// in the console.
func NewPlatform(scope string, idSegments ...string) *inventory.Platform {
	name := scopePlatform[scope]
	pf := &inventory.Platform{
		TechnologyUrlSegments: append([]string{"saas", "hcp", scope}, idSegments...),
	}
	if entry := PlatformByName(name); entry != nil {
		entry.Apply(pf)
	}
	return pf
}

// NewPlatformID builds the stable platform id for a scoped asset by joining the
// scope and its identifying segments under the HCP runtime prefix.
func NewPlatformID(scope string, idSegments ...string) string {
	var id strings.Builder
	id.WriteString(platformIDPrefix + scope)
	for _, seg := range idSegments {
		id.WriteString("/" + seg)
	}
	return id.String()
}

// PlatformInfo returns the platform for this connection's own asset based on
// its scope and the ids it carries.
func (c *HcpConnection) PlatformInfo() (*inventory.Platform, error) {
	switch c.scope {
	case ScopeOrg:
		return NewPlatform(ScopeOrg, c.orgID), nil
	case ScopeProject:
		return NewPlatform(ScopeProject, c.projectID), nil
	case ScopeVaultCluster, ScopeConsulCluster, ScopeBoundaryCluster, ScopeWaypointApplication:
		return NewPlatform(c.scope, c.projectID, c.resourceID), nil
	case ScopePackerRegistry:
		return NewPlatform(ScopePackerRegistry, c.projectID), nil
	}
	return nil, fmt.Errorf("unknown HCP asset scope %q", c.scope)
}
