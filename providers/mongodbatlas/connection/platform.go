// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	DiscoveryAll      = "all"
	DiscoveryAuto     = "auto"
	DiscoveryProjects = "projects"
)

var (
	PlatformIdMongoDBAtlasOrg     = "//platformid.api.mondoo.app/runtime/mongodbatlas/org/"
	PlatformIdMongoDBAtlasProject = "//platformid.api.mondoo.app/runtime/mongodbatlas/project/"
)

// PlatformInfo returns the platform for this connection's asset based on its plane.
func (c *MongoDBAtlasConnection) PlatformInfo() (*inventory.Platform, error) {
	switch c.plane {
	case PlaneOrg:
		return NewMongoDBAtlasOrgPlatform(c.orgID), nil
	case PlaneProject:
		return NewMongoDBAtlasProjectPlatform(c.projectID), nil
	}
	return nil, errors.New("could not detect MongoDB Atlas asset type")
}

func NewMongoDBAtlasOrgPlatform(orgID string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "mongodbatlas", "org", orgID},
	}
	PlatformByName("mongodbatlas-org").Apply(pf)
	return pf
}

func NewMongoDBAtlasProjectPlatform(projectID string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "mongodbatlas", "project", projectID},
	}
	PlatformByName("mongodbatlas-project").Apply(pf)
	return pf
}

func NewMongoDBAtlasOrgIdentifier(orgID string) string {
	return PlatformIdMongoDBAtlasOrg + orgID
}

func NewMongoDBAtlasProjectIdentifier(projectID string) string {
	return PlatformIdMongoDBAtlasProject + projectID
}
