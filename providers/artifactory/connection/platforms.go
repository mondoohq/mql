// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// PlatformIdArtifactory prefixes the identifier of an Artifactory instance
// asset. The suffix is the instance's service identifier, which stays the same
// across restarts and URL changes.
const PlatformIdArtifactory = "//platformid.api.mondoo.app/runtime/artifactory/instance/"

// Platforms is the static catalog of platforms this provider emits.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "artifactory",
		Title:   "JFrog Artifactory",
		Family:  []string{"artifactory"},
		Kind:    []string{"api"},
		Runtime: []string{"artifactory"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}

// NewArtifactoryPlatform describes an Artifactory instance asset.
func NewArtifactoryPlatform(instanceID string, version string) *inventory.Platform {
	pf := &inventory.Platform{
		Version:               version,
		TechnologyUrlSegments: []string{"saas", "artifactory", instanceID},
	}
	PlatformByName("artifactory").Apply(pf)
	return pf
}

// NewArtifactoryIdentifier builds the platform identifier of an instance.
func NewArtifactoryIdentifier(instanceID string) string {
	return PlatformIdArtifactory + instanceID
}
