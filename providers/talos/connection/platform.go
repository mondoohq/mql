// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/talos.json so the CLI and generated docs can list what
// the provider supports.
//
// The name is the os provider's, which detects Talos in an image or on a disk
// from /etc/os-release. The runtime tells the two apart: only an asset reached
// through the Talos API has the runtime talos, and only such an asset has the
// talos resources.
var Platforms = []*plugin.PlatformInfo{
	{Name: "talos", Title: "Talos Linux", Family: []string{"talos"}, Kind: []string{"api"}, Runtime: []string{"talos"}},
}

var platformIdTalosNode = "//platformid.api.mondoo.app/runtime/talos/node/"

// NewTalosNodePlatform returns the platform of a Talos node. The version is
// the release tag without its "v", as the os provider reports it.
func NewTalosNodePlatform(nodeID, tag, arch string) *inventory.Platform {
	return &inventory.Platform{
		Name:                  "talos",
		Title:                 "Talos Linux",
		Family:                []string{"talos"},
		Kind:                  "api",
		Runtime:               "talos",
		Version:               strings.TrimPrefix(tag, "v"),
		Arch:                  arch,
		TechnologyUrlSegments: []string{"os", "talos", "node", nodeID},
	}
}

// NewTalosNodeIdentifier returns the stable platform id of a node.
func NewTalosNodeIdentifier(nodeID string) string {
	return platformIdTalosNode + nodeID
}
