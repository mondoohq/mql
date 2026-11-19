// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strconv"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	DiscoveryAll            = "all"
	DiscoveryAuto           = "auto"
	DiscoveryOrganizations  = "organizations"
	DiscoveryResourceGroups = "resource-groups"
	DiscoveryWorkspaces     = "workspaces"
)

const (
	PlatformInstallation  = "codesphere-installation"
	PlatformOrganization  = "codesphere-organization"
	PlatformResourceGroup = "codesphere-resource-group"
	PlatformWorkspace     = "codesphere-workspace"
)

// Platforms is the static catalog of platforms this provider emits.
var Platforms = []*plugin.PlatformInfo{
	{Name: PlatformInstallation, Title: "Codesphere Installation", Family: []string{"codesphere"}, Kind: []string{"api"}, Runtime: []string{"codesphere"}},
	{Name: PlatformOrganization, Title: "Codesphere Organization", Family: []string{"codesphere"}, Kind: []string{"api"}, Runtime: []string{"codesphere"}},
	{Name: PlatformResourceGroup, Title: "Codesphere Resource Group", Family: []string{"codesphere"}, Kind: []string{"api"}, Runtime: []string{"codesphere"}},
	{Name: PlatformWorkspace, Title: "Codesphere Workspace", Family: []string{"codesphere"}, Kind: []string{"api"}, Runtime: []string{"codesphere"}},
}

var platformsByName = plugin.PlatformsByName(Platforms)

const platformIDPrefix = "//platformid.api.mondoo.app/runtime/codesphere/host/"

// Integer IDs are only unique within one installation, so every identifier
// starts with the installation's API host.

func InstallationID(host string) string {
	return platformIDPrefix + host
}

func OrganizationID(host, orgID string) string {
	return InstallationID(host) + "/organization/" + orgID
}

// ResourceGroupID and WorkspaceID are not nested under the organization: a
// resource group without one can be moved into an organization later, and
// its identity must not change when it does.
func ResourceGroupID(host string, id int) string {
	return InstallationID(host) + "/resource-group/" + strconv.Itoa(id)
}

func WorkspaceID(host string, id int) string {
	return InstallationID(host) + "/workspace/" + strconv.Itoa(id)
}

func newPlatform(name string, segments ...string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: append([]string{"saas", "codesphere"}, segments...),
	}
	platformsByName[name].Apply(pf)
	return pf
}

func NewInstallationPlatform(host string) *inventory.Platform {
	return newPlatform(PlatformInstallation, host)
}

func NewOrganizationPlatform(host, orgID string) *inventory.Platform {
	return newPlatform(PlatformOrganization, host, "organization", orgID)
}

func NewResourceGroupPlatform(host string, id int) *inventory.Platform {
	return newPlatform(PlatformResourceGroup, host, "resource-group", strconv.Itoa(id))
}

func NewWorkspacePlatform(host string, rgID, wsID int) *inventory.Platform {
	return newPlatform(PlatformWorkspace, host, "resource-group", strconv.Itoa(rgID), "workspace", strconv.Itoa(wsID))
}
