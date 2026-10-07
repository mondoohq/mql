// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/url"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Discovery targets. The names follow the GitHub provider where one exists.
const (
	// DiscoveryAll expands to every other target.
	DiscoveryAll = "all"
	// DiscoveryAuto emits the organization asset on an organization connection
	// and the repository assets, without any IaC children.
	DiscoveryAuto = "auto"
	// DiscoveryOrganization emits the organization asset.
	DiscoveryOrganization = "organization"
	// DiscoveryRepos emits one asset per repository.
	DiscoveryRepos = "repos"
	// DiscoveryTerraform emits a terraform-hcl-git child for each repository
	// that holds a .tf file.
	DiscoveryTerraform = "terraform"
	// DiscoveryK8sManifests emits a k8s child for each repository that holds a
	// YAML file.
	DiscoveryK8sManifests = "k8s-manifests"
)

// Platform names and the identifier prefixes that make asset ids.
const (
	PlatformOrg  = "azuredevops-org"
	PlatformRepo = "azuredevops-repo"

	identifierPrefix = "//platformid.api.mondoo.app/runtime/azuredevops/organization/"
	// terraformIdentifierPrefix is the id of the terraform-hcl-git child. It
	// is preset because the ssh-url parse returns the organization "v3" for
	// every Azure DevOps remote, so the derived id collides across
	// organizations.
	terraformIdentifierPrefix = "//platformid.api.mondoo.app/runtime/terraform/domain/dev.azure.com/org/"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/azuredevops.json so the CLI and generated docs can list
// what the provider supports, and the runtime builders below read it too.
var Platforms = []*plugin.PlatformInfo{
	{Name: PlatformOrg, Title: "Azure DevOps Organization", Family: []string{"azuredevops"}, Kind: []string{"api"}, Runtime: []string{"azuredevops"}},
	{Name: PlatformRepo, Title: "Azure DevOps Repository", Family: []string{"azuredevops"}, Kind: []string{"api"}, Runtime: []string{"azuredevops"}},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the static descriptor for a platform name, or nil.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}

func newPlatform(name string) *inventory.Platform {
	pf := &inventory.Platform{}
	platformsByName[name].Apply(pf)
	return pf
}

// maxURLSegmentLen is the longest value an asset url segment may have.
const maxURLSegmentLen = 200

// urlSegment fits a name into the alphabet of an asset url value, which is
// letters, digits, space, underscore, dot and hyphen, and into its length cap.
// Anything else becomes an underscore. The segments only group assets for
// browsing. The platform id is what identifies an asset, so two names that
// collapse to the same segment do not merge two assets.
func urlSegment(name string) string {
	var b strings.Builder
	for _, r := range name {
		if b.Len() == maxURLSegmentLen {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == ' ', r == '_', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// NewOrgPlatform is the platform of an organization asset.
//
// The technology url segments carry the names as they are, not percent
// escaped: the asset url validator rejects a percent sign, so unlike the
// platform ids they are never escaped. A character the validator rejects for
// another reason, such as a letter with an accent, becomes an underscore.
func NewOrgPlatform(org string) *inventory.Platform {
	pf := newPlatform(PlatformOrg)
	pf.TechnologyUrlSegments = []string{"saas", "azuredevops", "organization", urlSegment(org), "organization"}
	return pf
}

// NewRepoPlatform is the platform of a repository asset.
func NewRepoPlatform(org, project string) *inventory.Platform {
	pf := newPlatform(PlatformRepo)
	pf.TechnologyUrlSegments = []string{"saas", "azuredevops", "organization", urlSegment(org), "project", urlSegment(project), "repository"}
	return pf
}

// idSegment is one segment of a platform id. Azure DevOps names are
// case-insensitive, so a name typed two ways is one segment; it is escaped
// because project names may hold spaces.
func idSegment(name string) string {
	return url.PathEscape(strings.ToLower(name))
}

// NewOrgIdentifier is the platform id of an organization asset.
func NewOrgIdentifier(org string) string {
	return identifierPrefix + idSegment(org)
}

// NewRepoIdentifier is the platform id of a repository asset. The project is
// part of the id because a repository name is unique only within its project.
// Every segment is lower-cased and escaped. xgrep sends decoded names and never
// builds the id itself, so the server and this provider each mint it, and both
// tests pin the same golden value.
func NewRepoIdentifier(org, project, repo string) string {
	return identifierPrefix + idSegment(org) +
		"/project/" + idSegment(project) +
		"/repository/" + idSegment(repo)
}

// NewTerraformRepoIdentifier is the preset platform id of a repository's
// terraform-hcl-git child.
func NewTerraformRepoIdentifier(org, project, repo string) string {
	return terraformIdentifierPrefix + idSegment(org) +
		"/project/" + idSegment(project) +
		"/repo/" + idSegment(repo)
}
