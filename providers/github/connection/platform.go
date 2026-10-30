// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	DiscoveryAll            = "all"
	DiscoveryAuto           = "auto"
	DiscoveryRepos          = "repos"
	DiscoveryUsers          = "users"
	DiscoveryOrganization   = "organization"
	DiscoveryTerraform      = "terraform"
	DiscoveryK8sManifests   = "k8s-manifests"
	DiscoveryCloudformation = "cloudformation"
	DiscoveryDockerfiles    = "dockerfiles"
	DiscoveryBicep          = "bicep"
	DiscoveryHelm           = "helm"
	DiscoveryKustomize      = "kustomize"
)

// Platforms is the static catalog of platforms the GitHub provider can emit.
// It is the single source of truth for both the provider config and the
// runtime platform builders (NewGithub*Platform).
var Platforms = []*plugin.PlatformInfo{
	{Name: "github-org", Title: "GitHub Organization", Family: []string{"github"}, Kind: []string{"api"}, Runtime: []string{"github"}},
	{Name: "github-user", Title: "GitHub User", Family: []string{"github"}, Kind: []string{"api"}, Runtime: []string{"github"}},
	{Name: "github-repo", Title: "GitHub Repository", Family: []string{"github"}, Kind: []string{"api"}, Runtime: []string{"github"}},
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

type OrganizationId struct {
	Name string
}

type UserId struct {
	Name string
}

type RepositoryId struct {
	Owner string
	Name  string
}

func (c *GithubConnection) PlatformInfo() (*inventory.Platform, error) {
	conf := c.asset.Connections[0]
	if orgId := conf.Options["organization"]; orgId != "" {
		return NewGithubOrgPlatform(orgId), nil
	}

	if userId := conf.Options["user"]; userId != "" {
		return NewGithubUserPlatform(userId), nil
	}

	if repo := conf.Options["repository"]; repo != "" {
		owner := conf.Options["owner"]
		return NewGitHubRepoPlatform(owner, repo), nil
	}

	return nil, errors.New("could not detect GitHub asset type")
}

func NewGithubOrgPlatform(orgId string) *inventory.Platform {
	pf := newPlatform("github-org")
	pf.TechnologyUrlSegments = []string{"saas", "github", "organization", orgId, "organization"}
	return pf
}

func NewGithubUserPlatform(userId string) *inventory.Platform {
	pf := newPlatform("github-user")
	pf.TechnologyUrlSegments = []string{"saas", "github", "user"}
	return pf
}

func NewGitHubRepoPlatform(owner, repo string) *inventory.Platform {
	pf := newPlatform("github-repo")
	pf.TechnologyUrlSegments = []string{"saas", "github", "organization", owner, "repository"}
	return pf
}

func NewGithubOrgIdentifier(orgId string) string {
	return "//platformid.api.mondoo.app/runtime/github/organization/" + orgId
}

func NewGithubUserIdentifier(userId string) string {
	return "//platformid.api.mondoo.app/runtime/github/user/" + userId
}

func NewGitHubRepoIdentifier(ownerId string, repoId string) string {
	return "//platformid.api.mondoo.app/runtime/github/owner/" + ownerId + "/repository/" + repoId
}

func (c *GithubConnection) Identifier() (string, error) {
	conf := c.asset.Connections[0]
	orgId := conf.Options["organization"]
	if orgId != "" {
		return NewGithubOrgIdentifier(orgId), nil
	}

	userId := conf.Options["user"]
	if userId != "" {
		return NewGithubUserIdentifier(userId), nil
	}

	repoId := conf.Options["repository"]
	if repoId != "" {
		ownerId := conf.Options["owner"]
		if ownerId == "" {
			ownerId = conf.Options["organization"]
		}
		if ownerId == "" {
			ownerId = conf.Options["user"]
		}
		return NewGitHubRepoIdentifier(ownerId, repoId), nil
	}

	return "", errors.New("could not identifier GitHub asset")
}

func (c *GithubConnection) Organization() (*OrganizationId, error) {
	conf := c.asset.Connections[0]
	orgId := conf.Options["organization"]
	if orgId == "" {
		orgId = conf.Options["owner"]
	}
	if orgId != "" {
		return &OrganizationId{Name: orgId}, nil
	}

	return nil, errors.New("no organization provided")
}

func (c *GithubConnection) User() (*UserId, error) {
	conf := c.asset.Connections[0]
	userId := conf.Options["user"]
	if userId == "" {
		userId = conf.Options["owner"]
	}

	if userId != "" {
		return &UserId{Name: userId}, nil
	}
	return nil, errors.New("no user provided")
}

func (c *GithubConnection) Repository() (*RepositoryId, error) {
	conf := c.asset.Connections[0]
	ownerId := conf.Options["owner"]
	if ownerId == "" {
		ownerId = conf.Options["organization"]
	}
	if ownerId == "" {
		ownerId = conf.Options["user"]
	}

	repoId := conf.Options["repository"]
	if ownerId != "" && repoId != "" {
		return &RepositoryId{Owner: ownerId, Name: repoId}, nil
	}
	return nil, errors.New("no repository provided")
}
