// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestNewGithubOrgPlatform(t *testing.T) {
	pf := NewGithubOrgPlatform("mondoohq")
	assert.NotNil(t, pf)
	assert.Equal(t, "github-org", pf.Name)
	assert.Equal(t, "GitHub Organization", pf.Title)
	assert.Equal(t, "api", pf.Kind)
	assert.Equal(t, "github", pf.Runtime)
	assert.Equal(t, []string{"github"}, pf.Family)
	assert.Equal(t, []string{"saas", "github", "organization", "mondoohq", "organization"}, pf.TechnologyUrlSegments)
}

func TestNewGithubUserPlatform(t *testing.T) {
	pf := NewGithubUserPlatform("octocat")
	assert.NotNil(t, pf)
	assert.Equal(t, "github-user", pf.Name)
	assert.Equal(t, "api", pf.Kind)
	assert.Equal(t, []string{"saas", "github", "user"}, pf.TechnologyUrlSegments)
}

func TestNewGitHubRepoPlatform(t *testing.T) {
	pf := NewGitHubRepoPlatform("mondoohq", "cnquery")
	assert.NotNil(t, pf)
	assert.Equal(t, "github-repo", pf.Name)
	assert.Equal(t, "api", pf.Kind)
	assert.Equal(t, []string{"saas", "github", "organization", "mondoohq", "repository"}, pf.TechnologyUrlSegments)
}

func TestNewGithubOrgIdentifier(t *testing.T) {
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/github/organization/mondoohq",
		NewGithubOrgIdentifier("mondoohq"),
	)
}

func TestNewGithubUserIdentifier(t *testing.T) {
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/github/user/octocat",
		NewGithubUserIdentifier("octocat"),
	)
}

func TestNewGitHubRepoIdentifier(t *testing.T) {
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/github/owner/mondoohq/repository/cnquery",
		NewGitHubRepoIdentifier("mondoohq", "cnquery"),
	)
}

func TestHostIdentifiers(t *testing.T) {
	tests := []struct {
		name          string
		enterpriseURL string
		org           string
		user          string
		repo          string
	}{
		{
			name:          "github.com without an enterprise url",
			enterpriseURL: "",
			org:           "//platformid.api.mondoo.app/runtime/github/organization/acme",
			user:          "//platformid.api.mondoo.app/runtime/github/user/octocat",
			repo:          "//platformid.api.mondoo.app/runtime/github/owner/acme/repository/app",
		},
		{
			name:          "github.com as the enterprise url",
			enterpriseURL: "https://github.com",
			org:           "//platformid.api.mondoo.app/runtime/github/organization/acme",
			user:          "//platformid.api.mondoo.app/runtime/github/user/octocat",
			repo:          "//platformid.api.mondoo.app/runtime/github/owner/acme/repository/app",
		},
		{
			name:          "enterprise cloud with data residency",
			enterpriseURL: "https://acme.ghe.com",
			org:           "//platformid.api.mondoo.app/runtime/github/host/acme.ghe.com/organization/acme",
			user:          "//platformid.api.mondoo.app/runtime/github/host/acme.ghe.com/user/octocat",
			repo:          "//platformid.api.mondoo.app/runtime/github/host/acme.ghe.com/owner/acme/repository/app",
		},
		{
			name:          "api host and api path give the web host",
			enterpriseURL: "https://api.acme.ghe.com/api/v3/",
			org:           "//platformid.api.mondoo.app/runtime/github/host/acme.ghe.com/organization/acme",
			user:          "//platformid.api.mondoo.app/runtime/github/host/acme.ghe.com/user/octocat",
			repo:          "//platformid.api.mondoo.app/runtime/github/host/acme.ghe.com/owner/acme/repository/app",
		},
		{
			name:          "upper-case host",
			enterpriseURL: "https://ACME.GHE.com/",
			org:           "//platformid.api.mondoo.app/runtime/github/host/acme.ghe.com/organization/acme",
			user:          "//platformid.api.mondoo.app/runtime/github/host/acme.ghe.com/user/octocat",
			repo:          "//platformid.api.mondoo.app/runtime/github/host/acme.ghe.com/owner/acme/repository/app",
		},
		{
			name:          "enterprise server on a custom domain",
			enterpriseURL: "https://github.example.com",
			org:           "//platformid.api.mondoo.app/runtime/github/organization/acme",
			user:          "//platformid.api.mondoo.app/runtime/github/user/octocat",
			repo:          "//platformid.api.mondoo.app/runtime/github/owner/acme/repository/app",
		},
		{
			name:          "enterprise server with a port",
			enterpriseURL: "https://github.example.com:8443",
			org:           "//platformid.api.mondoo.app/runtime/github/organization/acme",
			user:          "//platformid.api.mondoo.app/runtime/github/user/octocat",
			repo:          "//platformid.api.mondoo.app/runtime/github/owner/acme/repository/app",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := NewGithubConnection(1, &inventory.Asset{
				Connections: []*inventory.Config{{
					Options: map[string]string{
						OPTION_TOKEN:          "token",
						OPTION_ENTERPRISE_URL: tt.enterpriseURL,
					},
				}},
			})
			require.NoError(t, err)
			assert.Equal(t, tt.org, conn.OrgIdentifier("acme"))
			assert.Equal(t, tt.user, conn.UserIdentifier("octocat"))
			assert.Equal(t, tt.repo, conn.RepoIdentifier("acme", "app"))
		})
	}
}
