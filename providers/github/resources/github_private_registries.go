// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/google/go-github/v93/github"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
)

// Private registries hold the credentials Dependabot and other GitHub
// features use to reach an organization's package registries. The credential
// value is write-only in the API and is never modelled.

type mqlGithubPrivateRegistryInternal struct {
	cacheOrg *mqlGithubOrganization
}

func (g *mqlGithubPrivateRegistry) id() (string, error) {
	return g.__id, nil
}

func stringTypePtr[T ~string](v *T) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.StringData(string(*v))
}

func privateRegistryArgs(orgLogin string, p *github.PrivateRegistry) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                     llx.StringData("github.privateRegistry/" + orgLogin + "/" + p.GetName()),
		"name":                     llx.StringDataPtr(p.Name),
		"registryType":             stringTypePtr(p.RegistryType),
		"url":                      llx.StringDataPtr(p.URL),
		"authType":                 stringTypePtr(p.AuthType),
		"username":                 llx.StringDataPtr(p.Username),
		"replacesBase":             llx.BoolDataPtr(p.ReplacesBase),
		"visibility":               stringTypePtr(p.Visibility),
		"azureTenantId":            llx.StringDataPtr(p.TenantID),
		"azureClientId":            llx.StringDataPtr(p.ClientID),
		"awsRegion":                llx.StringDataPtr(p.AWSRegion),
		"awsAccountId":             llx.StringDataPtr(p.AccountID),
		"awsRoleName":              llx.StringDataPtr(p.RoleName),
		"codeArtifactDomain":       llx.StringDataPtr(p.Domain),
		"codeArtifactDomainOwner":  llx.StringDataPtr(p.DomainOwner),
		"jfrogOidcProviderName":    llx.StringDataPtr(p.JFrogOIDCProviderName),
		"jfrogIdentityMappingName": llx.StringDataPtr(p.IdentityMappingName),
		"oidcAudience":             llx.StringDataPtr(p.Audience),
		"createdAt":                llx.TimeDataPtr(githubTime(p.CreatedAt)),
		"updatedAt":                llx.TimeDataPtr(githubTime(p.UpdatedAt)),
	}
}

func (g *mqlGithubOrganization) privateRegistries() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.PrivateRegistry, *github.Response, error) {
		page, resp, err := conn.Client().PrivateRegistries.ListOrganizationPrivateRegistries(conn.Context(), orgLogin, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Configurations, resp, nil
	})
	if err != nil {
		if err := classifyReadErr(err, "private registries", orgLogin); err != nil {
			return nil, err
		}
		g.PrivateRegistries.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, p := range all {
		if p == nil || p.Name == nil {
			continue
		}
		r, err := CreateResource(g.MqlRuntime, "github.privateRegistry", privateRegistryArgs(orgLogin, p))
		if err != nil {
			return nil, err
		}
		r.(*mqlGithubPrivateRegistry).cacheOrg = g
		res = append(res, r)
	}
	return res, nil
}

// reposByID picks the repositories with the given ids out of a list of
// github.repository resources, in list order.
func reposByID(repos []any, ids []int64) []any {
	want := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	res := []any{}
	for _, x := range repos {
		repo, ok := x.(*mqlGithubRepository)
		if !ok || repo.Id.Error != nil {
			continue
		}
		if _, ok := want[repo.Id.Data]; ok {
			res = append(res, repo)
		}
	}
	return res
}

// selectedRepositories lists the repositories a registry with "selected"
// visibility is shared with. The listing leaves the selection out, so it is
// read from the registry itself and resolved against the organization's
// repository list, which is read once and shared.
func (g *mqlGithubPrivateRegistry) selectedRepositories() ([]any, error) {
	if g.Visibility.Error != nil {
		return nil, g.Visibility.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	if g.Visibility.Data != string(github.PrivateRegistryVisibilitySelected) || g.cacheOrg == nil {
		g.SelectedRepositories.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	orgLogin := g.cacheOrg.Login.Data

	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	reg, _, err := conn.Client().PrivateRegistries.GetOrganizationPrivateRegistry(conn.Context(), orgLogin, g.Name.Data)
	if err != nil {
		if err := classifyReadErr(err, "private registry", orgLogin); err != nil {
			return nil, err
		}
		g.SelectedRepositories.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if reg == nil || len(reg.SelectedRepositoryIDs) == 0 {
		return []any{}, nil
	}

	repos := g.cacheOrg.GetRepositories()
	if repos.Error != nil {
		return nil, repos.Error
	}
	return reposByID(repos.Data, reg.SelectedRepositoryIDs), nil
}
