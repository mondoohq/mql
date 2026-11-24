// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/google/go-github/v93/github"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

// Repository security advisories are the maintainer side of the advisory
// database: drafts, published and closed advisories for vulnerabilities in a
// repository's own code. The accounts and teams embedded in an advisory are
// kept on the resource and resolved only when queried, so listing advisories
// costs no user lookups.

type mqlGithubRepositorySecurityAdvisoryInternal struct {
	cacheOrgLogin string
	cacheAdvisory *github.SecurityAdvisory
}

func (g *mqlGithubRepositorySecurityAdvisory) id() (string, error) {
	return g.__id, nil
}

// advisoryCWEIDs returns the CWE IDs of an advisory. The repository advisory
// representation carries them as `cwes` objects, and older responses as the
// flat `cwe_ids` list, so the flat list is the fallback.
func advisoryCWEIDs(a *github.SecurityAdvisory) []any {
	res := []any{}
	for _, c := range a.CWEs {
		if c != nil && c.CWEID != nil {
			res = append(res, *c.CWEID)
		}
	}
	if len(res) > 0 {
		return res
	}
	for _, id := range a.CWEIDs {
		res = append(res, id)
	}
	return res
}

// advisoryCVSS returns the CVSS score and vector, null when the advisory
// carries no CVSS assessment. A score of 0 without a vector is GitHub's
// placeholder for "not scored", which is not a measured score of 0.
func advisoryCVSS(a *github.SecurityAdvisory) (*llx.RawData, *llx.RawData) {
	if a.CVSS == nil || a.CVSS.VectorString == nil || *a.CVSS.VectorString == "" {
		return llx.NilData, llx.NilData
	}
	score := llx.NilData
	if a.CVSS.Score != nil {
		score = llx.FloatData(*a.CVSS.Score)
	}
	return score, llx.StringData(*a.CVSS.VectorString)
}

func advisoriesToMql(runtime *plugin.Runtime, orgLogin string, advisories []*github.SecurityAdvisory) ([]any, error) {
	res := make([]any, 0, len(advisories))
	for _, a := range advisories {
		if a == nil || a.GHSAID == nil {
			continue
		}
		score, vector := advisoryCVSS(a)
		r, err := CreateResource(runtime, "github.repositorySecurityAdvisory", map[string]*llx.RawData{
			"__id":        llx.StringData("github.repositorySecurityAdvisory/" + *a.GHSAID),
			"ghsaId":      llx.StringDataPtr(a.GHSAID),
			"cveId":       llx.StringData(a.GetCVEID()),
			"summary":     llx.StringDataPtr(a.Summary),
			"description": llx.StringDataPtr(a.Description),
			"state":       llx.StringDataPtr(a.State),
			"severity":    llx.StringDataPtr(a.Severity),
			"cvssScore":   score,
			"cvssVector":  vector,
			"cweIds":      llx.ArrayData(advisoryCWEIDs(a), types.String),
			"createdAt":   llx.TimeDataPtr(githubTime(a.CreatedAt)),
			"updatedAt":   llx.TimeDataPtr(githubTime(a.UpdatedAt)),
			"publishedAt": llx.TimeDataPtr(githubTime(a.PublishedAt)),
			"closedAt":    llx.TimeDataPtr(githubTime(a.ClosedAt)),
			"withdrawnAt": llx.TimeDataPtr(githubTime(a.WithdrawnAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlAdvisory := r.(*mqlGithubRepositorySecurityAdvisory)
		mqlAdvisory.cacheOrgLogin = orgLogin
		mqlAdvisory.cacheAdvisory = a
		res = append(res, r)
	}
	return res, nil
}

func listAdvisories(fetch func(opts *github.ListRepositorySecurityAdvisoriesOptions) ([]*github.SecurityAdvisory, *github.Response, error)) ([]*github.SecurityAdvisory, error) {
	return collectCursorPages(func(after string) ([]*github.SecurityAdvisory, *github.Response, error) {
		opts := &github.ListRepositorySecurityAdvisoriesOptions{}
		opts.PerPage = paginationPerPage
		opts.After = after
		return fetch(opts)
	})
}

func (g *mqlGithubOrganization) securityAdvisories() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	all, err := listAdvisories(func(opts *github.ListRepositorySecurityAdvisoriesOptions) ([]*github.SecurityAdvisory, *github.Response, error) {
		return conn.Client().SecurityAdvisories.ListRepositorySecurityAdvisoriesForOrg(conn.Context(), orgLogin, opts)
	})
	if err != nil {
		if err := classifyReadErr(err, "repository security advisories", orgLogin); err != nil {
			return nil, err
		}
		g.SecurityAdvisories.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return advisoriesToMql(g.MqlRuntime, orgLogin, all)
}

func (g *mqlGithubRepository) securityAdvisories() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	owner, repo, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	all, err := listAdvisories(func(opts *github.ListRepositorySecurityAdvisoriesOptions) ([]*github.SecurityAdvisory, *github.Response, error) {
		return conn.Client().SecurityAdvisories.ListRepositorySecurityAdvisories(conn.Context(), owner, repo, opts)
	})
	if err != nil {
		if err := classifyReadErr(err, "repository security advisories", owner+"/"+repo); err != nil {
			return nil, err
		}
		g.SecurityAdvisories.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return advisoriesToMql(g.MqlRuntime, owner, all)
}

func (g *mqlGithubRepositorySecurityAdvisory) author() (*mqlGithubUser, error) {
	return embeddedUser(g.MqlRuntime, g.cacheAdvisory.GetAuthor(), &g.Author)
}

func (g *mqlGithubRepositorySecurityAdvisory) publisher() (*mqlGithubUser, error) {
	return embeddedUser(g.MqlRuntime, g.cacheAdvisory.GetPublisher(), &g.Publisher)
}

func embeddedUser(runtime *plugin.Runtime, user *github.User, field *plugin.TValue[*mqlGithubUser]) (*mqlGithubUser, error) {
	r, err := githubUserRef(runtime, user)
	if err != nil {
		return nil, err
	}
	if r == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.(*mqlGithubUser), nil
}

func (g *mqlGithubRepositorySecurityAdvisory) collaboratingUsers() ([]any, error) {
	res := []any{}
	if g.cacheAdvisory == nil {
		return res, nil
	}
	for _, u := range g.cacheAdvisory.CollaboratingUsers {
		r, err := githubUserRef(g.MqlRuntime, u)
		if err != nil {
			return nil, err
		}
		if r != nil {
			res = append(res, r)
		}
	}
	return res, nil
}

func (g *mqlGithubRepositorySecurityAdvisory) collaboratingTeams() ([]any, error) {
	res := []any{}
	if g.cacheAdvisory == nil || len(g.cacheAdvisory.CollaboratingTeams) == 0 {
		return res, nil
	}
	org := organizationResource(g.MqlRuntime, g.cacheOrgLogin)
	for _, t := range g.cacheAdvisory.CollaboratingTeams {
		if t == nil || t.ID == nil {
			continue
		}
		r, err := newMqlGithubTeam(g.MqlRuntime, t, org, false)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGithubRepositorySecurityAdvisory) privateFork() (*mqlGithubRepository, error) {
	if g.cacheAdvisory == nil || g.cacheAdvisory.PrivateFork == nil || g.cacheAdvisory.PrivateFork.ID == nil {
		g.PrivateFork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlGithubRepository(g.MqlRuntime, g.cacheAdvisory.PrivateFork)
}
