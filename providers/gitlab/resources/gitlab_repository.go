// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gitlab/connection"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

// This file models what guards a project's repository beyond protected
// branches: every branch (protected or not), the external services a merge
// request has to pass, the snippets stored next to the code, and the
// configuration of a pull mirror. Branch names, status check ids, and snippet
// ids repeat across projects, so every resource here keys on projectScopedID.

// gitlabLargePage is the page size for collections that can run to thousands
// of entries, such as branches and dependencies. 100 is the most GitLab
// returns per page.
const gitlabLargePage = int64(100)

//
// Branches
//

// branches lists every branch of the repository. A repository can carry
// thousands of branches, so this is only read when queried. The commit at the
// tip comes with the listing; per-commit signature lookups are not made.
func (p *mqlGitlabProject) branches() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := p.Id.Data

	all, err := collectPages(func(page int64) ([]*gitlab.Branch, *gitlab.Response, error) {
		return conn.Client().Branches.ListBranches(projectID, &gitlab.ListBranchesOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabLargePage},
		})
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		return []any{}, nil
	}

	res := make([]any, 0, len(all))
	for _, branch := range all {
		if branch == nil {
			continue
		}
		args := map[string]*llx.RawData{
			"__id":               llx.StringData(projectScopedID("gitlab.project.branch", projectID, branch.Name)),
			"name":               llx.StringData(branch.Name),
			"protected":          llx.BoolData(branch.Protected),
			"default":            llx.BoolData(branch.Default),
			"merged":             llx.BoolData(branch.Merged),
			"canPush":            llx.BoolData(branch.CanPush),
			"developersCanPush":  llx.BoolData(branch.DevelopersCanPush),
			"developersCanMerge": llx.BoolData(branch.DevelopersCanMerge),
			"webURL":             llx.StringData(branch.WebURL),
			"lastCommitSha":      llx.NilData,
			"lastCommittedAt":    llx.NilData,
		}
		if branch.Commit != nil {
			args["lastCommitSha"] = llx.StringData(branch.Commit.ID)
			args["lastCommittedAt"] = llx.TimeDataPtr(branch.Commit.CommittedDate)
		}
		mqlBranch, err := CreateResource(p.MqlRuntime, "gitlab.project.branch", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBranch)
	}
	return res, nil
}

//
// External status checks
//

// mqlGitlabProjectExternalStatusCheckInternal keeps the owning project and the
// names of the protected branches the check applies to, which the typed
// accessor resolves against the project's protected branch list.
type mqlGitlabProjectExternalStatusCheckInternal struct {
	project       *mqlGitlabProject
	cacheBranches []string
}

// externalStatusChecks lists the external services a merge request must pass.
// Ultimate only; other tiers answer 404 and read as an empty list.
func (p *mqlGitlabProject) externalStatusChecks() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := p.Id.Data

	all, err := collectPages(func(page int64) ([]*gitlab.ProjectStatusCheck, *gitlab.Response, error) {
		return conn.Client().ExternalStatusChecks.ListProjectExternalStatusChecks(projectID, &gitlab.ListProjectExternalStatusChecksOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		return []any{}, nil
	}

	res := make([]any, 0, len(all))
	for _, check := range all {
		if check == nil {
			continue
		}
		mqlCheck, err := CreateResource(p.MqlRuntime, "gitlab.project.externalStatusCheck", map[string]*llx.RawData{
			"__id":        llx.StringData(projectScopedID("gitlab.project.externalStatusCheck", projectID, strconv.FormatInt(check.ID, 10))),
			"id":          llx.IntData(check.ID),
			"name":        llx.StringData(check.Name),
			"externalUrl": llx.StringData(check.ExternalURL),
			"hmac":        llx.BoolData(check.HMAC),
		})
		if err != nil {
			return nil, err
		}
		internal := mqlCheck.(*mqlGitlabProjectExternalStatusCheck)
		internal.project = p
		internal.cacheBranches = statusCheckBranchNames(check.ProtectedBranches)
		res = append(res, mqlCheck)
	}
	return res, nil
}

// statusCheckBranchNames returns the names of the protected branches a status
// check lists, in order, skipping entries without a name.
func statusCheckBranchNames(branches []gitlab.StatusCheckProtectedBranch) []string {
	names := make([]string, 0, len(branches))
	for _, b := range branches {
		if b.Name != "" {
			names = append(names, b.Name)
		}
	}
	return names
}

// filterByName keeps the resources whose name is in names, in the order of
// resources. name reads a resource's name; resources it cannot read are
// skipped.
func filterByName(resources []any, names []string, name func(any) (string, bool)) []any {
	wanted := make(map[string]struct{}, len(names))
	for _, n := range names {
		wanted[n] = struct{}{}
	}
	out := []any{}
	for _, r := range resources {
		n, ok := name(r)
		if !ok {
			continue
		}
		if _, ok := wanted[n]; ok {
			out = append(out, r)
		}
	}
	return out
}

// protectedBranches resolves the branches the check names through the
// project's protected branch list, which carries their access levels.
func (c *mqlGitlabProjectExternalStatusCheck) protectedBranches() ([]any, error) {
	if len(c.cacheBranches) == 0 || c.project == nil {
		return []any{}, nil
	}
	branches := c.project.GetProtectedBranches()
	if branches.Error != nil {
		return nil, branches.Error
	}
	return filterByName(branches.Data, c.cacheBranches, func(r any) (string, bool) {
		b, ok := r.(*mqlGitlabProjectProtectedBranch)
		if !ok {
			return "", false
		}
		return b.Name.Data, true
	}), nil
}

//
// Snippets
//

type mqlGitlabProjectSnippetInternal struct {
	cacheAuthorID int64
}

// snippets lists the project's snippets. Only their metadata is read, never
// their content.
func (p *mqlGitlabProject) snippets() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := p.Id.Data

	all, err := collectPages(func(page int64) ([]*gitlab.Snippet, *gitlab.Response, error) {
		return conn.Client().ProjectSnippets.ListSnippets(projectID, &gitlab.ListProjectSnippetsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		return []any{}, nil
	}

	res := make([]any, 0, len(all))
	for _, snippet := range all {
		if snippet == nil {
			continue
		}
		mqlSnippet, err := CreateResource(p.MqlRuntime, "gitlab.project.snippet", map[string]*llx.RawData{
			"__id":        llx.StringData(projectScopedID("gitlab.project.snippet", projectID, strconv.FormatInt(snippet.ID, 10))),
			"id":          llx.IntData(snippet.ID),
			"title":       llx.StringData(snippet.Title),
			"fileName":    llx.StringData(snippet.FileName),
			"description": llx.StringData(snippet.Description),
			"visibility":  llx.StringData(snippet.Visibility),
			"webURL":      llx.StringData(snippet.WebURL),
			"createdAt":   llx.TimeDataPtr(snippet.CreatedAt),
			"updatedAt":   llx.TimeDataPtr(snippet.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		mqlSnippet.(*mqlGitlabProjectSnippet).cacheAuthorID = snippet.Author.ID
		res = append(res, mqlSnippet)
	}
	return res, nil
}

func (s *mqlGitlabProjectSnippet) author() (*mqlGitlabUser, error) {
	if s.cacheAuthorID <= 0 {
		s.Author.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(s.MqlRuntime, s.cacheAuthorID)
}

//
// Pull mirror
//

// pullMirror reads the pull mirror configuration. A project that is not a
// mirror has none, so it is null without a request.
func (p *mqlGitlabProject) pullMirror() (*mqlGitlabPullMirror, error) {
	if !p.Mirror.Data {
		p.PullMirror.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	mirror, _, err := conn.Client().Projects.GetProjectPullMirrorDetails(p.Id.Data)
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		p.PullMirror.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if mirror == nil {
		p.PullMirror.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(p.MqlRuntime, "gitlab.pullMirror", map[string]*llx.RawData{
		"__id":                             llx.StringData(projectScopedID("gitlab.pullMirror", p.Id.Data)),
		"id":                               llx.IntData(mirror.ID),
		"enabled":                          llx.BoolData(mirror.Enabled),
		"url":                              llx.StringData(mirror.URL),
		"mirrorTriggerBuilds":              llx.BoolData(mirror.MirrorTriggerBuilds),
		"onlyMirrorProtectedBranches":      llx.BoolData(mirror.OnlyMirrorProtectedBranches),
		"mirrorOverwritesDivergedBranches": llx.BoolData(mirror.MirrorOverwritesDivergedBranches),
		"mirrorBranchRegex":                llx.StringData(mirror.MirrorBranchRegex),
		"updateStatus":                     llx.StringData(mirror.UpdateStatus),
		"lastError":                        llx.StringData(mirror.LastError),
		"lastUpdateAt":                     llx.TimeDataPtr(mirror.LastUpdateAt),
		"lastUpdateStartedAt":              llx.TimeDataPtr(mirror.LastUpdateStartedAt),
		"lastSuccessfulUpdateAt":           llx.TimeDataPtr(mirror.LastSuccessfulUpdateAt),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabPullMirror), nil
}
