// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

type saField int

const (
	saAdvancedSecurity saField = iota
	saSecretScanning
	saSecretScanningPushProtection
	saDependabotSecurityUpdates
	saSecretScanningValidityChecks
	saCodeSecurity
)

func saEnabled(sa *github.SecurityAndAnalysis, field saField) bool {
	if sa == nil {
		return false
	}
	switch field {
	case saAdvancedSecurity:
		if sa.AdvancedSecurity != nil {
			return sa.AdvancedSecurity.GetStatus() == "enabled"
		}
	case saSecretScanning:
		if sa.SecretScanning != nil {
			return sa.SecretScanning.GetStatus() == "enabled"
		}
	case saSecretScanningPushProtection:
		if sa.SecretScanningPushProtection != nil {
			return sa.SecretScanningPushProtection.GetStatus() == "enabled"
		}
	case saDependabotSecurityUpdates:
		if sa.DependabotSecurityUpdates != nil {
			return sa.DependabotSecurityUpdates.GetStatus() == "enabled"
		}
	case saSecretScanningValidityChecks:
		if sa.SecretScanningValidityChecks != nil {
			return sa.SecretScanningValidityChecks.GetStatus() == "enabled"
		}
	case saCodeSecurity:
		if sa.CodeSecurity != nil {
			return sa.CodeSecurity.GetStatus() == "enabled"
		}
	}
	return false
}

func newMqlGithubRepository(runtime *plugin.Runtime, repo *github.Repository) (*mqlGithubRepository, error) {
	var id int64
	if repo.ID != nil {
		id = *repo.ID
	}

	// repo.Owner can be nil on fork entries and some list responses. Skip the
	// owner resource in that case rather than constructing a degenerate
	// `github.user/0` that every nil-owner repo would share.
	ownerData := llx.NilData
	if repo.Owner != nil && repo.GetOwner().GetLogin() != "" {
		owner, err := NewResource(runtime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntData(repo.GetOwner().GetID()),
			"login": llx.StringData(repo.GetOwner().GetLogin()),
		})
		if err != nil {
			return nil, err
		}
		ownerData = llx.ResourceData(owner, "github.user")
	}

	res, err := CreateResource(runtime, "github.repository", map[string]*llx.RawData{
		"id":                                  llx.IntData(id),
		"name":                                llx.StringDataPtr(repo.Name),
		"fullName":                            llx.StringDataPtr(repo.FullName),
		"description":                         llx.StringDataPtr(repo.Description),
		"homepage":                            llx.StringDataPtr(repo.Homepage),
		"topics":                              llx.ArrayData(convert.SliceAnyToInterface[string](repo.Topics), types.String),
		"language":                            llx.StringData(repo.GetLanguage()),
		"createdAt":                           llx.TimeDataPtr(githubTimestamp(repo.CreatedAt)),
		"updatedAt":                           llx.TimeDataPtr(githubTimestamp(repo.UpdatedAt)),
		"pushedAt":                            llx.TimeDataPtr(githubTimestamp(repo.PushedAt)),
		"archived":                            llx.BoolDataPtr(repo.Archived),
		"disabled":                            llx.BoolDataPtr(repo.Disabled),
		"private":                             llx.BoolDataPtr(repo.Private),
		"isFork":                              llx.BoolDataPtr(repo.Fork),
		"watchersCount":                       llx.IntData(int64(repo.GetWatchersCount())),
		"forksCount":                          llx.IntData(int64(repo.GetForksCount())),
		"openIssuesCount":                     llx.IntData(int64(repo.GetOpenIssues())),
		"stargazersCount":                     llx.IntData(int64(repo.GetStargazersCount())),
		"visibility":                          llx.StringDataPtr(repo.Visibility),
		"allowAutoMerge":                      llx.BoolDataPtr(repo.AllowAutoMerge),
		"allowForking":                        llx.BoolDataPtr(repo.AllowForking),
		"allowMergeCommit":                    llx.BoolDataPtr(repo.AllowMergeCommit),
		"allowRebaseMerge":                    llx.BoolDataPtr(repo.AllowRebaseMerge),
		"allowSquashMerge":                    llx.BoolDataPtr(repo.AllowSquashMerge),
		"hasIssues":                           llx.BoolData(repo.GetHasIssues()),
		"hasProjects":                         llx.BoolData(repo.GetHasProjects()),
		"hasWiki":                             llx.BoolData(repo.GetHasWiki()),
		"hasPages":                            llx.BoolData(repo.GetHasPages()),
		"hasDownloads":                        llx.BoolData(repo.GetHasDownloads()),
		"hasDiscussions":                      llx.BoolData(repo.GetHasDiscussions()),
		"hasPullRequests":                     llx.BoolData(repo.GetHasPullRequests()),
		"pullRequestCreationPolicy":           llx.StringDataPtr(repo.PullRequestCreationPolicy),
		"isTemplate":                          llx.BoolData(repo.GetIsTemplate()),
		"defaultBranchName":                   llx.StringDataPtr(repo.DefaultBranch),
		"cloneUrl":                            llx.StringData(repo.GetCloneURL()),
		"sshUrl":                              llx.StringData(repo.GetSSHURL()),
		"owner":                               ownerData,
		"customProperties":                    llx.DictData(repo.CustomProperties),
		"webCommitSignoffRequired":            llx.BoolDataPtr(repo.WebCommitSignoffRequired),
		"advancedSecurityEnabled":             llx.BoolData(saEnabled(repo.SecurityAndAnalysis, saAdvancedSecurity)),
		"secretScanningEnabled":               llx.BoolData(saEnabled(repo.SecurityAndAnalysis, saSecretScanning)),
		"secretScanningPushProtectionEnabled": llx.BoolData(saEnabled(repo.SecurityAndAnalysis, saSecretScanningPushProtection)),
		"dependabotSecurityUpdatesEnabled":    llx.BoolData(saEnabled(repo.SecurityAndAnalysis, saDependabotSecurityUpdates)),
		"secretScanningValidityChecksEnabled": llx.BoolData(saEnabled(repo.SecurityAndAnalysis, saSecretScanningValidityChecks)),
		"codeSecurityEnabled":                 llx.BoolData(saEnabled(repo.SecurityAndAnalysis, saCodeSecurity)),
	})
	if err != nil {
		return nil, err
	}
	r := res.(*mqlGithubRepository)
	r.mqlGithubRepositoryInternal.findSpecialFilesOnceFunc = sync.OnceValue[error](r.findSpecialFiles)

	// Every repository record already carries its license, so set the field
	// here and the resolver never runs -- it was costing one
	// Repositories.License call per repository for data that arrived with the
	// repository itself.
	//
	// Null included, which is what makes this worth doing: a repository with no
	// license is the common case, and leaving those unset would still spend a
	// call each to learn nothing. Every endpoint feeding this returns one of
	// GitHub's repository representations, and repository, full-repository and
	// minimal-repository all define license as present-but-nullable, so a nil
	// here means the repository has no license rather than that the listing
	// omitted it.
	//
	// First writer wins: CreateResource hands back the already-cached instance
	// for a repository some other listing has built, and a second record must
	// not overwrite what the first one recorded.
	if !r.License.IsSet() {
		if repo.License == nil {
			r.License = plugin.TValue[*mqlGithubLicense]{State: plugin.StateIsSet | plugin.StateIsNull}
		} else {
			license, err := newMqlGithubLicense(runtime, repo.License)
			if err != nil {
				return nil, err
			}
			r.License = plugin.TValue[*mqlGithubLicense]{Data: license, State: plugin.StateIsSet}
		}
	}
	return r, nil
}

func (g *mqlGithubBranchprotection) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return g.Id.Data, nil
}

func (g *mqlGithubBranch) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	branchName := g.Name.Data
	if g.RepoName.Error != nil {
		return "", g.RepoName.Error
	}
	repoName := g.RepoName.Data
	return repoName + "/" + branchName, nil
}

func (g *mqlGithubCommit) id() (string, error) {
	// the url is unique, e.g. "https://api.github.com/repos/vjeffrey/victoria-website/git/commits/7730d2707fdb6422f335fddc944ab169d45f3aa5"
	if g.Url.Error != nil {
		return "", g.Url.Error
	}
	return g.Url.Data, nil
}

func (g *mqlGithubReview) id() (string, error) {
	if g.Url.Error != nil {
		return "", g.Url.Error
	}
	return g.Url.Data, nil
}

func (g *mqlGithubRelease) id() (string, error) {
	if g.Url.Error != nil {
		return "", g.Url.Error
	}
	return g.Url.Data, nil
}

func (g *mqlGithubRepository) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return strconv.FormatInt(id, 10), nil
}

func initGithubRepository(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	defer logger.FuncDur(time.Now(), "provider.github.initGithubRepository")

	conn := runtime.Connection.(*connection.GithubConnection)

	// determine the owner object
	var org *mqlGithubOrganization
	var user *mqlGithubUser
	var err error
	owner := ""
	orgId, err := conn.Organization()
	if err == nil {
		obj, err := NewResource(runtime, "github.organization", map[string]*llx.RawData{
			"login": llx.StringData(orgId.Name),
		})
		if err != nil {
			// If the owner isn't an org, we try to find a user
			if strings.Contains(err.Error(), "404") {
				userId, err := conn.User()
				if err != nil {
					return nil, nil, err
				}
				// NewResource so the user's init runs and fills in the id;
				// CreateResource would cache a bare resource under the
				// degenerate key "github.user/0" and shadow the real user for
				// the rest of the scan.
				obj, err = NewResource(runtime, "github.user", map[string]*llx.RawData{
					"login": llx.StringData(userId.Name),
				})
				if err != nil {
					// If a user doesn't exist either, then we error out
					return nil, nil, err
				}
				user = obj.(*mqlGithubUser)
				owner = userId.Name
			}
		} else {
			org = obj.(*mqlGithubOrganization)
			owner = orgId.Name
		}
	} else if userId, uerr := conn.User(); uerr == nil {
		// User-scoped connections (e.g. repo assets discovered from a
		// personal-account scan) carry only the user option — there is no
		// organization/owner to try first.
		obj, err := CreateResource(runtime, "github.user", map[string]*llx.RawData{
			"login": llx.StringData(userId.Name),
		})
		if err != nil {
			return nil, nil, err
		}
		user = obj.(*mqlGithubUser)
		owner = userId.Name
	}

	// gather the repo name or fallback to the repo name defined in the connection
	reponame := ""
	if x, ok := args["name"]; ok {
		reponame = x.Value.(string)
	} else {
		repo, err := conn.Repository()
		if err != nil {
			return nil, nil, err
		}
		reponame = repo.Name
	}

	if reponame == "" {
		return nil, nil, errors.New("name must be set for github.repository initialization")
	}

	if org != nil {
		// to avoid loading a large list of repos, we first check if the repositories is in the cached map
		repo, ok := org.repoCacheMap[reponame]
		if ok {
			return args, repo, nil
		}
	} else if user != nil {
		// to avoid loading a large list of repos, we first check if the repositories is in the cached map
		repo, ok := user.repoCacheMap[reponame]
		if ok {
			return args, repo, nil
		}
	} else {
		return nil, nil, errors.New("no user and no org specified")
	}

	// if the repo is not cached, we fetch it from the github api
	if owner != "" {
		// we reach this point if the repo was not cached. Use the resolved
		// owner rather than the organization name: when the organization
		// lookup fell through to the user path, the org name is not the
		// account that holds the repository.
		ghRepo, _, err := conn.Client().Repositories.Get(conn.Context(), owner, reponame)
		if err != nil {
			return nil, nil, err
		}
		r, err := newMqlGithubRepository(runtime, ghRepo)
		if err != nil {
			return nil, nil, err
		}
		return args, r, nil
	}

	return args, nil, fmt.Errorf("could not find repository %q. Make sure the repository exists and the token has sufficient permissions to access it", reponame)
}

func (g *mqlGithubLicense) id() (string, error) {
	if g.SpdxId.Error != nil {
		return "", g.SpdxId.Error
	}
	id := g.SpdxId.Data
	return "github.license/" + id, nil
}

func (g *mqlGithubRepository) license() (*mqlGithubLicense, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	repoLicense, _, err := conn.Client().Repositories.License(conn.Context(), ownerLogin, repoName)
	if err != nil {
		// A repository without a LICENSE file returns 404; that is a valid
		// empty state, not an error.
		if strings.Contains(err.Error(), "404") {
			g.License.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	if repoLicense == nil || repoLicense.License == nil {
		g.License.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	return newMqlGithubLicense(g.MqlRuntime, repoLicense.License)
}

func newMqlGithubLicense(runtime *plugin.Runtime, license *github.License) (*mqlGithubLicense, error) {
	res, err := CreateResource(runtime, "github.license", map[string]*llx.RawData{
		"key":    llx.StringData(license.GetKey()),
		"name":   llx.StringData(license.GetName()),
		"url":    llx.StringData(license.GetURL()),
		"spdxId": llx.StringData(license.GetSPDXID()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubLicense), nil
}

// pullRequestStackFields maps a pull request's stacked-pull-request membership.
//
// Every field stays null when the pull request is not part of a stack, and the
// base fields stay null independently of the counters. Reporting zeros instead
// would read as a real stack of size 0 at position 0 to any policy comparing
// the numbers, which is worse than reporting nothing.
func pullRequestStackFields(pr *github.PullRequest) map[string]*llx.RawData {
	fields := map[string]*llx.RawData{
		"stackId":         llx.NilData,
		"stackNumber":     llx.NilData,
		"stackSize":       llx.NilData,
		"stackPosition":   llx.NilData,
		"stackBaseBranch": llx.NilData,
		"stackBaseSha":    llx.NilData,
	}

	stack := pr.GetStack()
	if stack == nil {
		return fields
	}

	fields["stackId"] = llx.IntDataPtr(stack.ID)
	fields["stackNumber"] = llx.IntDataPtr(stack.Number)
	fields["stackSize"] = llx.IntDataPtr(stack.Size)
	fields["stackPosition"] = llx.IntDataPtr(stack.Position)

	if base := stack.Base; base != nil {
		fields["stackBaseBranch"] = llx.StringData(base.Ref)
		fields["stackBaseSha"] = llx.StringData(base.SHA)
	}

	return fields
}

func (g *mqlGithubRepository) getMergeRequests(state string) ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.PullRequestListOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
		State:       state,
	}
	var allPulls []*github.PullRequest
	for {
		pulls, resp, err := conn.Client().PullRequests.List(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allPulls = append(allPulls, pulls...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allPulls {
		pr := allPulls[i]

		labels, err := convert.JsonToDictSlice(pr.Labels)
		if err != nil {
			return nil, err
		}
		ownerData := llx.NilData
		if pr.User != nil {
			ownerRes, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(pr.User.ID),
				"login": llx.StringDataPtr(pr.User.Login),
			})
			if err != nil {
				return nil, err
			}
			ownerData = llx.ResourceData(ownerRes, "github.user")
		}

		assigneesRes := []any{}
		for i := range pr.Assignees {
			assignee, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(pr.Assignees[i].ID),
				"login": llx.StringDataPtr(pr.Assignees[i].Login),
			})
			if err != nil {
				return nil, err
			}
			assigneesRes = append(assigneesRes, assignee)
		}

		var milestone plugin.Resource
		if pr.Milestone != nil {
			m, err := newMqlGithubMilestone(g.MqlRuntime, pr.Milestone)
			if err != nil {
				return nil, err
			}
			milestone = m
		}

		requestedReviewers := make([]any, 0, len(pr.RequestedReviewers))
		for _, reviewer := range pr.RequestedReviewers {
			r, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(reviewer.ID),
				"login": llx.StringDataPtr(reviewer.Login),
			})
			if err != nil {
				return nil, err
			}
			requestedReviewers = append(requestedReviewers, r)
		}

		var mergedBy any
		if pr.MergedBy != nil {
			r, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(pr.MergedBy.ID),
				"login": llx.StringDataPtr(pr.MergedBy.Login),
			})
			if err != nil {
				return nil, err
			}
			mergedBy = r
		}

		args := map[string]*llx.RawData{
			"id":                 llx.IntDataPtr(pr.ID),
			"repoOwnerLogin":     llx.StringData(ownerLogin),
			"number":             llx.IntData(int64(pr.GetNumber())),
			"state":              llx.StringDataPtr(pr.State),
			"labels":             llx.ArrayData(labels, types.Any),
			"createdAt":          llx.TimeDataPtr(githubTimestamp(pr.CreatedAt)),
			"updatedAt":          llx.TimeDataPtr(githubTimestamp(pr.UpdatedAt)),
			"closedAt":           llx.TimeDataPtr(githubTimestamp(pr.ClosedAt)),
			"title":              llx.StringDataPtr(pr.Title),
			"owner":              ownerData,
			"assignees":          llx.ArrayData(assigneesRes, types.Any),
			"requestedReviewers": llx.ArrayData(requestedReviewers, types.Resource("github.user")),
			"repoName":           llx.StringData(repoName),
			"milestone":          llx.ResourceData(milestone, "github.milestone"),
			"merged":             llx.BoolDataPtr(pr.Merged),
			"mergedAt":           llx.TimeDataPtr(githubTimestamp(pr.MergedAt)),
			"mergedBy":           llx.AnyData(mergedBy),
		}
		maps.Copy(args, pullRequestStackFields(pr))

		r, err := CreateResource(g.MqlRuntime, "github.mergeRequest", args)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}

func (g *mqlGithubRepository) allMergeRequests() ([]any, error) {
	res, err := g.getMergeRequests("all")
	if err != nil {
		return nil, err
	}
	return res, err
}

func (g *mqlGithubRepository) closedMergeRequests() ([]any, error) {
	res, err := g.getMergeRequests("closed")
	if err != nil {
		return nil, err
	}
	return res, err
}

func (g *mqlGithubRepository) openMergeRequests() ([]any, error) {
	res, err := g.getMergeRequests("open")
	if err != nil {
		return nil, err
	}
	return res, err
}

func (g *mqlGithubMergeRequest) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return strconv.FormatInt(id, 10), nil
}

func (g *mqlGithubRepository) branches() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}
	owner, err := repoOwner(g)
	if err != nil {
		return nil, err
	}

	if g.DefaultBranchName.Error != nil {
		return nil, g.DefaultBranchName.Error
	}
	repoDefaultBranchName := g.DefaultBranchName.Data

	listOpts := &github.BranchListOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var allBranches []*github.Branch
	for {
		branches, resp, err := conn.Client().Repositories.ListBranches(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allBranches = append(allBranches, branches...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}
	res := []any{}
	for i := range allBranches {
		branch := allBranches[i]

		defaultBranch := false
		if repoDefaultBranchName == branch.GetName() {
			defaultBranch = true
		}

		mqlBranch, err := newMqlBranch(g.MqlRuntime, branch, owner, ownerLogin, repoName, defaultBranch)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBranch)
	}
	return res, nil
}

// branchID keys a branch by owner as well as repository. Repository names are
// only unique within an owner, and forks keep the name of the repository they
// were forked from, so an owner-less key aliased branches across forks.
func branchID(ownerLogin, repoName, branchName string) string {
	return "github.branch/" + ownerLogin + "/" + repoName + "/" + branchName
}

func newMqlBranch(runtime *plugin.Runtime, branch *github.Branch, owner *mqlGithubUser, ownerLogin string, repoName string, defaultBranch bool) (*mqlGithubBranch, error) {
	mqlBranch, err := CreateResource(runtime, "github.branch", map[string]*llx.RawData{
		"__id":          llx.StringData(branchID(ownerLogin, repoName, branch.GetName())),
		"name":          llx.StringData(branch.GetName()),
		"isProtected":   llx.BoolData(branch.GetProtected()),
		"headCommitSha": llx.StringData(branch.GetCommit().GetSHA()),
		"repoName":      llx.StringData(repoName),
		"owner":         llx.ResourceData(owner, owner.MqlName()),
		"isDefault":     llx.BoolData(defaultBranch),
	})
	if err != nil {
		return nil, err
	}
	return mqlBranch.(*mqlGithubBranch), nil
}

func (g *mqlGithubRepository) defaultBranch() (*mqlGithubBranch, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}
	owner, err := repoOwner(g)
	if err != nil {
		return nil, err
	}

	if g.DefaultBranchName.Error != nil {
		return nil, g.DefaultBranchName.Error
	}
	repoDefaultBranchName := g.DefaultBranchName.Data

	branch, _, err := conn.Client().Repositories.GetBranch(conn.Context(), ownerLogin, repoName, repoDefaultBranchName, 3)
	if err != nil {
		// An empty repository (or one without the named default branch) returns
		// 404; that is a valid empty state, not an error.
		if strings.Contains(err.Error(), "404") {
			g.DefaultBranch.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	return newMqlBranch(g.MqlRuntime, branch, owner, ownerLogin, repoName, true)
}

type githubDismissalRestrictions struct {
	Users []string `json:"users"`
	Teams []string `json:"teams"`
}

type githubBypassAllowances struct {
	Users []string `json:"users"`
	Teams []string `json:"teams"`
	Apps  []string `json:"apps"`
}

type githubRequiredPullRequestReviews struct {
	DismissalRestrictions        *githubDismissalRestrictions `json:"dismissalRestrictions"`
	DismissStaleReviews          bool                         `json:"dismissStaleReviews"`
	RequireCodeOwnerReviews      bool                         `json:"requireCodeOwnerReviews"`
	RequiredApprovingReviewCount int                          `json:"requiredApprovingReviewCount"`
	RequireLastPushApproval      bool                         `json:"requireLastPushApproval"`
	BypassPullRequestAllowances  *githubBypassAllowances      `json:"bypassPullRequestAllowances"`
}

func (g *mqlGithubBranch) protectionRules() (*mqlGithubBranchprotection, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	var err error

	// if the branch is not protected, we don't need to fetch the protection rules
	if g.IsProtected.Error != nil {
		return nil, g.IsProtected.Error
	}
	if !g.IsProtected.Data {
		g.ProtectionRules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	if g.RepoName.Error != nil {
		return nil, g.RepoName.Error
	}
	repoName := g.RepoName.Data
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	branchName := g.Name.Data
	if g.Owner.Error != nil {
		return nil, g.Owner.Error
	}
	owner := g.Owner.Data
	if owner == nil {
		g.ProtectionRules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if owner.Login.Error != nil {
		log.Debug().Err(owner.Login.Error).Msg("note: branch protection can only be accessed by admin users")
		if strings.Contains(owner.Login.Error.Error(), "404") {
			g.ProtectionRules.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, owner.Login.Error
	}
	ownerName := owner.Login.Data

	branchProtection, _, err := conn.Client().Repositories.GetBranchProtection(conn.Context(), ownerName, repoName, branchName)
	if err != nil {
		// NOTE it is possible that the branch does not have any protection rules, therefore we don't return an error
		if strings.Contains(err.Error(), "Not Found") {
			g.ProtectionRules.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// TODO: figure out if the client has the permission to fetch the protection rules
		return nil, err
	}

	rsc, err := convert.JsonToDict(branchProtection.RequiredStatusChecks)
	if err != nil {
		return nil, err
	}

	var ghDismissalRestrictions *githubDismissalRestrictions

	var rprr map[string]any
	if branchProtection.RequiredPullRequestReviews != nil {

		if branchProtection.RequiredPullRequestReviews.DismissalRestrictions != nil {
			ghDismissalRestrictions = &githubDismissalRestrictions{
				Users: make([]string, 0, len(branchProtection.RequiredPullRequestReviews.DismissalRestrictions.Users)),
				Teams: make([]string, 0, len(branchProtection.RequiredPullRequestReviews.DismissalRestrictions.Teams)),
			}

			for i := range branchProtection.RequiredPullRequestReviews.DismissalRestrictions.Teams {
				ghDismissalRestrictions.Teams = append(ghDismissalRestrictions.Teams, branchProtection.RequiredPullRequestReviews.DismissalRestrictions.Teams[i].GetName())
			}
			for i := range branchProtection.RequiredPullRequestReviews.DismissalRestrictions.Users {
				ghDismissalRestrictions.Users = append(ghDismissalRestrictions.Users, branchProtection.RequiredPullRequestReviews.DismissalRestrictions.Users[i].GetLogin())
			}
		}

		var ghBypassAllowances *githubBypassAllowances
		if branchProtection.RequiredPullRequestReviews.BypassPullRequestAllowances != nil {
			bpa := branchProtection.RequiredPullRequestReviews.BypassPullRequestAllowances
			ghBypassAllowances = &githubBypassAllowances{
				Users: make([]string, 0, len(bpa.Users)),
				Teams: make([]string, 0, len(bpa.Teams)),
				Apps:  make([]string, 0, len(bpa.Apps)),
			}
			for _, u := range bpa.Users {
				ghBypassAllowances.Users = append(ghBypassAllowances.Users, u.GetLogin())
			}
			for _, t := range bpa.Teams {
				ghBypassAllowances.Teams = append(ghBypassAllowances.Teams, t.GetName())
			}
			for _, a := range bpa.Apps {
				ghBypassAllowances.Apps = append(ghBypassAllowances.Apps, a.GetSlug())
			}
		}

		// we use a separate struct to ensure that the output is proper camelCase
		rprr, err = convert.JsonToDict(githubRequiredPullRequestReviews{
			DismissStaleReviews:          branchProtection.RequiredPullRequestReviews.DismissStaleReviews,
			RequireCodeOwnerReviews:      branchProtection.RequiredPullRequestReviews.RequireCodeOwnerReviews,
			RequiredApprovingReviewCount: branchProtection.RequiredPullRequestReviews.RequiredApprovingReviewCount,
			RequireLastPushApproval:      branchProtection.RequiredPullRequestReviews.RequireLastPushApproval,
			DismissalRestrictions:        ghDismissalRestrictions,
			BypassPullRequestAllowances:  ghBypassAllowances,
		})
		if err != nil {
			return nil, err
		}
	}

	ea, err := convert.JsonToDict(branchProtection.EnforceAdmins)
	if err != nil {
		return nil, err
	}
	r, err := convert.JsonToDict(branchProtection.Restrictions)
	if err != nil {
		return nil, err
	}
	rlh, err := convert.JsonToDict(branchProtection.RequireLinearHistory)
	if err != nil {
		return nil, err
	}
	afp, err := convert.JsonToDict(branchProtection.AllowForcePushes)
	if err != nil {
		return nil, err
	}
	ad, err := convert.JsonToDict(branchProtection.AllowDeletions)
	if err != nil {
		return nil, err
	}
	rcr, err := convert.JsonToDict(branchProtection.RequiredConversationResolution)
	if err != nil {
		return nil, err
	}

	sc, _, err := conn.Client().Repositories.GetSignaturesProtectedBranch(conn.Context(), ownerName, repoName, branchName)
	if err != nil {
		log.Debug().Err(err).Msg("note: branch protection can only be accessed by admin users")
		return nil, err
	}

	// Flatten the most-frequently-asserted PR review fields onto the resource
	// for easier MQL queries (e.g. branchprotection.requireCodeOwnerReviews).
	var (
		requiredApprovingReviewCount int64
		requireCodeOwnerReviews      bool
		dismissStaleReviews          bool
		requireLastPushApproval      bool
		dismissalRestrictionsDict    map[string]any
	)
	if branchProtection.RequiredPullRequestReviews != nil {
		rpr := branchProtection.RequiredPullRequestReviews
		requiredApprovingReviewCount = int64(rpr.RequiredApprovingReviewCount)
		requireCodeOwnerReviews = rpr.RequireCodeOwnerReviews
		dismissStaleReviews = rpr.DismissStaleReviews
		requireLastPushApproval = rpr.RequireLastPushApproval
		if ghDismissalRestrictions != nil {
			dismissalRestrictionsDict, _ = convert.JsonToDict(ghDismissalRestrictions)
		}
	}

	res, err := CreateResource(g.MqlRuntime, "github.branchprotection", map[string]*llx.RawData{
		"id":                             llx.StringData(repoName + "/" + branchName),
		"requiredStatusChecks":           llx.MapData(rsc, types.Any),
		"requiredPullRequestReviews":     llx.MapData(rprr, types.Any),
		"enforceAdmins":                  llx.MapData(ea, types.Any),
		"restrictions":                   llx.MapData(r, types.Any),
		"requireLinearHistory":           llx.MapData(rlh, types.Any),
		"allowForcePushes":               llx.MapData(afp, types.Any),
		"allowDeletions":                 llx.MapData(ad, types.Any),
		"requiredConversationResolution": llx.MapData(rcr, types.Any),
		"requiredSignatures":             llx.BoolDataPtr(sc.Enabled),
		"requireSignedCommits":           llx.BoolData(convert.ToValue(sc.Enabled)),
		"blockCreations":                 llx.BoolData(branchProtection.GetBlockCreations().GetEnabled()),
		"lockBranch":                     llx.BoolData(branchProtection.GetLockBranch().GetEnabled()),
		"allowForkSyncing":               llx.BoolData(branchProtection.GetAllowForkSyncing().GetEnabled()),
		// Typed "enabled" accessors flattened from the corresponding dict fields above
		// for easier MQL queries (e.g. branchprotection.allowForcePushesEnabled == false).
		"enforceAdminsEnabled":                  llx.BoolData(branchProtection.GetEnforceAdmins().GetEnabled()),
		"allowForcePushesEnabled":               llx.BoolData(branchProtection.GetAllowForcePushes().GetEnabled()),
		"allowDeletionsEnabled":                 llx.BoolData(branchProtection.GetAllowDeletions().GetEnabled()),
		"requiredConversationResolutionEnabled": llx.BoolData(branchProtection.GetRequiredConversationResolution().GetEnabled()),
		"requireLinearHistoryEnabled":           llx.BoolData(branchProtection.GetRequireLinearHistory().GetEnabled()),
		// These two protection categories have no "enabled" flag in the API; the
		// object is present only when the protection is configured.
		"requiredPullRequestReviewsEnabled": llx.BoolData(branchProtection.RequiredPullRequestReviews != nil),
		"requiredStatusChecksEnabled":       llx.BoolData(branchProtection.RequiredStatusChecks != nil),
		"requiredApprovingReviewCount":      llx.IntData(requiredApprovingReviewCount),
		"requireCodeOwnerReviews":           llx.BoolData(requireCodeOwnerReviews),
		"dismissStaleReviews":               llx.BoolData(dismissStaleReviews),
		"requireLastPushApproval":           llx.BoolData(requireLastPushApproval),
		"dismissalRestrictions":             llx.MapData(dismissalRestrictionsDict, types.Any),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubBranchprotection), nil
}

func (g *mqlGithubBranch) headCommit() (*mqlGithubCommit, error) {
	if g.Owner.Error != nil {
		return nil, g.Owner.Error
	}
	// newMqlGithubRepository sets owner to null for owner-less repos, so
	// g.Owner.Data can be nil; guard before dereferencing it.
	ownerName := g.Owner.Data
	if ownerName == nil {
		g.HeadCommit.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if ownerName.Login.Error != nil {
		return nil, ownerName.Login.Error
	}
	if g.HeadCommitSha.Error != nil {
		return nil, g.HeadCommitSha.Error
	}
	if g.RepoName.Error != nil {
		return nil, g.RepoName.Error
	}
	ownerLogin := ownerName.Login.Data

	commit, err := newMqlGithubCommit(g.MqlRuntime, &github.RepositoryCommit{
		SHA: &g.HeadCommitSha.Data,
	}, ownerLogin, g.RepoName.Data)
	if err != nil {
		return nil, err
	}
	return commit.(*mqlGithubCommit), nil
}

func newMqlGithubCommit(runtime *plugin.Runtime, rc *github.RepositoryCommit, owner string, repo string) (any, error) {
	var githubAuthor any
	var err error
	conn := runtime.Connection.(*connection.GithubConnection)

	// If the commit payload is missing we have to load the commit again. A nil
	// Author is not a reason to refetch: it means the commit's email is not
	// linked to any GitHub account, and the detail endpoint reports the same
	// null. Refetching on it cost one extra API call per unlinked commit and
	// changed nothing.
	if rc.Commit == nil {
		rc, _, err = conn.Client().Repositories.GetCommit(conn.Context(), owner, repo, rc.GetSHA(), nil)
		if err != nil {
			return nil, err
		}
	}

	if rc.Author != nil && rc.Author.ID != nil && rc.Author.Login != nil {
		githubAuthor, err = NewResource(runtime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataPtr(rc.Author.ID),
			"login": llx.StringDataPtr(rc.Author.Login),
		})
		if err != nil {
			return nil, err
		}
	}
	var githubCommitter any
	if rc.Committer != nil && rc.Committer.ID != nil && rc.Committer.Login != nil {
		githubCommitter, err = NewResource(runtime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataPtr(rc.Committer.ID),
			"login": llx.StringDataPtr(rc.Committer.Login),
		})
		if err != nil {
			return nil, err
		}
	}

	sha := rc.GetSHA()

	stats, err := convert.JsonToDict(rc.GetStats())
	if err != nil {
		return nil, err
	}

	mqlGitCommit, err := newMqlGitCommit(runtime, sha, rc.Commit)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "github.commit", map[string]*llx.RawData{
		"url":           llx.StringData(rc.GetURL()),
		"sha":           llx.StringData(sha),
		"author":        llx.AnyData(githubAuthor),
		"committer":     llx.AnyData(githubCommitter),
		"owner":         llx.StringData(owner),
		"repository":    llx.StringData(repo),
		"commit":        llx.AnyData(mqlGitCommit),
		"stats":         llx.MapData(stats, types.Any),
		"authoredDate":  llx.TimeData(rc.Commit.GetAuthor().GetDate().Time),
		"committedDate": llx.TimeData(rc.Commit.GetCommitter().GetDate().Time),
	})
}

func (g *mqlGithubRepository) commits() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.CommitsListOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var allCommits []*github.RepositoryCommit
	for {
		commits, resp, err := conn.Client().Repositories.ListCommits(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			// An empty repository has no commits; the API reports this as a 409.
			if strings.Contains(err.Error(), "Git Repository is empty") {
				return []any{}, nil
			}
			return nil, err
		}
		allCommits = append(allCommits, commits...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage

	}
	res := []any{}
	for i := range allCommits {
		rc := allCommits[i]
		mqlCommit, err := newMqlGithubCommit(g.MqlRuntime, rc, ownerLogin, repoName)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCommit)
	}
	return res, nil
}

// mergeRequestRepo returns the owner login and name of the repository a pull
// request belongs to. It reads repoOwnerLogin rather than owner: owner is the
// account that *authored* the pull request, which for organization
// repositories is almost never the account that owns the repository. Addressing
// the API with the author's login used to 404 and, because the callers treat a
// 404 as "nothing here", silently returned no commits and no reviews.
func mergeRequestRepo(g *mqlGithubMergeRequest) (string, string, error) {
	if g.RepoName.Error != nil {
		return "", "", g.RepoName.Error
	}
	if g.RepoOwnerLogin.Error != nil {
		return "", "", g.RepoOwnerLogin.Error
	}
	if g.RepoOwnerLogin.Data == "" {
		return "", "", errors.New("pull request is missing the owner of its repository")
	}
	return g.RepoOwnerLogin.Data, g.RepoName.Data, nil
}

func (g *mqlGithubMergeRequest) reviews() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := mergeRequestRepo(g)
	if err != nil {
		return nil, err
	}
	if g.Number.Error != nil {
		return nil, g.Number.Error
	}
	prID := g.Number.Data

	listOpts := &github.ListOptions{
		PerPage: paginationPerPage,
	}
	var allReviews []*github.PullRequestReview
	for {
		reviews, resp, err := conn.Client().PullRequests.ListReviews(conn.Context(), ownerLogin, repoName, int(prID), listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allReviews = append(allReviews, reviews...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}
	res := []any{}
	for i := range allReviews {
		r := allReviews[i]
		var user any
		if r.User != nil {
			user, err = NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(r.User.ID),
				"login": llx.StringDataPtr(r.User.Login),
			})
			if err != nil {
				return nil, err
			}
		}
		mqlReview, err := CreateResource(g.MqlRuntime, "github.review", map[string]*llx.RawData{
			"url":               llx.StringDataPtr(r.HTMLURL),
			"state":             llx.StringDataPtr(r.State),
			"authorAssociation": llx.StringDataPtr(r.AuthorAssociation),
			"user":              llx.AnyData(user),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlReview)
	}

	return res, nil
}

func (g *mqlGithubMergeRequest) commits() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := mergeRequestRepo(g)
	if err != nil {
		return nil, err
	}
	if g.Number.Error != nil {
		return nil, g.Number.Error
	}
	prID := g.Number.Data

	listOpts := &github.ListOptions{
		PerPage: paginationPerPage,
	}
	var allCommits []*github.RepositoryCommit
	for {
		commits, resp, err := conn.Client().PullRequests.ListCommits(conn.Context(), ownerLogin, repoName, int(prID), listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allCommits = append(allCommits, commits...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}
	res := []any{}
	for i := range allCommits {
		rc := allCommits[i]

		mqlCommit, err := newMqlGithubCommit(g.MqlRuntime, rc, ownerLogin, repoName)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCommit)
	}
	return res, nil
}

func (g *mqlGithubRepository) contributors() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.ListContributorsOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var allContributors []*github.Contributor
	for {
		contributors, resp, err := conn.Client().Repositories.ListContributors(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allContributors = append(allContributors, contributors...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}
	res := []any{}
	for i := range allContributors {
		mqlUser, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataPtr(allContributors[i].ID),
			"login": llx.StringDataPtr(allContributors[i].Login),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}
	return res, nil
}

func (g *mqlGithubRepository) collaborators() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.ListCollaboratorsOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var allContributors []*github.User
	for {
		contributors, resp, err := conn.Client().Repositories.ListCollaborators(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allContributors = append(allContributors, contributors...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}
	res := []any{}
	for i := range allContributors {
		contributor := allContributors[i]
		mqlUser, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataPtr(contributor.ID),
			"login": llx.StringDataPtr(contributor.Login),
		})
		if err != nil {
			return nil, err
		}

		permissions := permissionsFromUser(contributor)

		mqlContributor, err := CreateResource(g.MqlRuntime, "github.collaborator", map[string]*llx.RawData{
			"__id":        llx.StringData(collaboratorID(ownerLogin, repoName, contributor.GetID())),
			"id":          llx.IntDataPtr(contributor.ID),
			"user":        llx.ResourceData(mqlUser, mqlUser.MqlName()),
			"permissions": llx.ArrayData(convert.SliceAnyToInterface[string](permissions), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlContributor)
	}
	return res, nil
}

// collaboratorID keys a collaborator by the repository the permissions apply
// to. The same account collaborates on many repositories with different
// permission sets, so keying on the user alone made every repository after the
// first reuse the first one's permissions.
func collaboratorID(ownerLogin, repoName string, userID int64) string {
	return "github.collaborator/" + ownerLogin + "/" + repoName + "/" + strconv.FormatInt(userID, 10)
}

// alertID keys a security alert by repository. Alert numbers are assigned per
// repository and restart at 1, so an unqualified number aliased alerts across
// every repository reached in the same scan.
func alertID(resource, ownerLogin, repoName string, number int64) string {
	return resource + "/" + ownerLogin + "/" + repoName + "/" + strconv.FormatInt(number, 10)
}

func permissionsFromUser(u *github.User) []string {
	if u.Permissions == nil {
		return []string{}
	}
	perms := []string{}
	if u.Permissions.GetAdmin() {
		perms = append(perms, "admin")
	}
	if u.Permissions.GetMaintain() {
		perms = append(perms, "maintain")
	}
	if u.Permissions.GetPush() {
		perms = append(perms, "push")
	}
	if u.Permissions.GetTriage() {
		perms = append(perms, "triage")
	}
	if u.Permissions.GetPull() {
		perms = append(perms, "pull")
	}
	return perms
}

func (g *mqlGithubRepository) adminCollaborators() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.ListCollaboratorsOptions{
		Permission:  "admin",
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var adminCollaborators []*github.User
	for {
		contributors, resp, err := conn.Client().Repositories.ListCollaborators(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		adminCollaborators = append(adminCollaborators, contributors...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}
	res := []any{}
	for i := range adminCollaborators {
		contributor := adminCollaborators[i]
		mqlUser, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataPtr(contributor.ID),
			"login": llx.StringDataPtr(contributor.Login),
		})
		if err != nil {
			return nil, err
		}

		permissions := permissionsFromUser(contributor)

		mqlContributor, err := CreateResource(g.MqlRuntime, "github.collaborator", map[string]*llx.RawData{
			"__id":        llx.StringData(collaboratorID(ownerLogin, repoName, contributor.GetID())),
			"id":          llx.IntDataPtr(contributor.ID),
			"user":        llx.ResourceData(mqlUser, mqlUser.MqlName()),
			"permissions": llx.ArrayData(convert.SliceAnyToInterface[string](permissions), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlContributor)
	}
	return res, nil
}

func (g *mqlGithubRepository) releases() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.ListOptions{
		PerPage: paginationPerPage,
	}
	var allReleases []*github.RepositoryRelease
	for {
		releases, resp, err := conn.Client().Repositories.ListReleases(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allReleases = append(allReleases, releases...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allReleases {
		r := allReleases[i]

		var author any
		if r.Author != nil {
			var authorErr error
			author, authorErr = NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(r.Author.ID),
				"login": llx.StringDataPtr(r.Author.Login),
			})
			if authorErr != nil {
				return nil, authorErr
			}
		}

		mqlRelease, err := CreateResource(g.MqlRuntime, "github.release", map[string]*llx.RawData{
			"url":         llx.StringData(r.HTMLURL),
			"name":        llx.StringDataPtr(r.Name),
			"tagName":     llx.StringData(r.TagName),
			"preRelease":  llx.BoolData(r.Prerelease),
			"createdAt":   llx.TimeDataPtr(githubTimestamp(&r.CreatedAt)),
			"publishedAt": llx.TimeDataPtr(githubTimestamp(r.PublishedAt)),
			"author":      llx.AnyData(author),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRelease)
	}

	return res, nil
}

func (g *mqlGithubWebhook) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "github.webhook/" + strconv.FormatInt(id, 10), nil
}

func (g *mqlGithubRepository) webhooks() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.ListOptions{
		PerPage: paginationPerPage,
	}
	var allWebhooks []*github.Hook
	for {
		hooks, resp, err := conn.Client().Repositories.ListHooks(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allWebhooks = append(allWebhooks, hooks...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}
	res := []any{}
	for i := range allWebhooks {
		h := allWebhooks[i]
		config, err := convert.JsonToDict(h.Config)
		if err != nil {
			return nil, err
		}

		mqlWebhook, err := CreateResource(g.MqlRuntime, "github.webhook", map[string]*llx.RawData{
			"id":          llx.IntDataPtr(h.ID),
			"name":        llx.StringDataPtr(h.Name),
			"events":      llx.ArrayData(convert.SliceAnyToInterface[string](h.Events), types.String),
			"config":      llx.MapData(config, types.Any),
			"contentType": llx.StringData(h.Config.GetContentType()),
			"insecureSsl": llx.BoolData(h.Config.GetInsecureSSL() == "1"),
			"url":         llx.StringDataPtr(h.URL),
			"active":      llx.BoolDataPtr(h.Active),
			"createdAt":   llx.TimeDataPtr(githubTimestamp(h.CreatedAt)),
			"updatedAt":   llx.TimeDataPtr(githubTimestamp(h.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlWebhook)
	}

	return res, nil
}

type mqlGithubWorkflowInternal struct {
	repositoryFullName string
	defaultBranchName  string
	parentResource     *mqlGithubRepository
}

func (g *mqlGithubRepository) workflows() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	if g.FullName.Error != nil {
		return nil, g.FullName.Error
	}
	fullName := g.FullName.Data

	defaultBranchName := ""
	if g.DefaultBranchName.Error == nil {
		defaultBranchName = g.DefaultBranchName.Data
	}

	listOpts := &github.ListOptions{
		PerPage: paginationPerPage,
	}
	var allWorkflows []*github.Workflow
	for {
		workflows, resp, err := conn.Client().Actions.ListWorkflows(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			// The Actions API returns 404/403 when the token lacks the "Actions"
			// (read) permission on a fine-grained PAT, or the full "repo" scope on
			// a classic PAT (and also when Actions is disabled on the repository).
			// Surface this instead of returning an empty list: an empty list makes
			// a security check (e.g. "packages are scanned for vulnerabilities")
			// silently FAIL as if no scanning workflow were configured, when in
			// fact the scanner simply could not read the workflows.
			if isAccessDeniedOrNotFound(err) {
				return nil, fmt.Errorf("cannot list workflows for %q: %w; grant the scanning token the \"Actions\" read permission (fine-grained PAT) or the full \"repo\" scope (classic PAT)", fullName, err)
			}
			return nil, err
		}
		allWorkflows = append(allWorkflows, workflows.Workflows...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allWorkflows {
		w := allWorkflows[i]

		mqlWebhook, err := CreateResource(g.MqlRuntime, "github.workflow", map[string]*llx.RawData{
			"id":        llx.IntDataPtr(w.ID),
			"name":      llx.StringDataPtr(w.Name),
			"path":      llx.StringDataPtr(w.Path),
			"state":     llx.StringDataPtr(w.State),
			"createdAt": llx.TimeDataPtr(githubTimestamp(w.CreatedAt)),
			"updatedAt": llx.TimeDataPtr(githubTimestamp(w.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}

		gw := mqlWebhook.(*mqlGithubWorkflow)
		gw.repositoryFullName = fullName
		gw.defaultBranchName = defaultBranchName
		res = append(res, gw)
	}
	return res, nil
}

// isBinaryFile reports whether a repository entry is a known binary artifact,
// based on its file extension. It uses path.Ext rather than splitting the whole
// path on ".", which misclassified every file living under a directory that has
// a dot in its name (`v1.2/tool.exe`, `.github/x.exe`).
func isBinaryFile(fileType, filePath string) bool {
	if fileType != "file" {
		return false
	}
	return binaryFileTypes[strings.TrimPrefix(path.Ext(filePath), ".")]
}

func newMqlGithubFile(runtime *plugin.Runtime, ownerName string, repoName string, content *github.RepositoryContent) (*mqlGithubFile, error) {
	isBinary := isBinaryFile(convert.ToValue(content.Type), convert.ToValue(content.Path))
	res, err := CreateResource(runtime, "github.file", map[string]*llx.RawData{
		"path":        llx.StringDataPtr(content.Path),
		"name":        llx.StringDataPtr(content.Name),
		"type":        llx.StringDataPtr(content.Type),
		"sha":         llx.StringDataPtr(content.SHA),
		"isBinary":    llx.BoolData(isBinary),
		"ownerName":   llx.StringData(ownerName),
		"repoName":    llx.StringData(repoName),
		"downloadUrl": llx.StringDataPtr(content.DownloadURL),
		"exists":      llx.BoolData(true),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubFile), nil
}

func newMqlGithubFileDoesNotExist(runtime *plugin.Runtime, ownerName string, repoName string, filePath string) (*mqlGithubFile, error) {
	name := path.Base(filePath)

	res, err := CreateResource(runtime, "github.file", map[string]*llx.RawData{
		"path":        llx.StringData(filePath),
		"name":        llx.StringData(name),
		"type":        llx.StringDataPtr(nil),
		"sha":         llx.StringData("0000000000000000000000000000000000000000"),
		"isBinary":    llx.BoolData(false),
		"ownerName":   llx.StringData(ownerName),
		"repoName":    llx.StringData(repoName),
		"downloadUrl": llx.StringDataPtr(nil),
		"exists":      llx.BoolData(false),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubFile), nil
}

// allFiles lists every entry in the repository's default branch in one Git Trees
// API call. files() returns the root level only, so a query built on it cannot
// see anything nested more than one directory deep.
func (g *mqlGithubRepository) allFiles() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	if g.DefaultBranchName.Error != nil {
		return nil, g.DefaultBranchName.Error
	}
	ref := g.DefaultBranchName.Data
	if ref == "" {
		ref = "HEAD"
	}

	tree, _, err := conn.Client().Git.GetTree(conn.Context(), ownerLogin, repoName, ref, true)
	if err != nil {
		// An empty repository has no tree to read: 404 when the ref does not
		// resolve, 409 when the repository carries no commits.
		switch githubResponseStatus(err) {
		case http.StatusNotFound, http.StatusConflict:
			return []any{}, nil
		}
		log.Error().Err(err).Msg("unable to get repository tree")
		return nil, err
	}

	if tree.GetTruncated() {
		log.Warn().
			Str("owner", ownerLogin).
			Str("repo", repoName).
			Msg("repository tree was truncated by the GitHub API, the file listing is incomplete")
	}

	res := make([]any, 0, len(tree.Entries))
	for i := range tree.Entries {
		entryPath := convert.ToValue(tree.Entries[i].Path)
		fileType := gitTreeEntryType(convert.ToValue(tree.Entries[i].Type))

		mqlFile, err := CreateResource(g.MqlRuntime, "github.file", map[string]*llx.RawData{
			"path":        llx.StringData(entryPath),
			"name":        llx.StringData(path.Base(entryPath)),
			"type":        llx.StringData(fileType),
			"sha":         llx.StringDataPtr(tree.Entries[i].SHA),
			"isBinary":    llx.BoolData(isBinaryFile(fileType, entryPath)),
			"ownerName":   llx.StringData(ownerLogin),
			"repoName":    llx.StringData(repoName),
			"downloadUrl": llx.StringDataPtr(nil),
			"exists":      llx.BoolData(true),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFile)
	}
	return res, nil
}

// gitTreeEntryType maps a Git object type onto the vocabulary github.file.type
// already uses, so allFiles and files can be filtered the same way.
func gitTreeEntryType(objectType string) string {
	switch objectType {
	case "tree":
		return "dir"
	case "blob":
		return "file"
	case "commit":
		return "submodule"
	default:
		return objectType
	}
}

func (g *mqlGithubRepository) files() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}
	_, dirContent, _, err := conn.Client().Repositories.GetContents(conn.Context(), ownerLogin, repoName, "", &github.RepositoryContentGetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		log.Error().Err(err).Msg("unable to get contents list")
		return nil, err
	}
	res := []any{}
	for i := range dirContent {
		mqlFile, err := newMqlGithubFile(g.MqlRuntime, ownerLogin, repoName, dirContent[i])
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFile)

	}
	return res, nil
}

var binaryFileTypes = map[string]bool{
	"crx":    true,
	"deb":    true,
	"dex":    true,
	"dey":    true,
	"elf":    true,
	"o":      true,
	"so":     true,
	"iso":    true,
	"class":  true,
	"jar":    true,
	"bundle": true,
	"dylib":  true,
	"lib":    true,
	"msi":    true,
	"dll":    true,
	"drv":    true,
	"efi":    true,
	"exe":    true,
	"ocx":    true,
	"pyc":    true,
	"pyo":    true,
	"par":    true,
	"rpm":    true,
	"whl":    true,
}

func (g *mqlGithubFile) id() (string, error) {
	// Include the owner: repository names are unique only within an owner, and
	// forks keep the name of their upstream repository.
	if g.OwnerName.Error != nil {
		return "", g.OwnerName.Error
	}
	o := g.OwnerName.Data
	if g.RepoName.Error != nil {
		return "", g.RepoName.Error
	}
	r := g.RepoName.Data
	if g.Path.Error != nil {
		return "", g.Path.Error
	}
	p := g.Path.Data
	if g.Sha.Error != nil {
		return "", g.Sha.Error
	}
	s := g.Sha.Data
	return o + "/" + r + "/" + p + "/" + s, nil
}

func (g *mqlGithubFile) files() ([]any, error) {
	if g.Type.Error != nil {
		return nil, g.Type.Error
	}
	fileType := g.Type.Data
	if fileType != "dir" {
		return nil, nil
	}
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.RepoName.Error != nil {
		return nil, g.RepoName.Error
	}
	repoName := g.RepoName.Data
	if g.OwnerName.Error != nil {
		return nil, g.OwnerName.Error
	}
	ownerName := g.OwnerName.Data
	if g.Path.Error != nil {
		return nil, g.Path.Error
	}
	path := g.Path.Data
	_, dirContent, _, err := conn.Client().Repositories.GetContents(conn.Context(), ownerName, repoName, path, &github.RepositoryContentGetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		log.Error().Err(err).Msg("unable to get contents list")
		return nil, err
	}
	res := []any{}
	for i := range dirContent {
		// Build through the shared constructor so nested entries carry the same
		// fields as top-level ones. Setting them here by hand left downloadUrl
		// and exists unset, which reaches the client as a value with no type.
		mqlFile, err := newMqlGithubFile(g.MqlRuntime, ownerName, repoName, dirContent[i])
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFile)

	}
	return res, nil
}

func (g *mqlGithubFile) content() (string, error) {
	if g.Type.Error != nil {
		return "", g.Type.Error
	}
	fileType := g.Type.Data
	if fileType == "dir" {
		return "", nil
	}
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.RepoName.Error != nil {
		return "", g.RepoName.Error
	}
	repoName := g.RepoName.Data
	if g.OwnerName.Error != nil {
		return "", g.OwnerName.Error
	}
	ownerName := g.OwnerName.Data
	if g.Path.Error != nil {
		return "", g.Path.Error
	}
	path := g.Path.Data
	fileContent, _, _, err := conn.Client().Repositories.GetContents(conn.Context(), ownerName, repoName, path, &github.RepositoryContentGetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			log.Debug().Err(err).
				Msg("unable to get contents list")
			return "", nil
		}
		log.Error().Err(err).Msg("unable to get contents list")
		return "", err
	}

	content, err := fileContent.GetContent()
	if err != nil {
		if strings.Contains(err.Error(), "unsupported content encoding: none") {
			// TODO: i'm unclear why this error happens. the function checks for bas64 encoding and empty string encoding. if it's neither, it returns this error.
			// the error blocks the rest of the output, so we log it instead
			log.Error().Msgf("unable to get content for path %v", path)
			return "", nil
		}
	}
	return content, nil
}

func (g *mqlGithubRepository) forks() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.RepositoryListForksOptions{
		ListOptions: github.ListOptions{
			PerPage: paginationPerPage,
		},
	}
	var allForks []*github.Repository
	for {
		forks, resp, err := conn.Client().Repositories.ListForks(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			log.Error().Err(err).Msg("unable to get forks")
			return nil, err
		}
		allForks = append(allForks, forks...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allForks {
		repo := allForks[i]
		r, err := newMqlGithubRepository(g.MqlRuntime, repo)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGithubRepository) stargazers() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.ListOptions{
		PerPage: paginationPerPage,
	}
	var allStargazers []*github.Stargazer
	for {
		stargazers, resp, err := conn.Client().Activity.ListStargazers(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			log.Error().Err(err).Msg("unable to get stargazers")
			return nil, err
		}
		allStargazers = append(allStargazers, stargazers...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allStargazers {
		stargazer := allStargazers[i]
		if stargazer.User == nil {
			continue
		}
		r, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataPtr(stargazer.User.ID),
			"login": llx.StringDataPtr(stargazer.User.Login),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGithubIssue) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data

	return "github.issue/" + strconv.FormatInt(id, 10), nil
}

func (g *mqlGithubRepository) openIssues() ([]any, error) {
	return g.getIssues("open")
}

func (g *mqlGithubRepository) closedIssues() ([]any, error) {
	return g.getIssues("closed")
}

func listIssuesRaw(ctx context.Context, client *github.Client, ownerLogin, repoName, state string) ([]*github.Issue, error) {
	listOpts := &github.IssueListByRepoOptions{
		State: state,
		ListOptions: github.ListOptions{
			PerPage: paginationPerPage,
		},
	}
	var allIssues []*github.Issue
	for {
		issues, resp, err := client.Issues.ListByRepo(ctx, ownerLogin, repoName, listOpts)
		if err != nil {
			return nil, err
		}
		for _, issue := range issues {
			// Every pull request is also an issue, and this endpoint returns
			// both. Only the `pull_request` member tells them apart. Pull
			// requests are reported by openMergeRequests/closedMergeRequests,
			// so keeping them here would count the same work twice.
			if issue.IsPullRequest() {
				continue
			}
			allIssues = append(allIssues, issue)
		}
		if resp.NextPage == 0 {
			break
		}
		listOpts.ListOptions.Page = resp.NextPage
	}
	return allIssues, nil
}

func (g *mqlGithubRepository) getIssues(state string) ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	allIssues, err := listIssuesRaw(conn.Context(), conn.Client(), ownerLogin, repoName, state)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		log.Error().Err(err).Msg("unable to get issues")
		return nil, err
	}

	res := []any{}
	for i := range allIssues {
		issue := allIssues[i]

		var assignees []any
		for _, assignee := range issue.Assignees {
			r, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(assignee.ID),
				"login": llx.StringDataPtr(assignee.Login),
			})
			if err != nil {
				return nil, err
			}
			assignees = append(assignees, r)
		}

		var closedBy any
		if issue.GetClosedBy() != nil {
			r, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(issue.GetClosedBy().ID),
				"login": llx.StringDataPtr(issue.GetClosedBy().Login),
			})
			if err != nil {
				return nil, err
			}
			closedBy = r
		}

		var milestone plugin.Resource
		if issue.Milestone != nil {
			m, err := newMqlGithubMilestone(g.MqlRuntime, issue.Milestone)
			if err != nil {
				return nil, err
			}
			milestone = m
		}

		var user any
		if issue.User != nil {
			u, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(issue.User.ID),
				"login": llx.StringDataPtr(issue.User.Login),
			})
			if err != nil {
				return nil, err
			}
			user = u
		}

		labels := make([]any, 0, len(issue.Labels))
		for _, l := range issue.Labels {
			labelDict, err := convert.JsonToDict(l)
			if err != nil {
				return nil, err
			}
			labels = append(labels, labelDict)
		}

		r, err := CreateResource(g.MqlRuntime, "github.issue", map[string]*llx.RawData{
			"id":        llx.IntData(issue.GetID()),
			"number":    llx.IntData(int64(issue.GetNumber())),
			"title":     llx.StringData(issue.GetTitle()),
			"state":     llx.StringData(issue.GetState()),
			"body":      llx.StringData(issue.GetBody()),
			"url":       llx.StringData(issue.GetURL()),
			"createdAt": llx.TimeDataPtr(githubTimestamp(issue.CreatedAt)),
			"updatedAt": llx.TimeDataPtr(githubTimestamp(issue.UpdatedAt)),
			"closedAt":  llx.TimeDataPtr(githubTimestamp(issue.ClosedAt)),
			"user":      llx.AnyData(user),
			"labels":    llx.ArrayData(labels, types.Dict),
			"assignees": llx.ArrayData(assignees, types.Any),
			"closedBy":  llx.AnyData(closedBy),
			"draft":     llx.BoolData(issue.GetDraft()),
			"locked":    llx.BoolData(issue.GetLocked()),
			"milestone": llx.ResourceData(milestone, "github.milestone"),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGithubMilestone) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data

	return "github.milestone/" + strconv.FormatInt(id, 10), nil
}

func newMqlGithubMilestone(runtime *plugin.Runtime, milestone *github.Milestone) (*mqlGithubMilestone, error) {
	if milestone == nil {
		return nil, nil
	}

	var creator plugin.Resource
	if milestone.Creator != nil {
		c, err := NewResource(runtime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataPtr(milestone.Creator.ID),
			"login": llx.StringDataPtr(milestone.Creator.Login),
		})
		if err != nil {
			return nil, err
		}
		creator = c
	}

	r, err := CreateResource(runtime, "github.milestone", map[string]*llx.RawData{
		"id":           llx.IntData(milestone.GetID()),
		"number":       llx.IntData(int64(milestone.GetNumber())),
		"title":        llx.StringData(milestone.GetTitle()),
		"description":  llx.StringData(milestone.GetDescription()),
		"state":        llx.StringData(milestone.GetState()),
		"url":          llx.StringData(milestone.GetURL()),
		"htmlUrl":      llx.StringData(milestone.GetHTMLURL()),
		"creator":      llx.ResourceData(creator, "github.user"),
		"openIssues":   llx.IntData(int64(milestone.GetOpenIssues())),
		"closedIssues": llx.IntData(int64(milestone.GetClosedIssues())),
		"createdAt":    llx.TimeDataPtr(githubTimestamp(milestone.CreatedAt)),
		"updatedAt":    llx.TimeDataPtr(githubTimestamp(milestone.UpdatedAt)),
		"closedAt":     llx.TimeDataPtr(githubTimestamp(milestone.ClosedAt)),
		"dueOn":        llx.TimeDataPtr(githubTimestamp(milestone.DueOn)),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlGithubMilestone), nil
}

func (g *mqlGithubRepository) milestones() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.MilestoneListOptions{
		State: "all",
		ListOptions: github.ListOptions{
			PerPage: paginationPerPage,
		},
	}
	var allMilestones []*github.Milestone
	for {
		milestones, resp, err := conn.Client().Issues.ListMilestones(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			log.Error().Err(err).Msg("unable to get milestones")
			return nil, err
		}
		allMilestones = append(allMilestones, milestones...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.ListOptions.Page = resp.NextPage
	}

	res := []any{}
	for _, milestone := range allMilestones {
		r, err := newMqlGithubMilestone(g.MqlRuntime, milestone)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGithubRepository) supportFile() (*mqlGithubFile, error) {
	err := g.findSpecialFilesOnceFunc()
	if err != nil {
		return nil, err
	}
	if g.SupportFile.Error != nil {
		return nil, g.SupportFile.Error
	}

	return g.SupportFile.Data, nil
}

func (g *mqlGithubRepository) codeOfConductFile() (*mqlGithubFile, error) {
	err := g.findSpecialFilesOnceFunc()
	if err != nil {
		return nil, err
	}
	if g.CodeOfConductFile.Error != nil {
		return nil, g.CodeOfConductFile.Error
	}

	return g.CodeOfConductFile.Data, nil
}

func (g *mqlGithubRepository) securityFile() (*mqlGithubFile, error) {
	err := g.findSpecialFilesOnceFunc()
	if err != nil {
		return nil, err
	}
	if g.SecurityFile.Error != nil {
		return nil, g.SecurityFile.Error
	}

	return g.SecurityFile.Data, nil
}

type mqlGithubRepositoryInternal struct {
	findSpecialFilesOnceFunc func() error

	// The code scanning default-setup endpoint answers two fields,
	// codeScanningEnabled and codeScanningDefaultSetup. Memoizing it keeps a
	// query that reads both from spending two requests per repository, which
	// on an organization-wide scan is the difference GitHub's secondary rate
	// limit reacts to.
	defaultSetupOnce sync.Once
	defaultSetup     *github.DefaultSetupConfiguration
	defaultSetupErr  error
}

// defaultSetupConfig returns the repository's code scanning default setup,
// fetching it at most once. The error is returned as GitHub gave it, so
// callers can still tell a 404 (the repository has no default setup endpoint)
// from a 403 (the token may not read it).
func (g *mqlGithubRepository) defaultSetupConfig() (*github.DefaultSetupConfiguration, error) {
	g.defaultSetupOnce.Do(func() {
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		ownerLogin, repoName, err := repoOwnerAndName(g)
		if err != nil {
			g.defaultSetupErr = err
			return
		}
		g.defaultSetup, _, g.defaultSetupErr = conn.Client().CodeScanning.GetDefaultSetupConfiguration(
			conn.Context(), ownerLogin, repoName)
	})
	return g.defaultSetup, g.defaultSetupErr
}

// claimSpecialFiles assigns any of the wanted files present in a directory
// listing, recording what it matched in found so a later directory cannot
// override an earlier one.
//
// Entries are the same github.file resources the files field hands out, so a
// special file and its entry in that listing are one resource rather than two
// views of it.
func claimSpecialFiles(entries []any, wanted map[string]*plugin.TValue[*mqlGithubFile], found map[string]struct{}) {
	for i := range entries {
		file, ok := entries[i].(*mqlGithubFile)
		if !ok || file == nil || file.Type.Error != nil || file.Name.Error != nil {
			continue
		}
		if file.Type.Data != "file" {
			continue
		}

		// found is keyed lowercase; probe it the same way, otherwise which copy
		// of a file wins depends on how the second one happens to be
		// capitalized.
		name := strings.ToLower(file.Name.Data)
		if _, ok := found[name]; ok {
			continue
		}
		if v, ok := wanted[name]; ok && v != nil {
			(*v) = plugin.TValue[*mqlGithubFile]{Data: file, State: plugin.StateIsSet, Error: nil}
			found[name] = struct{}{}
		}
	}
}

// githubDirEntry returns the named subdirectory of a listing, or nil when the
// listing has no such directory. Looking before descending is what keeps a
// repository without a .github directory from paying for a 404.
func githubDirEntry(entries []any, name string) *mqlGithubFile {
	for i := range entries {
		dir, ok := entries[i].(*mqlGithubFile)
		if !ok || dir == nil || dir.Type.Error != nil || dir.Name.Error != nil {
			continue
		}
		if dir.Type.Data == "dir" && dir.Name.Data == name {
			return dir
		}
	}
	return nil
}

func (g *mqlGithubRepository) findSpecialFiles() error {
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return err
	}

	specialFilesCaseInsensitive := map[string]*plugin.TValue[*mqlGithubFile]{
		"code_of_conduct.md": &g.CodeOfConductFile,
		"support.md":         &g.SupportFile,
		"security.md":        &g.SecurityFile,
	}
	foundFiles := map[string]struct{}{}

	// The repository root, read through the files field rather than fetched
	// here, so the listing is resolved once per repository however it is
	// reached: asking for securityFile and asking for files are the same
	// request, and whichever arrives second reuses the cached field. That holds
	// across assets too, because a repository scanned as its own asset shares
	// the organization's resource cache and so the same resource.
	root := g.GetFiles()
	if root.Error != nil {
		return root.Error
	}
	claimSpecialFiles(root.Data, specialFilesCaseInsensitive, foundFiles)

	// .github, only when the root did not already answer everything. Descending
	// through the entry means the listing comes from that directory's own files
	// field, shared with any policy that walks into .github itself.
	if len(foundFiles) < len(specialFilesCaseInsensitive) {
		if dir := githubDirEntry(root.Data, ".github"); dir != nil {
			sub := dir.GetFiles()
			if sub.Error != nil {
				return sub.Error
			}
			claimSpecialFiles(sub.Data, specialFilesCaseInsensitive, foundFiles)
		}
	}

	for k, v := range specialFilesCaseInsensitive {
		if _, ok := foundFiles[k]; !ok {
			dneFile, err := newMqlGithubFileDoesNotExist(g.MqlRuntime, ownerLogin, repoName, k)
			if err != nil {
				return err
			}
			(*v) = plugin.TValue[*mqlGithubFile]{Data: dneFile, State: plugin.StateIsSet, Error: nil}
		}
	}

	return nil
}

func (g *mqlGithubDependabotAlert) id() (string, error) {
	if g.Number.Error != nil {
		return "", g.Number.Error
	}
	return "github.dependabotAlert/" + strconv.FormatInt(g.Number.Data, 10), nil
}

// listDependabotAlertsRaw collects every Dependabot alert for a repository.
//
// The endpoint paginates by cursor, not by page: its Link header advertises the
// next page as `after=<cursor>`, so the page-based NextPage stays zero and a
// walk driven by it stops after the first page, silently reporting at most
// paginationPerPage alerts for a repository that has more.
func listDependabotAlertsRaw(ctx context.Context, client *github.Client, ownerLogin, repoName string) ([]*github.DependabotAlert, error) {
	listOpts := &github.ListAlertsOptions{
		ListCursorOptions: github.ListCursorOptions{PerPage: paginationPerPage},
	}

	var allAlerts []*github.DependabotAlert
	seenCursors := map[string]struct{}{}
	for {
		alerts, resp, err := client.Dependabot.ListRepoAlerts(ctx, ownerLogin, repoName, listOpts)
		if err != nil {
			return nil, err
		}
		allAlerts = append(allAlerts, alerts...)
		if resp.After == "" {
			break
		}
		// A server that keeps handing back a cursor we already followed would
		// otherwise loop forever, re-collecting the same page.
		if _, ok := seenCursors[resp.After]; ok {
			break
		}
		seenCursors[resp.After] = struct{}{}
		listOpts.ListCursorOptions.After = resp.After
	}
	return allAlerts, nil
}

func (g *mqlGithubRepository) dependabotAlerts() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	allAlerts, err := listDependabotAlertsRaw(conn.Context(), conn.Client(), ownerLogin, repoName)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		// Dependabot alerts may not be enabled or accessible
		if strings.Contains(err.Error(), "403") {
			log.Debug().Msg("Dependabot alerts are not accessible for this repository")
			return nil, nil
		}
		return nil, err
	}

	res := []any{}
	for _, alert := range allAlerts {
		var dismissedBy any
		if alert.DismissedBy != nil {
			var err error
			dismissedBy, err = NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(alert.DismissedBy.ID),
				"login": llx.StringDataPtr(alert.DismissedBy.Login),
			})
			if err != nil {
				return nil, err
			}
		}

		dependency, err := convert.JsonToDict(alert.Dependency)
		if err != nil {
			return nil, err
		}

		securityAdvisory, err := convert.JsonToDict(alert.SecurityAdvisory)
		if err != nil {
			return nil, err
		}

		securityVulnerability, err := convert.JsonToDict(alert.SecurityVulnerability)
		if err != nil {
			return nil, err
		}

		mqlAlert, err := CreateResource(g.MqlRuntime, "github.dependabotAlert", map[string]*llx.RawData{
			"__id":                  llx.StringData(alertID("github.dependabotAlert", ownerLogin, repoName, int64(alert.GetNumber()))),
			"number":                llx.IntData(int64(alert.GetNumber())),
			"state":                 llx.StringData(alert.GetState()),
			"severity":              llx.StringData(alert.GetSecurityVulnerability().GetSeverity()),
			"dependency":            llx.DictData(dependency),
			"securityAdvisory":      llx.DictData(securityAdvisory),
			"securityVulnerability": llx.DictData(securityVulnerability),
			"url":                   llx.StringData(alert.GetURL()),
			"htmlUrl":               llx.StringData(alert.GetHTMLURL()),
			"createdAt":             llx.TimeDataPtr(githubTimestamp(alert.CreatedAt)),
			"updatedAt":             llx.TimeDataPtr(githubTimestamp(alert.UpdatedAt)),
			"dismissedAt":           llx.TimeDataPtr(githubTimestamp(alert.DismissedAt)),
			"fixedAt":               llx.TimeDataPtr(githubTimestamp(alert.FixedAt)),
			"autoDismissedAt":       llx.TimeDataPtr(githubTimestamp(alert.AutoDismissedAt)),
			"dismissedBy":           llx.AnyData(dismissedBy),
			"dismissedReason":       llx.StringData(alert.GetDismissedReason()),
			"dismissedComment":      llx.StringData(alert.GetDismissedComment()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAlert)
	}

	return res, nil
}

func (g *mqlGithubSecretScanningAlert) id() (string, error) {
	if g.Number.Error != nil {
		return "", g.Number.Error
	}
	return "github.secretScanningAlert/" + strconv.FormatInt(g.Number.Data, 10), nil
}

func (g *mqlGithubRepository) secretScanningAlerts() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.SecretScanningAlertListOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}

	var allAlerts []*github.SecretScanningAlert
	for {
		alerts, resp, err := conn.Client().SecretScanning.ListAlertsForRepo(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			// Secret scanning may not be enabled or accessible
			if strings.Contains(err.Error(), "403") {
				log.Debug().Msg("Secret scanning alerts are not accessible for this repository")
				return nil, nil
			}
			return nil, err
		}
		allAlerts = append(allAlerts, alerts...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.ListOptions.Page = resp.NextPage
	}

	res := []any{}
	for _, alert := range allAlerts {
		var resolvedBy any
		if alert.ResolvedBy != nil {
			var err error
			resolvedBy, err = NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(alert.ResolvedBy.ID),
				"login": llx.StringDataPtr(alert.ResolvedBy.Login),
			})
			if err != nil {
				return nil, err
			}
		}

		var pushProtectionBypassedBy any
		if alert.PushProtectionBypassedBy != nil {
			var err error
			pushProtectionBypassedBy, err = NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(alert.PushProtectionBypassedBy.ID),
				"login": llx.StringDataPtr(alert.PushProtectionBypassedBy.Login),
			})
			if err != nil {
				return nil, err
			}
		}

		mqlAlert, err := CreateResource(g.MqlRuntime, "github.secretScanningAlert", map[string]*llx.RawData{
			"__id":                     llx.StringData(alertID("github.secretScanningAlert", ownerLogin, repoName, int64(alert.GetNumber()))),
			"number":                   llx.IntData(int64(alert.GetNumber())),
			"state":                    llx.StringData(alert.GetState()),
			"resolution":               llx.StringData(alert.GetResolution()),
			"secretType":               llx.StringData(alert.GetSecretType()),
			"secretTypeDisplayName":    llx.StringData(alert.GetSecretTypeDisplayName()),
			"secret":                   llx.StringData(alert.GetSecret()),
			"validity":                 llx.StringData(alert.GetValidity()),
			"publiclyLeaked":           llx.BoolData(alert.GetPubliclyLeaked()),
			"multiRepo":                llx.BoolData(alert.GetMultiRepo()),
			"url":                      llx.StringData(alert.GetURL()),
			"htmlUrl":                  llx.StringData(alert.GetHTMLURL()),
			"createdAt":                llx.TimeDataPtr(githubTimestamp(alert.CreatedAt)),
			"updatedAt":                llx.TimeDataPtr(githubTimestamp(alert.UpdatedAt)),
			"resolvedAt":               llx.TimeDataPtr(githubTimestamp(alert.ResolvedAt)),
			"resolvedBy":               llx.AnyData(resolvedBy),
			"pushProtectionBypassed":   llx.BoolData(alert.GetPushProtectionBypassed()),
			"pushProtectionBypassedBy": llx.AnyData(pushProtectionBypassedBy),
			"pushProtectionBypassedAt": llx.TimeDataPtr(githubTimestamp(alert.PushProtectionBypassedAt)),
			"resolutionComment":        llx.StringData(alert.GetResolutionComment()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAlert)
	}

	return res, nil
}

func (g *mqlGithubCodeScanningAlert) id() (string, error) {
	if g.Number.Error != nil {
		return "", g.Number.Error
	}
	return "github.codeScanningAlert/" + strconv.FormatInt(g.Number.Data, 10), nil
}

// codeScanningEnabled answers whether the repository has code scanning
// configured at all. codeScanningAlerts returns an empty list both for a
// repository with no findings and for one that never enabled scanning, so a
// check asserting there are no open alerts cannot tell the two apart without
// this.
//
// Two endpoints are needed because the two setup modes report differently.
// Default setup is visible on the default-setup endpoint. Advanced setup runs
// from a GitHub Actions workflow, never reports a configured default setup,
// and shows up only as uploaded analyses.
func (g *mqlGithubRepository) codeScanningEnabled() (bool, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return false, err
	}

	setup, setupErr := g.defaultSetupConfig()
	if setupErr == nil && setup.GetState() == "configured" {
		return true, nil
	}

	analyses, _, analysisErr := conn.Client().CodeScanning.ListAnalysesForRepo(conn.Context(), ownerLogin, repoName,
		&github.AnalysesListOptions{ListOptions: github.ListOptions{PerPage: 1}})
	if analysisErr == nil {
		return len(analyses) > 0, nil
	}

	// A repository with scanning available but no analysis yet answers 404
	// here, which is a real negative rather than an unknown, provided the
	// default-setup endpoint answered.
	if githubResponseStatus(analysisErr) == http.StatusNotFound && setupErr == nil {
		return false, nil
	}

	log.Debug().
		Str("owner", ownerLogin).Str("repo", repoName).
		AnErr("defaultSetup", setupErr).AnErr("analyses", analysisErr).
		Msg("unable to determine whether code scanning is enabled")
	g.CodeScanningEnabled.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

func (g *mqlGithubRepository) codeScanningAlerts() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.AlertListOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}

	var allAlerts []*github.Alert
	for {
		alerts, resp, err := conn.Client().CodeScanning.ListAlertsForRepo(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			// Code scanning may not be enabled or accessible
			if strings.Contains(err.Error(), "403") {
				log.Debug().Msg("Code scanning alerts are not accessible for this repository")
				return nil, nil
			}
			return nil, err
		}
		allAlerts = append(allAlerts, alerts...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.ListOptions.Page = resp.NextPage
	}

	res := []any{}
	for _, alert := range allAlerts {
		var closedBy any
		if alert.ClosedBy != nil {
			var err error
			closedBy, err = NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(alert.ClosedBy.ID),
				"login": llx.StringDataPtr(alert.ClosedBy.Login),
			})
			if err != nil {
				return nil, err
			}
		}

		var dismissedBy any
		if alert.DismissedBy != nil {
			var err error
			dismissedBy, err = NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataPtr(alert.DismissedBy.ID),
				"login": llx.StringDataPtr(alert.DismissedBy.Login),
			})
			if err != nil {
				return nil, err
			}
		}

		rule, err := convert.JsonToDict(alert.Rule)
		if err != nil {
			return nil, err
		}

		tool, err := convert.JsonToDict(alert.Tool)
		if err != nil {
			return nil, err
		}

		mostRecentInstance, err := convert.JsonToDict(alert.MostRecentInstance)
		if err != nil {
			return nil, err
		}

		mqlAlert, err := CreateResource(g.MqlRuntime, "github.codeScanningAlert", map[string]*llx.RawData{
			"__id":               llx.StringData(alertID("github.codeScanningAlert", ownerLogin, repoName, int64(alert.GetNumber()))),
			"number":             llx.IntData(int64(alert.GetNumber())),
			"state":              llx.StringData(alert.GetState()),
			"rule":               llx.DictData(rule),
			"tool":               llx.DictData(tool),
			"url":                llx.StringData(alert.GetURL()),
			"htmlUrl":            llx.StringData(alert.GetHTMLURL()),
			"createdAt":          llx.TimeDataPtr(githubTimestamp(alert.CreatedAt)),
			"updatedAt":          llx.TimeDataPtr(githubTimestamp(alert.UpdatedAt)),
			"fixedAt":            llx.TimeDataPtr(githubTimestamp(alert.FixedAt)),
			"closedAt":           llx.TimeDataPtr(githubTimestamp(alert.ClosedAt)),
			"closedBy":           llx.AnyData(closedBy),
			"dismissedAt":        llx.TimeDataPtr(githubTimestamp(alert.DismissedAt)),
			"dismissedBy":        llx.AnyData(dismissedBy),
			"dismissedReason":    llx.StringData(alert.GetDismissedReason()),
			"dismissedComment":   llx.StringData(alert.GetDismissedComment()),
			"mostRecentInstance": llx.DictData(mostRecentInstance),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAlert)
	}

	return res, nil
}

func (g *mqlGithubRepository) spdxSbom() (*mqlGithubRepositorySbom, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	result, _, err := conn.Client().DependencyGraph.GetSBOM(conn.Context(), ownerLogin, repoName)
	if err != nil {
		// The dependency graph is not enabled on every repository, and reading
		// it needs its own permission; both are a valid empty state.
		if isAccessDeniedOrNotFound(err) {
			log.Debug().Err(err).Msg("SPDX SBOM is not accessible for this repository")
			g.SpdxSbom.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if result == nil || result.SBOM == nil {
		g.SpdxSbom.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	info := result.SBOM

	var createdAt *time.Time
	if info.CreationInfo != nil && info.CreationInfo.Created != nil {
		createdAt = &info.CreationInfo.Created.Time
	}

	creators := []any{}
	if info.CreationInfo != nil {
		for _, c := range info.CreationInfo.Creators {
			creators = append(creators, c)
		}
	}

	packages := make([]any, 0, len(info.Packages))
	for i, pkg := range info.Packages {
		externalRefs := make([]any, 0, len(pkg.ExternalRefs))
		for j, ref := range pkg.ExternalRefs {
			mqlExternalRef, err := CreateResource(g.MqlRuntime, ResourceGithubRepositorySbomPackageExternalRef, map[string]*llx.RawData{
				"__id":              llx.StringData(fmt.Sprintf("%s/%s/%s/%d/%d", ResourceGithubRepositorySbomPackageExternalRef, ownerLogin, repoName, i, j)),
				"referenceCategory": llx.StringData(ref.ReferenceCategory),
				"referenceType":     llx.StringData(ref.ReferenceType),
				"referenceLocator":  llx.StringData(ref.ReferenceLocator),
			})
			if err != nil {
				return nil, err
			}
			externalRefs = append(externalRefs, mqlExternalRef)
		}
		mqlPkg, err := CreateResource(g.MqlRuntime, ResourceGithubRepositorySbomPackage, map[string]*llx.RawData{
			"__id":             llx.StringData(fmt.Sprintf("%s/%s/%s/%d", ResourceGithubRepositorySbomPackage, ownerLogin, repoName, i)),
			"spdxId":           llx.StringDataPtr(pkg.SPDXID),
			"name":             llx.StringDataPtr(pkg.Name),
			"versionInfo":      llx.StringDataPtr(pkg.VersionInfo),
			"downloadLocation": llx.StringDataPtr(pkg.DownloadLocation),
			"filesAnalyzed":    llx.BoolDataPtr(pkg.FilesAnalyzed),
			"licenseConcluded": llx.StringDataPtr(pkg.LicenseConcluded),
			"licenseDeclared":  llx.StringDataPtr(pkg.LicenseDeclared),
			"externalRefs":     llx.ArrayData(externalRefs, types.Resource(ResourceGithubRepositorySbomPackageExternalRef)),
		})
		if err != nil {
			return nil, err
		}
		packages = append(packages, mqlPkg)
	}

	relationships := make([]any, 0, len(info.Relationships))
	for i, rel := range info.Relationships {
		mqlRel, err := CreateResource(g.MqlRuntime, ResourceGithubRepositorySbomRelationship, map[string]*llx.RawData{
			"__id":               llx.StringData(fmt.Sprintf("%s/%s/%s/%d", ResourceGithubRepositorySbomRelationship, ownerLogin, repoName, i)),
			"relationshipType":   llx.StringData(rel.RelationshipType),
			"spdxElementId":      llx.StringData(rel.SPDXElementID),
			"relatedSpdxElement": llx.StringData(rel.RelatedSPDXElement),
		})
		if err != nil {
			return nil, err
		}
		relationships = append(relationships, mqlRel)
	}

	mqlSbom, err := CreateResource(g.MqlRuntime, ResourceGithubRepositorySbom, map[string]*llx.RawData{
		"__id":              llx.StringData(ResourceGithubRepositorySbom + "/" + ownerLogin + "/" + repoName),
		"spdxId":            llx.StringDataPtr(info.SPDXID),
		"spdxVersion":       llx.StringDataPtr(info.SPDXVersion),
		"name":              llx.StringDataPtr(info.Name),
		"dataLicense":       llx.StringDataPtr(info.DataLicense),
		"documentNamespace": llx.StringDataPtr(info.DocumentNamespace),
		"createdAt":         llx.TimeDataPtr(createdAt),
		"creators":          llx.ArrayData(creators, types.String),
		"packages":          llx.ArrayData(packages, types.Resource(ResourceGithubRepositorySbomPackage)),
		"relationships":     llx.ArrayData(relationships, types.Resource(ResourceGithubRepositorySbomRelationship)),
	})
	if err != nil {
		return nil, err
	}
	return mqlSbom.(*mqlGithubRepositorySbom), nil
}

func (g *mqlGithubRepositoryRuleset) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubRepository) rulesets() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.RepositoryListRulesetsOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var allRulesets []*github.RepositoryRuleset
	for {
		rulesets, resp, err := conn.Client().Repositories.GetAllRulesets(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "403") {
				return nil, nil
			}
			return nil, err
		}
		allRulesets = append(allRulesets, rulesets...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := make([]any, 0, len(allRulesets))
	for _, rs := range allRulesets {
		r, err := newMqlRepositoryRuleset(g.MqlRuntime, ownerLogin+"/"+repoName, rs)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGithubRepositoryActionsSettings) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubRepository) actionsSettings() (*mqlGithubRepositoryActionsSettings, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	perms, _, err := conn.Client().Repositories.GetActionsPermissions(conn.Context(), ownerLogin, repoName)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "403") {
			g.ActionsSettings.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	wfPerms, _, err := conn.Client().Repositories.GetDefaultWorkflowPermissions(conn.Context(), ownerLogin, repoName)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "403") {
			g.ActionsSettings.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var defaultWfPerms string
	var canApprove bool
	if wfPerms != nil {
		defaultWfPerms = wfPerms.GetDefaultWorkflowPermissions()
		canApprove = wfPerms.GetCanApprovePullRequestReviews()
	}

	res, err := CreateResource(g.MqlRuntime, "github.repositoryActionsSettings", map[string]*llx.RawData{
		"__id":                         llx.StringData("github.repositoryActionsSettings/" + ownerLogin + "/" + repoName),
		"enabled":                      llx.BoolDataPtr(perms.Enabled),
		"allowedActions":               llx.StringDataPtr(perms.AllowedActions),
		"shaPinningRequired":           llx.BoolDataPtr(perms.SHAPinningRequired),
		"defaultWorkflowPermissions":   llx.StringData(defaultWfPerms),
		"canApprovePullRequestReviews": llx.BoolData(canApprove),
	})
	if err != nil {
		return nil, err
	}
	settings := res.(*mqlGithubRepositoryActionsSettings)
	settings.ownerLogin = ownerLogin
	settings.repoName = repoName
	return settings, nil
}

// githubResponseStatus returns the HTTP status code of a go-github error, or
// 0 when err is not an *github.ErrorResponse. Used to classify 404 (feature
// does not apply) versus 403 (no permission) without brittle substring
// matching on err.Error().
func githubResponseStatus(err error) int {
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode
	}
	return 0
}

func (g *mqlGithubRepository) vulnerabilityAlertsEnabled() (bool, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return false, err
	}
	enabled, _, err := conn.Client().Repositories.GetVulnerabilityAlerts(conn.Context(), ownerLogin, repoName)
	if err != nil {
		switch githubResponseStatus(err) {
		case http.StatusNotFound:
			// Feature does not apply to this repo (e.g., archived repos
			// where the setting is disabled at the org level). Surface
			// as `false` cleanly.
			return false, nil
		case http.StatusForbidden:
			// Caller lacks permission to read the setting. Returning
			// `false` would falsely report "alerts disabled", so we log
			// a warning to surface the unreliable result and still
			// return false so the rest of the audit row renders.
			log.Warn().Err(err).Str("owner", ownerLogin).Str("repo", repoName).
				Msg("permission denied reading vulnerability-alerts setting; reporting as disabled")
			return false, nil
		}
		return false, err
	}
	return enabled, nil
}

func privateVulnerabilityReportingEnabledRaw(ctx context.Context, client *github.Client, ownerLogin, repoName string) (bool, error) {
	enabled, _, err := client.Repositories.IsPrivateReportingEnabled(ctx, ownerLogin, repoName)
	if err != nil {
		switch githubResponseStatus(err) {
		case http.StatusNotFound:
			return false, nil
		case http.StatusUnprocessableEntity:
			// GitHub answers 422 "Repository must be public and not archived"
			// for every private or archived repository. The setting genuinely
			// cannot be on for those, so this is a normal answer, not a
			// failure: letting it escape fails the entire repository listing
			// this field was read from.
			log.Debug().Str("owner", ownerLogin).Str("repo", repoName).
				Msg("private vulnerability reporting is unavailable for this repository (private or archived)")
			return false, nil
		case http.StatusForbidden:
			log.Warn().Err(err).Str("owner", ownerLogin).Str("repo", repoName).
				Msg("permission denied reading private-vulnerability-reporting setting; reporting as disabled")
			return false, nil
		}
		return false, err
	}
	return enabled, nil
}

func (g *mqlGithubRepository) privateVulnerabilityReportingEnabled() (bool, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return false, err
	}
	return privateVulnerabilityReportingEnabledRaw(conn.Context(), conn.Client(), ownerLogin, repoName)
}
