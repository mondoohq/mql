// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"go.mondoo.com/mql/types"
)

// mqlGitlabProjectInternal caches the full project payload from
// `GET /projects/:id` so multiple lazy fields (mergeMethod,
// containerExpirationPolicy, …) share one API call rather than each issuing
// its own GetProject for a different scalar.
type mqlGitlabProjectInternal struct {
	detailsOnce       sync.Once
	details           *gitlab.Project
	detailsCI         *projectCIPolicy
	detailsErr        error
	detailsStatusCode int
}

// projectCIPolicy is the pointer-typed view of the project CI/CD settings this
// provider reports as posture. GitLab omits these attributes for a token below
// the Maintainer role, and the SDK types them as a plain bool and slice, so an
// omitted attribute would otherwise read as "fork pipelines cannot run here"
// on a project nobody was actually allowed to check.
type projectCIPolicy struct {
	IDTokenSubClaimComponents       []string `json:"ci_id_token_sub_claim_components"`
	AllowForkPipelinesToRunInParent *bool    `json:"ci_allow_fork_pipelines_to_run_in_parent_project"`
}

// projectDetails returns the full *gitlab.Project payload, fetching it on
// first call and reusing it thereafter. Used by lazy accessors that need
// fields not seeded by getGitlabProjectArgs (MergeMethod,
// ContainerExpirationPolicy, etc.). detailsStatusCode is set whenever the
// SDK gave us a response, so callers can distinguish access-denied/missing
// (silent null) from real transport errors (propagate).
func (p *mqlGitlabProject) projectDetails(conn *connection.GitLabConnection) (*gitlab.Project, error) {
	p.detailsOnce.Do(func() {
		var raw json.RawMessage
		resp, err := getRawJSON(conn.Client(), "projects/"+strconv.FormatInt(p.Id.Data, 10), nil, &raw)
		if resp != nil {
			p.detailsStatusCode = resp.StatusCode
		}
		if err != nil {
			p.detailsErr = err
			return
		}

		project := &gitlab.Project{}
		if err := json.Unmarshal(raw, project); err != nil {
			p.detailsErr = err
			return
		}
		ci := &projectCIPolicy{}
		if err := json.Unmarshal(raw, ci); err != nil {
			p.detailsErr = err
			return
		}

		p.details = project
		p.detailsCI = ci
	})
	return p.details, p.detailsErr
}

func getGitlabProjectArgs(prj *gitlab.Project) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"allowMergeOnSkippedPipeline": llx.BoolData(prj.AllowMergeOnSkippedPipeline),
		"archived":                    llx.BoolData(prj.Archived),
		"autocloseReferencedIssues":   llx.BoolData(prj.AutocloseReferencedIssues),
		"autoDevopsEnabled":           llx.BoolData(prj.AutoDevopsEnabled),
		"createdAt":                   llx.TimeDataPtr(prj.CreatedAt),
		"defaultBranch":               llx.StringData(prj.DefaultBranch),
		"description":                 llx.StringData(prj.Description),
		"emptyRepo":                   llx.BoolData(prj.EmptyRepo),
		"fullName":                    llx.StringData(prj.NameWithNamespace),
		"fullPath":                    llx.StringData(prj.PathWithNamespace),
		"groupRunnersEnabled":         llx.BoolData(prj.GroupRunnersEnabled),
		"id":                          llx.IntData(int64(prj.ID)),
		"lfsEnabled":                  llx.BoolData(prj.LFSEnabled),
		"mirror":                      llx.BoolData(prj.Mirror),
		"name":                        llx.StringData(prj.Name),
		"onlyAllowMergeIfAllDiscussionsAreResolved": llx.BoolData(prj.OnlyAllowMergeIfAllDiscussionsAreResolved),
		"onlyAllowMergeIfPipelineSucceeds":          llx.BoolData(prj.OnlyAllowMergeIfPipelineSucceeds),
		"packagesEnabled":                           llx.BoolData(prj.PackagesEnabled),
		"path":                                      llx.StringData(prj.Path),
		"removeSourceBranchAfterMerge":              llx.BoolData(prj.RemoveSourceBranchAfterMerge),
		"requirementsEnabled":                       llx.BoolData(prj.RequirementsEnabled),
		"serviceDeskEnabled":                        llx.BoolData(prj.ServiceDeskEnabled),
		"sharedRunnersEnabled":                      llx.BoolData(prj.SharedRunnersEnabled),
		"visibility":                                llx.StringData(string(prj.Visibility)),
		"webURL":                                    llx.StringData(prj.WebURL),
		"forksCount":                                llx.IntData(prj.ForksCount),
		"starCount":                                 llx.IntData(prj.StarCount),
		"lastActivityAt":                            llx.TimeDataPtr(prj.LastActivityAt),
		"emailsEnabled":                             llx.BoolData(prj.EmailsEnabled),
		"issuesAccessLevel":                         llx.StringData(string(prj.IssuesAccessLevel)),
		"mergeRequestsAccessLevel":                  llx.StringData(string(prj.MergeRequestsAccessLevel)),
		"wikiAccessLevel":                           llx.StringData(string(prj.WikiAccessLevel)),
		"snippetsAccessLevel":                       llx.StringData(string(prj.SnippetsAccessLevel)),
		"containerRegistryAccessLevel":              llx.StringData(string(prj.ContainerRegistryAccessLevel)),
		"buildsAccessLevel":                         llx.StringData(string(prj.BuildsAccessLevel)),
		"repositoryAccessLevel":                     llx.StringData(string(prj.RepositoryAccessLevel)),
		"forkingAccessLevel":                        llx.StringData(string(prj.ForkingAccessLevel)),
		"securityAndComplianceAccessLevel":          llx.StringData(string(prj.SecurityAndComplianceAccessLevel)),
		"securityAndComplianceEnabled":              llx.BoolData(prj.SecurityAndComplianceEnabled),
		"ciJobTokenScopeEnabled":                    llx.BoolData(prj.CIJobTokenScopeEnabled),
		"publicJobs":                                llx.BoolData(prj.PublicJobs),
		"preReceiveSecretDetectionEnabled":          llx.BoolData(prj.PreReceiveSecretDetectionEnabled),
		"complianceFrameworks":                      llx.ArrayData(convert.SliceAnyToInterface(prj.ComplianceFrameworks), types.String),
		"sharedWithGroups":                          llx.ArrayData(projectSharedGroupsToDicts(prj.SharedWithGroups), types.Dict),
		"mirrorTriggerBuilds":                       llx.BoolData(prj.MirrorTriggerBuilds),
		"onlyMirrorProtectedBranches":               llx.BoolData(prj.OnlyMirrorProtectedBranches),
		"autoDuoCodeReviewEnabled":                  llx.BoolData(prj.AutoDuoCodeReviewEnabled),
		"modelExperimentsAccessLevel":               llx.StringData(string(prj.ModelExperimentsAccessLevel)),
		"modelRegistryAccessLevel":                  llx.StringData(string(prj.ModelRegistryAccessLevel)),
	}
}

// projectSharedGroupsToDicts flattens the groups a project is shared with into
// queryable dicts (group identity + the access level granted to that group).
func projectSharedGroupsToDicts(groups []gitlab.ProjectSharedWithGroup) []any {
	out := make([]any, 0, len(groups))
	for _, g := range groups {
		out = append(out, map[string]any{
			"groupId":          int64(g.GroupID),
			"groupName":        g.GroupName,
			"groupFullPath":    g.GroupFullPath,
			"groupAccessLevel": int64(g.GroupAccessLevel),
		})
	}
	return out
}

func (g *mqlGitlabProject) id() (string, error) {
	return "gitlab.project/" + strconv.FormatInt(g.Id.Data, 10), nil
}

// forkedFromProject returns the project this project was forked from, or null
// when it is not a fork. The fork parent is read from the full project payload
// (shared via projectDetails); access-denied/missing yields null rather than
// failing the resource graph.
func (p *mqlGitlabProject) forkedFromProject() (*mqlGitlabProject, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	details, err := p.projectDetails(conn)
	if err != nil {
		if p.detailsStatusCode == 403 || p.detailsStatusCode == 404 {
			p.ForkedFromProject.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if details == nil || details.ForkedFromProject == nil || details.ForkedFromProject.ID <= 0 {
		p.ForkedFromProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(p.MqlRuntime, "gitlab.project", map[string]*llx.RawData{
		"id": llx.IntData(details.ForkedFromProject.ID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabProject), nil
}

// init initializes the gitlab project with the arguments
func initGitlabProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.GitLabConnection)

	// If only id is provided, fetch the project by id - used by typed refs
	// (e.g. webhook.project(), deployKey.project(), auditEvent.entityProject()).
	// 403/404 yields a bare resource so the typed back-ref doesn't fail the
	// whole resource graph on insufficient perms.
	if idArg, ok := args["id"]; ok && idArg != nil && idArg.Error == nil {
		pid, ok := idArg.Value.(int64)
		if !ok {
			return nil, nil, errors.New("gitlab.project: id must be an integer")
		}
		project, resp, err := conn.Client().Projects.GetProject(int(pid), nil)
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return args, nil, nil
			}
			return nil, nil, err
		}
		args = getGitlabProjectArgs(project)
		return args, nil, nil
	}

	// GetProject also accepts a URL-encoded full path, and the SDK escapes it
	// for us. Without this branch, `gitlab.project(fullPath: "acme/other")`
	// fell through to the connection's own project and then overwrote fullPath
	// with that project's value — returning a fully-populated resource for a
	// different project than the caller asked for.
	if pathArg, ok := args["fullPath"]; ok && pathArg != nil && pathArg.Error == nil {
		fullPath, ok := pathArg.Value.(string)
		if !ok || fullPath == "" {
			return nil, nil, errors.New("gitlab.project: fullPath must be a non-empty string")
		}
		project, _, err := conn.Client().Projects.GetProject(fullPath, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("gitlab.project with fullPath %q not found: %w", fullPath, err)
		}
		args = getGitlabProjectArgs(project)
		return args, nil, nil
	}

	project, err := conn.Project()
	if err != nil {
		return nil, nil, err
	}

	args = getGitlabProjectArgs(project)
	return args, nil, nil
}

// approvalSettings fetches project approval settings
func (p *mqlGitlabProject) approvalSettings() (*mqlGitlabProjectApprovalSetting, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)
	approvalConfig, _, err := conn.Client().Projects.GetApprovalConfiguration(projectID)
	if err != nil {
		return nil, err
	}

	approverUsers := make([]any, 0, len(approvalConfig.Approvers))
	for _, a := range approvalConfig.Approvers {
		if a == nil || a.User == nil {
			continue
		}
		u, err := NewResource(p.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
			"id": llx.IntData(a.User.ID),
		})
		if err != nil {
			return nil, err
		}
		approverUsers = append(approverUsers, u)
	}

	approverGroups := make([]any, 0, len(approvalConfig.ApproverGroups))
	for _, g := range approvalConfig.ApproverGroups {
		if g == nil {
			continue
		}
		grp, err := NewResource(p.MqlRuntime, "gitlab.group", map[string]*llx.RawData{
			"id": llx.IntData(g.Group.ID),
		})
		if err != nil {
			return nil, err
		}
		approverGroups = append(approverGroups, grp)
	}

	approvalSettings := map[string]*llx.RawData{
		"__id":                 llx.StringData(projectScopedID("gitlab.project.approvalSetting", p.Id.Data)),
		"approvalsBeforeMerge": llx.IntData(int64(approvalConfig.ApprovalsBeforeMerge)),
		"resetApprovalsOnPush": llx.BoolData(approvalConfig.ResetApprovalsOnPush),
		"disableOverridingApproversPerMergeRequest": llx.BoolData(approvalConfig.DisableOverridingApproversPerMergeRequest),
		"mergeRequestsAuthorApproval":               llx.BoolData(approvalConfig.MergeRequestsAuthorApproval),
		"mergeRequestsDisableCommittersApproval":    llx.BoolData(approvalConfig.MergeRequestsDisableCommittersApproval),
		"requirePasswordToApprove":                  llx.BoolData(approvalConfig.RequirePasswordToApprove),
		"selectiveCodeOwnerRemovals":                llx.BoolData(approvalConfig.SelectiveCodeOwnerRemovals),
		"approvers":                                 llx.ArrayData(approverUsers, types.Resource("gitlab.user")),
		"approverGroups":                            llx.ArrayData(approverGroups, types.Resource("gitlab.group")),
	}

	mqlApprovalSettings, err := CreateResource(p.MqlRuntime, "gitlab.project.approvalSetting", approvalSettings)
	if err != nil {
		return nil, err
	}

	return mqlApprovalSettings.(*mqlGitlabProjectApprovalSetting), nil
}

// approvalRules fetches project approval rules
func (p *mqlGitlabProject) approvalRules() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)
	perPage := int64(50)
	page := int64(1)
	var approvals []*gitlab.ProjectApprovalRule
	for {
		rules, resp, err := conn.Client().Projects.GetProjectApprovalRules(projectID, &gitlab.GetProjectApprovalRulesListsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage},
		})
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, rules...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	defaultBranchName := p.DefaultBranch.Data

	approvalRules := make([]any, 0, len(approvals))
	for _, rule := range approvals {
		users, err := basicUsersToMqlUsers(p.MqlRuntime, rule.Users)
		if err != nil {
			return nil, err
		}
		eligible, err := basicUsersToMqlUsers(p.MqlRuntime, rule.EligibleApprovers)
		if err != nil {
			return nil, err
		}
		branches, err := approvalRuleProtectedBranches(p.MqlRuntime, p.Id.Data, rule.ProtectedBranches, defaultBranchName)
		if err != nil {
			return nil, err
		}

		approvalRule := map[string]*llx.RawData{
			"id":                            llx.IntData(rule.ID),
			"name":                          llx.StringData(rule.Name),
			"approvalsRequired":             llx.IntData(rule.ApprovalsRequired),
			"ruleType":                      llx.StringData(rule.RuleType),
			"reportType":                    llx.StringData(rule.ReportType),
			"appliesToAllProtectedBranches": llx.BoolData(rule.AppliesToAllProtectedBranches),
			"containsHiddenGroups":          llx.BoolData(rule.ContainsHiddenGroups),
			"users":                         llx.ArrayData(users, types.Resource("gitlab.user")),
			"eligibleApprovers":             llx.ArrayData(eligible, types.Resource("gitlab.user")),
			"groups":                        llx.ArrayData(groupsToDicts(rule.Groups), types.Dict),
			"protectedBranches":             llx.ArrayData(branches, types.Resource("gitlab.project.protectedBranch")),
		}
		mqlApprovalRule, err := CreateResource(p.MqlRuntime, "gitlab.project.approvalRule", approvalRule)
		if err != nil {
			return nil, err
		}
		approvalRules = append(approvalRules, mqlApprovalRule)
	}

	return approvalRules, nil
}

// basicUsersToMqlUsers converts SDK BasicUser entries into gitlab.user
// resources via NewResource. BasicUser only carries a subset of the fields
// gitlab.user declares (no email, 2FA, bot, job/org/location, etc.), so
// instead of seeding the runtime cache with hardcoded zero values — which
// would poison the cache for any later `gitlab.users` query that returns
// real data on the same id — we hand only the id to NewResource and let
// `initGitlabUser` lazily fetch the full record on first access.
func basicUsersToMqlUsers(runtime *plugin.Runtime, users []*gitlab.BasicUser) ([]any, error) {
	out := make([]any, 0, len(users))
	for _, u := range users {
		if u == nil {
			continue
		}
		mqlUser, err := NewResource(runtime, "gitlab.user", map[string]*llx.RawData{
			"id": llx.IntData(u.ID),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, mqlUser)
	}
	return out, nil
}

// groupsToDicts flattens the linked-group summaries the API returns alongside
// an approval rule. A typed gitlab.group resource carries far more fields than
// the approval-rule payload provides, so we expose the subset as a dict.
func groupsToDicts(groups []*gitlab.Group) []any {
	out := make([]any, 0, len(groups))
	for _, g := range groups {
		if g == nil {
			continue
		}
		out = append(out, map[string]any{
			"id":          g.ID,
			"name":        g.Name,
			"fullPath":    g.FullPath,
			"visibility":  string(g.Visibility),
			"description": g.Description,
		})
	}
	return out
}

// newMqlProtectedBranch builds a gitlab.project.protectedBranch from the SDK
// type. Both gitlab.project.protectedBranches() and the approval-rule path go
// through here so the two producers agree on the cache key *and* on the field
// set: a branch built by one and then fetched through the other must not be
// missing its access levels.
//
// The cache key is project-qualified because a branch name ("main") is only
// unique within a project. Keying on the name alone made every project in a
// `gitlab.group.projects { protectedBranches }` query resolve to the first
// project's branch settings.
func newMqlProtectedBranch(runtime *plugin.Runtime, projectID int64, b *gitlab.ProtectedBranch, defaultBranchName string) (plugin.Resource, error) {
	prefix := projectScopedID("gitlab.project.protectedBranch", projectID, b.Name)

	push, err := projectBranchAccessLevels(runtime, prefix+"/push", b.PushAccessLevels)
	if err != nil {
		return nil, err
	}
	merge, err := projectBranchAccessLevels(runtime, prefix+"/merge", b.MergeAccessLevels)
	if err != nil {
		return nil, err
	}
	unprotect, err := projectBranchAccessLevels(runtime, prefix+"/unprotect", b.UnprotectAccessLevels)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "gitlab.project.protectedBranch", map[string]*llx.RawData{
		"__id":                  llx.StringData(prefix),
		"name":                  llx.StringData(b.Name),
		"allowForcePush":        llx.BoolData(b.AllowForcePush),
		"defaultBranch":         llx.BoolData(b.Name == defaultBranchName),
		"codeOwnerApproval":     llx.BoolData(b.CodeOwnerApprovalRequired),
		"pushAccessLevels":      llx.ArrayData(push, types.Resource("gitlab.protectedBranch.accessLevel")),
		"mergeAccessLevels":     llx.ArrayData(merge, types.Resource("gitlab.protectedBranch.accessLevel")),
		"unprotectAccessLevels": llx.ArrayData(unprotect, types.Resource("gitlab.protectedBranch.accessLevel")),
	})
}

// approvalRuleProtectedBranches constructs the per-branch sub-resources
// associated with an approval rule. defaultBranchName comes from the parent
// project so each branch's `defaultBranch` flag stays consistent with the
// values surfaced by gitlab.project.protectedBranches(). The GitLab
// `/approval_rules` response embeds the full ProtectedBranch object, not a
// name-only summary, so the shared constructor can populate every field.
func approvalRuleProtectedBranches(runtime *plugin.Runtime, projectID int64, branches []*gitlab.ProtectedBranch, defaultBranchName string) ([]any, error) {
	out := make([]any, 0, len(branches))
	for _, b := range branches {
		if b == nil {
			continue
		}
		mqlBranch, err := newMqlProtectedBranch(runtime, projectID, b, defaultBranchName)
		if err != nil {
			return nil, err
		}
		out = append(out, mqlBranch)
	}
	return out, nil
}

// mergeMethod fetches the project merge method
func (p *mqlGitlabProject) mergeMethod() (string, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	project, err := p.projectDetails(conn)
	if err != nil {
		// Stay consistent with containerExpirationPolicy and initGitlabProject:
		// 403/404 on the shared GetProject call shouldn't fail a broader query
		// just because the token can't read this scalar.
		if p.detailsStatusCode == 403 || p.detailsStatusCode == 404 {
			return "", nil
		}
		return "", err
	}

	var mergeMethodString string
	switch project.MergeMethod {
	case "ff":
		mergeMethodString = "fast-forward merge"
	case "rebase_merge":
		mergeMethodString = "semi-linear merge"
	default:
		mergeMethodString = string(project.MergeMethod)
	}

	return mergeMethodString, nil
}

// ciIdTokenSubClaimComponents reports the components GitLab builds the subject
// claim of a job's OIDC token from, which is what a cloud trust policy matches
// on. Null when the shared project payload did not carry the attribute, either
// because the token cannot read the project's CI/CD settings or because the
// instance predates the setting.
func (p *mqlGitlabProject) ciIdTokenSubClaimComponents() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	if _, err := p.projectDetails(conn); err != nil {
		if p.detailsStatusCode == 403 || p.detailsStatusCode == 404 {
			p.CiIdTokenSubClaimComponents.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	if p.detailsCI == nil || p.detailsCI.IDTokenSubClaimComponents == nil {
		p.CiIdTokenSubClaimComponents.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	components := make([]any, 0, len(p.detailsCI.IDTokenSubClaimComponents))
	for _, c := range p.detailsCI.IDTokenSubClaimComponents {
		components = append(components, c)
	}
	return components, nil
}

// ciAllowForkPipelinesToRunInParentProject reports whether a merge request from
// a fork runs its pipeline in this project, where it reaches this project's
// protected variables and runners. Null when the shared project payload did not
// carry the attribute rather than false, which would claim the fork path is
// closed on a project the token cannot read.
func (p *mqlGitlabProject) ciAllowForkPipelinesToRunInParentProject() (bool, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	if _, err := p.projectDetails(conn); err != nil {
		if p.detailsStatusCode == 403 || p.detailsStatusCode == 404 {
			p.CiAllowForkPipelinesToRunInParentProject.State = plugin.StateIsSet | plugin.StateIsNull
			return false, nil
		}
		return false, err
	}

	if p.detailsCI == nil || p.detailsCI.AllowForkPipelinesToRunInParent == nil {
		p.CiAllowForkPipelinesToRunInParentProject.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}

	return *p.detailsCI.AllowForkPipelinesToRunInParent, nil
}

// protectedBranches fetches protected branch settings
func (p *mqlGitlabProject) protectedBranches() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)
	defaultBranch := p.DefaultBranch.Data

	perPage := int64(50)
	page := int64(1)
	var protectedBranches []*gitlab.ProtectedBranch
	for {
		branches, resp, err := conn.Client().ProtectedBranches.ListProtectedBranches(projectID, &gitlab.ListProtectedBranchesOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage}})
		if err != nil {
			return nil, err
		}
		protectedBranches = append(protectedBranches, branches...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlProtectedBranches []any
	for _, branch := range protectedBranches {
		mqlProtectedBranch, err := newMqlProtectedBranch(p.MqlRuntime, p.Id.Data, branch, defaultBranch)
		if err != nil {
			return nil, err
		}

		mqlProtectedBranches = append(mqlProtectedBranches, mqlProtectedBranch)
	}

	return mqlProtectedBranches, nil
}

// mqlGitlabProtectedBranchAccessLevelInternal caches the user/group id so the
// typed user()/group() accessors resolve lazily. Exactly one of accessLevel,
// user, group, or deployKeyId is meaningful per row.
type mqlGitlabProtectedBranchAccessLevelInternal struct {
	cacheUserID  int64
	cacheGroupID int64
}

func (a *mqlGitlabProtectedBranchAccessLevel) user() (*mqlGitlabUser, error) {
	if a.cacheUserID <= 0 {
		a.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(a.cacheUserID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

func (a *mqlGitlabProtectedBranchAccessLevel) group() (*mqlGitlabGroup, error) {
	if a.cacheGroupID <= 0 {
		a.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "gitlab.group", map[string]*llx.RawData{
		"id": llx.IntData(a.cacheGroupID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabGroup), nil
}

// newMqlProtectedBranchAccessLevel builds one access-level row. idPrefix
// (parent protected-branch + action) namespaces the synthetic __id so rows
// from different branches or scopes don't collide in the resource cache.
func newMqlProtectedBranchAccessLevel(runtime *plugin.Runtime, idPrefix string, id, accessLevel, userID, groupID, deployKeyID int64, desc string) (*mqlGitlabProtectedBranchAccessLevel, error) {
	res, err := CreateResource(runtime, "gitlab.protectedBranch.accessLevel", map[string]*llx.RawData{
		"__id":                   llx.StringData(fmt.Sprintf("%s/%d", idPrefix, id)),
		"accessLevel":            llx.IntData(accessLevel),
		"accessLevelDescription": llx.StringData(desc),
		"deployKeyId":            llx.IntData(deployKeyID),
	})
	if err != nil {
		return nil, err
	}
	al := res.(*mqlGitlabProtectedBranchAccessLevel)
	al.cacheUserID = userID
	al.cacheGroupID = groupID
	return al, nil
}

func projectBranchAccessLevels(runtime *plugin.Runtime, idPrefix string, descs []*gitlab.BranchAccessDescription) ([]any, error) {
	out := make([]any, 0, len(descs))
	for _, d := range descs {
		if d == nil {
			continue
		}
		al, err := newMqlProtectedBranchAccessLevel(runtime, idPrefix, d.ID, int64(d.AccessLevel), d.UserID, d.GroupID, d.DeployKeyID, d.AccessLevelDescription)
		if err != nil {
			return nil, err
		}
		out = append(out, al)
	}
	return out, nil
}

// projectTagAccessLevels reuses the shared protectedBranch.accessLevel row for
// protected-tag create-access grants (TagAccessDescription is structurally
// identical to BranchAccessDescription).
func projectTagAccessLevels(runtime *plugin.Runtime, idPrefix string, descs []*gitlab.TagAccessDescription) ([]any, error) {
	out := make([]any, 0, len(descs))
	for _, d := range descs {
		if d == nil {
			continue
		}
		al, err := newMqlProtectedBranchAccessLevel(runtime, idPrefix, d.ID, int64(d.AccessLevel), d.UserID, d.GroupID, d.DeployKeyID, d.AccessLevelDescription)
		if err != nil {
			return nil, err
		}
		out = append(out, al)
	}
	return out, nil
}

func (i *mqlGitlabProjectIntegration) id() (string, error) {
	return "gitlab.project.integration/" + strconv.FormatInt(i.Id.Data, 10), nil
}

// integrations lists the project's active external integrations (services).
// ListServices returns the full set of active integrations (a bounded,
// non-paginated collection), so there is no page loop.
func (p *mqlGitlabProject) integrations() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	services, resp, err := conn.Client().Services.ListServices(int(p.Id.Data))
	if err != nil {
		if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
			return []any{}, nil
		}
		return nil, err
	}
	out := make([]any, 0, len(services))
	for _, s := range services {
		if s == nil {
			continue
		}
		res, err := CreateResource(p.MqlRuntime, "gitlab.project.integration", map[string]*llx.RawData{
			"id":                       llx.IntData(s.ID),
			"title":                    llx.StringData(s.Title),
			"slug":                     llx.StringData(s.Slug),
			"active":                   llx.BoolData(s.Active),
			"inherited":                llx.BoolData(s.Inherited),
			"createdAt":                llx.TimeDataPtr(s.CreatedAt),
			"updatedAt":                llx.TimeDataPtr(s.UpdatedAt),
			"commentOnEventEnabled":    llx.BoolData(s.CommentOnEventEnabled),
			"pushEvents":               llx.BoolData(s.PushEvents),
			"issuesEvents":             llx.BoolData(s.IssuesEvents),
			"confidentialIssuesEvents": llx.BoolData(s.ConfidentialIssuesEvents),
			"mergeRequestsEvents":      llx.BoolData(s.MergeRequestsEvents),
			"noteEvents":               llx.BoolData(s.NoteEvents),
			"confidentialNoteEvents":   llx.BoolData(s.ConfidentialNoteEvents),
			"pipelineEvents":           llx.BoolData(s.PipelineEvents),
			"tagPushEvents":            llx.BoolData(s.TagPushEvents),
			"jobEvents":                llx.BoolData(s.JobEvents),
			"deploymentEvents":         llx.BoolData(s.DeploymentEvents),
			"wikiPageEvents":           llx.BoolData(s.WikiPageEvents),
			"commitEvents":             llx.BoolData(s.CommitEvents),
			"alertEvents":              llx.BoolData(s.AlertEvents),
			"incidentEvents":           llx.BoolData(s.IncidentEvents),
			"vulnerabilityEvents":      llx.BoolData(s.VulnerabilityEvents),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// protectedEnvironments lists the project's protected deployment environments
// and their deploy/approval gates.
func (p *mqlGitlabProject) protectedEnvironments() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var all []*gitlab.ProtectedEnvironment
	for {
		envs, resp, err := conn.Client().ProtectedEnvironments.ListProtectedEnvironments(projectID, &gitlab.ListProtectedEnvironmentsOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage}})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, envs...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	out := make([]any, 0, len(all))
	for _, env := range all {
		res, err := CreateResource(p.MqlRuntime, "gitlab.project.protectedEnvironment", map[string]*llx.RawData{
			"__id":                  llx.StringData(fmt.Sprintf("gitlab.project.protectedEnvironment/%d/%s", p.Id.Data, env.Name)),
			"name":                  llx.StringData(env.Name),
			"requiredApprovalCount": llx.IntData(env.RequiredApprovalCount),
			"deployAccessLevels":    llx.ArrayData(envDeployAccessLevelsToDicts(env.DeployAccessLevels), types.Dict),
			"approvalRules":         llx.ArrayData(envApprovalRulesToDicts(env.ApprovalRules), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func envDeployAccessLevelsToDicts(descs []*gitlab.EnvironmentAccessDescription) []any {
	out := make([]any, 0, len(descs))
	for _, d := range descs {
		if d == nil {
			continue
		}
		out = append(out, map[string]any{
			"accessLevel":            int64(d.AccessLevel),
			"accessLevelDescription": d.AccessLevelDescription,
			"userId":                 int64(d.UserID),
			"groupId":                int64(d.GroupID),
			"groupInheritanceType":   int64(d.GroupInheritanceType),
		})
	}
	return out
}

func envApprovalRulesToDicts(rules []*gitlab.EnvironmentApprovalRule) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		out = append(out, map[string]any{
			"id":                     int64(r.ID),
			"accessLevel":            int64(r.AccessLevel),
			"accessLevelDescription": r.AccessLevelDescription,
			"userId":                 int64(r.UserID),
			"groupId":                int64(r.GroupID),
			"requiredApprovalCount":  int64(r.RequiredApprovalCount),
			"groupInheritanceType":   int64(r.GroupInheritanceType),
		})
	}
	return out
}

// protectedTags lists the project's protected tags and who may create them.
func (p *mqlGitlabProject) protectedTags() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var all []*gitlab.ProtectedTag
	for {
		tags, resp, err := conn.Client().ProtectedTags.ListProtectedTags(projectID, &gitlab.ListProtectedTagsOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage}})
		if err != nil {
			return nil, err
		}
		all = append(all, tags...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	out := make([]any, 0, len(all))
	for _, tag := range all {
		prefix := fmt.Sprintf("gitlab.project.protectedTag/%d/%s", p.Id.Data, tag.Name)
		levels, err := projectTagAccessLevels(p.MqlRuntime, prefix+"/create", tag.CreateAccessLevels)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(p.MqlRuntime, "gitlab.project.protectedTag", map[string]*llx.RawData{
			"__id":               llx.StringData(prefix),
			"name":               llx.StringData(tag.Name),
			"createAccessLevels": llx.ArrayData(levels, types.Resource("gitlab.protectedBranch.accessLevel")),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// mqlGitlabProjectJobTokenScopeInternal caches the project id so the lazy
// allowlist accessors can page their respective endpoints.
type mqlGitlabProjectJobTokenScopeInternal struct {
	projectID int64
}

// jobTokenScope returns the project's CI/CD job-token access scope, or null
// when the setting is unavailable (permissions/tier).
func (p *mqlGitlabProject) jobTokenScope() (*mqlGitlabProjectJobTokenScope, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	settings, resp, err := conn.Client().JobTokenScope.GetProjectJobTokenAccessSettings(int(p.Id.Data))
	if err != nil {
		if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
			p.JobTokenScope.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	res, err := CreateResource(p.MqlRuntime, "gitlab.project.jobTokenScope", map[string]*llx.RawData{
		"__id":           llx.StringData(fmt.Sprintf("gitlab.project.jobTokenScope/%d", p.Id.Data)),
		"inboundEnabled": llx.BoolData(settings.InboundEnabled),
	})
	if err != nil {
		return nil, err
	}
	res.(*mqlGitlabProjectJobTokenScope).projectID = p.Id.Data
	return res.(*mqlGitlabProjectJobTokenScope), nil
}

func (j *mqlGitlabProjectJobTokenScope) inboundAllowlistProjects() ([]any, error) {
	conn := j.MqlRuntime.Connection.(*connection.GitLabConnection)
	pid := int(j.projectID)

	perPage := int64(50)
	page := int64(1)
	var out []any
	for {
		projects, resp, err := conn.Client().JobTokenScope.GetProjectJobTokenInboundAllowList(pid, &gitlab.GetJobTokenInboundAllowListOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage}})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, pr := range projects {
			mqlPr, err := NewResource(j.MqlRuntime, "gitlab.project", map[string]*llx.RawData{"id": llx.IntData(int64(pr.ID))})
			if err != nil {
				return nil, err
			}
			out = append(out, mqlPr)
		}
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return out, nil
}

func (j *mqlGitlabProjectJobTokenScope) allowlistGroups() ([]any, error) {
	conn := j.MqlRuntime.Connection.(*connection.GitLabConnection)
	pid := int(j.projectID)

	perPage := int64(50)
	page := int64(1)
	var out []any
	for {
		groups, resp, err := conn.Client().JobTokenScope.GetJobTokenAllowlistGroups(pid, &gitlab.GetJobTokenAllowlistGroupsOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage}})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, g := range groups {
			mqlGrp, err := NewResource(j.MqlRuntime, "gitlab.group", map[string]*llx.RawData{"id": llx.IntData(int64(g.ID))})
			if err != nil {
				return nil, err
			}
			out = append(out, mqlGrp)
		}
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return out, nil
}

// projectMembers fetches the list of members in the project with their roles
func (p *mqlGitlabProject) projectMembers() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var allMembers []*gitlab.ProjectMember

	for {
		members, resp, err := conn.Client().ProjectMembers.ListAllProjectMembers(projectID, &gitlab.ListProjectMembersOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
			// GitLab omits is_using_seat from the members payload unless it is
			// asked for, and the SDK models it as a plain bool — without this
			// every member would decode as isUsingSeat=false.
			ShowSeatInfo: gitlab.Ptr(true),
		})
		if err != nil {
			return nil, err
		}

		allMembers = append(allMembers, members...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlMembers []any
	for _, member := range allMembers {
		role := mapAccessLevelToRole(int(member.AccessLevel))

		// Seed only the id and let initGitlabUser lazily fetch the full record.
		// Hardcoding zero values for fields the member payload doesn't carry
		// (twoFactorEnabled, locked, bot, jobTitle, organization, location)
		// would poison the runtime cache for any later gitlab.user lookup on
		// the same id — e.g. reporting twoFactorEnabled=false for a user who
		// actually has it enabled.
		mqlUser, err := NewResource(p.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
			"id": llx.IntData(int64(member.ID)),
		})
		if err != nil {
			return nil, err
		}

		var expiresAt *time.Time
		if member.ExpiresAt != nil {
			t := time.Time(*member.ExpiresAt)
			expiresAt = &t
		}

		memberInfo := map[string]*llx.RawData{
			// ProjectMember.ID is the *user* id, not a membership id, so it is
			// the same value in every project and group the user belongs to.
			// The membership is what this resource models, so the key has to
			// carry the owning project too — otherwise a user who is Owner in
			// one project and Guest in another resolves to whichever
			// membership was materialized first.
			"__id":        llx.StringData(projectScopedID("gitlab.member/project", p.Id.Data, strconv.FormatInt(int64(member.ID), 10))),
			"id":          llx.IntData(int64(member.ID)),
			"user":        llx.ResourceData(mqlUser, "gitlab.user"),
			"role":        llx.StringData(role),
			"accessLevel": llx.IntData(int64(member.AccessLevel)),
			"state":       llx.StringData(member.State),
			"expiresAt":   llx.TimeDataPtr(expiresAt),
			"createdAt":   llx.TimeDataPtr(member.CreatedAt),
			"isUsingSeat": llx.BoolData(member.IsUsingSeat),
		}

		mqlMember, err := CreateResource(p.MqlRuntime, "gitlab.member", memberInfo)
		if err != nil {
			return nil, err
		}
		mm := mqlMember.(*mqlGitlabMember)
		if member.CreatedBy != nil {
			mm.cacheCreatedByID = member.CreatedBy.ID
		}
		mm.cacheMemberRole = member.MemberRole

		mqlMembers = append(mqlMembers, mqlMember)
	}

	return mqlMembers, nil
}

// mqlGitlabProjectFileInternal carries the parent project context needed to
// lazily fetch file content. We don't expose these as schema fields because
// they only exist to satisfy the per-file GetFile lookup and would clutter
// the resource for users.
type mqlGitlabProjectFileInternal struct {
	projectID int
	ref       string
}

// content lazily fetches the file's raw content via the repository files
// endpoint. Eager fetching here would force an HTTP call per blob even for
// queries that never read `content` (e.g. `projectFiles { path }`); doing
// it on demand keeps the cost proportional to what the query asks for.
func (f *mqlGitlabProjectFile) content() (string, error) {
	if f.projectID == 0 || f.ref == "" || f.Path.Error != nil {
		return "", errors.New("gitlab.project.file: missing project context for content fetch")
	}
	conn := f.MqlRuntime.Connection.(*connection.GitLabConnection)
	fileContent, _, err := conn.Client().RepositoryFiles.GetFile(f.projectID, f.Path.Data, &gitlab.GetFileOptions{Ref: &f.ref})
	if err != nil {
		return "", err
	}
	contentBytes, err := base64.StdEncoding.DecodeString(fileContent.Content)
	if err != nil {
		return "", err
	}
	return string(contentBytes), nil
}

// projectFiles fetches the list of files in the project repository. File
// content is fetched lazily on access (see gitlab.project.file.content) so
// that queries reading only path/name/type don't pay for an HTTP round-trip
// per blob.
func (p *mqlGitlabProject) projectFiles() ([]any, error) {
	// Return empty array if repository is empty to avoid 404 errors
	if p.EmptyRepo.Data {
		return []any{}, nil
	}

	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)
	defaultBranch := p.DefaultBranch.Data

	ref := &defaultBranch
	recursive := true

	listFilesOptions := &gitlab.ListTreeOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100},
		Ref:         ref,
		Recursive:   &recursive,
	}

	var files []*gitlab.TreeNode
	for {
		batch, resp, err := conn.Client().Repositories.ListTree(projectID, listFilesOptions)
		if err != nil {
			if resp != nil && resp.StatusCode == 404 {
				// new project with no commits/files
				break
			}
			return nil, fmt.Errorf("failed to list files in repository: %w", err)
		}
		files = append(files, batch...)
		if resp.NextPage == 0 {
			break
		}
		listFilesOptions.Page = resp.NextPage
	}

	var mqlFiles []any
	for _, file := range files {
		if file.Type != "blob" {
			continue
		}
		fileInfo := map[string]*llx.RawData{
			// A repo path ("README.md") repeats across projects, and the ref
			// decides which revision content() reads, so both belong in the
			// key. Keying on the path alone let one project's file resource be
			// handed back for another project — and the projectID/ref assigned
			// just below would then be written onto the *cached* resource,
			// pointing content() at the wrong repository.
			"__id": llx.StringData(projectScopedID("gitlab.project.file", p.Id.Data, defaultBranch, file.Path)),
			"path": llx.StringData(file.Path),
			"type": llx.StringData(file.Type),
			"name": llx.StringData(file.Name),
		}

		mqlFile, err := CreateResource(p.MqlRuntime, "gitlab.project.file", fileInfo)
		if err != nil {
			return nil, err
		}
		mf := mqlFile.(*mqlGitlabProjectFile)
		mf.projectID = projectID
		mf.ref = defaultBranch

		mqlFiles = append(mqlFiles, mqlFile)
	}

	return mqlFiles, nil
}

// id function for gitlab.project.webhook - hook ID is unique per project, but
// hooks are scoped to a project so we include the project ID for global uniqueness.
func (g *mqlGitlabProjectWebhook) id() (string, error) {
	return "gitlab.project.webhook/" + strconv.FormatInt(g.Id.Data, 10), nil
}

// mqlGitlabProjectWebhookInternal stores parent project context for typed refs.
type mqlGitlabProjectWebhookInternal struct {
	projectID int64
}

// project returns a typed reference to the parent project this webhook is registered on.
func (h *mqlGitlabProjectWebhook) project() (*mqlGitlabProject, error) {
	if h.projectID == 0 {
		h.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlProject, err := NewResource(h.MqlRuntime, "gitlab.project", map[string]*llx.RawData{
		"id": llx.IntData(h.projectID),
	})
	if err != nil {
		return nil, err
	}
	return mqlProject.(*mqlGitlabProject), nil
}

// webhooks fetches the webhooks for a project. The configured secret token is
// write-only and never returned, but GitLab does report whether one is set, and
// that is decoded separately from the SDK type so an instance that does not
// report it leaves tokenPresent null instead of claiming no token is set.
func (p *mqlGitlabProject) webhooks() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	raw, _, err := listRawPages(conn.Client(), "projects/"+strconv.FormatInt(p.Id.Data, 10)+"/hooks", 50)
	if err != nil {
		return nil, err
	}

	allHooks, presence, err := decodeHooks[gitlab.ProjectHook](raw)
	if err != nil {
		return nil, err
	}

	var mqlWebhooks []any
	for i, hook := range allHooks {
		customHeaders := map[string]any{}
		for _, h := range hook.CustomHeaders {
			if h == nil {
				continue
			}
			customHeaders[h.Key] = h.Value
		}
		urlVariables := map[string]any{}
		for _, v := range hook.URLVariables {
			urlVariables[v.Key] = v.Value
		}

		hookInfo := map[string]*llx.RawData{
			"id":                        llx.IntData(hook.ID),
			"url":                       llx.StringData(hook.URL),
			"name":                      llx.StringData(hook.Name),
			"description":               llx.StringData(hook.Description),
			"sslVerification":           llx.BoolData(hook.EnableSSLVerification),
			"pushEvents":                llx.BoolData(hook.PushEvents),
			"pushEventsBranchFilter":    llx.StringData(hook.PushEventsBranchFilter),
			"issuesEvents":              llx.BoolData(hook.IssuesEvents),
			"confidentialIssuesEvents":  llx.BoolData(hook.ConfidentialIssuesEvents),
			"mergeRequestsEvents":       llx.BoolData(hook.MergeRequestsEvents),
			"tagPushEvents":             llx.BoolData(hook.TagPushEvents),
			"noteEvents":                llx.BoolData(hook.NoteEvents),
			"confidentialNoteEvents":    llx.BoolData(hook.ConfidentialNoteEvents),
			"jobEvents":                 llx.BoolData(hook.JobEvents),
			"pipelineEvents":            llx.BoolData(hook.PipelineEvents),
			"wikiPageEvents":            llx.BoolData(hook.WikiPageEvents),
			"deploymentEvents":          llx.BoolData(hook.DeploymentEvents),
			"releasesEvents":            llx.BoolData(hook.ReleasesEvents),
			"resourceAccessTokenEvents": llx.BoolData(hook.ResourceAccessTokenEvents),
			"vulnerabilityEvents":       llx.BoolData(hook.VulnerabilityEvents),
			"featureFlagEvents":         llx.BoolData(hook.FeatureFlagEvents),
			"milestoneEvents":           llx.BoolData(hook.MilestoneEvents),
			"emojiEvents":               llx.BoolData(hook.EmojiEvents),
			"repositoryUpdateEvents":    llx.BoolData(hook.RepositoryUpdateEvents),
			"tokenPresent":              llx.BoolDataPtr(presence[i].TokenPresent),
			"branchFilterStrategy":      llx.StringData(hook.BranchFilterStrategy),
			"customWebhookTemplate":     llx.StringData(hook.CustomWebhookTemplate),
			"customHeaders":             llx.MapData(customHeaders, types.String),
			"urlVariables":              llx.MapData(urlVariables, types.String),
			"createdAt":                 llx.TimeDataPtr(hook.CreatedAt),
			"disabledUntil":             llx.TimeDataPtr(hook.DisabledUntil),
			"alertStatus":               llx.StringData(hook.AlertStatus),
		}

		mqlWebhook, err := CreateResource(p.MqlRuntime, "gitlab.project.webhook", hookInfo)
		if err != nil {
			return nil, err
		}

		mqlWebhook.(*mqlGitlabProjectWebhook).projectID = p.Id.Data
		mqlWebhooks = append(mqlWebhooks, mqlWebhook)
	}

	return mqlWebhooks, nil
}

// id function for gitlab.project.mergeRequest
func (m *mqlGitlabProjectMergeRequest) id() (string, error) {
	return strconv.FormatInt(m.Id.Data, 10), nil
}

// Helper function to create a milestone resource from API data
func createMilestoneResource(runtime *plugin.Runtime, milestone *gitlab.Milestone) (*mqlGitlabProjectMilestone, error) {
	if milestone == nil {
		return nil, nil
	}

	milestoneInfo := map[string]*llx.RawData{
		"__id":        llx.StringData(strconv.FormatInt(milestone.ID, 10)),
		"id":          llx.IntData(milestone.ID),
		"internalId":  llx.IntData(milestone.IID),
		"projectId":   llx.IntData(milestone.ProjectID),
		"title":       llx.StringData(milestone.Title),
		"description": llx.StringData(milestone.Description),
		"state":       llx.StringData(milestone.State),
		"updatedAt":   llx.TimeDataPtr(milestone.UpdatedAt),
		"createdAt":   llx.TimeDataPtr(milestone.CreatedAt),
	}

	// Always set these keys. Skipping them for a milestone with no start/due
	// date leaves the field unset rather than null, which surfaces client-side
	// as "primitive with no type information" instead of a clean null.
	milestoneInfo["startDate"] = llx.TimeDataPtr(isoTimePtr(milestone.StartDate))
	milestoneInfo["dueDate"] = llx.TimeDataPtr(isoTimePtr(milestone.DueDate))

	// A nil Expired means GitLab did not report the flag, which is not the
	// same as reporting "not expired" — flattening it to false invents a
	// value the API never sent. BoolDataPtr maps nil to a real MQL null.
	milestoneInfo["expired"] = llx.BoolDataPtr(milestone.Expired)

	mqlMilestone, err := CreateResource(runtime, "gitlab.project.milestone", milestoneInfo)
	if err != nil {
		return nil, err
	}

	return mqlMilestone.(*mqlGitlabProjectMilestone), nil
}

// milestone fetches the milestone for a merge request. The milestone is
// populated eagerly when the merge request is materialized; this fallback
// covers MRs without an attached milestone.
func (m *mqlGitlabProjectMergeRequest) milestone() (*mqlGitlabProjectMilestone, error) {
	m.Milestone.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// mergeRequests fetches the list of merge requests for the project
func (p *mqlGitlabProject) mergeRequests() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	// Fetch all merge requests with pagination
	perPage := int64(50)
	page := int64(1)
	var allMergeRequests []*gitlab.BasicMergeRequest

	for {
		mergeRequests, resp, err := conn.Client().MergeRequests.ListProjectMergeRequests(projectID, &gitlab.ListProjectMergeRequestsOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allMergeRequests = append(allMergeRequests, mergeRequests...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlMergeRequests []any
	for _, mr := range allMergeRequests {
		authorName := ""
		if mr.Author != nil {
			authorName = mr.Author.Username
		}

		reviewers, err := basicUsersToMqlUsers(p.MqlRuntime, mr.Reviewers)
		if err != nil {
			return nil, err
		}
		assignees, err := basicUsersToMqlUsers(p.MqlRuntime, mr.Assignees)
		if err != nil {
			return nil, err
		}

		mrInfo := map[string]*llx.RawData{
			"id":                          llx.IntData(int64(mr.ID)),
			"internalId":                  llx.IntData(int64(mr.IID)),
			"title":                       llx.StringData(mr.Title),
			"state":                       llx.StringData(mr.State),
			"description":                 llx.StringData(mr.Description),
			"sourceBranch":                llx.StringData(mr.SourceBranch),
			"targetBranch":                llx.StringData(mr.TargetBranch),
			"author":                      llx.StringData(authorName),
			"createdAt":                   llx.TimeDataPtr(mr.CreatedAt),
			"updatedAt":                   llx.TimeDataPtr(mr.UpdatedAt),
			"mergedAt":                    llx.TimeDataPtr(mr.MergedAt),
			"closedAt":                    llx.TimeDataPtr(mr.ClosedAt),
			"draft":                       llx.BoolData(mr.Draft),
			"webURL":                      llx.StringData(mr.WebURL),
			"labels":                      llx.ArrayData(convert.SliceAnyToInterface([]string(mr.Labels)), types.String),
			"reviewers":                   llx.ArrayData(reviewers, types.Resource("gitlab.user")),
			"assignees":                   llx.ArrayData(assignees, types.Resource("gitlab.user")),
			"detailedMergeStatus":         llx.StringData(mr.DetailedMergeStatus),
			"sha":                         llx.StringData(mr.SHA),
			"mergeCommitSha":              llx.StringData(mr.MergeCommitSHA),
			"squashCommitSha":             llx.StringData(mr.SquashCommitSHA),
			"hasConflicts":                llx.BoolData(mr.HasConflicts),
			"blockingDiscussionsResolved": llx.BoolData(mr.BlockingDiscussionsResolved),
			"mergeWhenPipelineSucceeds":   llx.BoolData(mr.MergeWhenPipelineSucceeds),
			"forceRemoveSourceBranch":     llx.BoolData(mr.ForceRemoveSourceBranch),
			"allowMaintainerToPush":       llx.BoolData(mr.AllowMaintainerToPush),
			"discussionLocked":            llx.BoolData(mr.DiscussionLocked),
			"upvotes":                     llx.IntData(mr.Upvotes),
			"downvotes":                   llx.IntData(mr.Downvotes),
		}

		// Add milestone if present
		if mr.Milestone != nil {
			mqlMilestone, err := createMilestoneResource(p.MqlRuntime, mr.Milestone)
			if err != nil {
				return nil, err
			}
			if mqlMilestone != nil {
				mrInfo["milestone"] = llx.ResourceData(mqlMilestone, "gitlab.project.milestone")
			}
		}

		mqlMR, err := CreateResource(p.MqlRuntime, "gitlab.project.mergeRequest", mrInfo)
		if err != nil {
			return nil, err
		}
		mm := mqlMR.(*mqlGitlabProjectMergeRequest)
		if mr.Author != nil {
			mm.cacheAuthorID = mr.Author.ID
		}
		if mr.MergeUser != nil {
			mm.cacheMergeUserID = mr.MergeUser.ID
		}
		if mr.ClosedBy != nil {
			mm.cacheClosedByID = mr.ClosedBy.ID
		}

		mqlMergeRequests = append(mqlMergeRequests, mqlMR)
	}

	return mqlMergeRequests, nil
}

// mqlGitlabProjectMergeRequestInternal caches the merge/close actor ids so the
// typed mergeUser()/closedBy() accessors resolve lazily.
type mqlGitlabProjectMergeRequestInternal struct {
	cacheAuthorID    int64
	cacheMergeUserID int64
	cacheClosedByID  int64
}

// authorUser returns the user who opened the merge request, or null when the
// author cannot be resolved.
func (m *mqlGitlabProjectMergeRequest) authorUser() (*mqlGitlabUser, error) {
	if m.cacheAuthorID <= 0 {
		m.AuthorUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheAuthorID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

// mergeUser returns the user who merged the request, or null when it was not
// merged (or GitLab does not report the actor).
func (m *mqlGitlabProjectMergeRequest) mergeUser() (*mqlGitlabUser, error) {
	if m.cacheMergeUserID <= 0 {
		m.MergeUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheMergeUserID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

// closedBy returns the user who closed the request, or null when it was not
// closed.
func (m *mqlGitlabProjectMergeRequest) closedBy() (*mqlGitlabUser, error) {
	if m.cacheClosedByID <= 0 {
		m.ClosedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheClosedByID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

// id function for gitlab.project.issue
func (i *mqlGitlabProjectIssue) id() (string, error) {
	return strconv.FormatInt(i.Id.Data, 10), nil
}

// mqlGitlabProjectIssueInternal caches the issue author id so the typed
// authorUser() accessor resolves lazily.
type mqlGitlabProjectIssueInternal struct {
	cacheAuthorID int64
}

// authorUser returns the user who opened the issue, or null when the author
// cannot be resolved.
func (i *mqlGitlabProjectIssue) authorUser() (*mqlGitlabUser, error) {
	if i.cacheAuthorID <= 0 {
		i.AuthorUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(i.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(i.cacheAuthorID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

// milestone fetches the milestone for an issue. The milestone is populated
// eagerly when the issue is materialized; this fallback covers issues without
// an attached milestone.
func (i *mqlGitlabProjectIssue) milestone() (*mqlGitlabProjectMilestone, error) {
	i.Milestone.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// issues fetches the list of issues for the project
func (p *mqlGitlabProject) issues() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	// Fetch all issues with pagination
	perPage := int64(50)
	page := int64(1)
	var allIssues []*gitlab.Issue

	for {
		issues, resp, err := conn.Client().Issues.ListProjectIssues(projectID, &gitlab.ListProjectIssuesOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allIssues = append(allIssues, issues...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlIssues []any
	for _, issue := range allIssues {
		authorName := ""
		if issue.Author != nil {
			authorName = issue.Author.Username
		}

		var dueDate *time.Time
		if issue.DueDate != nil {
			t := time.Time(*issue.DueDate)
			dueDate = &t
		}

		issueInfo := map[string]*llx.RawData{
			"id":           llx.IntData(int64(issue.ID)),
			"internalId":   llx.IntData(int64(issue.IID)),
			"title":        llx.StringData(issue.Title),
			"state":        llx.StringData(issue.State),
			"description":  llx.StringData(issue.Description),
			"author":       llx.StringData(authorName),
			"createdAt":    llx.TimeDataPtr(issue.CreatedAt),
			"updatedAt":    llx.TimeDataPtr(issue.UpdatedAt),
			"closedAt":     llx.TimeDataPtr(issue.ClosedAt),
			"dueDate":      llx.TimeDataPtr(dueDate),
			"confidential": llx.BoolData(issue.Confidential),
			"webURL":       llx.StringData(issue.WebURL),
			"labels":       llx.ArrayData(convert.SliceAnyToInterface([]string(issue.Labels)), types.String),
		}

		// Add milestone if present
		if issue.Milestone != nil {
			mqlMilestone, err := createMilestoneResource(p.MqlRuntime, issue.Milestone)
			if err != nil {
				return nil, err
			}
			if mqlMilestone != nil {
				issueInfo["milestone"] = llx.ResourceData(mqlMilestone, "gitlab.project.milestone")
			}
		}

		mqlIssue, err := CreateResource(p.MqlRuntime, "gitlab.project.issue", issueInfo)
		if err != nil {
			return nil, err
		}
		if issue.Author != nil {
			mqlIssue.(*mqlGitlabProjectIssue).cacheAuthorID = int64(issue.Author.ID)
		}

		mqlIssues = append(mqlIssues, mqlIssue)
	}

	return mqlIssues, nil
}

// releases fetches the list of releases for the project
func (p *mqlGitlabProject) releases() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	// Fetch all releases with pagination
	perPage := int64(50)
	page := int64(1)
	var allReleases []*gitlab.Release

	for {
		releases, resp, err := conn.Client().Releases.ListReleases(projectID, &gitlab.ListReleasesOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allReleases = append(allReleases, releases...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlReleases []any
	for _, release := range allReleases {
		releaseInfo := map[string]*llx.RawData{
			// A release tag ("v1.0.0") is unique per project, not per
			// instance, so the project id has to be part of the key.
			"__id":            llx.StringData(projectScopedID("gitlab.project.release", p.Id.Data, release.TagName)),
			"tagName":         llx.StringData(release.TagName),
			"name":            llx.StringData(release.Name),
			"description":     llx.StringData(release.Description),
			"createdAt":       llx.TimeDataPtr(release.CreatedAt),
			"releasedAt":      llx.TimeDataPtr(release.ReleasedAt),
			"author":          llx.StringData(release.Author.Username),
			"upcomingRelease": llx.BoolData(release.UpcomingRelease),
			"commit":          llx.DictData(releaseCommitToDict(release.Commit)),
			"evidences":       llx.ArrayData(releaseEvidencesToDicts(release.Evidences), types.Dict),
			"assets":          llx.DictData(releaseAssetsToDict(release.Assets)),
		}

		mqlRelease, err := CreateResource(p.MqlRuntime, "gitlab.project.release", releaseInfo)
		if err != nil {
			return nil, err
		}
		mqlRelease.(*mqlGitlabProjectRelease).cacheAuthorID = release.Author.ID

		mqlReleases = append(mqlReleases, mqlRelease)
	}

	return mqlReleases, nil
}

// mqlGitlabProjectReleaseInternal caches the release author id so the typed
// authorUser() accessor resolves lazily.
type mqlGitlabProjectReleaseInternal struct {
	cacheAuthorID int64
}

func (r *mqlGitlabProjectRelease) authorUser() (*mqlGitlabUser, error) {
	if r.cacheAuthorID <= 0 {
		r.AuthorUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(r.cacheAuthorID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

// dictTime renders a timestamp for embedding in a dict field. Dict values are
// serialized by llx's dict2primitive, which accepts only JSON-native types
// (nil, bool, int64, float64, string, []any, map[string]any) — handing it a
// *time.Time fails the whole field at query time, and a typed nil pointer
// fails too because the interface is non-nil. RFC3339 keeps the value both
// serializable and comparable.
func dictTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Format(time.RFC3339)
}

func releaseCommitToDict(c gitlab.Commit) any {
	if c.ID == "" {
		return nil
	}
	return map[string]any{
		"id":            c.ID,
		"shortId":       c.ShortID,
		"title":         c.Title,
		"authorName":    c.AuthorName,
		"authoredDate":  dictTime(c.AuthoredDate),
		"committedDate": dictTime(c.CommittedDate),
		"webUrl":        c.WebURL,
	}
}

func releaseEvidencesToDicts(evidences []*gitlab.ReleaseEvidence) []any {
	out := make([]any, 0, len(evidences))
	for _, e := range evidences {
		if e == nil {
			continue
		}
		out = append(out, map[string]any{
			"sha":         e.SHA,
			"filepath":    e.Filepath,
			"collectedAt": dictTime(e.CollectedAt),
		})
	}
	return out
}

func releaseAssetsToDict(a gitlab.ReleaseAssets) any {
	sources := make([]any, 0, len(a.Sources))
	for _, s := range a.Sources {
		sources = append(sources, map[string]any{
			"format": s.Format,
			"url":    s.URL,
		})
	}
	links := make([]any, 0, len(a.Links))
	for _, l := range a.Links {
		if l == nil {
			continue
		}
		links = append(links, map[string]any{
			"id":       l.ID,
			"name":     l.Name,
			"url":      l.URL,
			"linkType": string(l.LinkType),
			"external": l.External,
		})
	}
	return map[string]any{
		"count":   a.Count,
		"sources": sources,
		"links":   links,
	}
}

// variables fetches the list of CI/CD variables for the project
func (p *mqlGitlabProject) variables() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	// Fetch all variables with pagination
	perPage := int64(50)
	page := int64(1)
	var allVariables []*gitlab.ProjectVariable

	for {
		variables, resp, err := conn.Client().ProjectVariables.ListVariables(projectID, &gitlab.ListProjectVariablesOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allVariables = append(allVariables, variables...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlVariables []any
	for _, v := range allVariables {
		varInfo := map[string]*llx.RawData{
			// CI/CD variable keys are deliberately reused across projects
			// (AWS_ACCESS_KEY_ID, NPM_TOKEN, ...), so key+scope alone aliases
			// between them — and the aliased row carries the other project's
			// masked/protected flags.
			"__id":             llx.StringData(projectScopedID("gitlab.project.variable", p.Id.Data, v.Key, v.EnvironmentScope)),
			"key":              llx.StringData(v.Key),
			"variableType":     llx.StringData(string(v.VariableType)),
			"protected":        llx.BoolData(v.Protected),
			"masked":           llx.BoolData(v.Masked),
			"hidden":           llx.BoolData(v.Hidden),
			"raw":              llx.BoolData(v.Raw),
			"environmentScope": llx.StringData(v.EnvironmentScope),
			"description":      llx.StringData(v.Description),
		}

		mqlVar, err := CreateResource(p.MqlRuntime, "gitlab.project.variable", varInfo)
		if err != nil {
			return nil, err
		}

		mqlVariables = append(mqlVariables, mqlVar)
	}

	return mqlVariables, nil
}

// project returns the project a milestone belongs to, resolved from the
// milestone's cached projectId. Returns null when the project id is unknown.
func (m *mqlGitlabProjectMilestone) project() (*mqlGitlabProject, error) {
	if m.ProjectId.Data <= 0 {
		m.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, "gitlab.project", map[string]*llx.RawData{
		"id": llx.IntData(m.ProjectId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabProject), nil
}

// id function for gitlab.project.milestone
func (m *mqlGitlabProjectMilestone) id() (string, error) {
	return strconv.FormatInt(m.Id.Data, 10), nil
}

// milestones fetches the list of milestones for the project
func (p *mqlGitlabProject) milestones() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	// Fetch all milestones with pagination
	perPage := int64(50)
	page := int64(1)
	var allMilestones []*gitlab.Milestone

	for {
		milestones, resp, err := conn.Client().Milestones.ListMilestones(projectID, &gitlab.ListMilestonesOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allMilestones = append(allMilestones, milestones...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlMilestones []any
	for _, milestone := range allMilestones {
		milestoneInfo := map[string]*llx.RawData{
			"id":          llx.IntData(milestone.ID),
			"internalId":  llx.IntData(milestone.IID),
			"projectId":   llx.IntData(milestone.ProjectID),
			"title":       llx.StringData(milestone.Title),
			"description": llx.StringData(milestone.Description),
			"state":       llx.StringData(milestone.State),
			"updatedAt":   llx.TimeDataPtr(milestone.UpdatedAt),
			"createdAt":   llx.TimeDataPtr(milestone.CreatedAt),
		}

		// Always set these keys. Skipping them for a milestone with no start/due
		// date leaves the field unset rather than null, which surfaces client-side
		// as "primitive with no type information" instead of a clean null.
		milestoneInfo["startDate"] = llx.TimeDataPtr(isoTimePtr(milestone.StartDate))
		milestoneInfo["dueDate"] = llx.TimeDataPtr(isoTimePtr(milestone.DueDate))

		// A nil Expired means GitLab did not report the flag, which is not the
		// same as reporting "not expired" — flattening it to false invents a
		// value the API never sent. BoolDataPtr maps nil to a real MQL null.
		milestoneInfo["expired"] = llx.BoolDataPtr(milestone.Expired)

		mqlMilestone, err := CreateResource(p.MqlRuntime, "gitlab.project.milestone", milestoneInfo)
		if err != nil {
			return nil, err
		}

		mqlMilestones = append(mqlMilestones, mqlMilestone)
	}

	return mqlMilestones, nil
}

// id function for gitlab.project.label
func (l *mqlGitlabProjectLabel) id() (string, error) {
	return strconv.FormatInt(l.Id.Data, 10), nil
}

// labels fetches the list of labels for the project
func (p *mqlGitlabProject) labels() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	// Fetch all labels with pagination
	perPage := int64(50)
	page := int64(1)
	var allLabels []*gitlab.Label

	for {
		labels, resp, err := conn.Client().Labels.ListLabels(projectID, &gitlab.ListLabelsOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allLabels = append(allLabels, labels...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlLabels []any
	for _, label := range allLabels {
		labelInfo := map[string]*llx.RawData{
			"id":          llx.IntData(label.ID),
			"name":        llx.StringData(label.Name),
			"color":       llx.StringData(label.Color),
			"textColor":   llx.StringData(label.TextColor),
			"description": llx.StringData(label.Description),
			// The SDK's Label struct does not model description_html, so we have
			// no value to report. Null says "unknown"; an empty string would
			// claim, for every label on every project, that no HTML
			// description exists.
			"openIssuesCount":        llx.IntData(label.OpenIssuesCount),
			"closedIssuesCount":      llx.IntData(label.ClosedIssuesCount),
			"openMergeRequestsCount": llx.IntData(label.OpenMergeRequestsCount),
			"subscribed":             llx.BoolData(label.Subscribed),
			"priority":               llx.IntData(labelPriority(label.Priority)),
			"isProjectLabel":         llx.BoolData(label.IsProjectLabel),
		}

		mqlLabel, err := CreateResource(p.MqlRuntime, "gitlab.project.label", labelInfo)
		if err != nil {
			return nil, err
		}

		mqlLabels = append(mqlLabels, mqlLabel)
	}

	return mqlLabels, nil
}

// id function for gitlab.project.pipeline
func (p *mqlGitlabProjectPipeline) id() (string, error) {
	return strconv.FormatInt(p.Id.Data, 10), nil
}

// pipelines fetches the list of CI/CD pipelines for the project
func (p *mqlGitlabProject) pipelines() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	// Fetch all pipelines with pagination
	perPage := int64(50)
	page := int64(1)
	var allPipelines []*gitlab.PipelineInfo

	for {
		pipelines, resp, err := conn.Client().Pipelines.ListProjectPipelines(projectID, &gitlab.ListProjectPipelinesOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allPipelines = append(allPipelines, pipelines...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlPipelines []any
	for _, pipeline := range allPipelines {
		pipelineInfo := map[string]*llx.RawData{
			"id":         llx.IntData(pipeline.ID),
			"internalId": llx.IntData(pipeline.IID),
			"projectId":  llx.IntData(pipeline.ProjectID),
			"status":     llx.StringData(pipeline.Status),
			"source":     llx.StringData(pipeline.Source),
			"ref":        llx.StringData(pipeline.Ref),
			"sha":        llx.StringData(pipeline.SHA),
			"name":       llx.StringData(pipeline.Name),
			"webURL":     llx.StringData(pipeline.WebURL),
			"createdAt":  llx.TimeDataPtr(pipeline.CreatedAt),
			"updatedAt":  llx.TimeDataPtr(pipeline.UpdatedAt),
		}

		mqlPipeline, err := CreateResource(p.MqlRuntime, "gitlab.project.pipeline", pipelineInfo)
		if err != nil {
			return nil, err
		}

		mqlPipelines = append(mqlPipelines, mqlPipeline)
	}

	return mqlPipelines, nil
}

// mqlGitlabProjectPipelineInternal caches the full pipeline payload from
// GetPipeline. The list endpoint (ListProjectPipelines) only returns a subset
// of fields; richer provenance (triggering user, timing, coverage, detailed
// status) needs a per-pipeline fetch shared across accessors, mirroring the
// runner-details pattern.
type mqlGitlabProjectPipelineInternal struct {
	detailsOnce sync.Once
	details     *gitlab.Pipeline
	detailsErr  error
}

func (p *mqlGitlabProjectPipeline) loadDetails() (*gitlab.Pipeline, error) {
	p.detailsOnce.Do(func() {
		conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
		pipeline, _, err := conn.Client().Pipelines.GetPipeline(int(p.ProjectId.Data), p.Id.Data)
		p.details = pipeline
		p.detailsErr = err
	})
	return p.details, p.detailsErr
}

func (p *mqlGitlabProjectPipeline) beforeSha() (string, error) {
	d, err := p.loadDetails()
	if err != nil || d == nil {
		return "", err
	}
	return d.BeforeSHA, nil
}

func (p *mqlGitlabProjectPipeline) tag() (bool, error) {
	d, err := p.loadDetails()
	if err != nil || d == nil {
		return false, err
	}
	return d.Tag, nil
}

func (p *mqlGitlabProjectPipeline) yamlErrors() (string, error) {
	d, err := p.loadDetails()
	if err != nil || d == nil {
		return "", err
	}
	return d.YamlErrors, nil
}

func (p *mqlGitlabProjectPipeline) user() (*mqlGitlabUser, error) {
	d, err := p.loadDetails()
	if err != nil {
		return nil, err
	}
	if d == nil || d.User == nil {
		p.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(p.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(d.User.ID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

func (p *mqlGitlabProjectPipeline) detailedStatus() (interface{}, error) {
	d, err := p.loadDetails()
	if err != nil || d == nil || d.DetailedStatus == nil {
		return nil, err
	}
	s := d.DetailedStatus
	return map[string]interface{}{
		"icon":    s.Icon,
		"text":    s.Text,
		"label":   s.Label,
		"group":   s.Group,
		"tooltip": s.Tooltip,
	}, nil
}

func (p *mqlGitlabProjectPipeline) startedAt() (*time.Time, error) {
	d, err := p.loadDetails()
	if err != nil || d == nil {
		return nil, err
	}
	return d.StartedAt, nil
}

func (p *mqlGitlabProjectPipeline) finishedAt() (*time.Time, error) {
	d, err := p.loadDetails()
	if err != nil || d == nil {
		return nil, err
	}
	return d.FinishedAt, nil
}

func (p *mqlGitlabProjectPipeline) committedAt() (*time.Time, error) {
	d, err := p.loadDetails()
	if err != nil || d == nil {
		return nil, err
	}
	return d.CommittedAt, nil
}

func (p *mqlGitlabProjectPipeline) duration() (int64, error) {
	d, err := p.loadDetails()
	if err != nil || d == nil {
		return 0, err
	}
	return d.Duration, nil
}

func (p *mqlGitlabProjectPipeline) queuedDuration() (int64, error) {
	d, err := p.loadDetails()
	if err != nil || d == nil {
		return 0, err
	}
	return d.QueuedDuration, nil
}

func (p *mqlGitlabProjectPipeline) coverage() (string, error) {
	d, err := p.loadDetails()
	if err != nil || d == nil {
		return "", err
	}
	return d.Coverage, nil
}

// newMqlGitlabPipelineFromDetail builds a gitlab.project.pipeline from a full
// SDK Pipeline (as embedded in e.g. package files). Eager fields are seeded
// from the detail payload; lazy accessors re-fetch via GetPipeline if used.
func newMqlGitlabPipelineFromDetail(runtime *plugin.Runtime, pl *gitlab.Pipeline) (*mqlGitlabProjectPipeline, error) {
	res, err := CreateResource(runtime, "gitlab.project.pipeline", map[string]*llx.RawData{
		"id":         llx.IntData(pl.ID),
		"internalId": llx.IntData(pl.IID),
		"projectId":  llx.IntData(pl.ProjectID),
		"status":     llx.StringData(pl.Status),
		"source":     llx.StringData(string(pl.Source)),
		"ref":        llx.StringData(pl.Ref),
		"sha":        llx.StringData(pl.SHA),
		"name":       llx.StringData(pl.Name),
		"webURL":     llx.StringData(pl.WebURL),
		"createdAt":  llx.TimeDataPtr(pl.CreatedAt),
		"updatedAt":  llx.TimeDataPtr(pl.UpdatedAt),
	})
	if err != nil {
		return nil, err
	}
	pipeline := res.(*mqlGitlabProjectPipeline)
	// We already hold the full detail payload, so seed the cache and mark it
	// resolved. This spares the lazy accessors (user(), duration(), …) a
	// redundant GetPipeline when they're read off a package-file pipeline.
	//
	// The write has to happen *inside* the Once: CreateResource can hand back a
	// cached pipeline that another goroutine is already reading through
	// loadDetails, and a bare assignment carries no happens-before edge with
	// the write in there. If that Once has already run, this is a no-op and the
	// existing details stand — which is fine, since a cache hit means the same
	// pipeline id and therefore the same payload.
	pipeline.detailsOnce.Do(func() {
		pipeline.details = pl
	})
	return pipeline, nil
}

// id function for gitlab.project.runner
func (r *mqlGitlabProjectRunner) id() (string, error) {
	return strconv.FormatInt(r.Id.Data, 10), nil
}

// runners fetches the list of runners available to the project
func (p *mqlGitlabProject) runners() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	// Fetch all runners with pagination
	perPage := int64(50)
	page := int64(1)
	var allRunners []*gitlab.Runner

	for {
		runners, resp, err := conn.Client().Runners.ListProjectRunners(projectID, &gitlab.ListProjectRunnersOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allRunners = append(allRunners, runners...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlRunners []any
	for _, runner := range allRunners {
		runnerInfo := map[string]*llx.RawData{
			"id":             llx.IntData(runner.ID),
			"description":    llx.StringData(runner.Description),
			"name":           llx.StringData(runner.Name),
			"runnerType":     llx.StringData(runner.RunnerType),
			"paused":         llx.BoolData(runner.Paused),
			"isShared":       llx.BoolData(runner.IsShared),
			"online":         llx.BoolData(runner.Online),
			"status":         llx.StringData(runner.Status),
			"tokenExpiresAt": llx.TimeDataPtr(runner.TokenExpiresAt),
		}

		mqlRunner, err := CreateResource(p.MqlRuntime, "gitlab.project.runner", runnerInfo)
		if err != nil {
			return nil, err
		}

		mqlRunners = append(mqlRunners, mqlRunner)
	}

	return mqlRunners, nil
}

// id function for gitlab.project.pushRule
func (r *mqlGitlabProjectPushRule) id() (string, error) {
	return "gitlab.project.pushRule/" + strconv.FormatInt(r.Id.Data, 10), nil
}

// pushRules fetches push rules for the project
func (p *mqlGitlabProject) pushRules() (*mqlGitlabProjectPushRule, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)
	rules, resp, err := conn.Client().Projects.GetProjectPushRules(projectID)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			p.PushRules.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil // no push rules configured
		}
		return nil, err
	}
	if rules == nil {
		p.PushRules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	ruleInfo := map[string]*llx.RawData{
		"id":                         llx.IntData(rules.ID),
		"commitMessageRegex":         llx.StringData(rules.CommitMessageRegex),
		"commitMessageNegativeRegex": llx.StringData(rules.CommitMessageNegativeRegex),
		"branchNameRegex":            llx.StringData(rules.BranchNameRegex),
		"denyDeleteTag":              llx.BoolData(rules.DenyDeleteTag),
		"memberCheck":                llx.BoolData(rules.MemberCheck),
		"preventSecrets":             llx.BoolData(rules.PreventSecrets),
		"authorEmailRegex":           llx.StringData(rules.AuthorEmailRegex),
		"fileNameRegex":              llx.StringData(rules.FileNameRegex),
		"maxFileSize":                llx.IntData(rules.MaxFileSize),
		"commitCommitterCheck":       llx.BoolData(rules.CommitCommitterCheck),
		"commitCommitterNameCheck":   llx.BoolData(rules.CommitCommitterNameCheck),
		"rejectUnsignedCommits":      llx.BoolData(rules.RejectUnsignedCommits),
		"rejectNonDCOCommits":        llx.BoolData(rules.RejectNonDCOCommits),
		"createdAt":                  llx.TimeDataPtr(rules.CreatedAt),
	}

	mqlRule, err := CreateResource(p.MqlRuntime, "gitlab.project.pushRule", ruleInfo)
	if err != nil {
		return nil, err
	}

	return mqlRule.(*mqlGitlabProjectPushRule), nil
}

// id function for gitlab.project.accessToken
func (t *mqlGitlabProjectAccessToken) id() (string, error) {
	return "gitlab.project.accessToken/" + strconv.FormatInt(t.Id.Data, 10), nil
}

// accessTokens fetches the list of access tokens for the project
func (p *mqlGitlabProject) accessTokens() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var allTokens []*gitlab.ProjectAccessToken

	for {
		tokens, resp, err := conn.Client().ProjectAccessTokens.ListProjectAccessTokens(projectID, &gitlab.ListProjectAccessTokensOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allTokens = append(allTokens, tokens...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlTokens []any
	for _, token := range allTokens {
		var expiresAt *time.Time
		if token.ExpiresAt != nil {
			t := time.Time(*token.ExpiresAt)
			expiresAt = &t
		}

		tokenInfo := map[string]*llx.RawData{
			"id":          llx.IntData(token.ID),
			"name":        llx.StringData(token.Name),
			"revoked":     llx.BoolData(token.Revoked),
			"active":      llx.BoolData(token.Active),
			"scopes":      llx.ArrayData(convert.SliceAnyToInterface(token.Scopes), types.String),
			"createdAt":   llx.TimeDataPtr(token.CreatedAt),
			"expiresAt":   llx.TimeDataPtr(expiresAt),
			"lastUsedAt":  llx.TimeDataPtr(token.LastUsedAt),
			"accessLevel": llx.IntData(int64(token.AccessLevel)),
		}

		mqlToken, err := CreateResource(p.MqlRuntime, "gitlab.project.accessToken", tokenInfo)
		if err != nil {
			return nil, err
		}
		mqlToken.(*mqlGitlabProjectAccessToken).cacheUserID = token.UserID

		mqlTokens = append(mqlTokens, mqlToken)
	}

	return mqlTokens, nil
}

// mqlGitlabProjectAccessTokenInternal caches the bot user id so the typed
// user() accessor can resolve it lazily.
type mqlGitlabProjectAccessTokenInternal struct {
	cacheUserID int64
}

// user returns the bot user the token authenticates as. Access-token bot users
// are not always resolvable via the users API; initGitlabUser degrades to a
// bare resource on 403/404, and this returns null when there is no user id.
func (t *mqlGitlabProjectAccessToken) user() (*mqlGitlabUser, error) {
	if t.cacheUserID <= 0 {
		t.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(t.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(t.cacheUserID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

// id function for gitlab.project.deployKey
func (k *mqlGitlabProjectDeployKey) id() (string, error) {
	return "gitlab.project.deployKey/" + strconv.FormatInt(k.Id.Data, 10), nil
}

// mqlGitlabProjectDeployKeyInternal stores parent project context for typed refs.
type mqlGitlabProjectDeployKeyInternal struct {
	projectID int64
}

// daysOld returns the age of the deploy key in days. Returns -1 when createdAt
// isn't set so callers can distinguish "missing data" from "fresh key".
func (k *mqlGitlabProjectDeployKey) daysOld() (int64, error) {
	if !k.CreatedAt.IsSet() || k.CreatedAt.Data == nil || k.CreatedAt.Data.IsZero() {
		return -1, nil
	}
	return int64(time.Since(*k.CreatedAt.Data).Hours() / 24), nil
}

// project returns a typed reference to the parent project the deploy key is registered against.
func (k *mqlGitlabProjectDeployKey) project() (*mqlGitlabProject, error) {
	if k.projectID == 0 {
		k.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlProject, err := NewResource(k.MqlRuntime, "gitlab.project", map[string]*llx.RawData{
		"id": llx.IntData(k.projectID),
	})
	if err != nil {
		return nil, err
	}
	return mqlProject.(*mqlGitlabProject), nil
}

// deployKeys fetches the list of deploy keys for the project
func (p *mqlGitlabProject) deployKeys() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var allKeys []*gitlab.ProjectDeployKey

	for {
		keys, resp, err := conn.Client().DeployKeys.ListProjectDeployKeys(projectID, &gitlab.ListProjectDeployKeysOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allKeys = append(allKeys, keys...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlKeys []any
	for _, key := range allKeys {
		keyInfo := map[string]*llx.RawData{
			"id":                llx.IntData(key.ID),
			"title":             llx.StringData(key.Title),
			"key":               llx.StringData(key.Key),
			"fingerprint":       llx.StringData(key.Fingerprint),
			"fingerprintSHA256": llx.StringData(key.FingerprintSHA256),
			"createdAt":         llx.TimeDataPtr(key.CreatedAt),
			"expiresAt":         llx.TimeDataPtr(key.ExpiresAt),
			"canPush":           llx.BoolData(key.CanPush),
			"lastUsedAt":        llx.TimeDataPtr(key.LastUsedAt),
			"usageType":         llx.StringData(key.UsageType),
		}

		mqlKey, err := CreateResource(p.MqlRuntime, "gitlab.project.deployKey", keyInfo)
		if err != nil {
			return nil, err
		}

		mqlKey.(*mqlGitlabProjectDeployKey).projectID = p.Id.Data
		mqlKeys = append(mqlKeys, mqlKey)
	}

	return mqlKeys, nil
}

// id function for gitlab.project.deployToken
func (t *mqlGitlabProjectDeployToken) id() (string, error) {
	return "gitlab.project.deployToken/" + strconv.FormatInt(t.Id.Data, 10), nil
}

// deployTokens fetches the list of deploy tokens for the project
func (p *mqlGitlabProject) deployTokens() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var allTokens []*gitlab.DeployToken

	for {
		tokens, resp, err := conn.Client().DeployTokens.ListProjectDeployTokens(projectID, &gitlab.ListProjectDeployTokensOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allTokens = append(allTokens, tokens...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlTokens []any
	for _, token := range allTokens {
		tokenInfo := map[string]*llx.RawData{
			"id":        llx.IntData(token.ID),
			"name":      llx.StringData(token.Name),
			"username":  llx.StringData(token.Username),
			"expiresAt": llx.TimeDataPtr(token.ExpiresAt),
			"revoked":   llx.BoolData(token.Revoked),
			"expired":   llx.BoolData(token.Expired),
			"scopes":    llx.ArrayData(convert.SliceAnyToInterface(token.Scopes), types.String),
		}

		mqlToken, err := CreateResource(p.MqlRuntime, "gitlab.project.deployToken", tokenInfo)
		if err != nil {
			return nil, err
		}

		mqlTokens = append(mqlTokens, mqlToken)
	}

	return mqlTokens, nil
}

// securitySettings fetches security settings for the project
func (p *mqlGitlabProject) securitySettings() (*mqlGitlabProjectSecuritySetting, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)
	settings, resp, err := conn.Client().ProjectSecuritySettings.ListProjectSecuritySettings(projectID)
	if err != nil {
		if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
			p.SecuritySettings.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil // not available on this GitLab tier
		}
		return nil, err
	}
	if settings == nil {
		p.SecuritySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	settingInfo := map[string]*llx.RawData{
		"__id":                                llx.StringData("gitlab.project.securitySetting/" + strconv.Itoa(projectID)),
		"autoFixContainerScanning":            llx.BoolData(settings.AutoFixContainerScanning),
		"autoFixDAST":                         llx.BoolData(settings.AutoFixDAST),
		"autoFixDependencyScanning":           llx.BoolData(settings.AutoFixDependencyScanning),
		"autoFixSAST":                         llx.BoolData(settings.AutoFixSAST),
		"continuousVulnerabilityScansEnabled": llx.BoolData(settings.ContinuousVulnerabilityScansEnabled),
		"containerScanningForRegistryEnabled": llx.BoolData(settings.ContainerScanningForRegistryEnabled),
		"secretPushProtectionEnabled":         llx.BoolData(settings.SecretPushProtectionEnabled),
	}

	mqlSetting, err := CreateResource(p.MqlRuntime, "gitlab.project.securitySetting", settingInfo)
	if err != nil {
		return nil, err
	}

	return mqlSetting.(*mqlGitlabProjectSecuritySetting), nil
}

// id function for gitlab.project.auditEvent
func (a *mqlGitlabProjectAuditEvent) id() (string, error) {
	return "gitlab.project.auditEvent/" + strconv.FormatInt(a.Id.Data, 10), nil
}

// author returns a typed reference to the user who performed the action.
// Returns null when authorId is unknown (e.g. system-generated events).
func (a *mqlGitlabProjectAuditEvent) author() (*mqlGitlabUser, error) {
	if a.AuthorId.Data <= 0 {
		a.Author.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(a.AuthorId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

// entityUser returns a typed user reference when entityType is "User", null otherwise.
func (a *mqlGitlabProjectAuditEvent) entityUser() (*mqlGitlabUser, error) {
	if a.EntityType.Data != "User" || a.EntityId.Data <= 0 {
		a.EntityUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(a.EntityId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

// entityGroup returns a typed group reference when entityType is "Group", null otherwise.
func (a *mqlGitlabProjectAuditEvent) entityGroup() (*mqlGitlabGroup, error) {
	if a.EntityType.Data != "Group" || a.EntityId.Data <= 0 {
		a.EntityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "gitlab.group", map[string]*llx.RawData{
		"id": llx.IntData(a.EntityId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabGroup), nil
}

// entityProject returns a typed project reference when entityType is "Project", null otherwise.
func (a *mqlGitlabProjectAuditEvent) entityProject() (*mqlGitlabProject, error) {
	if a.EntityType.Data != "Project" || a.EntityId.Data <= 0 {
		a.EntityProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "gitlab.project", map[string]*llx.RawData{
		"id": llx.IntData(a.EntityId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabProject), nil
}

// auditEvents fetches audit events for the project.
//
// Project audit events are a Premium/Ultimate feature. On lower tiers the API
// returns 403/404, in which case we return an empty list rather than failing
// the whole resource graph.
//
// see https://docs.gitlab.com/api/audit_events/#project-audit-events
func (p *mqlGitlabProject) auditEvents() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	projectID := int(p.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var allEvents []*gitlab.AuditEvent

	for {
		events, resp, err := conn.Client().AuditEvents.ListProjectAuditEvents(projectID, &gitlab.ListAuditEventsOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil // not available on this GitLab tier
			}
			return nil, err
		}

		allEvents = append(allEvents, events...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlEvents []any
	for _, event := range allEvents {
		eventInfo := map[string]*llx.RawData{
			"id":            llx.IntData(event.ID),
			"authorId":      llx.IntData(event.AuthorID),
			"entityId":      llx.IntData(event.EntityID),
			"entityType":    llx.StringData(event.EntityType),
			"eventName":     llx.StringData(event.EventName),
			"eventType":     llx.StringData(event.EventType),
			"createdAt":     llx.TimeDataPtr(event.CreatedAt),
			"authorName":    llx.StringData(event.Details.AuthorName),
			"authorEmail":   llx.StringData(event.Details.AuthorEmail),
			"authorClass":   llx.StringData(event.Details.AuthorClass),
			"customMessage": llx.StringData(event.Details.CustomMessage),
			"targetType":    llx.StringData(event.Details.TargetType),
			"targetDetails": llx.StringData(event.Details.TargetDetails),
			"ipAddress":     llx.StringData(event.Details.IPAddress),
			"entityPath":    llx.StringData(event.Details.EntityPath),
			"failedLogin":   llx.StringData(event.Details.FailedLogin),
		}
		mqlEvent, err := CreateResource(p.MqlRuntime, "gitlab.project.auditEvent", eventInfo)
		if err != nil {
			return nil, err
		}
		mqlEvents = append(mqlEvents, mqlEvent)
	}

	return mqlEvents, nil
}
