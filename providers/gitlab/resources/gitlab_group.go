// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"go.mondoo.com/mql/types"
)

func (g *mqlGitlabGroup) id() (string, error) {
	return "gitlab.group/" + strconv.FormatInt(g.Id.Data, 10), nil
}

func (u *mqlGitlabUser) id() (string, error) {
	return "gitlab.user/" + strconv.FormatInt(u.Id.Data, 10), nil
}

// mqlGitlabMemberInternal caches source data needed to resolve the member's
// typed references (createdBy user, custom member role) lazily.
type mqlGitlabMemberInternal struct {
	cacheCreatedByID int64
	cacheMemberRole  *gitlab.MemberRole
}

// createdBy returns a typed reference to the user who granted the membership.
// Returns null when GitLab does not report a creator (e.g. legacy memberships).
func (m *mqlGitlabMember) createdBy() (*mqlGitlabUser, error) {
	if m.cacheCreatedByID <= 0 {
		m.CreatedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheCreatedByID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

// memberRole returns the custom role assigned to the member, or null when the
// member holds only a standard access level.
func (m *mqlGitlabMember) memberRole() (*mqlGitlabMemberRole, error) {
	if m.cacheMemberRole == nil {
		m.MemberRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlGitlabMemberRole(m.MqlRuntime, m.cacheMemberRole)
}

func (r *mqlGitlabMemberRole) id() (string, error) {
	return "gitlab.memberRole/" + strconv.FormatInt(r.Id.Data, 10), nil
}

// newMqlGitlabMemberRole builds a gitlab.memberRole resource from an SDK
// MemberRole. Shared by gitlab.group.memberRoles and gitlab.member.memberRole.
func newMqlGitlabMemberRole(runtime *plugin.Runtime, role *gitlab.MemberRole) (*mqlGitlabMemberRole, error) {
	res, err := CreateResource(runtime, "gitlab.memberRole", map[string]*llx.RawData{
		"id":                         llx.IntData(role.ID),
		"name":                       llx.StringData(role.Name),
		"description":                llx.StringData(role.Description),
		"baseAccessLevel":            llx.IntData(int64(role.BaseAccessLevel)),
		"adminCicdVariables":         llx.BoolData(role.AdminCICDVariables),
		"adminComplianceFramework":   llx.BoolData(role.AdminComplianceFramework),
		"adminGroupMembers":          llx.BoolData(role.AdminGroupMembers),
		"adminMergeRequests":         llx.BoolData(role.AdminMergeRequests),
		"adminPushRules":             llx.BoolData(role.AdminPushRules),
		"adminTerraformState":        llx.BoolData(role.AdminTerraformState),
		"adminVulnerability":         llx.BoolData(role.AdminVulnerability),
		"adminWebHook":               llx.BoolData(role.AdminWebHook),
		"archiveProject":             llx.BoolData(role.ArchiveProject),
		"manageDeployTokens":         llx.BoolData(role.ManageDeployTokens),
		"manageGroupAccessTokens":    llx.BoolData(role.ManageGroupAccessTokens),
		"manageMergeRequestSettings": llx.BoolData(role.ManageMergeRequestSettings),
		"manageProjectAccessTokens":  llx.BoolData(role.ManageProjectAccessTokens),
		"manageSecurityPolicyLink":   llx.BoolData(role.ManageSecurityPolicyLink),
		"readCode":                   llx.BoolData(role.ReadCode),
		"readRunners":                llx.BoolData(role.ReadRunners),
		"readDependency":             llx.BoolData(role.ReadDependency),
		"readVulnerability":          llx.BoolData(role.ReadVulnerability),
		"removeGroup":                llx.BoolData(role.RemoveGroup),
		"removeProject":              llx.BoolData(role.RemoveProject),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabMemberRole), nil
}

// memberRoles fetches the custom member roles defined in the group.
//
// Custom roles are a Premium/Ultimate feature. On lower tiers the API returns
// 403/404, in which case we return an empty list rather than failing the whole
// resource graph.
//
// see https://docs.gitlab.com/api/member_roles/
func (g *mqlGitlabGroup) memberRoles() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	// ListMemberRoles takes no typed options struct, but the endpoint still
	// paginates and GitLab defaults to 20 per page — a group with more custom
	// roles than that would silently report only the first 20. gitlab.WithNext
	// drives the next page for offset, keyset, and cursor styles alike, and is
	// what samlGroupLinks below already uses for the same SDK shape.
	var allRoles []*gitlab.MemberRole
	var nextOpts []gitlab.RequestOptionFunc
	for {
		roles, resp, err := conn.Client().MemberRolesService.ListMemberRoles(int(g.Id.Data), nextOpts...)
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil // not available on this GitLab tier
			}
			return nil, err
		}
		allRoles = append(allRoles, roles...)
		next, hasNext := gitlab.WithNext(resp)
		if !hasNext {
			break
		}
		nextOpts = []gitlab.RequestOptionFunc{next}
	}

	var mqlRoles []any
	for _, role := range allRoles {
		mqlRole, err := newMqlGitlabMemberRole(g.MqlRuntime, role)
		if err != nil {
			return nil, err
		}
		mqlRoles = append(mqlRoles, mqlRole)
	}

	return mqlRoles, nil
}

// init initializes the gitlab group with the arguments
// see https://docs.gitlab.com/ee/api/groups.html#new-group
func initGitlabGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.GitLabConnection)

	// If only id is provided, fetch the group by id - used by typed refs
	// (e.g. auditEvent.entityGroup()). 403/404 yields a bare resource so the
	// typed back-ref doesn't fail the whole resource graph on insufficient perms.
	if idArg, ok := args["id"]; ok && idArg != nil && idArg.Error == nil {
		gid := int(idArg.Value.(int64))
		grp, resp, err := conn.Client().Groups.GetGroup(gid, nil)
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return args, nil, nil
			}
			return nil, nil, err
		}
		populateGroupArgs(args, grp)
		return args, nil, nil
	}

	grp, err := conn.Group()
	if err != nil {
		return nil, nil, err
	}

	populateGroupArgs(args, grp)
	return args, nil, nil
}

// populateGroupArgs fills the args map from a *gitlab.Group. Shared between
// the connection-default and by-id paths in initGitlabGroup.
func populateGroupArgs(args map[string]*llx.RawData, grp *gitlab.Group) {
	args["id"] = llx.IntData(int64(grp.ID))
	args["name"] = llx.StringData(grp.Name)
	args["path"] = llx.StringData(grp.Path)
	args["fullName"] = llx.StringData(grp.FullName)
	args["fullPath"] = llx.StringData(grp.FullPath)
	args["description"] = llx.StringData(grp.Description)
	args["createdAt"] = llx.TimeDataPtr(grp.CreatedAt)
	args["webURL"] = llx.StringData(string(grp.WebURL))
	args["visibility"] = llx.StringData(string(grp.Visibility))
	args["requireTwoFactorAuthentication"] = llx.BoolData(grp.RequireTwoFactorAuth)
	args["twoFactorGracePeriod"] = llx.IntData(grp.TwoFactorGracePeriod)
	args["membershipLock"] = llx.BoolData(grp.MembershipLock)
	args["preventForkingOutsideGroup"] = llx.BoolData(grp.PreventForkingOutsideGroup)
	args["mentionsDisabled"] = llx.BoolData(grp.MentionsDisabled)
	args["requestAccessEnabled"] = llx.BoolData(grp.RequestAccessEnabled)
	// Convert ISOTime to time.Time
	var markedForDeletionOn *time.Time
	if grp.MarkedForDeletionOn != nil {
		t := time.Time(*grp.MarkedForDeletionOn)
		markedForDeletionOn = &t
	}
	args["markedForDeletionOn"] = llx.TimeDataPtr(markedForDeletionOn)
	args["allowedEmailDomainsList"] = llx.StringData(grp.AllowedEmailDomainsList)
	args["lfsEnabled"] = llx.BoolData(grp.LFSEnabled)
	args["emailsEnabled"] = llx.BoolData(grp.EmailsEnabled)
	args["ipRestrictionRanges"] = llx.StringData(grp.IPRestrictionRanges)
	args["shareWithGroupLock"] = llx.BoolData(grp.ShareWithGroupLock)
	args["sharedRunnersSetting"] = llx.StringData(string(grp.SharedRunnersSetting))
	args["projectCreationLevel"] = llx.StringData(string(grp.ProjectCreationLevel))
	args["subGroupCreationLevel"] = llx.StringData(string(grp.SubGroupCreationLevel))
	args["autoDevopsEnabled"] = llx.BoolData(grp.AutoDevopsEnabled)
	args["wikiAccessLevel"] = llx.StringData(string(grp.WikiAccessLevel))
	args["ldapCn"] = llx.StringData(grp.LDAPCN)
	args["ldapAccess"] = llx.IntData(int64(grp.LDAPAccess))
	args["sharedWithGroups"] = llx.ArrayData(groupSharedGroupsToDicts(grp.SharedWithGroups), types.Dict)
	args["ldapGroupLinks"] = llx.ArrayData(ldapGroupLinksToDicts(grp.LDAPGroupLinks), types.Dict)
	args["defaultBranchProtection"] = llx.DictData(branchProtectionDefaultsToDict(grp.DefaultBranchProtectionDefaults))
}

// groupSharedGroupsToDicts flattens the groups a group is shared with into
// queryable dicts (group identity + the access level granted).
func groupSharedGroupsToDicts(groups []gitlab.SharedWithGroup) []any {
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

// ldapGroupLinksToDicts flattens LDAP group links into queryable dicts mapping
// a directory group (cn/filter/provider) to the access level it grants.
func ldapGroupLinksToDicts(links []*gitlab.LDAPGroupLink) []any {
	out := make([]any, 0, len(links))
	for _, l := range links {
		if l == nil {
			continue
		}
		out = append(out, map[string]any{
			"cn":          l.CN,
			"filter":      l.Filter,
			"provider":    l.Provider,
			"groupAccess": int64(l.GroupAccess),
		})
	}
	return out
}

// branchProtectionDefaultsToDict summarizes the group's default branch-
// protection policy; returns nil (MQL null) when the group has none.
func branchProtectionDefaultsToDict(d *gitlab.BranchProtectionDefaults) any {
	if d == nil {
		return nil
	}
	accessLevels := func(levels []*gitlab.GroupAccessLevel) []any {
		out := make([]any, 0, len(levels))
		for _, l := range levels {
			if l == nil || l.AccessLevel == nil {
				continue
			}
			out = append(out, int64(*l.AccessLevel))
		}
		return out
	}
	return map[string]any{
		"allowForcePush":            d.AllowForcePush,
		"developerCanInitialPush":   d.DeveloperCanInitialPush,
		"codeOwnerApprovalRequired": d.CodeOwnerApprovalRequired,
		"allowedToPush":             accessLevels(d.AllowedToPush),
		"allowedToMerge":            accessLevels(d.AllowedToMerge),
	}
}

// projects lists all projects that belong to a group
// see https://docs.gitlab.com/ee/api/projects.html
func (g *mqlGitlabGroup) projects() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	if g.Path.Error != nil {
		return nil, g.Path.Error
	}
	gid := int(g.Id.Data)

	// Fetch all projects with pagination
	perPage := int64(50)
	page := int64(1)
	var allProjects []*gitlab.Project

	for {
		projects, resp, err := conn.Client().Groups.ListGroupProjects(gid, &gitlab.ListGroupProjectsOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allProjects = append(allProjects, projects...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlProjects []any
	for _, prj := range allProjects {
		mqlProject, err := CreateResource(g.MqlRuntime, "gitlab.project", getGitlabProjectArgs(prj))
		if err != nil {
			return nil, err
		}
		mqlProjects = append(mqlProjects, mqlProject)
	}

	return mqlProjects, nil
}

// members fetches the list of members in the group with their roles
func (g *mqlGitlabGroup) members() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	groupID := int(g.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var allMembers []*gitlab.GroupMember

	for {
		members, resp, err := conn.Client().Groups.ListAllGroupMembers(groupID, &gitlab.ListGroupMembersOptions{
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
		mqlUser, err := NewResource(g.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
			"id": llx.IntData(member.ID),
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
			// GroupMember.ID is the *user* id, so it repeats for every group
			// and project that user belongs to. ListAllGroupMembers also
			// returns inherited members, which means a parent-group membership
			// and a subgroup membership for the same user land in the same
			// runtime — keying on the user id alone made the second one
			// resolve to the first, hiding a deliberately narrowed role.
			"__id":        llx.StringData(groupScopedID("gitlab.member/group", g.Id.Data, strconv.FormatInt(member.ID, 10))),
			"id":          llx.IntData(member.ID),
			"user":        llx.ResourceData(mqlUser, "gitlab.user"),
			"role":        llx.StringData(role),
			"accessLevel": llx.IntData(int64(member.AccessLevel)),
			"state":       llx.StringData(member.State),
			"expiresAt":   llx.TimeDataPtr(expiresAt),
			"createdAt":   llx.TimeDataPtr(member.CreatedAt),
			"isUsingSeat": llx.BoolData(member.IsUsingSeat),
		}

		mqlMember, err := CreateResource(g.MqlRuntime, "gitlab.member", memberInfo)
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

// subgroups fetches the list of subgroups that belong to this group
func (g *mqlGitlabGroup) subgroups() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	groupID := int(g.Id.Data)

	// Fetch all subgroups with pagination
	perPage := int64(50)
	page := int64(1)
	var allSubgroups []*gitlab.Group

	for {
		subgroups, resp, err := conn.Client().Groups.ListSubGroups(groupID, &gitlab.ListSubGroupsOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allSubgroups = append(allSubgroups, subgroups...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlSubgroups []any
	for _, subgroup := range allSubgroups {
		// Reuse populateGroupArgs so subgroups expose the same field set as
		// top-level groups (and inherit new fields automatically).
		subgroupArgs := map[string]*llx.RawData{}
		populateGroupArgs(subgroupArgs, subgroup)

		mqlSubgroup, err := CreateResource(g.MqlRuntime, "gitlab.group", subgroupArgs)
		if err != nil {
			return nil, err
		}

		mqlSubgroups = append(mqlSubgroups, mqlSubgroup)
	}

	return mqlSubgroups, nil
}

// id function for gitlab.group.label
func (l *mqlGitlabGroupLabel) id() (string, error) {
	return strconv.FormatInt(l.Id.Data, 10), nil
}

// labels fetches the list of labels for the group
func (g *mqlGitlabGroup) labels() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	groupID := int(g.Id.Data)

	// Fetch all labels with pagination
	perPage := int64(50)
	page := int64(1)
	var allLabels []*gitlab.GroupLabel

	for {
		labels, resp, err := conn.Client().GroupLabels.ListGroupLabels(groupID, &gitlab.ListGroupLabelsOptions{
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

		mqlLabel, err := CreateResource(g.MqlRuntime, "gitlab.group.label", labelInfo)
		if err != nil {
			return nil, err
		}

		mqlLabels = append(mqlLabels, mqlLabel)
	}

	return mqlLabels, nil
}

// id function for gitlab.group.pushRule
func (r *mqlGitlabGroupPushRule) id() (string, error) {
	return "gitlab.group.pushRule/" + strconv.FormatInt(r.Id.Data, 10), nil
}

// pushRules fetches push rules for the group
func (g *mqlGitlabGroup) pushRules() (*mqlGitlabGroupPushRule, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	groupID := int(g.Id.Data)
	rules, resp, err := conn.Client().Groups.GetGroupPushRules(groupID)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			g.PushRules.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil // no push rules configured
		}
		return nil, err
	}
	if rules == nil {
		g.PushRules.State = plugin.StateIsSet | plugin.StateIsNull
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

	mqlRule, err := CreateResource(g.MqlRuntime, "gitlab.group.pushRule", ruleInfo)
	if err != nil {
		return nil, err
	}

	return mqlRule.(*mqlGitlabGroupPushRule), nil
}

// id function for gitlab.group.accessToken
func (t *mqlGitlabGroupAccessToken) id() (string, error) {
	return "gitlab.group.accessToken/" + strconv.FormatInt(t.Id.Data, 10), nil
}

// accessTokens fetches the list of access tokens for the group
func (g *mqlGitlabGroup) accessTokens() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	groupID := int(g.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var allTokens []*gitlab.GroupAccessToken

	for {
		tokens, resp, err := conn.Client().GroupAccessTokens.ListGroupAccessTokens(groupID, &gitlab.ListGroupAccessTokensOptions{
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

		mqlToken, err := CreateResource(g.MqlRuntime, "gitlab.group.accessToken", tokenInfo)
		if err != nil {
			return nil, err
		}
		mqlToken.(*mqlGitlabGroupAccessToken).cacheUserID = token.UserID

		mqlTokens = append(mqlTokens, mqlToken)
	}

	return mqlTokens, nil
}

// mqlGitlabGroupAccessTokenInternal caches the bot user id so the typed user()
// accessor can resolve it lazily.
type mqlGitlabGroupAccessTokenInternal struct {
	cacheUserID int64
}

// user returns the bot user the token authenticates as. Access-token bot users
// are not always resolvable via the users API; initGitlabUser degrades to a
// bare resource on 403/404, and this returns null when there is no user id.
func (t *mqlGitlabGroupAccessToken) user() (*mqlGitlabUser, error) {
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

// id function for gitlab.group.deployToken
func (t *mqlGitlabGroupDeployToken) id() (string, error) {
	return "gitlab.group.deployToken/" + strconv.FormatInt(t.Id.Data, 10), nil
}

// deployTokens fetches the list of deploy tokens for the group
func (g *mqlGitlabGroup) deployTokens() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	groupID := int(g.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var allTokens []*gitlab.DeployToken

	for {
		tokens, resp, err := conn.Client().DeployTokens.ListGroupDeployTokens(groupID, &gitlab.ListGroupDeployTokensOptions{
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

		mqlToken, err := CreateResource(g.MqlRuntime, "gitlab.group.deployToken", tokenInfo)
		if err != nil {
			return nil, err
		}

		mqlTokens = append(mqlTokens, mqlToken)
	}

	return mqlTokens, nil
}

// mqlGitlabGroupSamlGroupLinkInternal carries the parent group ID so the link
// __id stays unique across groups (provider+name alone collides between groups
// that share the same SAML provider and group name).
type mqlGitlabGroupSamlGroupLinkInternal struct {
	groupID int64
}

// samlGroupLinks fetches SAML group links for the group.
//
// SAML group links are a Premium/Ultimate feature. On lower tiers the API
// returns 403/404, in which case we return an empty list rather than failing
// the whole resource graph.
//
// see https://docs.gitlab.com/api/groups/#saml-group-links
func (g *mqlGitlabGroup) samlGroupLinks() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	groupID := int(g.Id.Data)

	var allLinks []*gitlab.SAMLGroupLink
	var opts []gitlab.RequestOptionFunc
	for {
		links, resp, err := conn.Client().Groups.ListGroupSAMLLinks(groupID, opts...)
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil // not available on this GitLab tier
			}
			return nil, err
		}

		allLinks = append(allLinks, links...)

		next, hasNext := gitlab.WithNext(resp)
		if !hasNext {
			break
		}
		opts = []gitlab.RequestOptionFunc{next}
	}

	var mqlLinks []any
	for _, link := range allLinks {
		linkInfo := map[string]*llx.RawData{
			// The group id has to be passed here rather than read back out of
			// the Internal struct by id(): CreateResource computes __id during
			// construction, so a field assigned afterwards is always still
			// zero at that point and every link keyed as ".../0/provider/name".
			"__id":         llx.StringData(groupScopedID("gitlab.group.samlGroupLink", g.Id.Data, link.Provider, link.Name)),
			"name":         llx.StringData(link.Name),
			"accessLevel":  llx.IntData(int64(link.AccessLevel)),
			"memberRoleId": llx.IntData(link.MemberRoleID),
			"provider":     llx.StringData(link.Provider),
		}
		mqlLink, err := CreateResource(g.MqlRuntime, "gitlab.group.samlGroupLink", linkInfo)
		if err != nil {
			return nil, err
		}
		mqlLink.(*mqlGitlabGroupSamlGroupLink).groupID = g.Id.Data
		mqlLinks = append(mqlLinks, mqlLink)
	}

	return mqlLinks, nil
}

// id function for gitlab.group.auditEvent
func (a *mqlGitlabGroupAuditEvent) id() (string, error) {
	return "gitlab.group.auditEvent/" + strconv.FormatInt(a.Id.Data, 10), nil
}

// author returns a typed reference to the user who performed the action.
// Returns null when authorId is unknown (e.g. system-generated events).
func (a *mqlGitlabGroupAuditEvent) author() (*mqlGitlabUser, error) {
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
func (a *mqlGitlabGroupAuditEvent) entityUser() (*mqlGitlabUser, error) {
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
func (a *mqlGitlabGroupAuditEvent) entityGroup() (*mqlGitlabGroup, error) {
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
func (a *mqlGitlabGroupAuditEvent) entityProject() (*mqlGitlabProject, error) {
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

// auditEvents fetches audit events for the group.
//
// Group audit events are a Premium/Ultimate feature. On lower tiers the API
// returns 403/404, in which case we return an empty list rather than failing
// the whole resource graph.
//
// see https://docs.gitlab.com/api/audit_events/#group-audit-events
func (g *mqlGitlabGroup) auditEvents() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	groupID := int(g.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var allEvents []*gitlab.AuditEvent

	for {
		events, resp, err := conn.Client().AuditEvents.ListGroupAuditEvents(groupID, &gitlab.ListAuditEventsOptions{
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
		mqlEvent, err := CreateResource(g.MqlRuntime, "gitlab.group.auditEvent", eventInfo)
		if err != nil {
			return nil, err
		}
		mqlEvents = append(mqlEvents, mqlEvent)
	}

	return mqlEvents, nil
}

// id function for gitlab.group.protectedBranch
func (b *mqlGitlabGroupProtectedBranch) id() (string, error) {
	return "gitlab.group.protectedBranch/" + strconv.FormatInt(b.Id.Data, 10), nil
}

// protectedBranches fetches the list of protected branches for the group
func (g *mqlGitlabGroup) protectedBranches() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	groupID := int(g.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var allBranches []*gitlab.GroupProtectedBranch

	for {
		branches, resp, err := conn.Client().GroupProtectedBranches.ListProtectedBranches(groupID, &gitlab.ListGroupProtectedBranchesOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allBranches = append(allBranches, branches...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlBranches []any
	for _, branch := range allBranches {
		prefix := "gitlab.group.protectedBranch/" + strconv.FormatInt(branch.ID, 10)
		push, err := groupBranchAccessLevels(g.MqlRuntime, prefix+"/push", branch.PushAccessLevels)
		if err != nil {
			return nil, err
		}
		merge, err := groupBranchAccessLevels(g.MqlRuntime, prefix+"/merge", branch.MergeAccessLevels)
		if err != nil {
			return nil, err
		}
		unprotect, err := groupBranchAccessLevels(g.MqlRuntime, prefix+"/unprotect", branch.UnprotectAccessLevels)
		if err != nil {
			return nil, err
		}

		branchInfo := map[string]*llx.RawData{
			"id":                        llx.IntData(branch.ID),
			"name":                      llx.StringData(branch.Name),
			"allowForcePush":            llx.BoolData(branch.AllowForcePush),
			"codeOwnerApprovalRequired": llx.BoolData(branch.CodeOwnerApprovalRequired),
			"pushAccessLevels":          llx.ArrayData(push, types.Resource("gitlab.protectedBranch.accessLevel")),
			"mergeAccessLevels":         llx.ArrayData(merge, types.Resource("gitlab.protectedBranch.accessLevel")),
			"unprotectAccessLevels":     llx.ArrayData(unprotect, types.Resource("gitlab.protectedBranch.accessLevel")),
		}

		mqlBranch, err := CreateResource(g.MqlRuntime, "gitlab.group.protectedBranch", branchInfo)
		if err != nil {
			return nil, err
		}

		mqlBranches = append(mqlBranches, mqlBranch)
	}

	return mqlBranches, nil
}

func groupBranchAccessLevels(runtime *plugin.Runtime, idPrefix string, descs []*gitlab.GroupBranchAccessDescription) ([]any, error) {
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

// parentGroup returns the group this group is nested under, or null when it is
// a top-level group. The parent id is read from the full group payload; on
// 403/404 it yields null rather than failing the resource graph.
func (g *mqlGitlabGroup) parentGroup() (*mqlGitlabGroup, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	grp, resp, err := conn.Client().Groups.GetGroup(int(g.Id.Data), nil)
	if err != nil {
		if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
			g.ParentGroup.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if grp.ParentID <= 0 {
		g.ParentGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gitlab.group", map[string]*llx.RawData{
		"id": llx.IntData(int64(grp.ParentID)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabGroup), nil
}

// variables lists the group-level CI/CD variables. These are inherited by
// every project in the group.
func (g *mqlGitlabGroup) variables() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	groupID := int(g.Id.Data)

	perPage := int64(50)
	page := int64(1)
	var allVars []*gitlab.GroupVariable

	for {
		vars, resp, err := conn.Client().GroupVariables.ListVariables(groupID, &gitlab.ListGroupVariablesOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			return nil, err
		}

		allVars = append(allVars, vars...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlVars []any
	for _, v := range allVars {
		varInfo := map[string]*llx.RawData{
			// Subgroups routinely redefine a parent group's variable at the
			// same scope (that is the whole point of group-level variables),
			// so key+scope without the group id aliases the override onto the
			// parent's row — including its masked/protected flags.
			"__id":             llx.StringData(groupScopedID("gitlab.group.variable", g.Id.Data, v.Key, v.EnvironmentScope)),
			"key":              llx.StringData(v.Key),
			"variableType":     llx.StringData(string(v.VariableType)),
			"protected":        llx.BoolData(v.Protected),
			"masked":           llx.BoolData(v.Masked),
			"hidden":           llx.BoolData(v.Hidden),
			"raw":              llx.BoolData(v.Raw),
			"environmentScope": llx.StringData(v.EnvironmentScope),
			"description":      llx.StringData(v.Description),
		}

		mqlVar, err := CreateResource(g.MqlRuntime, "gitlab.group.variable", varInfo)
		if err != nil {
			return nil, err
		}

		mqlVars = append(mqlVars, mqlVar)
	}

	return mqlVars, nil
}

func (h *mqlGitlabGroupWebhook) id() (string, error) {
	return "gitlab.group.webhook/" + strconv.FormatInt(h.Id.Data, 10), nil
}

// group returns the group a webhook is registered against.
func (h *mqlGitlabGroupWebhook) group() (*mqlGitlabGroup, error) {
	res, err := NewResource(h.MqlRuntime, "gitlab.group", map[string]*llx.RawData{
		"id": llx.IntData(h.groupID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabGroup), nil
}

// mqlGitlabGroupWebhookInternal carries the parent group ID so the group()
// back-reference resolves lazily.
type mqlGitlabGroupWebhookInternal struct {
	groupID int64
}

// webhooks lists the webhooks registered at the group level. Group hooks fire
// for events across every project in the group. The configured secret token is
// write-only and never returned, but GitLab does report whether one is set, and
// that is decoded separately from the SDK type so an instance that does not
// report it leaves tokenPresent null instead of claiming no token is set.
func (g *mqlGitlabGroup) webhooks() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	raw, _, err := listRawPages(conn.Client(), "groups/"+strconv.FormatInt(g.Id.Data, 10)+"/hooks", 50)
	if err != nil {
		return nil, err
	}

	allHooks, presence, err := decodeHooks[gitlab.GroupHook](raw)
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
			// Group webhooks have no repository_update_events attribute: the
			// GitLab API never returned one, and client-go dropped the field
			// from GroupHook accordingly. Null says we cannot see it; the
			// false this used to report claimed the trigger was switched off.
			"repositoryUpdateEvents": llx.BoolDataPtr(nil),
			"tokenPresent":           llx.BoolDataPtr(presence[i].TokenPresent),
			"subGroupEvents":         llx.BoolData(hook.SubGroupEvents),
			"memberEvents":           llx.BoolData(hook.MemberEvents),
			"projectEvents":          llx.BoolData(hook.ProjectEvents),
			"branchFilterStrategy":   llx.StringData(hook.BranchFilterStrategy),
			"customWebhookTemplate":  llx.StringData(hook.CustomWebhookTemplate),
			"customHeaders":          llx.MapData(customHeaders, types.String),
			"createdAt":              llx.TimeDataPtr(hook.CreatedAt),
			"alertStatus":            llx.StringData(hook.AlertStatus),
		}

		mqlWebhook, err := CreateResource(g.MqlRuntime, "gitlab.group.webhook", hookInfo)
		if err != nil {
			return nil, err
		}

		mqlWebhook.(*mqlGitlabGroupWebhook).groupID = g.Id.Data
		mqlWebhooks = append(mqlWebhooks, mqlWebhook)
	}

	return mqlWebhooks, nil
}
