// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/url"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/neon/connection"
	"go.mondoo.com/mql/types"
)

// projectBasePath is the project-scoped root the governance endpoints hang off.
func projectBasePath(projectID string) string {
	return "/projects/" + url.PathEscape(projectID)
}

// --- advisors -------------------------------------------------------------

type advisorIssueRecord struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Level       string         `json:"level"`
	Facing      string         `json:"facing"`
	Categories  []string       `json:"categories"`
	Description string         `json:"description"`
	Detail      string         `json:"detail"`
	Remediation string         `json:"remediation"`
	Metadata    map[string]any `json:"metadata"`
	CacheKey    string         `json:"cache_key"`
}

// advisorIssueKey identifies one advisor finding within a project. The cache
// key the API returns already distinguishes two findings of the same type
// against different objects, so that is what the key is built from when it is
// there. The issue name alone names the check, not the object it fired on, so
// falling back to it would collapse every finding of one type in a project
// into a single result and silently drop the rest. The detail reports the
// object the check fired on, which is what separates them, and an index keeps
// two findings apart where even the detail is empty.
func advisorIssueKey(rec *advisorIssueRecord, index int) string {
	if rec.CacheKey != "" {
		return rec.CacheKey
	}
	if rec.Detail != "" {
		return rec.Name + "/" + rec.Detail
	}
	return rec.Name + "/#" + itoa(int64(index))
}

func (p *mqlNeonProject) advisorIssues() ([]any, error) {
	c := neonConn(p.MqlRuntime)

	records, err := connection.GetList[advisorIssueRecord](context.Background(), c,
		projectBasePath(p.Id.Data)+"/advisors", nil, "issues")
	if err != nil {
		// The advisors run against a project's Postgres schema, which the API
		// cannot reach on a project whose compute has never started.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			p.AdvisorIssues = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		// The project qualifies the key so a finding cannot alias one in
		// another project.
		issue, err := CreateResource(p.MqlRuntime, "neon.project.advisorIssue", map[string]*llx.RawData{
			"__id":        llx.StringData(p.Id.Data + "/advisor/" + advisorIssueKey(&rec, i)),
			"name":        llx.StringData(rec.Name),
			"title":       llx.StringData(rec.Title),
			"level":       llx.StringData(rec.Level),
			"facing":      llx.StringData(rec.Facing),
			"categories":  llx.ArrayData(strSliceToAny(rec.Categories), types.String),
			"description": llx.StringData(rec.Description),
			"detail":      llx.StringData(rec.Detail),
			"remediation": llx.StringData(rec.Remediation),
			"metadata":    llx.DictData(rec.Metadata),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, issue)
	}
	return res, nil
}

// --- project members ------------------------------------------------------

// mqlNeonProjectMemberInternal caches the organization the member belongs to
// and the account behind the membership, so the organization roster entry can
// be reached without a lookup per member.
type mqlNeonProjectMemberInternal struct {
	cacheProjectID string
	cacheUserID    string
}

type projectMemberRecord struct {
	MemberID                    string  `json:"member_id"`
	UserID                      string  `json:"user_id"`
	Email                       *string `json:"email"`
	Name                        *string `json:"name"`
	OrgRole                     string  `json:"org_role"`
	ProjectRole                 *string `json:"project_role"`
	OrgDefaultProjectPermission *string `json:"org_default_project_permission"`
	ExplicitProjectPermission   *string `json:"explicit_project_permission"`
	EffectiveProjectPermission  *string `json:"effective_project_permission"`
	GrantSource                 *string `json:"grant_source"`
}

func (p *mqlNeonProject) members() ([]any, error) {
	c := neonConn(p.MqlRuntime)

	records, err := connection.GetPagedCursor[projectMemberRecord](context.Background(), c,
		projectBasePath(p.Id.Data)+"/members", nil, "project_members")
	if err != nil {
		// A personal project has no organization roster behind it, and reading
		// one takes organization admin rights.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			p.Members = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		member, err := CreateResource(p.MqlRuntime, "neon.project.member", map[string]*llx.RawData{
			"__id":                        llx.StringData(p.Id.Data + "/member/" + rec.MemberID),
			"id":                          llx.StringData(rec.MemberID),
			"email":                       optionalString(rec.Email),
			"name":                        optionalString(rec.Name),
			"orgRole":                     llx.StringData(rec.OrgRole),
			"projectRole":                 optionalString(rec.ProjectRole),
			"orgDefaultProjectPermission": optionalString(rec.OrgDefaultProjectPermission),
			"explicitProjectPermission":   optionalString(rec.ExplicitProjectPermission),
			"effectiveProjectPermission":  optionalString(rec.EffectiveProjectPermission),
			"grantSource":                 optionalString(rec.GrantSource),
		})
		if err != nil {
			return nil, err
		}

		mqlMember := member.(*mqlNeonProjectMember)
		mqlMember.cacheProjectID = p.Id.Data
		mqlMember.cacheUserID = rec.UserID
		res = append(res, mqlMember)
	}
	return res, nil
}

// organizationMember resolves the roster entry of the owning organization that
// the project membership belongs to.
func (m *mqlNeonProjectMember) organizationMember() (*mqlNeonOrganizationMember, error) {
	if m.cacheUserID == "" {
		m.OrganizationMember.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	project, err := projectByID(m.MqlRuntime, m.cacheProjectID)
	if err != nil {
		return nil, err
	}
	if project == nil {
		m.OrganizationMember.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	member, err := organizationMemberByUserID(m.MqlRuntime, project, m.cacheUserID)
	if err != nil {
		return nil, err
	}
	if member == nil {
		m.OrganizationMember.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return member, nil
}

// organizationMemberByUserID finds a roster entry of the project's organization
// by the account behind it. The roster is read once through the organization
// resource and reused, rather than once per member that points at it.
func organizationMemberByUserID(runtime *plugin.Runtime, project *mqlNeonProject, userID string) (*mqlNeonOrganizationMember, error) {
	org := project.GetOrganization()
	// A roster the key is not allowed to read already answers as null, so an
	// error here is a read that failed. Reporting the reference as null would
	// present a failed read as an account holding no organization role.
	if org.Error != nil {
		return nil, org.Error
	}
	if org.Data == nil {
		return nil, nil
	}

	members := org.Data.GetMembers()
	if members.Error != nil {
		return nil, members.Error
	}
	for _, it := range members.Data {
		member, ok := it.(*mqlNeonOrganizationMember)
		if ok && member.cacheUserID == userID {
			return member, nil
		}
	}
	return nil, nil
}

// --- organization invitations ---------------------------------------------

// mqlNeonOrganizationInvitationInternal caches the organization the invitation
// was sent for and the account that sent it.
type mqlNeonOrganizationInvitationInternal struct {
	cacheOrgID     string
	cacheInvitedBy string
}

type invitationRecord struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	OrgID     string   `json:"org_id"`
	InvitedBy string   `json:"invited_by"`
	InvitedAt neonTime `json:"invited_at"`
	Role      string   `json:"role"`
}

func (o *mqlNeonOrganization) invitations() ([]any, error) {
	c := neonConn(o.MqlRuntime)

	records, err := connection.GetList[invitationRecord](context.Background(), c,
		"/organizations/"+url.PathEscape(o.Id.Data)+"/invitations", nil, "invitations")
	if err != nil {
		// Reading outstanding invitations takes organization admin rights.
		if connection.IsForbidden(err) {
			o.Invitations = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		invitation, err := CreateResource(o.MqlRuntime, "neon.organization.invitation", map[string]*llx.RawData{
			"__id":      llx.StringData(o.Id.Data + "/invitation/" + rec.ID),
			"id":        llx.StringData(rec.ID),
			"email":     llx.StringData(rec.Email),
			"role":      llx.StringData(rec.Role),
			"invitedAt": llx.TimeDataPtr(rec.InvitedAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		mqlInvitation := invitation.(*mqlNeonOrganizationInvitation)
		mqlInvitation.cacheOrgID = o.Id.Data
		mqlInvitation.cacheInvitedBy = rec.InvitedBy
		res = append(res, mqlInvitation)
	}
	return res, nil
}

// invitedBy resolves the roster entry of the member who sent the invitation.
func (i *mqlNeonOrganizationInvitation) invitedBy() (*mqlNeonOrganizationMember, error) {
	if i.cacheInvitedBy == "" {
		i.InvitedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	org, err := organizationByID(i.MqlRuntime, i.cacheOrgID)
	if err != nil {
		return nil, err
	}
	if org == nil {
		i.InvitedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// The roster the organization already read answers this for every
	// invitation, rather than a lookup per invitation.
	members := org.GetMembers()
	// A roster the key is not allowed to read already answers as null, so an
	// error here is a read that failed rather than a sender who has left.
	if members.Error != nil {
		return nil, members.Error
	}
	for _, it := range members.Data {
		member, ok := it.(*mqlNeonOrganizationMember)
		if ok && member.cacheUserID == i.cacheInvitedBy {
			return member, nil
		}
	}

	// Whoever sent the invitation may have left the organization since.
	i.InvitedBy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// --- operations -----------------------------------------------------------

// mqlNeonProjectOperationInternal caches the project the operation ran on and
// the branch and compute endpoint it touched.
type mqlNeonProjectOperationInternal struct {
	cacheProjectID  string
	cacheBranchID   string
	cacheEndpointID string
}

type operationRecord struct {
	ID              string   `json:"id"`
	ProjectID       string   `json:"project_id"`
	BranchID        *string  `json:"branch_id"`
	EndpointID      *string  `json:"endpoint_id"`
	Action          string   `json:"action"`
	Status          string   `json:"status"`
	Error           *string  `json:"error"`
	FailuresCount   *int64   `json:"failures_count"`
	RetryAt         neonTime `json:"retry_at"`
	CreatedAt       neonTime `json:"created_at"`
	UpdatedAt       neonTime `json:"updated_at"`
	TotalDurationMs *int64   `json:"total_duration_ms"`
}

func (p *mqlNeonProject) operations() ([]any, error) {
	c := neonConn(p.MqlRuntime)

	records, err := connection.GetPagedCursor[operationRecord](context.Background(), c,
		projectBasePath(p.Id.Data)+"/operations", nil, "operations")
	if err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			p.Operations = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		operation, err := CreateResource(p.MqlRuntime, "neon.project.operation", map[string]*llx.RawData{
			"__id":            llx.StringData(p.Id.Data + "/operation/" + rec.ID),
			"id":              llx.StringData(rec.ID),
			"action":          llx.StringData(rec.Action),
			"status":          llx.StringData(rec.Status),
			"error":           optionalString(rec.Error),
			"failuresCount":   llx.IntDataPtr(rec.FailuresCount),
			"retryAt":         llx.TimeDataPtr(rec.RetryAt.Time()),
			"createdAt":       llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":       llx.TimeDataPtr(rec.UpdatedAt.Time()),
			"totalDurationMs": llx.IntDataPtr(rec.TotalDurationMs),
		})
		if err != nil {
			return nil, err
		}

		mqlOperation := operation.(*mqlNeonProjectOperation)
		mqlOperation.cacheProjectID = p.Id.Data
		mqlOperation.cacheBranchID = strPtr(rec.BranchID)
		mqlOperation.cacheEndpointID = strPtr(rec.EndpointID)
		res = append(res, mqlOperation)
	}
	return res, nil
}

// project resolves the project the operation ran on.
func (o *mqlNeonProjectOperation) project() (*mqlNeonProject, error) {
	project, err := projectByID(o.MqlRuntime, o.cacheProjectID)
	if err != nil {
		return nil, err
	}
	if project == nil {
		o.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

// branch resolves the branch the operation ran on. An operation may name a
// branch that has since been deleted, which is reported as none.
func (o *mqlNeonProjectOperation) branch() (*mqlNeonBranch, error) {
	if o.cacheBranchID == "" {
		o.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	branch, err := branchByID(o.MqlRuntime, o.cacheProjectID, o.cacheBranchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		o.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return branch, nil
}

// endpoint resolves the compute endpoint the operation ran on.
func (o *mqlNeonProjectOperation) endpoint() (*mqlNeonEndpoint, error) {
	if o.cacheEndpointID == "" {
		o.Endpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	project, err := projectByID(o.MqlRuntime, o.cacheProjectID)
	if err != nil {
		return nil, err
	}
	if project == nil {
		o.Endpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// The project's endpoint list is read once and reused, rather than reading
	// the endpoint once per operation that names one.
	endpoints := project.GetEndpoints()
	// An endpoint list the key is not allowed to read already answers as null,
	// so an error here is a read that failed rather than a project without
	// endpoints.
	if endpoints.Error != nil {
		return nil, endpoints.Error
	}
	for _, it := range endpoints.Data {
		endpoint, ok := it.(*mqlNeonEndpoint)
		if ok && endpoint.Id.Data == o.cacheEndpointID {
			return endpoint, nil
		}
	}

	// An operation may name a compute endpoint that has since been deleted.
	o.Endpoint.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// --- snapshots ------------------------------------------------------------

// mqlNeonProjectSnapshotInternal caches the branch the snapshot was captured
// from.
type mqlNeonProjectSnapshotInternal struct {
	cacheProjectID string
	cacheBranchID  string
}

type snapshotRecord struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Lsn            *string  `json:"lsn"`
	Timestamp      neonTime `json:"timestamp"`
	SourceBranchID *string  `json:"source_branch_id"`
	CreatedAt      neonTime `json:"created_at"`
	ExpiresAt      neonTime `json:"expires_at"`
	Manual         *bool    `json:"manual"`
	FullSize       *int64   `json:"full_size"`
	DiffSize       *int64   `json:"diff_size"`
}

func (p *mqlNeonProject) snapshots() ([]any, error) {
	c := neonConn(p.MqlRuntime)

	records, err := connection.GetList[snapshotRecord](context.Background(), c,
		projectBasePath(p.Id.Data)+"/snapshots", nil, "snapshots")
	if err != nil {
		// Snapshots are a plan-gated feature.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			p.Snapshots = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		snapshot, err := CreateResource(p.MqlRuntime, "neon.project.snapshot", map[string]*llx.RawData{
			"__id":      llx.StringData(p.Id.Data + "/snapshot/" + rec.ID),
			"id":        llx.StringData(rec.ID),
			"name":      llx.StringData(rec.Name),
			"lsn":       optionalString(rec.Lsn),
			"timestamp": llx.TimeDataPtr(rec.Timestamp.Time()),
			"createdAt": llx.TimeDataPtr(rec.CreatedAt.Time()),
			"expiresAt": llx.TimeDataPtr(rec.ExpiresAt.Time()),
			"manual":    llx.BoolDataPtr(rec.Manual),
			"fullSize":  llx.IntDataPtr(rec.FullSize),
			"diffSize":  llx.IntDataPtr(rec.DiffSize),
		})
		if err != nil {
			return nil, err
		}

		mqlSnapshot := snapshot.(*mqlNeonProjectSnapshot)
		mqlSnapshot.cacheProjectID = p.Id.Data
		mqlSnapshot.cacheBranchID = strPtr(rec.SourceBranchID)
		res = append(res, mqlSnapshot)
	}
	return res, nil
}

// sourceBranch resolves the branch the snapshot was captured from. A snapshot
// outlives the branch it came from, so that branch may be gone.
func (s *mqlNeonProjectSnapshot) sourceBranch() (*mqlNeonBranch, error) {
	if s.cacheBranchID == "" {
		s.SourceBranch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	branch, err := branchByID(s.MqlRuntime, s.cacheProjectID, s.cacheBranchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		s.SourceBranch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return branch, nil
}
