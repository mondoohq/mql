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

// mqlNeonBranchInternal caches the identifiers the branch's own child lookups
// and references need.
type mqlNeonBranchInternal struct {
	cacheProjectID string
	cacheParentID  string
}

type branchRecord struct {
	ID                string                   `json:"id"`
	ProjectID         string                   `json:"project_id"`
	ParentID          *string                  `json:"parent_id"`
	Name              string                   `json:"name"`
	Default           bool                     `json:"default"`
	Protected         bool                     `json:"protected"`
	CurrentState      string                   `json:"current_state"`
	LogicalSize       *int64                   `json:"logical_size"`
	InitSource        *string                  `json:"init_source"`
	RestrictedActions []branchRestrictedAction `json:"restricted_actions"`
	ExpiresAt         neonTime                 `json:"expires_at"`
	CreatedAt         neonTime                 `json:"created_at"`
	UpdatedAt         neonTime                 `json:"updated_at"`
	LastResetAt       neonTime                 `json:"last_reset_at"`
}

type branchRestrictedAction struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

func (p *mqlNeonProject) branches() ([]any, error) {
	c := neonConn(p.MqlRuntime)

	records, err := connection.GetPagedCursor[branchRecord](context.Background(), c,
		"/projects/"+url.PathEscape(p.Id.Data)+"/branches", nil, "branches")
	if err != nil {
		if connection.IsForbidden(err) {
			p.Branches = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		branch, err := newNeonBranch(p.MqlRuntime, p.Id.Data, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, branch)
	}
	return res, nil
}

func newNeonBranch(runtime *plugin.Runtime, projectID string, rec *branchRecord) (*mqlNeonBranch, error) {
	if rec.ProjectID != "" {
		projectID = rec.ProjectID
	}

	restricted := make([]any, 0, len(rec.RestrictedActions))
	for _, action := range rec.RestrictedActions {
		restricted = append(restricted, map[string]any{
			"name":   action.Name,
			"reason": action.Reason,
		})
	}

	logicalSize := llx.NilData
	if rec.LogicalSize != nil {
		logicalSize = llx.IntData(*rec.LogicalSize)
	}

	// Branch identifiers are scoped to their project, so the cache key carries
	// both. A bare branch id would let two projects alias each other.
	res, err := CreateResource(runtime, "neon.branch", map[string]*llx.RawData{
		"__id":              llx.StringData(projectID + "/" + rec.ID),
		"id":                llx.StringData(rec.ID),
		"name":              llx.StringData(rec.Name),
		"default":           llx.BoolData(rec.Default),
		"protected":         llx.BoolData(rec.Protected),
		"currentState":      llx.StringData(rec.CurrentState),
		"logicalSize":       logicalSize,
		"initSource":        optionalString(rec.InitSource),
		"restrictedActions": llx.ArrayData(restricted, types.Dict),
		"expiresAt":         llx.TimeDataPtr(rec.ExpiresAt.Time()),
		"createdAt":         llx.TimeDataPtr(rec.CreatedAt.Time()),
		"updatedAt":         llx.TimeDataPtr(rec.UpdatedAt.Time()),
		"lastResetAt":       llx.TimeDataPtr(rec.LastResetAt.Time()),
	})
	if err != nil {
		return nil, err
	}

	branch := res.(*mqlNeonBranch)
	branch.cacheProjectID = projectID
	branch.cacheParentID = strPtr(rec.ParentID)
	return branch, nil
}

func (b *mqlNeonBranch) id() (string, error) {
	return b.cacheProjectID + "/" + b.Id.Data, b.Id.Error
}

// project resolves the project the branch belongs to.
func (b *mqlNeonBranch) project() (*mqlNeonProject, error) {
	project, err := projectByID(b.MqlRuntime, b.cacheProjectID)
	if err != nil {
		return nil, err
	}
	if project == nil {
		b.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

// parent resolves the branch this branch was created from. A root branch has
// none.
func (b *mqlNeonBranch) parent() (*mqlNeonBranch, error) {
	if b.cacheParentID == "" {
		b.Parent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	parent, err := branchByID(b.MqlRuntime, b.cacheProjectID, b.cacheParentID)
	if err != nil {
		return nil, err
	}
	if parent == nil {
		b.Parent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return parent, nil
}

// defaultBranch resolves the branch applications connect to by default.
func (p *mqlNeonProject) defaultBranch() (*mqlNeonBranch, error) {
	branches := p.GetBranches()
	if branches.Error != nil {
		return nil, branches.Error
	}

	for _, it := range branches.Data {
		branch, ok := it.(*mqlNeonBranch)
		if ok && branch.Default.Data {
			return branch, nil
		}
	}

	p.DefaultBranch.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// --- roles ----------------------------------------------------------------

// mqlNeonRoleInternal caches the branch the role is defined on.
type mqlNeonRoleInternal struct {
	cacheProjectID string
	cacheBranchID  string
}

type roleRecord struct {
	Name                 string   `json:"name"`
	Protected            *bool    `json:"protected"`
	AuthenticationMethod string   `json:"authentication_method"`
	CreatedAt            neonTime `json:"created_at"`
	UpdatedAt            neonTime `json:"updated_at"`
}

func (b *mqlNeonBranch) roles() ([]any, error) {
	c := neonConn(b.MqlRuntime)

	records, err := connection.GetList[roleRecord](context.Background(), c,
		"/projects/"+url.PathEscape(b.cacheProjectID)+"/branches/"+url.PathEscape(b.Id.Data)+"/roles",
		nil, "roles")
	if err != nil {
		if connection.IsForbidden(err) {
			b.Roles = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		// A role is keyed by name within its branch, so the cache key carries
		// the branch it belongs to.
		resource, err := CreateResource(b.MqlRuntime, "neon.role", map[string]*llx.RawData{
			"__id":                 llx.StringData(b.cacheProjectID + "/" + b.Id.Data + "/" + rec.Name),
			"name":                 llx.StringData(rec.Name),
			"protected":            llx.BoolData(boolPtr(rec.Protected)),
			"authenticationMethod": llx.StringData(rec.AuthenticationMethod),
			"createdAt":            llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":            llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		role := resource.(*mqlNeonRole)
		role.cacheProjectID = b.cacheProjectID
		role.cacheBranchID = b.Id.Data
		res = append(res, role)
	}
	return res, nil
}

// branch resolves the branch the role is defined on.
func (r *mqlNeonRole) branch() (*mqlNeonBranch, error) {
	branch, err := branchByID(r.MqlRuntime, r.cacheProjectID, r.cacheBranchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		r.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return branch, nil
}

// --- databases ------------------------------------------------------------

// mqlNeonDatabaseInternal caches the branch the database is defined on and the
// role that owns it.
type mqlNeonDatabaseInternal struct {
	cacheProjectID string
	cacheBranchID  string
	cacheOwnerName string
}

type databaseRecord struct {
	ID        int64    `json:"id"`
	BranchID  string   `json:"branch_id"`
	Name      string   `json:"name"`
	OwnerName string   `json:"owner_name"`
	CreatedAt neonTime `json:"created_at"`
	UpdatedAt neonTime `json:"updated_at"`
}

func (b *mqlNeonBranch) databases() ([]any, error) {
	c := neonConn(b.MqlRuntime)

	records, err := connection.GetList[databaseRecord](context.Background(), c,
		"/projects/"+url.PathEscape(b.cacheProjectID)+"/branches/"+url.PathEscape(b.Id.Data)+"/databases",
		nil, "databases")
	if err != nil {
		if connection.IsForbidden(err) {
			b.Databases = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		resource, err := CreateResource(b.MqlRuntime, "neon.database", map[string]*llx.RawData{
			"__id":      llx.StringData(b.cacheProjectID + "/" + b.Id.Data + "/" + itoa(rec.ID)),
			"id":        llx.StringData(itoa(rec.ID)),
			"name":      llx.StringData(rec.Name),
			"createdAt": llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt": llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		database := resource.(*mqlNeonDatabase)
		database.cacheProjectID = b.cacheProjectID
		database.cacheBranchID = b.Id.Data
		database.cacheOwnerName = rec.OwnerName
		res = append(res, database)
	}
	return res, nil
}

func (d *mqlNeonDatabase) id() (string, error) {
	return d.cacheProjectID + "/" + d.cacheBranchID + "/" + d.Id.Data, d.Id.Error
}

// branch resolves the branch the database is defined on.
func (d *mqlNeonDatabase) branch() (*mqlNeonBranch, error) {
	branch, err := branchByID(d.MqlRuntime, d.cacheProjectID, d.cacheBranchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		d.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return branch, nil
}

// owner resolves the role that owns the database from its branch's role list.
func (d *mqlNeonDatabase) owner() (*mqlNeonRole, error) {
	if d.cacheOwnerName == "" {
		d.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	branch, err := branchByID(d.MqlRuntime, d.cacheProjectID, d.cacheBranchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		d.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	roles := branch.GetRoles()
	if roles.Error != nil {
		return nil, roles.Error
	}
	for _, it := range roles.Data {
		role, ok := it.(*mqlNeonRole)
		if ok && role.Name.Data == d.cacheOwnerName {
			return role, nil
		}
	}

	d.Owner.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
