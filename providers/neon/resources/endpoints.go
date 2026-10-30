// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/url"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/neon/connection"
)

// mqlNeonEndpointInternal caches the project and branch the endpoint serves.
type mqlNeonEndpointInternal struct {
	cacheProjectID string
	cacheBranchID  string
}

type endpointRecord struct {
	ID                    string   `json:"id"`
	ProjectID             string   `json:"project_id"`
	BranchID              string   `json:"branch_id"`
	Host                  string   `json:"host"`
	Type                  string   `json:"type"`
	CurrentState          string   `json:"current_state"`
	Disabled              bool     `json:"disabled"`
	PasswordlessAccess    bool     `json:"passwordless_access"`
	PoolerEnabled         bool     `json:"pooler_enabled"`
	PoolerMode            string   `json:"pooler_mode"`
	AutoscalingLimitMinCu float64  `json:"autoscaling_limit_min_cu"`
	AutoscalingLimitMaxCu float64  `json:"autoscaling_limit_max_cu"`
	SuspendTimeoutSeconds int64    `json:"suspend_timeout_seconds"`
	RegionID              string   `json:"region_id"`
	Provisioner           string   `json:"provisioner"`
	CreatedAt             neonTime `json:"created_at"`
	LastActive            neonTime `json:"last_active"`
	StartedAt             neonTime `json:"started_at"`
	SuspendedAt           neonTime `json:"suspended_at"`
}

// endpoints lists every compute endpoint across the project's branches.
func (p *mqlNeonProject) endpoints() ([]any, error) {
	c := neonConn(p.MqlRuntime)

	records, err := connection.GetList[endpointRecord](context.Background(), c,
		"/projects/"+url.PathEscape(p.Id.Data)+"/endpoints", nil, "endpoints")
	if err != nil {
		if connection.IsForbidden(err) {
			p.Endpoints = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		endpoint, err := newNeonEndpoint(p.MqlRuntime, p.Id.Data, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, endpoint)
	}
	return res, nil
}

// endpoints lists the compute endpoints attached to the branch.
func (b *mqlNeonBranch) endpoints() ([]any, error) {
	c := neonConn(b.MqlRuntime)

	records, err := connection.GetList[endpointRecord](context.Background(), c,
		"/projects/"+url.PathEscape(b.cacheProjectID)+"/branches/"+url.PathEscape(b.Id.Data)+"/endpoints",
		nil, "endpoints")
	if err != nil {
		if connection.IsForbidden(err) {
			b.Endpoints = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		endpoint, err := newNeonEndpoint(b.MqlRuntime, b.cacheProjectID, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, endpoint)
	}
	return res, nil
}

func newNeonEndpoint(runtime *plugin.Runtime, projectID string, rec *endpointRecord) (*mqlNeonEndpoint, error) {
	if rec.ProjectID != "" {
		projectID = rec.ProjectID
	}

	res, err := CreateResource(runtime, "neon.endpoint", map[string]*llx.RawData{
		"__id":                  llx.StringData(projectID + "/" + rec.ID),
		"id":                    llx.StringData(rec.ID),
		"host":                  llx.StringData(rec.Host),
		"type":                  llx.StringData(rec.Type),
		"currentState":          llx.StringData(rec.CurrentState),
		"disabled":              llx.BoolData(rec.Disabled),
		"passwordlessAccess":    llx.BoolData(rec.PasswordlessAccess),
		"poolerEnabled":         llx.BoolData(rec.PoolerEnabled),
		"poolerMode":            llx.StringData(rec.PoolerMode),
		"autoscalingLimitMinCu": llx.FloatData(rec.AutoscalingLimitMinCu),
		"autoscalingLimitMaxCu": llx.FloatData(rec.AutoscalingLimitMaxCu),
		"suspendTimeoutSeconds": llx.IntData(rec.SuspendTimeoutSeconds),
		"regionId":              llx.StringData(rec.RegionID),
		"provisioner":           llx.StringData(rec.Provisioner),
		"createdAt":             llx.TimeDataPtr(rec.CreatedAt.Time()),
		"lastActive":            llx.TimeDataPtr(rec.LastActive.Time()),
		"startedAt":             llx.TimeDataPtr(rec.StartedAt.Time()),
		"suspendedAt":           llx.TimeDataPtr(rec.SuspendedAt.Time()),
	})
	if err != nil {
		return nil, err
	}

	endpoint := res.(*mqlNeonEndpoint)
	endpoint.cacheProjectID = projectID
	endpoint.cacheBranchID = rec.BranchID
	return endpoint, nil
}

func (e *mqlNeonEndpoint) id() (string, error) {
	return e.cacheProjectID + "/" + e.Id.Data, e.Id.Error
}

// branch resolves the branch the endpoint serves.
func (e *mqlNeonEndpoint) branch() (*mqlNeonBranch, error) {
	branch, err := branchByID(e.MqlRuntime, e.cacheProjectID, e.cacheBranchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		e.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return branch, nil
}

// project resolves the project the endpoint belongs to.
func (e *mqlNeonEndpoint) project() (*mqlNeonProject, error) {
	project, err := projectByID(e.MqlRuntime, e.cacheProjectID)
	if err != nil {
		return nil, err
	}
	if project == nil {
		e.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}
