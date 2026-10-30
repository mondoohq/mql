// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/neon/connection"
	"go.mondoo.com/mql/types"
)

// mqlNeonProjectInternal caches the organization the project belongs to, which
// is only present on the project payload, and memoizes the owner read that the
// list endpoint does not answer.
type mqlNeonProjectInternal struct {
	cacheOrgID string

	ownerFetched atomic.Bool
	ownerEmail_  string
	ownerLock    sync.Mutex
}

type projectRecord struct {
	ID                      string               `json:"id"`
	Name                    string               `json:"name"`
	PlatformID              string               `json:"platform_id"`
	RegionID                string               `json:"region_id"`
	PgVersion               int64                `json:"pg_version"`
	Provisioner             string               `json:"provisioner"`
	ProxyHost               string               `json:"proxy_host"`
	StorePasswords          bool                 `json:"store_passwords"`
	HistoryRetentionSeconds *int64               `json:"history_retention_seconds"`
	HipaaEnabledAt          neonTime             `json:"hipaa_enabled_at"`
	OrgID                   *string              `json:"org_id"`
	Owner                   *projectOwnerRecord  `json:"owner"`
	CreatedAt               neonTime             `json:"created_at"`
	UpdatedAt               neonTime             `json:"updated_at"`
	ComputeLastActiveAt     neonTime             `json:"compute_last_active_at"`
	Settings                *projectSettingsData `json:"settings"`
}

type projectOwnerRecord struct {
	Email string `json:"email"`
}

// projectSettingsData holds the project-wide controls. Neon omits a setting
// that has never been switched on, so every field is optional.
type projectSettingsData struct {
	AllowedIps               *allowedIpsData `json:"allowed_ips"`
	AuditLogLevel            *string         `json:"audit_log_level"`
	BlockPublicConnections   *bool           `json:"block_public_connections"`
	BlockVpcConnections      *bool           `json:"block_vpc_connections"`
	EnableLogicalReplication *bool           `json:"enable_logical_replication"`
	Hipaa                    *bool           `json:"hipaa"`
}

type allowedIpsData struct {
	Ips                   *[]string `json:"ips"`
	ProtectedBranchesOnly *bool     `json:"protected_branches_only"`
}

// projects lists every project the API key can reach, narrowed to the
// organization and project the connection is scoped to.
//
// Every project belongs to an organization, and the list endpoint rejects a
// request that does not name one, so the projects of each accessible
// organization are collected in turn rather than asked for in one call.
func (n *mqlNeon) projects() ([]any, error) {
	c := neonConn(n.MqlRuntime)

	orgIDs := []string{}
	if orgID := c.OrganizationFilter(); orgID != "" {
		orgIDs = append(orgIDs, orgID)
	} else {
		organizations := n.GetOrganizations()
		if organizations.Error != nil {
			return nil, organizations.Error
		}
		for _, it := range organizations.Data {
			if org, ok := it.(*mqlNeonOrganization); ok {
				orgIDs = append(orgIDs, org.Id.Data)
			}
		}
	}

	projectFilter := c.ProjectFilter()

	var res []any
	for _, orgID := range orgIDs {
		records, err := listProjects(c, orgID)
		if err != nil {
			// One organization the key cannot read must not hide the projects
			// of the ones it can. A named organization that does not answer
			// leaves the organization list empty, which is the signal that the
			// --organization value was wrong.
			if connection.IsForbidden(err) || connection.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		for i := range records {
			rec := records[i]
			if projectFilter != "" && rec.ID != projectFilter {
				continue
			}
			project, err := newNeonProject(n.MqlRuntime, &rec)
			if err != nil {
				return nil, err
			}
			res = append(res, project)
		}
	}
	return res, nil
}

// listProjects reads the projects of one organization.
func listProjects(c *connection.NeonConnection, orgID string) ([]projectRecord, error) {
	query := url.Values{}
	query.Set("org_id", orgID)

	return connection.GetPagedCursor[projectRecord](context.Background(), c,
		"/projects", query, "projects")
}

// projects lists the organization's projects.
func (o *mqlNeonOrganization) projects() ([]any, error) {
	c := neonConn(o.MqlRuntime)

	query := url.Values{}
	query.Set("org_id", o.Id.Data)

	records, err := connection.GetPagedCursor[projectRecord](context.Background(), c,
		"/projects", query, "projects")
	if err != nil {
		if connection.IsForbidden(err) {
			o.Projects = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	projectFilter := c.ProjectFilter()

	var res []any
	for i := range records {
		rec := records[i]
		if projectFilter != "" && rec.ID != projectFilter {
			continue
		}
		project, err := newNeonProject(o.MqlRuntime, &rec)
		if err != nil {
			return nil, err
		}
		res = append(res, project)
	}
	return res, nil
}

func newNeonProject(runtime *plugin.Runtime, rec *projectRecord) (*mqlNeonProject, error) {
	settings := rec.Settings
	if settings == nil {
		settings = &projectSettingsData{}
	}

	var allowedIps []string
	protectedOnly := false
	if settings.AllowedIps != nil {
		if settings.AllowedIps.Ips != nil {
			allowedIps = *settings.AllowedIps.Ips
		}
		protectedOnly = boolPtr(settings.AllowedIps.ProtectedBranchesOnly)
	}

	historyRetention := int64(0)
	if rec.HistoryRetentionSeconds != nil {
		historyRetention = *rec.HistoryRetentionSeconds
	}

	res, err := CreateResource(runtime, "neon.project", map[string]*llx.RawData{
		"id":                              llx.StringData(rec.ID),
		"name":                            llx.StringData(rec.Name),
		"platformId":                      llx.StringData(rec.PlatformID),
		"regionId":                        llx.StringData(rec.RegionID),
		"pgVersion":                       llx.IntData(rec.PgVersion),
		"provisioner":                     llx.StringData(rec.Provisioner),
		"proxyHost":                       llx.StringData(rec.ProxyHost),
		"blockPublicConnections":          llx.BoolData(boolPtr(settings.BlockPublicConnections)),
		"blockVpcConnections":             llx.BoolData(boolPtr(settings.BlockVpcConnections)),
		"allowedIps":                      llx.ArrayData(strSliceToAny(allowedIps), types.String),
		"allowedIpsProtectedBranchesOnly": llx.BoolData(protectedOnly),
		"enableLogicalReplication":        llx.BoolData(boolPtr(settings.EnableLogicalReplication)),
		"storePasswords":                  llx.BoolData(rec.StorePasswords),
		"hipaa":                           llx.BoolData(boolPtr(settings.Hipaa)),
		"hipaaEnabledAt":                  llx.TimeDataPtr(rec.HipaaEnabledAt.Time()),
		"auditLogLevel":                   optionalString(settings.AuditLogLevel),
		"historyRetentionSeconds":         llx.IntData(historyRetention),
		"createdAt":                       llx.TimeDataPtr(rec.CreatedAt.Time()),
		"updatedAt":                       llx.TimeDataPtr(rec.UpdatedAt.Time()),
		"computeLastActiveAt":             llx.TimeDataPtr(rec.ComputeLastActiveAt.Time()),
	})
	if err != nil {
		return nil, err
	}

	project := res.(*mqlNeonProject)
	project.cacheOrgID = strPtr(rec.OrgID)
	if rec.Owner != nil {
		project.seedOwnerEmail(rec.Owner.Email)
	}
	return project, nil
}

// seedOwnerEmail records the owner a project payload carried so the read that
// the list endpoint cannot answer is skipped. It takes the same lock the lazy
// read takes, because CreateResource hands back an instance it already holds
// when one exists, and another query may be inside that read on it.
func (p *mqlNeonProject) seedOwnerEmail(email string) {
	p.ownerLock.Lock()
	defer p.ownerLock.Unlock()
	if p.ownerFetched.Load() {
		return
	}
	p.ownerEmail_ = email
	p.ownerFetched.Store(true)
}

// ownerEmail reports the account that owns the project. The list endpoint omits
// the owner, so a project reached through a list resolves it from the project
// endpoint on first read and holds the answer.
func (p *mqlNeonProject) ownerEmail() (string, error) {
	if p.ownerFetched.Load() {
		return p.ownerEmail_, nil
	}

	p.ownerLock.Lock()
	defer p.ownerLock.Unlock()
	if p.ownerFetched.Load() {
		return p.ownerEmail_, nil
	}

	c := neonConn(p.MqlRuntime)

	var resp struct {
		Project projectRecord `json:"project"`
	}
	if err := c.Get(context.Background(), "/projects/"+url.PathEscape(p.Id.Data), nil, &resp); err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			// A denied read is an answer, so it is memoized like a successful
			// one. Without this the negative result is re-fetched by every
			// in-provider caller, while a successful one is not.
			p.ownerFetched.Store(true)
			p.OwnerEmail = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
			return "", nil
		}
		return "", err
	}

	if resp.Project.Owner != nil {
		p.ownerEmail_ = resp.Project.Owner.Email
	}
	p.ownerFetched.Store(true)
	return p.ownerEmail_, nil
}

// initNeonProject resolves the project a query targets: an explicit id argument
// or the project a discovered asset is scoped to.
func initNeonProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	c := neonConn(runtime)

	projectID := ""
	if data, ok := args["id"]; ok {
		if s, ok := data.Value.(string); ok {
			projectID = s
		}
	}
	if projectID == "" && c.Asset() != nil {
		for _, pid := range c.Asset().PlatformIds {
			if t, ok := strings.CutPrefix(pid, connection.PlatformIdNeonProject); ok {
				projectID = t
				break
			}
		}
	}
	if projectID == "" {
		projectID = c.ProjectFilter()
	}
	if projectID == "" {
		return nil, nil, errors.New("neon.project requires a project id")
	}

	var resp struct {
		Project projectRecord `json:"project"`
	}
	if err := c.Get(context.Background(), "/projects/"+url.PathEscape(projectID), nil, &resp); err != nil {
		return nil, nil, err
	}
	if resp.Project.ID == "" {
		resp.Project.ID = projectID
	}

	project, err := newNeonProject(runtime, &resp.Project)
	if err != nil {
		return nil, nil, err
	}
	return args, project, nil
}

func (p *mqlNeonProject) id() (string, error) {
	return p.Id.Data, p.Id.Error
}

// organization resolves the organization the project belongs to. A personal
// project has none.
func (p *mqlNeonProject) organization() (*mqlNeonOrganization, error) {
	if p.cacheOrgID == "" {
		p.Organization.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// The organization list the root already fetched answers this for every
	// project of an organization the key can enumerate, which is one call for
	// the whole query rather than one per project.
	org, err := organizationByID(p.MqlRuntime, p.cacheOrgID)
	if err != nil {
		return nil, err
	}
	if org != nil {
		return org, nil
	}

	// An organization the key cannot enumerate is read directly.
	res, err := NewResource(p.MqlRuntime, "neon.organization", map[string]*llx.RawData{
		"id": llx.StringData(p.cacheOrgID),
	})
	if err != nil {
		// A project can belong to an organization the key is not a member of.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			p.Organization.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlNeonOrganization), nil
}

// --- project access -------------------------------------------------------

type permissionRecord struct {
	ID             string   `json:"id"`
	GrantedToEmail string   `json:"granted_to_email"`
	GrantedAt      neonTime `json:"granted_at"`
	RevokedAt      neonTime `json:"revoked_at"`
}

func (p *mqlNeonProject) permissions() ([]any, error) {
	c := neonConn(p.MqlRuntime)

	records, err := connection.GetList[permissionRecord](context.Background(), c,
		"/projects/"+url.PathEscape(p.Id.Data)+"/permissions", nil, "project_permissions")
	if err != nil {
		if connection.IsForbidden(err) {
			p.Permissions = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		// A grant is read through its project, so the cache key carries the
		// project it was read from and cannot alias one in another project.
		permission, err := CreateResource(p.MqlRuntime, "neon.project.permission", map[string]*llx.RawData{
			"__id":           llx.StringData(p.Id.Data + "/" + rec.ID),
			"id":             llx.StringData(rec.ID),
			"grantedToEmail": llx.StringData(rec.GrantedToEmail),
			"grantedAt":      llx.TimeDataPtr(rec.GrantedAt.Time()),
			"revokedAt":      llx.TimeDataPtr(rec.RevokedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, permission)
	}
	return res, nil
}

func (p *mqlNeonProjectPermission) id() (string, error) {
	return p.Id.Data, p.Id.Error
}

// --- trusted key sets -----------------------------------------------------

// mqlNeonProjectJwksEndpointInternal caches the project and branch the key set
// applies to so the branch can be resolved from the project's branch list.
type mqlNeonProjectJwksEndpointInternal struct {
	cacheProjectID string
	cacheBranchID  string
}

type jwksRecord struct {
	ID           string    `json:"id"`
	ProjectID    string    `json:"project_id"`
	BranchID     *string   `json:"branch_id"`
	JwksURL      string    `json:"jwks_url"`
	ProviderName string    `json:"provider_name"`
	JwtAudience  *string   `json:"jwt_audience"`
	RoleNames    *[]string `json:"role_names"`
	CreatedAt    neonTime  `json:"created_at"`
	UpdatedAt    neonTime  `json:"updated_at"`
}

func (p *mqlNeonProject) jwksEndpoints() ([]any, error) {
	c := neonConn(p.MqlRuntime)

	records, err := connection.GetList[jwksRecord](context.Background(), c,
		"/projects/"+url.PathEscape(p.Id.Data)+"/jwks", nil, "jwks")
	if err != nil {
		if connection.IsForbidden(err) {
			p.JwksEndpoints = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]

		var roleNames []string
		if rec.RoleNames != nil {
			roleNames = *rec.RoleNames
		}

		// A key set is read through its project, so the cache key carries the
		// project it was read from and cannot alias one in another project.
		endpoint, err := CreateResource(p.MqlRuntime, "neon.project.jwksEndpoint", map[string]*llx.RawData{
			"__id":         llx.StringData(p.Id.Data + "/" + rec.ID),
			"id":           llx.StringData(rec.ID),
			"jwksUrl":      llx.StringData(rec.JwksURL),
			"providerName": llx.StringData(rec.ProviderName),
			"jwtAudience":  optionalString(rec.JwtAudience),
			"roleNames":    llx.ArrayData(strSliceToAny(roleNames), types.String),
			"createdAt":    llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":    llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		jwks := endpoint.(*mqlNeonProjectJwksEndpoint)
		jwks.cacheProjectID = p.Id.Data
		jwks.cacheBranchID = strPtr(rec.BranchID)
		res = append(res, jwks)
	}
	return res, nil
}

func (j *mqlNeonProjectJwksEndpoint) id() (string, error) {
	return j.Id.Data, j.Id.Error
}

// branch resolves the branch the key set applies to. A key set registered for
// the whole project has none.
func (j *mqlNeonProjectJwksEndpoint) branch() (*mqlNeonBranch, error) {
	if j.cacheBranchID == "" {
		j.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	branch, err := branchByID(j.MqlRuntime, j.cacheProjectID, j.cacheBranchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		j.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return branch, nil
}

// --- private connectivity -------------------------------------------------

type vpcEndpointRecord struct {
	VpcEndpointID string `json:"vpc_endpoint_id"`
	Label         string `json:"label"`
}

// vpcEndpointDetailRecord decodes the attachment state of an endpoint, which
// the project-scoped list does not carry. It is only served under the
// organization that owns the endpoint, scoped to the region it sits in.
type vpcEndpointDetailRecord struct {
	VpcEndpointID             string   `json:"vpc_endpoint_id"`
	Label                     string   `json:"label"`
	State                     string   `json:"state"`
	NumRestrictedProjects     *int64   `json:"num_restricted_projects"`
	ExampleRestrictedProjects []string `json:"example_restricted_projects"`
}

// mqlNeonVpcEndpointInternal caches what the detail read needs and memoizes it,
// so a query touching several of the fields it backs reads it once.
type mqlNeonVpcEndpointInternal struct {
	cacheProjectID string
	cacheOrgID     string
	cacheRegionID  string

	detailOnce sync.Once
	detail     *vpcEndpointDetailRecord
	detailErr  error
}

func (p *mqlNeonProject) vpcEndpoints() ([]any, error) {
	c := neonConn(p.MqlRuntime)

	records, err := connection.GetList[vpcEndpointRecord](context.Background(), c,
		"/projects/"+url.PathEscape(p.Id.Data)+"/vpc_endpoints", nil, "endpoints")
	if err != nil {
		// Private connectivity is a plan-gated feature.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			p.VpcEndpoints = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		endpoint, err := CreateResource(p.MqlRuntime, "neon.vpcEndpoint", map[string]*llx.RawData{
			"__id":          llx.StringData(p.Id.Data + "/" + rec.VpcEndpointID),
			"vpcEndpointId": llx.StringData(rec.VpcEndpointID),
			"label":         llx.StringData(rec.Label),
		})
		if err != nil {
			return nil, err
		}

		mqlEndpoint := endpoint.(*mqlNeonVpcEndpoint)
		mqlEndpoint.cacheProjectID = p.Id.Data
		mqlEndpoint.cacheOrgID = p.cacheOrgID
		mqlEndpoint.cacheRegionID = p.RegionId.Data
		res = append(res, mqlEndpoint)
	}
	return res, nil
}

// fetchDetail reads the endpoint's attachment state once. The state is served
// only under the organization that owns the endpoint, so a personal project's
// endpoint has no read available and yields nil, which every caller reports as
// null rather than as an endpoint in no particular state. A read that failed
// for a reason other than access is reported as the failure it was, since an
// endpoint reported as being in no state would read as one that is fine.
func (v *mqlNeonVpcEndpoint) fetchDetail() (*vpcEndpointDetailRecord, error) {
	v.detailOnce.Do(func() {
		if v.cacheOrgID == "" || v.cacheRegionID == "" {
			return
		}

		c := neonConn(v.MqlRuntime)
		path := "/organizations/" + url.PathEscape(v.cacheOrgID) +
			"/vpc/region/" + url.PathEscape(v.cacheRegionID) +
			"/vpc_endpoints/" + url.PathEscape(v.VpcEndpointId.Data)

		var rec vpcEndpointDetailRecord
		if err := c.Get(context.Background(), path, nil, &rec); err != nil {
			if !connection.IsForbidden(err) && !connection.IsNotFound(err) {
				v.detailErr = err
			}
			return
		}
		v.detail = &rec
	})
	return v.detail, v.detailErr
}

// state reports whether Neon has accepted the endpoint's connection.
func (v *mqlNeonVpcEndpoint) state() (string, error) {
	detail, err := v.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		v.State = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return detail.State, nil
}

// numRestrictedProjects reports how many projects are restricted to reaching
// Neon over the endpoint.
func (v *mqlNeonVpcEndpoint) numRestrictedProjects() (int64, error) {
	detail, err := v.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail == nil || detail.NumRestrictedProjects == nil {
		v.NumRestrictedProjects = plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull}
		return 0, nil
	}
	return *detail.NumRestrictedProjects, nil
}

// exampleRestrictedProjects resolves the sample of restricted projects the API
// returns. Each is resolved from the project list the root already read.
func (v *mqlNeonVpcEndpoint) exampleRestrictedProjects() ([]any, error) {
	detail, err := v.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		v.ExampleRestrictedProjects = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	res := []any{}
	for _, projectID := range detail.ExampleRestrictedProjects {
		project, err := projectByID(v.MqlRuntime, projectID)
		if err != nil {
			return nil, err
		}
		// A project named here that the key cannot read is left out rather
		// than reported as a project with no fields.
		if project != nil {
			res = append(res, project)
		}
	}
	return res, nil
}
