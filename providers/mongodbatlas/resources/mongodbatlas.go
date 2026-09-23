// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mongodbatlas/connection"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

type mqlMongodbatlasInternal struct {
	orgSettingsLock sync.Mutex
	orgSettingsDone bool
	orgSettings     *admin.OrganizationSettings

	teamsOnce   sync.Once
	teamsByID   map[string]admin.TeamResponse
	teamsErr    error
	teamsDenied bool

	clustersOnce   sync.Once
	clustersByName map[string]*mqlMongodbatlasCluster
	clustersErr    error

	exportBucketsOnce sync.Once
	exportBucketsByID map[string]*mqlMongodbatlasSnapshotExportBucket
	exportBucketsErr  error

	accessRolesOnce sync.Once
	accessRolesByID map[string]*mqlMongodbatlasCloudProviderAccessRole
	accessRolesErr  error

	projectsOnce sync.Once
	projectsByID map[string]*mqlMongodbatlasProject
	projectsErr  error
}

// rootMongodbatlas returns the cached root resource singleton so sub-resources
// can share the org-wide caches (teams, clusters) that hang off its Internal
// struct.
func rootMongodbatlas(runtime *plugin.Runtime) (*mqlMongodbatlas, error) {
	res, err := CreateResource(runtime, "mongodbatlas", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlas), nil
}

func (r *mqlMongodbatlas) id() (string, error) {
	conn := r.MqlRuntime.Connection.(*connection.MongoDBAtlasConnection)
	if conn.Plane() == connection.PlaneProject {
		return "mongodbatlas/project/" + conn.ProjectID(), nil
	}
	return "mongodbatlas/org/" + conn.OrgID(), nil
}

func atlasClient(runtime *plugin.Runtime) *admin.APIClient {
	return runtime.Connection.(*connection.MongoDBAtlasConnection).Client()
}

// orgID returns the connected organization id, deriving it once (race-safe)
// from the accessible organizations when it was not supplied.
func orgID(runtime *plugin.Runtime) (string, error) {
	conn := runtime.Connection.(*connection.MongoDBAtlasConnection)
	return conn.EnsureOrgID(context.Background())
}

// projectID returns the connected project id, or an error when the asset is an
// organization rather than a single project.
func projectID(runtime *plugin.Runtime) (string, error) {
	conn := runtime.Connection.(*connection.MongoDBAtlasConnection)
	if conn.Plane() != connection.PlaneProject {
		return "", errors.New("this resource requires connecting to a single Atlas project (use --project-id or query a discovered project asset)")
	}
	return conn.ProjectID(), nil
}

// fetchOrgSettings loads the organization settings once and caches them for the
// several settings fields on the root resource. The endpoint requires
// organization-level privilege, so a project-scoped credential gets 401/403 (or
// 404); rather than failing the whole scan it degrades: the cached settings stay
// nil and each dependent field renders null.
func (r *mqlMongodbatlas) fetchOrgSettings() (*admin.OrganizationSettings, error) {
	r.orgSettingsLock.Lock()
	defer r.orgSettingsLock.Unlock()
	if r.orgSettingsDone {
		return r.orgSettings, nil
	}
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	settings, httpResp, err := atlasClient(r.MqlRuntime).OrganizationsAPI.GetOrgSettings(context.Background(), oid).Execute()
	if err != nil {
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			// Degrade: leave orgSettings nil and mark done. Each dependent
			// accessor checks `s == nil` and renders its field null.
			r.orgSettingsDone = true
			return nil, nil
		}
		return nil, err
	}
	r.orgSettings = settings
	r.orgSettingsDone = true
	return settings, nil
}

func (r *mqlMongodbatlas) organizationId() (string, error) {
	return orgID(r.MqlRuntime)
}

func (r *mqlMongodbatlas) organizationName() (string, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return "", err
	}
	org, httpResp, err := atlasClient(r.MqlRuntime).OrganizationsAPI.GetOrg(context.Background(), oid).Execute()
	if err != nil {
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			r.OrganizationName.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		return "", err
	}
	return org.GetName(), nil
}

func (r *mqlMongodbatlas) multiFactorAuthRequired() (bool, error) {
	s, err := r.fetchOrgSettings()
	if err != nil {
		return false, err
	}
	if s == nil {
		r.MultiFactorAuthRequired.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return s.GetMultiFactorAuthRequired(), nil
}

func (r *mqlMongodbatlas) apiAccessListRequired() (bool, error) {
	s, err := r.fetchOrgSettings()
	if err != nil {
		return false, err
	}
	if s == nil {
		r.ApiAccessListRequired.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return s.GetApiAccessListRequired(), nil
}

func (r *mqlMongodbatlas) restrictEmployeeAccess() (bool, error) {
	s, err := r.fetchOrgSettings()
	if err != nil {
		return false, err
	}
	if s == nil {
		r.RestrictEmployeeAccess.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return s.GetRestrictEmployeeAccess(), nil
}

func (r *mqlMongodbatlas) genAiFeaturesEnabled() (bool, error) {
	s, err := r.fetchOrgSettings()
	if err != nil {
		return false, err
	}
	if s == nil {
		r.GenAiFeaturesEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return s.GetGenAIFeaturesEnabled(), nil
}

func (r *mqlMongodbatlas) maxServiceAccountSecretValidityInHours() (int64, error) {
	s, err := r.fetchOrgSettings()
	if err != nil {
		return 0, err
	}
	if s == nil {
		r.MaxServiceAccountSecretValidityInHours.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(s.GetMaxServiceAccountSecretValidityInHours()), nil
}

func (r *mqlMongodbatlas) streamsCrossGroupEnabled() (bool, error) {
	s, err := r.fetchOrgSettings()
	if err != nil {
		return false, err
	}
	if s == nil {
		r.StreamsCrossGroupEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return s.GetStreamsCrossGroupEnabled(), nil
}

func (r *mqlMongodbatlas) securityContact() (string, error) {
	s, err := r.fetchOrgSettings()
	if err != nil {
		return "", err
	}
	if s == nil {
		r.SecurityContact.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return s.GetSecurityContact(), nil
}

// timePtr returns a pointer to t, or nil for the zero time, for llx.TimeDataPtr.
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// strSlice converts a string slice to the []any form llx.ArrayData expects.
func strSlice(vals []string) []any {
	out := make([]any, 0, len(vals))
	for _, v := range vals {
		out = append(out, v)
	}
	return out
}

// tagMap converts Atlas resource tags to the map form llx.MapData expects. A
// later tag wins on a duplicate key, which Atlas rejects at write time anyway.
func tagMap(tags []admin.ResourceTag) map[string]any {
	out := make(map[string]any, len(tags))
	for _, t := range tags {
		out[t.GetKey()] = t.GetValue()
	}
	return out
}

// labelMap converts the labels Atlas carries on a database user to the map form
// llx.MapData expects. Labels are a separate type from resource tags, with the
// same key/value shape.
func labelMap(labels []admin.ComponentLabel) map[string]any {
	out := make(map[string]any, len(labels))
	for _, l := range labels {
		out[l.GetKey()] = l.GetValue()
	}
	return out
}
