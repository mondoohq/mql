// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/neon/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlNeon) id() (string, error) {
	return "neon", nil
}

// --- shared helpers -------------------------------------------------------

// neonTime decodes a Neon timestamp, which arrives as an RFC 3339 string and is
// absent on records that never reached the state it describes.
type neonTime struct {
	t *time.Time
}

func (n *neonTime) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == "" {
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	if str == "" {
		return nil
	}
	tt, err := time.Parse(time.RFC3339, str)
	if err != nil {
		// A timestamp the API changed the shape of is reported as null rather
		// than failing the whole resource, but it is logged so the change is
		// visible instead of looking like a record that never reached the
		// state the field describes.
		log.Warn().Str("value", str).Msg("neon> could not parse timestamp; reporting it as null")
		return nil
	}
	n.t = &tt
	return nil
}

// Time returns the decoded time value, or nil when the source was absent.
func (n neonTime) Time() *time.Time {
	return n.t
}

// strSliceToAny widens a string slice into an any slice for llx.ArrayData.
func strSliceToAny(in []string) []any {
	out := make([]any, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

// boolPtr dereferences an optional boolean, treating an absent value as false.
// Neon omits a setting that has never been switched on.
func boolPtr(v *bool) bool {
	return v != nil && *v
}

// strPtr dereferences an optional string, treating an absent value as empty.
func strPtr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// optionalString reports an absent value as null rather than as an empty
// string, so a setting the plan does not carry is distinguishable from one that
// is set to nothing.
func optionalString(v *string) *llx.RawData {
	if v == nil || *v == "" {
		return llx.NilData
	}
	return llx.StringData(*v)
}

// itoa renders a numeric identifier as the string form the schema exposes.
func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}

// neonConn returns the Neon connection backing the runtime.
func neonConn(runtime *plugin.Runtime) *connection.NeonConnection {
	return runtime.Connection.(*connection.NeonConnection)
}

// getNeon returns the root resource. Cross-resource accessors go through it so
// they reuse its cached project list rather than refetching a project each time
// a child needs to reach one.
func getNeon(runtime *plugin.Runtime) (*mqlNeon, error) {
	res, err := CreateResource(runtime, "neon", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNeon), nil
}

// cachedResource returns a resource the runtime already holds under the given
// name and identifier. NewResource runs a resource's init before it consults
// this cache, so a lookup that falls back to it would re-read the API once per
// caller without this check.
func cachedResource[T plugin.Resource](runtime *plugin.Runtime, name, id string) (T, bool) {
	var empty T
	if id == "" {
		return empty, false
	}
	res, ok := runtime.Resources.Get(name + "\x00" + id)
	if !ok {
		return empty, false
	}
	typed, ok := res.(T)
	if !ok {
		return empty, false
	}
	return typed, true
}

// projectByID resolves a project from the root resource's project list. Going
// through the cached list keeps a query that walks from many children back to
// their project down to the one call the list already made.
//
// That list only holds the projects of the organizations the API key can
// enumerate. A project outside it, either a personal project that belongs to no
// organization or one in an organization the key can read but not list, is read
// from the project endpoint instead, so a child still reaches its project
// rather than reporting none.
func projectByID(runtime *plugin.Runtime, projectID string) (*mqlNeonProject, error) {
	if projectID == "" {
		return nil, nil
	}

	root, err := getNeon(runtime)
	if err != nil {
		return nil, err
	}

	projects := root.GetProjects()
	if projects.Error != nil {
		return nil, projects.Error
	}
	for _, it := range projects.Data {
		project, ok := it.(*mqlNeonProject)
		if ok && project.Id.Data == projectID {
			return project, nil
		}
	}

	if project, ok := cachedResource[*mqlNeonProject](runtime, "neon.project", projectID); ok {
		return project, nil
	}

	res, err := NewResource(runtime, "neon.project", map[string]*llx.RawData{
		"id": llx.StringData(projectID),
	})
	if err != nil {
		// A project the key cannot read is reported as absent rather than
		// failing the query that reached it.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlNeonProject), nil
}

// organizationByID resolves an organization from the root resource's
// organization list. Reusing that list keeps a query that walks from many
// projects to their organization down to the one call the list already made,
// instead of a read per project.
func organizationByID(runtime *plugin.Runtime, orgID string) (*mqlNeonOrganization, error) {
	if orgID == "" {
		return nil, nil
	}

	root, err := getNeon(runtime)
	if err != nil {
		return nil, err
	}

	organizations := root.GetOrganizations()
	// An organization list the key cannot read is not an answer about any one
	// organization, so a caller is left to read it directly.
	if organizations.Error == nil {
		for _, it := range organizations.Data {
			org, ok := it.(*mqlNeonOrganization)
			if ok && org.Id.Data == orgID {
				return org, nil
			}
		}
	}

	if org, ok := cachedResource[*mqlNeonOrganization](runtime, "neon.organization", orgID); ok {
		return org, nil
	}
	return nil, nil
}

// branchByID resolves a branch from its project's branch list.
func branchByID(runtime *plugin.Runtime, projectID, branchID string) (*mqlNeonBranch, error) {
	if branchID == "" {
		return nil, nil
	}

	project, err := projectByID(runtime, projectID)
	if err != nil || project == nil {
		return nil, err
	}

	branches := project.GetBranches()
	if branches.Error != nil {
		return nil, branches.Error
	}
	for _, it := range branches.Data {
		branch, ok := it.(*mqlNeonBranch)
		if ok && branch.Id.Data == branchID {
			return branch, nil
		}
	}
	return nil, nil
}

// --- root resource --------------------------------------------------------

type userRecord struct {
	ID            string              `json:"id"`
	Email         string              `json:"email"`
	Name          string              `json:"name"`
	LastName      string              `json:"last_name"`
	Plan          string              `json:"plan"`
	ProjectsLimit int64               `json:"projects_limit"`
	BranchesLimit int64               `json:"branches_limit"`
	AuthAccounts  []authAccountRecord `json:"auth_accounts"`
}

type authAccountRecord struct {
	Provider string `json:"provider"`
}

func (n *mqlNeon) currentUser() (*mqlNeonUser, error) {
	c := neonConn(n.MqlRuntime)

	var rec userRecord
	if err := c.Get(context.Background(), "/users/me", nil, &rec); err != nil {
		// An organization-scoped API key authenticates as the organization
		// rather than as a person, so there is no user behind it to report.
		if connection.IsForbidden(err) {
			n.CurrentUser.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	providers := make([]string, 0, len(rec.AuthAccounts))
	for _, account := range rec.AuthAccounts {
		if account.Provider != "" {
			providers = append(providers, account.Provider)
		}
	}

	res, err := CreateResource(n.MqlRuntime, "neon.user", map[string]*llx.RawData{
		"id":            llx.StringData(rec.ID),
		"email":         llx.StringData(rec.Email),
		"name":          llx.StringData(rec.Name),
		"lastName":      llx.StringData(rec.LastName),
		"plan":          llx.StringData(rec.Plan),
		"authProviders": llx.ArrayData(strSliceToAny(providers), types.String),
		"projectsLimit": llx.IntData(rec.ProjectsLimit),
		"branchesLimit": llx.IntData(rec.BranchesLimit),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNeonUser), nil
}

func (u *mqlNeonUser) id() (string, error) {
	return u.Id.Data, u.Id.Error
}

// --- api keys -------------------------------------------------------------

type apiKeyRecord struct {
	ID               int64             `json:"id"`
	Name             string            `json:"name"`
	CreatedAt        neonTime          `json:"created_at"`
	CreatedBy        *apiKeyCreatorRec `json:"created_by"`
	LastUsedAt       neonTime          `json:"last_used_at"`
	LastUsedFromAddr string            `json:"last_used_from_addr"`
}

type apiKeyCreatorRec struct {
	Name string `json:"name"`
}

// apiKeys lists the keys owned by the authenticated account.
func (n *mqlNeon) apiKeys() ([]any, error) {
	c := neonConn(n.MqlRuntime)

	records, err := connection.GetList[apiKeyRecord](context.Background(), c, "/api_keys", nil, "")
	if err != nil {
		// An organization-scoped key cannot read the personal key list.
		if connection.IsForbidden(err) {
			n.ApiKeys = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	return newNeonApiKeys(n.MqlRuntime, "user", records)
}

// newNeonApiKeys builds a resource per key. The scope qualifies the cache key so
// a personal key and an organization key that share an identifier stay
// distinct.
func newNeonApiKeys(runtime *plugin.Runtime, scope string, records []apiKeyRecord) ([]any, error) {
	var res []any
	for i := range records {
		rec := records[i]

		createdBy := ""
		if rec.CreatedBy != nil {
			createdBy = rec.CreatedBy.Name
		}

		lastUsedFrom := llx.StringData(rec.LastUsedFromAddr)
		if rec.LastUsedFromAddr == "" {
			lastUsedFrom = llx.NilData
		}

		key, err := CreateResource(runtime, "neon.apiKey", map[string]*llx.RawData{
			"__id":             llx.StringData(scope + "/" + itoa(rec.ID)),
			"id":               llx.StringData(itoa(rec.ID)),
			"name":             llx.StringData(rec.Name),
			"createdByName":    llx.StringData(createdBy),
			"createdAt":        llx.TimeDataPtr(rec.CreatedAt.Time()),
			"lastUsedAt":       llx.TimeDataPtr(rec.LastUsedAt.Time()),
			"lastUsedFromAddr": lastUsedFrom,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, key)
	}
	return res, nil
}
