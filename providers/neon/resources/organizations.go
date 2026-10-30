// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/neon/connection"
)

type organizationRecord struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Handle             string   `json:"handle"`
	Plan               string   `json:"plan"`
	ManagedBy          string   `json:"managed_by"`
	AllowHipaaProjects *bool    `json:"allow_hipaa_projects"`
	RequireMfa         *bool    `json:"require_mfa"`
	CreatedAt          neonTime `json:"created_at"`
	UpdatedAt          neonTime `json:"updated_at"`
}

// organizations lists the organizations the API key can reach, narrowed to the
// organization the --organization flag or a discovered child asset scopes the
// connection to.
func (n *mqlNeon) organizations() ([]any, error) {
	c := neonConn(n.MqlRuntime)

	records, err := connection.GetList[organizationRecord](context.Background(), c,
		"/users/me/organizations", nil, "organizations")
	if err != nil {
		// An organization-scoped API key cannot enumerate organizations
		// through the user endpoint, so fall back to the one it is scoped to.
		if connection.IsForbidden(err) {
			if orgID := c.OrganizationFilter(); orgID != "" {
				org, err := n.fetchOrganization(orgID)
				if err != nil {
					return nil, err
				}
				if org != nil {
					return []any{org}, nil
				}
			}
			n.Organizations = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	filter := c.OrganizationFilter()

	var res []any
	for i := range records {
		rec := records[i]
		if filter != "" && rec.ID != filter && rec.Handle != filter {
			continue
		}
		org, err := newNeonOrganization(n.MqlRuntime, &rec)
		if err != nil {
			return nil, err
		}
		res = append(res, org)
	}
	return res, nil
}

// fetchOrganization reads a single organization directly, which is the only
// path available to a key that cannot enumerate them.
func (n *mqlNeon) fetchOrganization(orgID string) (*mqlNeonOrganization, error) {
	c := neonConn(n.MqlRuntime)

	var rec organizationRecord
	err := c.Get(context.Background(), "/organizations/"+url.PathEscape(orgID), nil, &rec)
	if err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if rec.ID == "" {
		rec.ID = orgID
	}
	return newNeonOrganization(n.MqlRuntime, &rec)
}

func newNeonOrganization(runtime *plugin.Runtime, rec *organizationRecord) (*mqlNeonOrganization, error) {
	res, err := CreateResource(runtime, "neon.organization", map[string]*llx.RawData{
		"id":                 llx.StringData(rec.ID),
		"name":               llx.StringData(rec.Name),
		"handle":             llx.StringData(rec.Handle),
		"plan":               llx.StringData(rec.Plan),
		"managedBy":          llx.StringData(rec.ManagedBy),
		"allowHipaaProjects": llx.BoolData(boolPtr(rec.AllowHipaaProjects)),
		"requireMfa":         llx.BoolData(boolPtr(rec.RequireMfa)),
		"createdAt":          llx.TimeDataPtr(rec.CreatedAt.Time()),
		"updatedAt":          llx.TimeDataPtr(rec.UpdatedAt.Time()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNeonOrganization), nil
}

// initNeonOrganization resolves the organization a query targets: an explicit
// id argument, the organization a discovered asset is scoped to, or the
// --organization connection option.
func initNeonOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	c := neonConn(runtime)

	orgID := ""
	if data, ok := args["id"]; ok {
		if s, ok := data.Value.(string); ok {
			orgID = s
		}
	}
	if orgID == "" && c.Asset() != nil {
		for _, pid := range c.Asset().PlatformIds {
			if t, ok := strings.CutPrefix(pid, connection.PlatformIdNeonOrganization); ok {
				orgID = t
				break
			}
		}
	}
	if orgID == "" {
		orgID = c.OrganizationFilter()
	}
	if orgID == "" {
		return nil, nil, errors.New("neon.organization requires an id")
	}

	var rec organizationRecord
	if err := c.Get(context.Background(), "/organizations/"+url.PathEscape(orgID), nil, &rec); err != nil {
		return nil, nil, err
	}
	if rec.ID == "" {
		rec.ID = orgID
	}

	org, err := newNeonOrganization(runtime, &rec)
	if err != nil {
		return nil, nil, err
	}
	return args, org, nil
}

func (o *mqlNeonOrganization) id() (string, error) {
	return o.Id.Data, o.Id.Error
}

// --- members --------------------------------------------------------------

type memberWithUserRecord struct {
	Member memberRecord     `json:"member"`
	User   memberUserRecord `json:"user"`
}

type memberRecord struct {
	ID       string   `json:"id"`
	OrgID    string   `json:"org_id"`
	UserID   string   `json:"user_id"`
	Role     string   `json:"role"`
	JoinedAt neonTime `json:"joined_at"`
}

type memberUserRecord struct {
	Email         string   `json:"email"`
	HasMfa        bool     `json:"has_mfa"`
	DeactivatedAt neonTime `json:"deactivated_at"`
}

// mqlNeonOrganizationMemberInternal caches the account behind the membership,
// which is what an invitation and a project membership name rather than the
// membership id.
type mqlNeonOrganizationMemberInternal struct {
	cacheUserID string
}

// organizationMemberID keys a roster entry by the organization it belongs to.
// The membership id the API returns is unique on its own, but qualifying it
// keeps the key self-describing and matches the other organization-scoped
// resources, so a roster entry cannot alias one read from another
// organization.
func organizationMemberID(orgID, memberID string) string {
	return orgID + "/member/" + memberID
}

func (o *mqlNeonOrganization) members() ([]any, error) {
	c := neonConn(o.MqlRuntime)

	records, err := connection.GetPagedCursor[memberWithUserRecord](context.Background(), c,
		"/organizations/"+url.PathEscape(o.Id.Data)+"/members", nil, "members")
	if err != nil {
		// Reading the roster takes organization admin rights.
		if connection.IsForbidden(err) {
			o.Members = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		member, err := CreateResource(o.MqlRuntime, "neon.organization.member", map[string]*llx.RawData{
			"__id":          llx.StringData(organizationMemberID(o.Id.Data, rec.Member.ID)),
			"id":            llx.StringData(rec.Member.ID),
			"email":         llx.StringData(rec.User.Email),
			"role":          llx.StringData(rec.Member.Role),
			"hasMfa":        llx.BoolData(rec.User.HasMfa),
			"joinedAt":      llx.TimeDataPtr(rec.Member.JoinedAt.Time()),
			"deactivatedAt": llx.TimeDataPtr(rec.User.DeactivatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		mqlMember := member.(*mqlNeonOrganizationMember)
		mqlMember.cacheUserID = rec.Member.UserID
		res = append(res, mqlMember)
	}
	return res, nil
}

func (m *mqlNeonOrganizationMember) id() (string, error) {
	return m.Id.Data, m.Id.Error
}

// apiKeys lists the keys scoped to the organization rather than to a person.
func (o *mqlNeonOrganization) apiKeys() ([]any, error) {
	c := neonConn(o.MqlRuntime)

	records, err := connection.GetList[apiKeyRecord](context.Background(), c,
		"/organizations/"+url.PathEscape(o.Id.Data)+"/api_keys", nil, "")
	if err != nil {
		if connection.IsForbidden(err) {
			o.ApiKeys = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	return newNeonApiKeys(o.MqlRuntime, "org/"+o.Id.Data, records)
}
