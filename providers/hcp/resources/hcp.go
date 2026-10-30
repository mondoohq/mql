// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-openapi/strfmt"
	org_service "github.com/hashicorp/hcp-sdk-go/clients/cloud-resource-manager/stable/2019-12-10/client/organization_service"
	project_service "github.com/hashicorp/hcp-sdk-go/clients/cloud-resource-manager/stable/2019-12-10/client/project_service"
	rmmodels "github.com/hashicorp/hcp-sdk-go/clients/cloud-resource-manager/stable/2019-12-10/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/hcp/connection"
)

const projectScopeType = "ORGANIZATION"

// hcpConn returns the HCP connection backing the runtime.
func hcpConn(runtime *plugin.Runtime) *connection.HcpConnection {
	return runtime.Connection.(*connection.HcpConnection)
}

// orgID resolves the organization id for the connection, deriving it from the
// service principal when it was not supplied on the command line.
func orgID(runtime *plugin.Runtime) (string, error) {
	return hcpConn(runtime).EnsureOrgID(context.Background())
}

// strfmtTime converts an SDK date-time to a *time.Time, returning nil for the
// zero value so it round-trips cleanly across the plugin boundary.
func strfmtTime(dt strfmt.DateTime) *time.Time {
	t := time.Time(dt)
	if t.IsZero() {
		return nil
	}
	return &t
}

// enumStr dereferences a pointer to a string-backed SDK enum, returning the
// empty string for a nil pointer.
func enumStr[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

// toDict renders an SDK struct as a JSON-native dict value (nil when the input
// marshals to null), keeping the value within the types dict fields accept.
func toDict(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// strSlice converts a slice of strings to the []any llx array fields expect.
func strSlice(in []string) []any {
	out := make([]any, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

func (r *mqlHcp) id() (string, error) {
	return "hcp", nil
}

// organization resolves the organization the connection is rooted at.
func (r *mqlHcp) organization() (*mqlHcpOrganization, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return fetchMqlHcpOrganization(r.MqlRuntime, oid)
}

// projects lists the projects in the connection's organization.
func (r *mqlHcp) projects() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return listMqlHcpProjects(r.MqlRuntime, oid)
}

// fetchMqlHcpOrganization gets a single organization by id and maps it.
func fetchMqlHcpOrganization(runtime *plugin.Runtime, id string) (*mqlHcpOrganization, error) {
	conn := hcpConn(runtime)
	client := org_service.New(conn.Transport(), nil)
	params := org_service.NewOrganizationServiceGetParams()
	params.SetID(id)
	resp, err := client.OrganizationServiceGet(params, nil)
	if err != nil {
		return nil, err
	}
	if resp.Payload == nil || resp.Payload.Organization == nil {
		return nil, fmt.Errorf("hcp organization %q not found", id)
	}
	return newMqlHcpOrganization(runtime, resp.Payload.Organization)
}

func newMqlHcpOrganization(runtime *plugin.Runtime, o *rmmodels.HashicorpCloudResourcemanagerOrganization) (*mqlHcpOrganization, error) {
	ownerID := ""
	if o.Owner != nil {
		ownerID = o.Owner.User
	}
	res, err := CreateResource(runtime, "hcp.organization", map[string]*llx.RawData{
		"__id":      llx.StringData("hcp.organization/" + o.ID),
		"id":        llx.StringData(o.ID),
		"name":      llx.StringData(o.Name),
		"state":     llx.StringData(enumStr(o.State)),
		"createdAt": llx.TimeDataPtr(strfmtTime(o.CreatedAt)),
		"ownerId":   llx.StringData(ownerID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHcpOrganization), nil
}

// initHcpOrganization resolves an organization from an explicit id argument or,
// when none is given, the organization the connection is rooted at.
func initHcpOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// A fully-specified resource carries more than the id and the injected
	// __id; fetch on anything less so a bare id reference hydrates completely.
	if len(args) > 2 {
		return args, nil, nil
	}
	id := ""
	if idRaw, ok := args["id"]; ok {
		id, _ = idRaw.Value.(string)
	}
	if id == "" {
		var err error
		id, err = orgID(runtime)
		if err != nil {
			return nil, nil, err
		}
	}
	if id == "" {
		return nil, nil, fmt.Errorf("hcp.organization requires an organization id")
	}
	res, err := fetchMqlHcpOrganization(runtime, id)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlHcpOrganization) projects() ([]any, error) {
	return listMqlHcpProjects(r.MqlRuntime, r.Id.Data)
}

// listMqlHcpProjects lists every project under the given organization.
func listMqlHcpProjects(runtime *plugin.Runtime, orgID string) ([]any, error) {
	conn := hcpConn(runtime)
	client := project_service.New(conn.Transport(), nil)

	scopeID := orgID
	scopeType := projectScopeType
	out := []any{}
	var nextToken *string
	for {
		params := project_service.NewProjectServiceListParams()
		params.ScopeID = &scopeID
		params.ScopeType = &scopeType
		params.PaginationNextPageToken = nextToken
		resp, err := client.ProjectServiceList(params, nil)
		if err != nil {
			return nil, err
		}
		if resp.Payload == nil {
			break
		}
		for _, p := range resp.Payload.Projects {
			res, err := newMqlHcpProject(runtime, p)
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if resp.Payload.Pagination == nil || resp.Payload.Pagination.NextPageToken == "" {
			break
		}
		token := resp.Payload.Pagination.NextPageToken
		nextToken = &token
	}
	return out, nil
}

func newMqlHcpProject(runtime *plugin.Runtime, p *rmmodels.HashicorpCloudResourcemanagerProject) (*mqlHcpProject, error) {
	res, err := CreateResource(runtime, "hcp.project", map[string]*llx.RawData{
		"__id":        llx.StringData("hcp.project/" + p.ID),
		"id":          llx.StringData(p.ID),
		"name":        llx.StringData(p.Name),
		"description": llx.StringData(p.Description),
		"state":       llx.StringData(enumStr(p.State)),
		"createdAt":   llx.TimeDataPtr(strfmtTime(p.CreatedAt)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHcpProject), nil
}

// fetchMqlHcpProject gets a single project by id and maps it.
func fetchMqlHcpProject(runtime *plugin.Runtime, id string) (*mqlHcpProject, error) {
	conn := hcpConn(runtime)
	client := project_service.New(conn.Transport(), nil)
	params := project_service.NewProjectServiceGetParams()
	params.SetID(id)
	resp, err := client.ProjectServiceGet(params, nil)
	if err != nil {
		return nil, err
	}
	if resp.Payload == nil || resp.Payload.Project == nil {
		return nil, fmt.Errorf("hcp project %q not found", id)
	}
	return newMqlHcpProject(runtime, resp.Payload.Project)
}

// initHcpProject resolves a project from an explicit id argument or, when none
// is given, the project the connection is scoped to. The typed project()
// references on clusters, registries, and applications hydrate through here.
func initHcpProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// A fully-specified resource carries more than the id and the injected
	// __id; fetch on anything less so a bare id reference hydrates completely.
	if len(args) > 2 {
		return args, nil, nil
	}
	id := ""
	if idRaw, ok := args["id"]; ok {
		id, _ = idRaw.Value.(string)
	}
	if id == "" {
		id = hcpConn(runtime).ProjectID()
	}
	if id == "" {
		return nil, nil, fmt.Errorf("hcp.project requires a project id")
	}
	res, err := fetchMqlHcpProject(runtime, id)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// projectRef builds the typed project() reference from a cached project id,
// marking the field null when no project id is known.
func projectRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlHcpProject], projectID string) (*mqlHcpProject, error) {
	if projectID == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "hcp.project", map[string]*llx.RawData{
		"id": llx.StringData(projectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHcpProject), nil
}
