// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strconv"

	cs "github.com/codesphere-cloud/cs-go/api/openapi_client"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/codesphere/connection"
)

type mqlCodesphereResourceGroupInternal struct {
	orgID        *string
	dataCenterID int64
}

// resourceGroupRecord is one resource group, normalized from the three API
// shapes that return one: the token's list (/teams), an organization's list,
// and a single lookup.
type resourceGroupRecord struct {
	id           int
	name         string
	description  *string
	orgID        *string
	dataCenterID int
}

func resourceGroupFromTeam(t cs.TeamsListTeams200ResponseInner) resourceGroupRecord {
	return resourceGroupRecord{
		id:           t.Id,
		name:         t.Name,
		description:  t.Description.Get(),
		orgID:        nonEmpty(t.OrganizationId),
		dataCenterID: t.DefaultDataCenterId,
	}
}

// resourceGroupFromOrgTeam takes the organization from the list it came from,
// since the organization's list does not repeat it on each entry.
func resourceGroupFromOrgTeam(orgID string, t cs.OrganizationsListOrgTeams200ResponseInner) resourceGroupRecord {
	return resourceGroupRecord{
		id:           t.Id,
		name:         t.Name,
		description:  t.Description,
		orgID:        nonEmpty(&orgID),
		dataCenterID: t.DefaultDataCenterId,
	}
}

func resourceGroupFromGet(t *cs.TeamsGetTeam200Response) resourceGroupRecord {
	return resourceGroupRecord{
		id:           t.Id,
		name:         t.Name,
		description:  t.Description.Get(),
		orgID:        nonEmpty(t.OrganizationId),
		dataCenterID: t.DefaultDataCenterId,
	}
}

func nonEmpty(s *string) *string {
	if s == nil || *s == "" {
		return nil
	}
	return s
}

// mergeResourceGroups combines the token's own resource groups with those of
// its organizations, which an organization admin sees without being a member.
// Each resource group appears once, in first-seen order, and the
// --org/--resource-group filters apply.
func mergeResourceGroups(own []resourceGroupRecord, byOrg [][]resourceGroupRecord, orgFilter string, rgFilter int) []resourceGroupRecord {
	seen := map[int]bool{}
	out := []resourceGroupRecord{}
	add := func(rec resourceGroupRecord) {
		if seen[rec.id] {
			return
		}
		if rgFilter != 0 && rec.id != rgFilter {
			return
		}
		if orgFilter != "" && (rec.orgID == nil || *rec.orgID != orgFilter) {
			return
		}
		seen[rec.id] = true
		out = append(out, rec)
	}
	for _, rec := range own {
		add(rec)
	}
	for _, list := range byOrg {
		for _, rec := range list {
			add(rec)
		}
	}
	return out
}

func newResourceGroup(runtime *plugin.Runtime, rec resourceGroupRecord) (*mqlCodesphereResourceGroup, error) {
	o, err := CreateResource(runtime, "codesphere.resourceGroup", map[string]*llx.RawData{
		"id":          llx.IntData(rec.id),
		"name":        llx.StringData(rec.name),
		"description": llx.StringDataPtr(rec.description),
	})
	if err != nil {
		return nil, err
	}
	rg := o.(*mqlCodesphereResourceGroup)
	rg.orgID = rec.orgID
	rg.dataCenterID = int64(rec.dataCenterID)
	return rg, nil
}

func (r *mqlCodesphere) resourceGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CodesphereConnection)
	teams, resp, err := conn.API().TeamsAPI.TeamsListTeams(conn.Context()).Execute()
	if err != nil {
		return nil, connection.Classify(resp, err)
	}
	own := make([]resourceGroupRecord, 0, len(teams))
	for _, t := range teams {
		own = append(own, resourceGroupFromTeam(t))
	}

	// Only organization admins can list an organization's resource groups.
	// Anyone else is refused, which is a gap in that partition, not a failure
	// of the whole list (ADR 046 §8).
	var byOrg [][]resourceGroupRecord
	orgs := r.GetOrganizations()
	if orgs.Error != nil {
		log.Debug().Err(orgs.Error).Msg("codesphere> could not list organizations, listing own resource groups only")
	}
	for _, it := range orgs.Data {
		org := it.(*mqlCodesphereOrganization)
		list, resp, err := conn.API().OrganizationsAPI.OrganizationsListOrgTeams(conn.Context(), org.Id.Data).Execute()
		if err != nil {
			log.Debug().Err(connection.Classify(resp, err)).Str("organization", org.Id.Data).Msg("codesphere> skipping resource groups of organization")
			continue
		}
		recs := make([]resourceGroupRecord, 0, len(list))
		for _, t := range list {
			recs = append(recs, resourceGroupFromOrgTeam(org.Id.Data, t))
		}
		byOrg = append(byOrg, recs)
	}

	merged := mergeResourceGroups(own, byOrg, conn.OrgFilter(), conn.ResourceGroupFilter())
	res := make([]any, 0, len(merged))
	for _, rec := range merged {
		rg, err := newResourceGroup(r.MqlRuntime, rec)
		if err != nil {
			return nil, err
		}
		res = append(res, rg)
	}
	return res, nil
}

// initCodesphereResourceGroup resolves a resource group by ID, from the scope
// of a discovered asset when no ID is given.
func initCodesphereResourceGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.CodesphereConnection)

	id := int64(conn.ScopedResourceGroup())
	if v, ok := args["id"]; ok {
		id, _ = v.Value.(int64)
	}
	if id == 0 {
		return nil, nil, errors.New("codesphere.resourceGroup requires an id")
	}
	if res, ok := cachedResource(runtime, "codesphere.resourceGroup", strconv.FormatInt(id, 10)); ok {
		return nil, res, nil
	}

	t, resp, err := conn.API().TeamsAPI.TeamsGetTeam(conn.Context(), int(id)).Execute()
	if err != nil {
		return nil, nil, connection.Classify(resp, err)
	}
	if t == nil {
		return nil, nil, llx.NotFound(fmt.Errorf("codesphere.resourceGroup with id %d not found", id))
	}
	res, err := newResourceGroup(runtime, resourceGroupFromGet(t))
	return nil, res, err
}

func (r *mqlCodesphereResourceGroup) id() (string, error) {
	return strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlCodesphereResourceGroup) organization() (*mqlCodesphereOrganization, error) {
	if r.orgID == nil {
		r.Organization.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "codesphere.organization", map[string]*llx.RawData{
		"id": llx.StringData(*r.orgID),
	})
	if err != nil {
		// The token's owner is not in the organization, so it cannot be read.
		if errors.Is(err, llx.ErrNotFound) {
			r.Organization.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlCodesphereOrganization), nil
}

func (r *mqlCodesphereResourceGroup) defaultDataCenter() (*mqlCodesphereDataCenter, error) {
	dc, err := findDataCenter(r.MqlRuntime, r.dataCenterID)
	if err != nil {
		return nil, err
	}
	if dc == nil {
		r.DefaultDataCenter.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return dc, nil
}

func (r *mqlCodesphereResourceGroup) members() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CodesphereConnection)
	list, resp, err := conn.API().TeamsAPI.TeamsListMembers(conn.Context(), int(r.Id.Data)).Execute()
	if err != nil {
		return nil, connection.Classify(resp, err)
	}
	res := make([]any, 0, len(list))
	for _, m := range list {
		o, err := CreateResource(r.MqlRuntime, "codesphere.resourceGroup.member", rgMemberArgs(m))
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func rgMemberArgs(m cs.TeamsListMembers200ResponseInner) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":      llx.StringData(fmt.Sprintf("%d/%d", m.TeamId, m.UserId)),
		"userId":    llx.IntData(m.UserId),
		"name":      llx.StringDataPtr(m.Name.Get()),
		"email":     llx.StringDataPtr(m.Email.Get()),
		"role":      llx.StringData(roleName(m.Role)),
		"pending":   llx.BoolData(m.Pending),
		"createdAt": llx.TimeData(m.CreatedAt),
		"deletedAt": llx.TimeDataPtr(m.DeletedAt),
	}
}

func (r *mqlCodesphereResourceGroup) workspaces() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CodesphereConnection)
	list, resp, err := conn.API().WorkspacesAPI.WorkspacesListWorkspaces(conn.Context(), int(r.Id.Data)).Execute()
	if err != nil {
		return nil, connection.Classify(resp, err)
	}
	res := make([]any, 0, len(list))
	for i := range list {
		ws, err := newWorkspace(r.MqlRuntime, &list[i])
		if err != nil {
			return nil, err
		}
		res = append(res, ws)
	}
	return res, nil
}
