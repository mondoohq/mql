// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"

	cs "github.com/codesphere-cloud/cs-go/api/openapi_client"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/codesphere/connection"
)

func (r *mqlCodesphere) organizations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CodesphereConnection)
	list, resp, err := conn.API().OrganizationsAPI.OrganizationsListOrganizations(conn.Context()).Execute()
	if err != nil {
		return nil, connection.Classify(resp, err)
	}
	filter := conn.OrgFilter()
	res := make([]any, 0, len(list))
	for _, org := range list {
		if filter != "" && org.Id != filter {
			continue
		}
		o, err := newOrganization(r.MqlRuntime, org)
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func newOrganization(runtime *plugin.Runtime, org cs.ClustersListAllOrganizations200ResponseInner) (*mqlCodesphereOrganization, error) {
	o, err := CreateResource(runtime, "codesphere.organization", map[string]*llx.RawData{
		"id":        llx.StringData(org.Id),
		"name":      llx.StringData(org.Name),
		"createdAt": llx.TimeData(org.CreatedAt),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlCodesphereOrganization), nil
}

// initCodesphereOrganization resolves an organization by ID, from the scope of
// a discovered organization asset when no ID is given. The API has no endpoint
// for a single organization, so it is looked up in the token's list.
func initCodesphereOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.CodesphereConnection)

	id := conn.ScopedOrganization()
	if v, ok := args["id"]; ok {
		id, _ = v.Value.(string)
	}
	if id == "" {
		return nil, nil, errors.New("codesphere.organization requires an id")
	}
	if res, ok := cachedResource(runtime, "codesphere.organization", id); ok {
		return nil, res, nil
	}

	list, resp, err := conn.API().OrganizationsAPI.OrganizationsListOrganizations(conn.Context()).Execute()
	if err != nil {
		return nil, nil, connection.Classify(resp, err)
	}
	for _, org := range list {
		if org.Id == id {
			res, err := newOrganization(runtime, org)
			return nil, res, err
		}
	}
	return nil, nil, llx.NotFound(fmt.Errorf("codesphere.organization with id %q not found", id))
}

func (r *mqlCodesphereOrganization) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlCodesphereOrganization) members() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CodesphereConnection)
	list, resp, err := conn.API().OrganizationsAPI.OrganizationsListOrgMembers(conn.Context(), r.Id.Data).Execute()
	if err != nil {
		return nil, connection.Classify(resp, err)
	}
	res := make([]any, 0, len(list))
	for _, m := range list {
		o, err := CreateResource(r.MqlRuntime, "codesphere.organization.member", orgMemberArgs(m))
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func orgMemberArgs(m cs.OrganizationsListOrgMembers200ResponseInner) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":      llx.StringData(fmt.Sprintf("%s/%d", m.OrganizationId, m.UserId)),
		"userId":    llx.IntData(m.UserId),
		"name":      llx.StringDataPtr(m.Name),
		"email":     llx.StringDataPtr(m.Email),
		"role":      llx.StringData(m.Role),
		"pending":   llx.BoolData(m.Pending),
		"createdAt": llx.TimeData(m.CreatedAt),
		"deletedAt": llx.TimeDataPtr(m.DeletedAt),
	}
}

func (r *mqlCodesphereOrganization) resourceGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CodesphereConnection)
	list, resp, err := conn.API().OrganizationsAPI.OrganizationsListOrgTeams(conn.Context(), r.Id.Data).Execute()
	if err != nil {
		return nil, connection.Classify(resp, err)
	}
	res := make([]any, 0, len(list))
	for _, t := range list {
		o, err := newResourceGroup(r.MqlRuntime, resourceGroupFromOrgTeam(r.Id.Data, t))
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}
