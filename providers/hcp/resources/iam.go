// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	sp_service "github.com/hashicorp/hcp-sdk-go/clients/cloud-iam/stable/2019-12-10/client/service_principals_service"
	iammodels "github.com/hashicorp/hcp-sdk-go/clients/cloud-iam/stable/2019-12-10/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlHcpIamServicePrincipalInternal struct {
	cacheOrgID       string
	cacheProjectID   string
	cachePrincipalID string
}

// servicePrincipals lists the organization-scoped service principals.
func (r *mqlHcpOrganization) servicePrincipals() ([]any, error) {
	conn := hcpConn(r.MqlRuntime)
	client := sp_service.New(conn.Transport(), nil)

	out := []any{}
	var nextToken *string
	for {
		params := sp_service.NewServicePrincipalsServiceListOrganizationServicePrincipalsParams()
		params.OrganizationID = r.Id.Data
		params.PaginationNextPageToken = nextToken
		resp, err := client.ServicePrincipalsServiceListOrganizationServicePrincipals(params, nil)
		if err != nil {
			// The service principal may lack IAM read permission on the org, or
			// IAM may be unavailable; degrade to whatever was retrieved (with a
			// warning that reports the count) rather than failing the query.
			if isServiceUnavailable(err) {
				log.Warn().Str("org", r.Id.Data).Int("retrieved", len(out)).
					Msg("hcp: stopped listing organization service principals (service unavailable or permission denied)")
				return out, nil
			}
			return nil, err
		}
		if resp.Payload == nil {
			break
		}
		for _, sp := range resp.Payload.ServicePrincipals {
			res, err := newMqlHcpIamServicePrincipal(r.MqlRuntime, r.Id.Data, sp)
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

// servicePrincipals lists the project-scoped service principals.
func (r *mqlHcpProject) servicePrincipals() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	conn := hcpConn(r.MqlRuntime)
	client := sp_service.New(conn.Transport(), nil)

	out := []any{}
	var nextToken *string
	for {
		params := sp_service.NewServicePrincipalsServiceListProjectServicePrincipalsParams()
		params.OrganizationID = oid
		params.ProjectID = r.Id.Data
		params.PaginationNextPageToken = nextToken
		resp, err := client.ServicePrincipalsServiceListProjectServicePrincipals(params, nil)
		if err != nil {
			// The service principal may lack IAM read permission on the project,
			// or IAM may be unavailable; degrade to whatever was retrieved (with
			// a warning that reports the count) rather than failing the query.
			if isServiceUnavailable(err) {
				log.Warn().Str("project", r.Id.Data).Int("retrieved", len(out)).
					Msg("hcp: stopped listing project service principals (service unavailable or permission denied)")
				return out, nil
			}
			return nil, err
		}
		if resp.Payload == nil {
			break
		}
		for _, sp := range resp.Payload.ServicePrincipals {
			res, err := newMqlHcpIamServicePrincipal(r.MqlRuntime, oid, sp)
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

func newMqlHcpIamServicePrincipal(runtime *plugin.Runtime, orgID string, sp *iammodels.HashicorpCloudIamServicePrincipal) (*mqlHcpIamServicePrincipal, error) {
	// Scope the cache key by org and project so an organization-level and a
	// project-level principal that happen to share an id cannot collide.
	res, err := CreateResource(runtime, "hcp.iam.servicePrincipal", map[string]*llx.RawData{
		"__id":         llx.StringData("hcp.iam.servicePrincipal/" + orgID + "/" + sp.ProjectID + "/" + sp.ID),
		"id":           llx.StringData(sp.ID),
		"name":         llx.StringData(sp.Name),
		"resourceName": llx.StringData(sp.ResourceName),
		"createdAt":    llx.TimeDataPtr(strfmtTime(sp.CreatedAt)),
	})
	if err != nil {
		return nil, err
	}
	principal := res.(*mqlHcpIamServicePrincipal)
	principal.cacheOrgID = orgID
	principal.cacheProjectID = sp.ProjectID
	principal.cachePrincipalID = sp.ID
	return principal, nil
}

// project resolves the project the principal is scoped to, or null for an
// organization-level principal.
func (r *mqlHcpIamServicePrincipal) project() (*mqlHcpProject, error) {
	return projectRef(r.MqlRuntime, &r.Project, r.cacheProjectID)
}

// keys lists the access keys issued to the service principal.
func (r *mqlHcpIamServicePrincipal) keys() ([]any, error) {
	conn := hcpConn(r.MqlRuntime)
	client := sp_service.New(conn.Transport(), nil)

	var keys []*iammodels.HashicorpCloudIamServicePrincipalKey
	if r.cacheProjectID != "" {
		params := sp_service.NewServicePrincipalsServiceGetProjectServicePrincipalParams()
		params.OrganizationID = r.cacheOrgID
		params.ProjectID = r.cacheProjectID
		params.PrincipalID = r.cachePrincipalID
		resp, err := client.ServicePrincipalsServiceGetProjectServicePrincipal(params, nil)
		if err != nil {
			return nil, err
		}
		if resp.Payload != nil {
			keys = resp.Payload.Keys
		}
	} else {
		params := sp_service.NewServicePrincipalsServiceGetOrganizationServicePrincipalParams()
		params.OrganizationID = r.cacheOrgID
		params.PrincipalID = r.cachePrincipalID
		resp, err := client.ServicePrincipalsServiceGetOrganizationServicePrincipal(params, nil)
		if err != nil {
			return nil, err
		}
		if resp.Payload != nil {
			keys = resp.Payload.Keys
		}
	}

	out := []any{}
	for _, k := range keys {
		res, err := CreateResource(r.MqlRuntime, "hcp.iam.servicePrincipal.key", map[string]*llx.RawData{
			"__id":         llx.StringData("hcp.iam.servicePrincipal.key/" + k.ResourceName),
			"clientId":     llx.StringData(k.ClientID),
			"resourceName": llx.StringData(k.ResourceName),
			"state":        llx.StringData(enumStr(k.State)),
			"createdAt":    llx.TimeDataPtr(strfmtTime(k.CreatedAt)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
