// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sort"
	"strconv"

	cs "github.com/codesphere-cloud/cs-go/api/openapi_client"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/codesphere/connection"
)

type mqlCodesphereCustomDomainInternal struct {
	resourceGroupID int64
	dataCenterID    int64
	routes          []domainRoute
}

type mqlCodesphereCustomDomainConnectionInternal struct {
	resourceGroupID int64
	workspaceIDs    []int
}

// domainRoute is one path of a custom domain and the workspaces it routes to.
type domainRoute struct {
	path         string
	workspaceIDs []int
}

// domainRoutes turns the API's path → workspace map into a list sorted by path,
// so the order is stable across scans.
func domainRoutes(m map[string][]int) []domainRoute {
	routes := make([]domainRoute, 0, len(m))
	for path, ids := range m {
		routes = append(routes, domainRoute{path: path, workspaceIDs: ids})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].path < routes[j].path })
	return routes
}

func customDomainArgs(d *cs.DomainsGetDomain200Response) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":                        llx.StringData(strconv.Itoa(d.TeamId) + "/" + d.Name),
		"name":                        llx.StringData(d.Name),
		"verified":                    llx.BoolData(d.DomainVerificationStatus.Verified),
		"verificationReason":          llx.StringDataPtr(d.DomainVerificationStatus.Reason.Get()),
		"certificateIssued":           llx.BoolData(d.CertificateRequestStatus.Issued),
		"certificateReason":           llx.StringDataPtr(d.CertificateRequestStatus.Reason.Get()),
		"restricted":                  llx.BoolDataPtr(d.Restricted),
		"aRecord":                     llx.StringData(d.DnsEntries.A),
		"cname":                       llx.StringData(d.DnsEntries.Cname),
		"txt":                         llx.StringData(d.DnsEntries.Txt),
		"maxBodySizeMb":               floatDataPtr(nil),
		"maxConnectionTimeoutSeconds": floatDataPtr(nil),
		"useRegex":                    llx.BoolDataPtr(nil),
	}
	if c := d.CustomConfig; c != nil {
		args["maxBodySizeMb"] = floatDataPtr(c.MaxBodySizeMb)
		args["maxConnectionTimeoutSeconds"] = floatDataPtr(c.MaxConnectionTimeoutS)
		args["useRegex"] = llx.BoolDataPtr(c.UseRegex)
	}
	return args
}

func (r *mqlCodesphereResourceGroup) customDomains() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CodesphereConnection)
	list, resp, err := conn.API().DomainsAPI.DomainsListDomains(conn.Context(), int(r.Id.Data)).Execute()
	if err != nil {
		return nil, connection.Classify(resp, err)
	}
	res := make([]any, 0, len(list))
	for i := range list {
		d := &list[i]
		o, err := CreateResource(r.MqlRuntime, "codesphere.customDomain", customDomainArgs(d))
		if err != nil {
			return nil, err
		}
		cd := o.(*mqlCodesphereCustomDomain)
		cd.resourceGroupID = int64(d.TeamId)
		cd.dataCenterID = int64(d.DataCenterId)
		cd.routes = domainRoutes(d.Workspaces)
		res = append(res, cd)
	}
	return res, nil
}

func (r *mqlCodesphereCustomDomain) resourceGroup() (*mqlCodesphereResourceGroup, error) {
	res, err := NewResource(r.MqlRuntime, "codesphere.resourceGroup", map[string]*llx.RawData{
		"id": llx.IntData(r.resourceGroupID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCodesphereResourceGroup), nil
}

func (r *mqlCodesphereCustomDomain) dataCenter() (*mqlCodesphereDataCenter, error) {
	dc, err := findDataCenter(r.MqlRuntime, r.dataCenterID)
	if err != nil {
		return nil, err
	}
	if dc == nil {
		r.DataCenter.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return dc, nil
}

func (r *mqlCodesphereCustomDomain) connections() ([]any, error) {
	res := make([]any, 0, len(r.routes))
	for _, route := range r.routes {
		o, err := CreateResource(r.MqlRuntime, "codesphere.customDomain.connection", map[string]*llx.RawData{
			"__id": llx.StringData(r.__id + "\x00" + route.path),
			"path": llx.StringData(route.path),
		})
		if err != nil {
			return nil, err
		}
		c := o.(*mqlCodesphereCustomDomainConnection)
		c.resourceGroupID = r.resourceGroupID
		c.workspaceIDs = route.workspaceIDs
		res = append(res, c)
	}
	return res, nil
}

// workspaces resolves the connected workspaces through the resource group's
// cached workspace list. A workspace that no longer exists is left out.
func (r *mqlCodesphereCustomDomainConnection) workspaces() ([]any, error) {
	// Listing the resource group's workspaces once puts them in the cache, so
	// each lookup below is served from it instead of one call per workspace.
	rg, err := NewResource(r.MqlRuntime, "codesphere.resourceGroup", map[string]*llx.RawData{
		"id": llx.IntData(r.resourceGroupID),
	})
	if err != nil {
		return nil, err
	}
	if list := rg.(*mqlCodesphereResourceGroup).GetWorkspaces(); list.Error != nil {
		return nil, list.Error
	}

	res := make([]any, 0, len(r.workspaceIDs))
	for _, id := range r.workspaceIDs {
		ws, err := NewResource(r.MqlRuntime, "codesphere.workspace", map[string]*llx.RawData{
			"id": llx.IntData(id),
		})
		if err != nil {
			if errors.Is(err, llx.ErrNotFound) {
				log.Debug().Int("workspace", id).Str("path", r.Path.Data).Msg("codesphere> custom domain routes to a workspace that does not exist")
				continue
			}
			return nil, err
		}
		res = append(res, ws)
	}
	return res, nil
}
