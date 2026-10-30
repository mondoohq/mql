// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	boundary_service "github.com/hashicorp/hcp-sdk-go/clients/cloud-boundary-service/stable/2021-12-21/client/boundary_service"
	boundarymodels "github.com/hashicorp/hcp-sdk-go/clients/cloud-boundary-service/stable/2021-12-21/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlHcpBoundaryClusterInternal struct {
	cacheProjectID string
}

// boundaryClusters lists the Boundary clusters provisioned in the project.
func (r *mqlHcpProject) boundaryClusters() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return listMqlHcpBoundaryClusters(r.MqlRuntime, oid, r.Id.Data)
}

func listMqlHcpBoundaryClusters(runtime *plugin.Runtime, orgID, projectID string) ([]any, error) {
	conn := hcpConn(runtime)
	client := boundary_service.New(conn.Transport(), nil)

	out := []any{}
	var nextToken *string
	for {
		params := boundary_service.NewBoundaryServiceListParams()
		params.LocationOrganizationID = orgID
		params.LocationProjectID = projectID
		params.PaginationNextPageToken = nextToken
		resp, err := client.BoundaryServiceList(params, nil)
		if err != nil {
			// HCP Boundary is not enabled for every organization; degrade to no
			// clusters rather than failing the whole scan.
			if isServiceUnavailable(err) {
				return out, nil
			}
			return nil, err
		}
		if resp.Payload == nil {
			break
		}
		for _, c := range resp.Payload.Clusters {
			res, err := newMqlHcpBoundaryCluster(runtime, projectID, c)
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

func newMqlHcpBoundaryCluster(runtime *plugin.Runtime, projectID string, c *boundarymodels.HashicorpCloudBoundary20211221Cluster) (*mqlHcpBoundaryCluster, error) {
	res, err := CreateResource(runtime, "hcp.boundary.cluster", map[string]*llx.RawData{
		"__id":       llx.StringData("hcp.boundary.cluster/" + c.ClusterID),
		"id":         llx.StringData(c.ClusterID),
		"state":      llx.StringData(enumStr(c.State)),
		"version":    llx.StringData(c.BoundaryVersion),
		"tier":       llx.StringData(enumStr(c.MarketingSku)),
		"clusterUrl": llx.StringData(c.ClusterURL),
		"createdAt":  llx.TimeDataPtr(strfmtTime(c.CreatedAt)),
	})
	if err != nil {
		return nil, err
	}
	cluster := res.(*mqlHcpBoundaryCluster)
	cluster.cacheProjectID = projectID
	return cluster, nil
}

// initHcpBoundaryCluster hydrates a single Boundary cluster, either from an
// explicit id argument or from the discovered asset the connection is scoped to.
func initHcpBoundaryCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	clusterID, projectID, err := scopedResourceIDs(runtime, args)
	if err != nil {
		return nil, nil, err
	}
	if clusterID == "" {
		return nil, nil, fmt.Errorf("hcp.boundary.cluster requires a cluster id")
	}
	oid, err := orgID(runtime)
	if err != nil {
		return nil, nil, err
	}
	clusters, err := listMqlHcpBoundaryClusters(runtime, oid, projectID)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range clusters {
		cluster := c.(*mqlHcpBoundaryCluster)
		if cluster.Id.Data == clusterID {
			return nil, cluster, nil
		}
	}
	return nil, nil, fmt.Errorf("hcp.boundary.cluster %q not found in project %q", clusterID, projectID)
}

// project resolves the project the cluster belongs to.
func (r *mqlHcpBoundaryCluster) project() (*mqlHcpProject, error) {
	return projectRef(r.MqlRuntime, &r.Project, r.cacheProjectID)
}
