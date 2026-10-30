// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	consul_service "github.com/hashicorp/hcp-sdk-go/clients/cloud-consul-service/stable/2021-02-04/client/consul_service"
	consulmodels "github.com/hashicorp/hcp-sdk-go/clients/cloud-consul-service/stable/2021-02-04/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

type mqlHcpConsulClusterInternal struct {
	cacheProjectID string
}

// consulClusters lists the Consul clusters provisioned in the project.
func (r *mqlHcpProject) consulClusters() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return listMqlHcpConsulClusters(r.MqlRuntime, oid, r.Id.Data)
}

func listMqlHcpConsulClusters(runtime *plugin.Runtime, orgID, projectID string) ([]any, error) {
	conn := hcpConn(runtime)
	client := consul_service.New(conn.Transport(), nil)

	out := []any{}
	var nextToken *string
	for {
		params := consul_service.NewListParams()
		params.LocationOrganizationID = orgID
		params.LocationProjectID = projectID
		params.PaginationNextPageToken = nextToken
		resp, err := client.List(params, nil)
		if err != nil {
			// HCP Consul is not enabled for every organization; degrade to no
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
			res, err := newMqlHcpConsulCluster(runtime, projectID, c)
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

func newMqlHcpConsulCluster(runtime *plugin.Runtime, projectID string, c *consulmodels.HashicorpCloudConsul20210204Cluster) (*mqlHcpConsulCluster, error) {
	tier := ""
	// A cluster with a private network exposes no public endpoint.
	publicEndpoint := false
	ipAllowlist := []any{}
	if c.Config != nil {
		tier = enumStr(c.Config.Tier)
		if c.Config.NetworkConfig != nil {
			publicEndpoint = !c.Config.NetworkConfig.Private
			for _, cidr := range c.Config.NetworkConfig.IPAllowlist {
				if cidr != nil && cidr.Address != "" {
					ipAllowlist = append(ipAllowlist, cidr.Address)
				}
			}
		}
	}

	provider, region := "", ""
	if c.Location != nil && c.Location.Region != nil {
		provider = c.Location.Region.Provider
		region = c.Location.Region.Region
	}

	externalURL := ""
	if c.DNSNames != nil {
		externalURL = c.DNSNames.Public
	}

	res, err := CreateResource(runtime, "hcp.consul.cluster", map[string]*llx.RawData{
		"__id":                      llx.StringData("hcp.consul.cluster/" + c.ID),
		"id":                        llx.StringData(c.ID),
		"state":                     llx.StringData(enumStr(c.State)),
		"consulVersion":             llx.StringData(c.ConsulVersion),
		"tier":                      llx.StringData(tier),
		"cloudProvider":             llx.StringData(provider),
		"region":                    llx.StringData(region),
		"publicEndpoint":            llx.BoolData(publicEndpoint),
		"ipAllowlist":               llx.ArrayData(ipAllowlist, types.String),
		"consulExternalEndpointUrl": llx.StringData(externalURL),
		"createdAt":                 llx.TimeDataPtr(strfmtTime(c.CreatedAt)),
	})
	if err != nil {
		return nil, err
	}
	cluster := res.(*mqlHcpConsulCluster)
	cluster.cacheProjectID = projectID
	return cluster, nil
}

// initHcpConsulCluster hydrates a single Consul cluster, either from an explicit
// id argument or from the discovered asset the connection is scoped to.
func initHcpConsulCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	clusterID, projectID, err := scopedResourceIDs(runtime, args)
	if err != nil {
		return nil, nil, err
	}
	if clusterID == "" {
		return nil, nil, fmt.Errorf("hcp.consul.cluster requires a cluster id")
	}
	oid, err := orgID(runtime)
	if err != nil {
		return nil, nil, err
	}
	clusters, err := listMqlHcpConsulClusters(runtime, oid, projectID)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range clusters {
		cluster := c.(*mqlHcpConsulCluster)
		if cluster.Id.Data == clusterID {
			return nil, cluster, nil
		}
	}
	return nil, nil, fmt.Errorf("hcp.consul.cluster %q not found in project %q", clusterID, projectID)
}

// project resolves the project the cluster belongs to.
func (r *mqlHcpConsulCluster) project() (*mqlHcpProject, error) {
	return projectRef(r.MqlRuntime, &r.Project, r.cacheProjectID)
}
