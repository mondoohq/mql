// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	vault_service "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-service/stable/2020-11-25/client/vault_service"
	vaultmodels "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-service/stable/2020-11-25/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

type mqlHcpVaultClusterInternal struct {
	cacheProjectID string
}

// vaultClusters lists the Vault clusters provisioned in the project.
func (r *mqlHcpProject) vaultClusters() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return listMqlHcpVaultClusters(r.MqlRuntime, oid, r.Id.Data)
}

func listMqlHcpVaultClusters(runtime *plugin.Runtime, orgID, projectID string) ([]any, error) {
	conn := hcpConn(runtime)
	client := vault_service.New(conn.Transport(), nil)

	out := []any{}
	var nextToken *string
	for {
		params := vault_service.NewListParams()
		params.LocationOrganizationID = orgID
		params.LocationProjectID = projectID
		params.PaginationNextPageToken = nextToken
		resp, err := client.List(params, nil)
		if err != nil {
			// HCP Vault is not enabled for every organization; degrade to no
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
			res, err := newMqlHcpVaultCluster(runtime, projectID, c)
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

func newMqlHcpVaultCluster(runtime *plugin.Runtime, projectID string, c *vaultmodels.HashicorpCloudVault20201125Cluster) (*mqlHcpVaultCluster, error) {
	tier := ""
	publicEndpoint := false
	ipAllowlist := []any{}
	var auditLogExport any
	if c.Config != nil {
		tier = enumStr(c.Config.Tier)
		if c.Config.NetworkConfig != nil {
			publicEndpoint = c.Config.NetworkConfig.PublicIpsEnabled
			for _, cidr := range c.Config.NetworkConfig.IPAllowlist {
				if cidr != nil && cidr.Address != "" {
					ipAllowlist = append(ipAllowlist, cidr.Address)
				}
			}
		}
		if c.Config.AuditLogExportConfig != nil {
			auditLogExport = toDict(c.Config.AuditLogExportConfig)
		}
	}

	provider, region := "", ""
	if c.Location != nil && c.Location.Region != nil {
		provider = c.Location.Region.Provider
		region = c.Location.Region.Region
	}

	publicURL, privateURL := "", ""
	if c.DNSNames != nil {
		publicURL = c.DNSNames.Public
		privateURL = c.DNSNames.Private
	}

	res, err := CreateResource(runtime, "hcp.vault.cluster", map[string]*llx.RawData{
		"__id":                    llx.StringData("hcp.vault.cluster/" + c.ID),
		"id":                      llx.StringData(c.ID),
		"state":                   llx.StringData(enumStr(c.State)),
		"vaultVersion":            llx.StringData(c.CurrentVersion),
		"tier":                    llx.StringData(tier),
		"cloudProvider":           llx.StringData(provider),
		"region":                  llx.StringData(region),
		"publicEndpoint":          llx.BoolData(publicEndpoint),
		"ipAllowlist":             llx.ArrayData(ipAllowlist, types.String),
		"auditLogExport":          llx.DictData(auditLogExport),
		"vaultPublicEndpointUrl":  llx.StringData(publicURL),
		"vaultPrivateEndpointUrl": llx.StringData(privateURL),
		"createdAt":               llx.TimeDataPtr(strfmtTime(c.CreatedAt)),
	})
	if err != nil {
		return nil, err
	}
	cluster := res.(*mqlHcpVaultCluster)
	cluster.cacheProjectID = projectID
	return cluster, nil
}

// initHcpVaultCluster hydrates a single Vault cluster, either from an explicit
// id argument or from the discovered asset the connection is scoped to.
func initHcpVaultCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	clusterID, projectID, err := scopedResourceIDs(runtime, args)
	if err != nil {
		return nil, nil, err
	}
	if clusterID == "" {
		return nil, nil, fmt.Errorf("hcp.vault.cluster requires a cluster id")
	}
	oid, err := orgID(runtime)
	if err != nil {
		return nil, nil, err
	}
	clusters, err := listMqlHcpVaultClusters(runtime, oid, projectID)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range clusters {
		cluster := c.(*mqlHcpVaultCluster)
		if cluster.Id.Data == clusterID {
			return nil, cluster, nil
		}
	}
	return nil, nil, fmt.Errorf("hcp.vault.cluster %q not found in project %q", clusterID, projectID)
}

// project resolves the project the cluster belongs to.
func (r *mqlHcpVaultCluster) project() (*mqlHcpProject, error) {
	return projectRef(r.MqlRuntime, &r.Project, r.cacheProjectID)
}
