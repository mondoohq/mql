// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// newMqlMongodbatlasCloudProviderAccessRole maps a cloud provider access role to
// its resource. Flat scalar params so the AWS, Azure, and GCP variants (and the
// pushBasedLogConfig accessor) share one mapper.
func newMqlMongodbatlasCloudProviderAccessRole(runtime *plugin.Runtime, pid, slug, providerName, id, iamAssumedRoleArn, atlasAWSAccountArn, azureAtlasAppId, azureTenantId, gcpServiceAccount string, authorizedDate *time.Time) (*mqlMongodbatlasCloudProviderAccessRole, error) {
	res, err := CreateResource(runtime, "mongodbatlas.cloudProviderAccessRole", map[string]*llx.RawData{
		"__id":               llx.StringData("mongodbatlas.cloudProviderAccessRole/" + pid + "/" + slug + "/" + id),
		"id":                 llx.StringData(id),
		"providerName":       llx.StringData(providerName),
		"iamAssumedRoleArn":  llx.StringData(iamAssumedRoleArn),
		"atlasAWSAccountArn": llx.StringData(atlasAWSAccountArn),
		"azureAtlasAppId":    llx.StringData(azureAtlasAppId),
		"azureTenantId":      llx.StringData(azureTenantId),
		"gcpServiceAccount":  llx.StringData(gcpServiceAccount),
		"authorizedDate":     llx.TimeDataPtr(authorizedDate),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasCloudProviderAccessRole), nil
}

func (r *mqlMongodbatlas) ipAccessList() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, _, err := client.ProjectIPAccessListAPI.ListAccessListEntries(ctx, pid).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			e := results[i]
			value := e.GetCidrBlock()
			if value == "" {
				value = e.GetIpAddress()
			}
			if value == "" {
				value = e.GetAwsSecurityGroup()
			}
			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.networkAccessEntry", map[string]*llx.RawData{
				"__id":             llx.StringData("mongodbatlas.networkAccessEntry/" + pid + "/" + value),
				"cidrBlock":        llx.StringData(e.GetCidrBlock()),
				"ipAddress":        llx.StringData(e.GetIpAddress()),
				"awsSecurityGroup": llx.StringData(e.GetAwsSecurityGroup()),
				"comment":          llx.StringData(e.GetComment()),
				"deleteAfterDate":  llx.TimeDataPtr(timePtr(e.GetDeleteAfterDate())),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

func (r *mqlMongodbatlas) privateEndpoints() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for _, provider := range []string{"AWS", "AZURE", "GCP"} {
		services, httpResp, err := client.PrivateEndpointServicesAPI.ListPrivateEndpointService(ctx, pid, provider).Execute()
		if err != nil {
			// A provider without any configured private endpoint service returns
			// 404; skip it, but surface auth, throttling, and other real errors.
			if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
				continue
			}
			return nil, err
		}
		for i := range services {
			svc := services[i]
			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.privateEndpointService", map[string]*llx.RawData{
				"__id":               llx.StringData("mongodbatlas.privateEndpointService/" + pid + "/" + svc.GetId()),
				"id":                 llx.StringData(svc.GetId()),
				"cloudProvider":      llx.StringData(svc.GetCloudProvider()),
				"regionName":         llx.StringData(svc.GetRegionName()),
				"status":             llx.StringData(svc.GetStatus()),
				"errorMessage":       llx.StringData(svc.GetErrorMessage()),
				"interfaceEndpoints": llx.ArrayData(strSlice(svc.GetInterfaceEndpoints()), types.String),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
	}
	return out, nil
}

func (r *mqlMongodbatlas) networkPeerings() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, _, err := client.NetworkPeeringAPI.ListGroupPeers(ctx, pid).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			p := results[i]
			// AWS reports status in statusName; Azure and GCP use status.
			status := p.GetStatusName()
			if status == "" {
				status = p.GetStatus()
			}
			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.networkPeering", map[string]*llx.RawData{
				"__id":                llx.StringData("mongodbatlas.networkPeering/" + pid + "/" + p.GetId()),
				"id":                  llx.StringData(p.GetId()),
				"providerName":        llx.StringData(p.GetProviderName()),
				"containerId":         llx.StringData(p.GetContainerId()),
				"status":              llx.StringData(status),
				"awsAccountId":        llx.StringData(p.GetAwsAccountId()),
				"vpcId":               llx.StringData(p.GetVpcId()),
				"vnetName":            llx.StringData(p.GetVnetName()),
				"networkName":         llx.StringData(p.GetNetworkName()),
				"routeTableCidrBlock": llx.StringData(p.GetRouteTableCidrBlock()),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

func (r *mqlMongodbatlas) cloudProviderAccessRoles() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	roles, _, err := client.CloudProviderAccessAPI.ListCloudProviderAccess(ctx, pid).Execute()
	if err != nil {
		return nil, err
	}

	out := []any{}
	for _, role := range roles.GetAwsIamRoles() {
		res, err := newMqlMongodbatlasCloudProviderAccessRole(r.MqlRuntime, pid, "aws", role.GetProviderName(), role.GetRoleId(), role.GetIamAssumedRoleArn(), role.GetAtlasAWSAccountArn(), "", "", "", timePtr(role.GetAuthorizedDate()))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	for _, sp := range roles.GetAzureServicePrincipals() {
		res, err := newMqlMongodbatlasCloudProviderAccessRole(r.MqlRuntime, pid, "azure", sp.GetProviderName(), sp.GetId(), "", "", sp.GetAtlasAzureAppId(), sp.GetTenantId(), "", timePtr(sp.GetCreatedDate()))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	for _, sa := range roles.GetGcpServiceAccounts() {
		res, err := newMqlMongodbatlasCloudProviderAccessRole(r.MqlRuntime, pid, "gcp", sa.GetProviderName(), sa.GetRoleId(), "", "", "", "", sa.GetGcpServiceAccountForAtlas(), timePtr(sa.GetCreatedDate()))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// resolveCloudProviderAccessRole finds a project's cloud provider access role by
// id and maps it, or returns nil when no role matches. It lists the project's
// roles on each call; the only caller today is pushBasedLogConfig, of which
// there is at most one per project, so the list call is bounded to one per scan.
func resolveCloudProviderAccessRole(runtime *plugin.Runtime, pid, roleID string) (*mqlMongodbatlasCloudProviderAccessRole, error) {
	roles, _, err := atlasClient(runtime).CloudProviderAccessAPI.ListCloudProviderAccess(context.Background(), pid).Execute()
	if err != nil {
		return nil, err
	}
	for _, role := range roles.GetAwsIamRoles() {
		if role.GetRoleId() == roleID {
			return newMqlMongodbatlasCloudProviderAccessRole(runtime, pid, "aws", role.GetProviderName(), role.GetRoleId(), role.GetIamAssumedRoleArn(), role.GetAtlasAWSAccountArn(), "", "", "", timePtr(role.GetAuthorizedDate()))
		}
	}
	for _, sp := range roles.GetAzureServicePrincipals() {
		if sp.GetId() == roleID {
			return newMqlMongodbatlasCloudProviderAccessRole(runtime, pid, "azure", sp.GetProviderName(), sp.GetId(), "", "", sp.GetAtlasAzureAppId(), sp.GetTenantId(), "", timePtr(sp.GetCreatedDate()))
		}
	}
	for _, sa := range roles.GetGcpServiceAccounts() {
		if sa.GetRoleId() == roleID {
			return newMqlMongodbatlasCloudProviderAccessRole(runtime, pid, "gcp", sa.GetProviderName(), sa.GetRoleId(), "", "", "", "", sa.GetGcpServiceAccountForAtlas(), timePtr(sa.GetCreatedDate()))
		}
	}
	return nil, nil
}
