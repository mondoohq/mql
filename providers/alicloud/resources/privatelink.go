// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"sync"

	privatelinkclient "github.com/alibabacloud-go/privatelink-20200415/v5/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// privateLinkPageSize is the page size used for the PrivateLink listings.
const privateLinkPageSize = 100

// mqlAlicloudPrivatelinkInternal memoizes each region's endpoint services, so
// the service listing and every endpoint resolving its service share one read
// per region.
type mqlAlicloudPrivatelinkInternal struct {
	serviceLock sync.Mutex
	services    map[string][]*mqlAlicloudPrivatelinkEndpointService
	serviceErrs map[string]error
}

func (r *mqlAlicloudPrivatelink) id() (string, error) {
	return "alicloud.privatelink", nil
}

func privateLinkResource(runtime *plugin.Runtime) (*mqlAlicloudPrivatelink, error) {
	res, err := CreateResource(runtime, "alicloud.privatelink", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudPrivatelink), nil
}

// privateLinkTokenDone reports whether a token-paged listing is complete. A
// page that returns the token it was called with would repeat forever, so it
// ends the walk too.
func privateLinkTokenDone(next, current *string) bool {
	n := tea.StringValue(next)
	return n == "" || n == tea.StringValue(current)
}

// servicesIn lists the endpoint services one region publishes, once, memoizing
// the outcome whether it succeeded or failed.
func (r *mqlAlicloudPrivatelink) servicesIn(region string) ([]*mqlAlicloudPrivatelinkEndpointService, error) {
	r.serviceLock.Lock()
	defer r.serviceLock.Unlock()
	if cached, ok := r.services[region]; ok {
		return cached, nil
	}
	if err, ok := r.serviceErrs[region]; ok {
		return nil, err
	}
	res, err := r.listServices(region)
	if err != nil {
		if r.serviceErrs == nil {
			r.serviceErrs = map[string]error{}
		}
		r.serviceErrs[region] = err
		return nil, err
	}
	if r.services == nil {
		r.services = map[string][]*mqlAlicloudPrivatelinkEndpointService{}
	}
	r.services[region] = res
	return res, nil
}

func (r *mqlAlicloudPrivatelink) listServices(region string) ([]*mqlAlicloudPrivatelinkEndpointService, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PrivateLinkClient(region)
	if err != nil {
		return nil, err
	}

	res := []*mqlAlicloudPrivatelinkEndpointService{}
	req := &privatelinkclient.ListVpcEndpointServicesRequest{
		RegionId:   tea.String(region),
		MaxResults: tea.Int32(privateLinkPageSize),
	}
	for {
		resp, err := client.ListVpcEndpointServices(req)
		if err != nil {
			return nil, classifyAlicloudError(err, "privatelink:ListVpcEndpointServices")
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, s := range resp.Body.Services {
			if s == nil || tea.StringValue(s.ServiceId) == "" {
				continue
			}
			svc, err := newPrivateLinkService(r.MqlRuntime, region, s)
			if err != nil {
				return nil, err
			}
			res = append(res, svc)
		}
		if privateLinkTokenDone(resp.Body.NextToken, req.NextToken) {
			break
		}
		req.NextToken = resp.Body.NextToken
	}
	return res, nil
}

func newPrivateLinkService(runtime *plugin.Runtime, region string, s *privatelinkclient.ListVpcEndpointServicesResponseBodyServices) (*mqlAlicloudPrivatelinkEndpointService, error) {
	tags := map[string]any{}
	for _, t := range s.Tags {
		if t == nil || tea.StringValue(t.Key) == "" {
			continue
		}
		tags[tea.StringValue(t.Key)] = tea.StringValue(t.Value)
	}
	res, err := CreateResource(runtime, "alicloud.privatelink.endpointService", map[string]*llx.RawData{
		"__id":                  llx.StringData(region + "/" + tea.StringValue(s.ServiceId)),
		"regionId":              llx.StringData(region),
		"serviceId":             llx.StringDataPtr(s.ServiceId),
		"serviceName":           llx.StringDataPtr(s.ServiceName),
		"description":           llx.StringDataPtr(s.ServiceDescription),
		"serviceType":           llx.StringDataPtr(s.ServiceType),
		"serviceResourceType":   llx.StringDataPtr(s.ServiceResourceType),
		"serviceDomain":         llx.StringDataPtr(s.ServiceDomain),
		"serviceStatus":         llx.StringDataPtr(s.ServiceStatus),
		"serviceBusinessStatus": llx.StringDataPtr(s.ServiceBusinessStatus),
		"autoAcceptEnabled":     llx.BoolDataPtr(s.AutoAcceptEnabled),
		"zoneAffinityEnabled":   llx.BoolDataPtr(s.ZoneAffinityEnabled),
		"payer":                 llx.StringDataPtr(s.Payer),
		"addressIpVersion":      llx.StringDataPtr(s.AddressIpVersion),
		"createTime":            llx.TimeDataPtr(parseAlicloudTime(s.CreateTime)),
		"resourceGroupId":       llx.StringDataPtr(s.ResourceGroupId),
		"tags":                  llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudPrivatelinkEndpointService), nil
}

func (r *mqlAlicloudPrivatelink) endpointServices() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, region := range regions {
		services, err := r.servicesIn(region)
		if err != nil {
			// a denied or unavailable region is a partial result; keep the others
			logSkippedRegion(err, "PrivateLink", region)
			continue
		}
		for _, s := range services {
			res = append(res, s)
		}
	}
	return res, nil
}

func (r *mqlAlicloudPrivatelinkEndpointService) id() (string, error) {
	return r.RegionId.Data + "/" + r.ServiceId.Data, nil
}

func (r *mqlAlicloudPrivatelinkEndpointService) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// allowlist reads one kind of the service's connection allowlist: Users for
// account IDs, UserARNs for RAM principal ARNs.
func (r *mqlAlicloudPrivatelinkEndpointService) allowlist(listType string) ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PrivateLinkClient(r.RegionId.Data)
	if err != nil {
		return nil, err
	}
	res := []any{}
	req := &privatelinkclient.ListVpcEndpointServiceUsersRequest{
		RegionId:     tea.String(r.RegionId.Data),
		ServiceId:    tea.String(r.ServiceId.Data),
		UserListType: tea.String(listType),
		MaxResults:   tea.Int32(privateLinkPageSize),
	}
	for {
		resp, err := client.ListVpcEndpointServiceUsers(req)
		if err != nil {
			return nil, classifyAlicloudError(err, "privatelink:ListVpcEndpointServiceUsers")
		}
		if resp == nil || resp.Body == nil {
			break
		}
		res = append(res, privateLinkAllowlistEntries(resp.Body)...)
		if privateLinkTokenDone(resp.Body.NextToken, req.NextToken) {
			break
		}
		req.NextToken = resp.Body.NextToken
	}
	return res, nil
}

// privateLinkAllowlistEntries flattens one page of an allowlist response. The
// response carries account IDs in Users and principal ARNs in UserARNs,
// depending on the list type requested; both are read so neither is dropped.
func privateLinkAllowlistEntries(body *privatelinkclient.ListVpcEndpointServiceUsersResponseBody) []any {
	res := []any{}
	for _, u := range body.Users {
		if u == nil || u.UserId == nil {
			continue
		}
		res = append(res, strconv.FormatInt(*u.UserId, 10))
	}
	for _, u := range body.UserARNs {
		if u == nil || tea.StringValue(u.UserARN) == "" {
			continue
		}
		res = append(res, tea.StringValue(u.UserARN))
	}
	return res
}

func (r *mqlAlicloudPrivatelinkEndpointService) allowedAccountIds() ([]any, error) {
	return r.allowlist("Users")
}

func (r *mqlAlicloudPrivatelinkEndpointService) allowedPrincipalArns() ([]any, error) {
	return r.allowlist("UserARNs")
}

func (r *mqlAlicloudPrivatelinkEndpointService) connections() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PrivateLinkClient(r.RegionId.Data)
	if err != nil {
		return nil, err
	}
	res := []any{}
	req := &privatelinkclient.ListVpcEndpointConnectionsRequest{
		RegionId:   tea.String(r.RegionId.Data),
		ServiceId:  tea.String(r.ServiceId.Data),
		MaxResults: tea.Int32(privateLinkPageSize),
	}
	for {
		resp, err := client.ListVpcEndpointConnections(req)
		if err != nil {
			return nil, classifyAlicloudError(err, "privatelink:ListVpcEndpointConnections")
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, c := range resp.Body.Connections {
			if c == nil || tea.StringValue(c.EndpointId) == "" {
				continue
			}
			ownerID := ""
			if c.EndpointOwnerId != nil {
				ownerID = strconv.FormatInt(*c.EndpointOwnerId, 10)
			}
			mqlConn, err := CreateResource(r.MqlRuntime, "alicloud.privatelink.endpointConnection", map[string]*llx.RawData{
				"__id":             llx.StringData(r.RegionId.Data + "/" + r.ServiceId.Data + "/" + tea.StringValue(c.EndpointId)),
				"endpointId":       llx.StringDataPtr(c.EndpointId),
				"endpointOwnerId":  llx.StringData(ownerID),
				"endpointRegionId": llx.StringDataPtr(c.EndpointRegionId),
				"endpointVpcId":    llx.StringDataPtr(c.EndpointVpcId),
				"connectionStatus": llx.StringDataPtr(c.ConnectionStatus),
				"bandwidth":        llx.IntDataPtr(c.Bandwidth),
				"modifiedTime":     llx.TimeDataPtr(parseAlicloudTime(c.ModifiedTime)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlConn)
		}
		if privateLinkTokenDone(resp.Body.NextToken, req.NextToken) {
			break
		}
		req.NextToken = resp.Body.NextToken
	}
	return res, nil
}

// mqlAlicloudPrivatelinkEndpointInternal caches the VPC id the endpoint's
// network reference resolves through.
type mqlAlicloudPrivatelinkEndpointInternal struct {
	cacheVpcID string
}

func (r *mqlAlicloudPrivatelink) endpoints() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.PrivateLinkClient(region)
		if err != nil {
			return nil, err
		}
		req := &privatelinkclient.ListVpcEndpointsRequest{
			RegionId:   tea.String(region),
			MaxResults: tea.Int32(privateLinkPageSize),
		}
		firstPage := true
		for {
			resp, err := client.ListVpcEndpoints(req)
			if err != nil {
				// A first-page error is a region the credential cannot read;
				// keep the other regions. A later-page error is real.
				if firstPage {
					logSkippedRegion(err, "PrivateLink", region)
					break
				}
				return nil, classifyAlicloudError(err, "privatelink:ListVpcEndpoints")
			}
			firstPage = false
			if resp == nil || resp.Body == nil {
				break
			}
			for _, e := range resp.Body.Endpoints {
				if e == nil || tea.StringValue(e.EndpointId) == "" {
					continue
				}
				endpoint, err := newPrivateLinkEndpoint(r.MqlRuntime, region, e)
				if err != nil {
					return nil, err
				}
				res = append(res, endpoint)
			}
			if privateLinkTokenDone(resp.Body.NextToken, req.NextToken) {
				break
			}
			req.NextToken = resp.Body.NextToken
		}
	}
	return res, nil
}

func newPrivateLinkEndpoint(runtime *plugin.Runtime, region string, e *privatelinkclient.ListVpcEndpointsResponseBodyEndpoints) (*mqlAlicloudPrivatelinkEndpoint, error) {
	tags := map[string]any{}
	for _, t := range e.Tags {
		if t == nil || tea.StringValue(t.Key) == "" {
			continue
		}
		tags[tea.StringValue(t.Key)] = tea.StringValue(t.Value)
	}
	res, err := CreateResource(runtime, "alicloud.privatelink.endpoint", map[string]*llx.RawData{
		"__id":                   llx.StringData(region + "/" + tea.StringValue(e.EndpointId)),
		"regionId":               llx.StringData(region),
		"endpointId":             llx.StringDataPtr(e.EndpointId),
		"endpointName":           llx.StringDataPtr(e.EndpointName),
		"description":            llx.StringDataPtr(e.EndpointDescription),
		"endpointType":           llx.StringDataPtr(e.EndpointType),
		"endpointStatus":         llx.StringDataPtr(e.EndpointStatus),
		"endpointBusinessStatus": llx.StringDataPtr(e.EndpointBusinessStatus),
		"connectionStatus":       llx.StringDataPtr(e.ConnectionStatus),
		"endpointDomain":         llx.StringDataPtr(e.EndpointDomain),
		"serviceId":              llx.StringDataPtr(e.ServiceId),
		"serviceName":            llx.StringDataPtr(e.ServiceName),
		"serviceRegionId":        llx.StringDataPtr(e.ServiceRegionId),
		"policyDocument":         llx.StringDataPtr(e.PolicyDocument),
		"zoneAffinityEnabled":    llx.BoolDataPtr(e.ZoneAffinityEnabled),
		"protectedEnabled":       llx.BoolDataPtr(e.ProtectedEnabled),
		"addressIpVersion":       llx.StringDataPtr(e.AddressIpVersion),
		"createTime":             llx.TimeDataPtr(parseAlicloudTime(e.CreateTime)),
		"resourceGroupId":        llx.StringDataPtr(e.ResourceGroupId),
		"tags":                   llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	endpoint := res.(*mqlAlicloudPrivatelinkEndpoint)
	endpoint.cacheVpcID = tea.StringValue(e.VpcId)
	return endpoint, nil
}

func (r *mqlAlicloudPrivatelinkEndpoint) id() (string, error) {
	return r.RegionId.Data + "/" + r.EndpointId.Data, nil
}

func (r *mqlAlicloudPrivatelinkEndpoint) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

func (r *mqlAlicloudPrivatelinkEndpoint) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.RegionId.Data, r.cacheVpcID)
}

// endpointService resolves the service the endpoint connects to from the
// memoized service list of the service's region. A service published by
// another account or by Alibaba Cloud is not in that list and reads null.
func (r *mqlAlicloudPrivatelinkEndpoint) endpointService() (*mqlAlicloudPrivatelinkEndpointService, error) {
	region := r.ServiceRegionId.Data
	if region == "" {
		region = r.RegionId.Data
	}
	if r.ServiceId.Data == "" {
		r.EndpointService.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pl, err := privateLinkResource(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	services, err := pl.servicesIn(region)
	if err != nil {
		log.Debug().Err(err).Str("serviceId", r.ServiceId.Data).Str("region", region).
			Msg("alicloud> could not list the endpoint services an endpoint may connect to")
		r.EndpointService.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	for _, s := range services {
		if s.ServiceId.Data == r.ServiceId.Data {
			return s, nil
		}
	}
	r.EndpointService.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (r *mqlAlicloudPrivatelinkEndpoint) securityGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PrivateLinkClient(r.RegionId.Data)
	if err != nil {
		return nil, err
	}
	ids := []any{}
	req := &privatelinkclient.ListVpcEndpointSecurityGroupsRequest{
		RegionId:   tea.String(r.RegionId.Data),
		EndpointId: tea.String(r.EndpointId.Data),
		MaxResults: tea.Int32(privateLinkPageSize),
	}
	for {
		resp, err := client.ListVpcEndpointSecurityGroups(req)
		if err != nil {
			return nil, classifyAlicloudError(err, "privatelink:ListVpcEndpointSecurityGroups")
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, sg := range resp.Body.SecurityGroups {
			if sg == nil || tea.StringValue(sg.SecurityGroupId) == "" {
				continue
			}
			ids = append(ids, tea.StringValue(sg.SecurityGroupId))
		}
		if privateLinkTokenDone(resp.Body.NextToken, req.NextToken) {
			break
		}
		req.NextToken = resp.Body.NextToken
	}
	return resolveEcsSecuritygroups(r.MqlRuntime, r.RegionId.Data, ids)
}
