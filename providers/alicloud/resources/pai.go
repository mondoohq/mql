// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	aiworkspaceclient "github.com/alibabacloud-go/aiworkspace-20210204/v6/client"
	easclient "github.com/alibabacloud-go/eas-20210701/v7/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// paiPageSize is the page size requested from the PAI list APIs. EAS and AI
// workspace both accept 100.
const paiPageSize = 100

// paiPagedList walks a PageNumber/PageSize listing. fetch returns one page and
// the total the API reports. The walk stops once the total is reached, or on a
// short or empty page, so an API that misreports its total cannot loop forever.
func paiPagedList[T any](pageSize int, fetch func(page int) ([]T, int64, error)) ([]T, error) {
	res := []T{}
	for page := 1; ; page++ {
		items, total, err := fetch(page)
		if err != nil {
			return nil, err
		}
		res = append(res, items...)
		if len(items) == 0 || len(items) < pageSize || int64(len(res)) >= total {
			return res, nil
		}
	}
}

func (r *mqlAlicloudPai) id() (string, error) {
	return "alicloud.pai", nil
}

// paiRegional collects one PAI listing across every region that offers PAI.
// A denied or failed region is a partial result: it is logged and skipped, and
// the other regions' results are kept.
func paiRegional(runtime *plugin.Runtime, service string, list func(region string) ([]any, error)) ([]any, error) {
	conn := runtime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.PaiRegions()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, region := range regions {
		items, err := list(region)
		if err != nil {
			logSkippedRegion(err, service, region)
			continue
		}
		res = append(res, items...)
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// AI workspaces
// ---------------------------------------------------------------------------

func (r *mqlAlicloudPai) workspaces() ([]any, error) {
	return paiRegional(r.MqlRuntime, "PAI workspace", func(region string) ([]any, error) {
		return listPaiWorkspaces(r.MqlRuntime, region, "")
	})
}

// listPaiWorkspaces lists the workspaces in a region, or only the named one
// when workspaceID is set.
func listPaiWorkspaces(runtime *plugin.Runtime, region, workspaceID string) ([]any, error) {
	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.AiWorkspaceClient(region)
	if err != nil {
		return nil, err
	}
	items, err := paiPagedList(paiPageSize, func(page int) ([]*aiworkspaceclient.ListWorkspacesResponseBodyWorkspaces, int64, error) {
		req := &aiworkspaceclient.ListWorkspacesRequest{
			PageNumber: tea.Int64(int64(page)),
			PageSize:   tea.Int32(paiPageSize),
			// Verbose returns the administrators and environment types
			Verbose: tea.Bool(true),
		}
		if workspaceID != "" {
			req.WorkspaceIds = new(workspaceID)
		}
		resp, err := client.ListWorkspaces(req)
		if err != nil {
			return nil, 0, classifyAlicloudError(err, "paiworkspace:ListWorkspaces")
		}
		if resp == nil || resp.Body == nil {
			return nil, 0, nil
		}
		return resp.Body.Workspaces, tea.Int64Value(resp.Body.TotalCount), nil
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, w := range items {
		if w == nil || tea.StringValue(w.WorkspaceId) == "" {
			continue
		}
		mqlW, err := newPaiWorkspace(runtime, region, w)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlW)
	}
	return res, nil
}

func newPaiWorkspace(runtime *plugin.Runtime, region string, w *aiworkspaceclient.ListWorkspacesResponseBodyWorkspaces) (*mqlAlicloudPaiWorkspace, error) {
	res, err := CreateResource(runtime, "alicloud.pai.workspace", map[string]*llx.RawData{
		"__id":            llx.StringData(region + "/" + tea.StringValue(w.WorkspaceId)),
		"regionId":        llx.StringData(region),
		"workspaceId":     llx.StringDataPtr(w.WorkspaceId),
		"name":            llx.StringDataPtr(w.WorkspaceName),
		"displayName":     llx.StringDataPtr(w.DisplayName),
		"description":     llx.StringDataPtr(w.Description),
		"status":          llx.StringDataPtr(w.Status),
		"creator":         llx.StringDataPtr(w.Creator),
		"adminNames":      llx.ArrayData(strPtrsToAny(w.AdminNames), types.String),
		"isDefault":       llx.BoolDataPtr(w.IsDefault),
		"envTypes":        llx.ArrayData(strPtrsToAny(w.EnvTypes), types.String),
		"createTime":      llx.TimeDataPtr(parseAlicloudTime(w.GmtCreateTime)),
		"modifiedTime":    llx.TimeDataPtr(parseAlicloudTime(w.GmtModifiedTime)),
		"resourceGroupId": llx.StringDataPtr(w.ResourceGroupId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudPaiWorkspace), nil
}

// initAlicloudPaiWorkspace resolves a workspace by id within a region, reusing
// an already-listed workspace from the resource cache.
func initAlicloudPaiWorkspace(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	workspaceID, err := requiredStringArg(args, "workspaceId", "alicloud.pai.workspace")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.pai.workspace")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.pai.workspace\x00" + region + "/" + workspaceID); ok {
		return nil, x, nil
	}
	found, err := listPaiWorkspaces(runtime, region, workspaceID)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range found {
		if w := f.(*mqlAlicloudPaiWorkspace); w.WorkspaceId.Data == workspaceID {
			return nil, w, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.pai.workspace %q not found in region %q", workspaceID, region)
}

func (r *mqlAlicloudPaiWorkspace) id() (string, error) {
	return r.RegionId.Data + "/" + r.WorkspaceId.Data, nil
}

func (r *mqlAlicloudPaiWorkspace) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

func (r *mqlAlicloudPaiWorkspace) members() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.AiWorkspaceClient(r.RegionId.Data)
	if err != nil {
		return nil, err
	}
	items, err := paiPagedList(paiPageSize, func(page int) ([]*aiworkspaceclient.ListMembersResponseBodyMembers, int64, error) {
		resp, err := client.ListMembers(new(r.WorkspaceId.Data), &aiworkspaceclient.ListMembersRequest{
			PageNumber: tea.Int64(int64(page)),
			PageSize:   tea.Int32(paiPageSize),
		})
		if err != nil {
			return nil, 0, classifyAlicloudError(err, "paiworkspace:ListMembers")
		}
		if resp == nil || resp.Body == nil {
			return nil, 0, nil
		}
		return resp.Body.Members, tea.Int64Value(resp.Body.TotalCount), nil
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, m := range items {
		if m == nil {
			continue
		}
		memberID := tea.StringValue(m.MemberId)
		if memberID == "" {
			memberID = tea.StringValue(m.UserId)
		}
		mqlM, err := CreateResource(r.MqlRuntime, "alicloud.pai.workspace.member", map[string]*llx.RawData{
			"__id":        llx.StringData(r.RegionId.Data + "/" + r.WorkspaceId.Data + "/" + memberID),
			"memberId":    llx.StringData(memberID),
			"accountName": llx.StringDataPtr(m.AccountName),
			"displayName": llx.StringDataPtr(m.DisplayName),
			"accountType": llx.StringDataPtr(m.AccountType),
			"roles":       llx.ArrayData(strPtrsToAny(m.Roles), types.String),
			"createTime":  llx.TimeDataPtr(parseAlicloudTime(m.GmtCreateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlM)
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// EAS services
// ---------------------------------------------------------------------------

func (r *mqlAlicloudPai) easServices() ([]any, error) {
	return paiRegional(r.MqlRuntime, "PAI-EAS service", func(region string) ([]any, error) {
		return listEasServices(r.MqlRuntime, region)
	})
}

func listEasServices(runtime *plugin.Runtime, region string) ([]any, error) {
	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.EasClient(region)
	if err != nil {
		return nil, err
	}
	items, err := paiPagedList(paiPageSize, func(page int) ([]*easclient.Service, int64, error) {
		resp, err := client.ListServices(&easclient.ListServicesRequest{
			PageNumber: tea.Int32(int32(page)),
			PageSize:   tea.Int32(paiPageSize),
		})
		if err != nil {
			return nil, 0, classifyAlicloudError(err, "eas:ListServices")
		}
		if resp == nil || resp.Body == nil {
			return nil, 0, nil
		}
		return resp.Body.Services, int64(tea.Int32Value(resp.Body.TotalCount)), nil
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, s := range items {
		if s == nil || tea.StringValue(s.ServiceName) == "" {
			continue
		}
		mqlS, err := newEasService(runtime, region, s, false)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlS)
	}
	return res, nil
}

// mqlAlicloudPaiEasServiceInternal keeps the identifiers for the typed
// references and the DescribeService detail, which is the only call that
// returns the service endpoints.
type mqlAlicloudPaiEasServiceInternal struct {
	cacheWorkspaceId   string
	cacheGatewayId     string
	cacheServiceConfig string

	detailLock    sync.Mutex
	detailFetched atomic.Bool
	detail        *easclient.Service
}

// newEasService builds an alicloud.pai.easService from a Service record.
// isDetail marks a record that came from DescribeService, so the endpoints it
// carries are not fetched a second time. The record's access token is never
// read.
func newEasService(runtime *plugin.Runtime, region string, s *easclient.Service, isDetail bool) (*mqlAlicloudPaiEasService, error) {
	name := tea.StringValue(s.ServiceName)
	id := tea.StringValue(s.ServiceId)
	if id == "" {
		id = tea.StringValue(s.ServiceUid)
	}

	labels := map[string]any{}
	for _, l := range s.Labels {
		if l == nil || l.LabelKey == nil {
			continue
		}
		labels[*l.LabelKey] = tea.StringValue(l.LabelValue)
	}

	res, err := CreateResource(runtime, "alicloud.pai.easService", map[string]*llx.RawData{
		"__id":              llx.StringData(region + "/" + name),
		"regionId":          llx.StringData(region),
		"name":              llx.StringData(name),
		"id":                llx.StringData(id),
		"status":            llx.StringDataPtr(s.Status),
		"reason":            llx.StringDataPtr(s.Reason),
		"message":           llx.StringDataPtr(s.Message),
		"image":             llx.StringDataPtr(s.Image),
		"source":            llx.StringDataPtr(s.Source),
		"role":              llx.StringDataPtr(s.Role),
		"appType":           llx.StringDataPtr(s.AppType),
		"safetyLock":        llx.StringDataPtr(s.SafetyLock),
		"serviceGroup":      llx.StringDataPtr(s.ServiceGroup),
		"trafficState":      llx.StringDataPtr(s.TrafficState),
		"cpu":               llx.IntData(int64(tea.Int32Value(s.Cpu))),
		"memory":            llx.IntData(int64(tea.Int32Value(s.Memory))),
		"gpu":               llx.IntData(int64(tea.Int32Value(s.Gpu))),
		"totalInstance":     llx.IntData(int64(tea.Int32Value(s.TotalInstance))),
		"runningInstance":   llx.IntData(int64(tea.Int32Value(s.RunningInstance))),
		"autoscalerEnabled": llx.BoolDataPtr(s.AutoscalerEnabled),
		"labels":            llx.MapData(labels, types.String),
		"createTime":        llx.TimeDataPtr(parseAlicloudTime(s.CreateTime)),
		"updateTime":        llx.TimeDataPtr(parseAlicloudTime(s.UpdateTime)),
		"callerUid":         llx.StringDataPtr(s.CallerUid),
	})
	if err != nil {
		return nil, err
	}
	mqlS := res.(*mqlAlicloudPaiEasService)
	mqlS.cacheWorkspaceId = tea.StringValue(s.WorkspaceId)
	mqlS.cacheGatewayId = tea.StringValue(s.Gateway)
	mqlS.cacheServiceConfig = tea.StringValue(s.ServiceConfig)
	if isDetail {
		mqlS.detail = s
		mqlS.detailFetched.Store(true)
	}
	return mqlS, nil
}

// initAlicloudPaiEasService resolves a service by name within a region,
// reusing an already-listed service from the resource cache and otherwise
// fetching it via DescribeService.
func initAlicloudPaiEasService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	name, err := requiredStringArg(args, "name", "alicloud.pai.easService")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.pai.easService")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.pai.easService\x00" + region + "/" + name); ok {
		return nil, x, nil
	}
	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.EasClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeService(new(region), new(name), &easclient.DescribeServiceRequest{})
	if err != nil {
		return nil, nil, classifyAlicloudError(err, "eas:DescribeService")
	}
	if resp == nil || resp.Body == nil || tea.StringValue(resp.Body.ServiceName) == "" {
		return nil, nil, fmt.Errorf("alicloud.pai.easService %q not found in region %q", name, region)
	}
	res, err := newEasService(runtime, region, resp.Body, true)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlAlicloudPaiEasService) id() (string, error) {
	return r.RegionId.Data + "/" + r.Name.Data, nil
}

// getDetail returns the DescribeService record, fetching it once.
func (r *mqlAlicloudPaiEasService) getDetail() (*easclient.Service, error) {
	if r.detailFetched.Load() {
		return r.detail, nil
	}
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailFetched.Load() {
		return r.detail, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.EasClient(r.RegionId.Data)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeService(new(r.RegionId.Data), new(r.Name.Data), &easclient.DescribeServiceRequest{})
	if err != nil {
		return nil, classifyAlicloudError(err, "eas:DescribeService")
	}
	if resp != nil {
		r.detail = resp.Body
	}
	if r.detail == nil {
		r.detail = &easclient.Service{}
	}
	r.detailFetched.Store(true)
	return r.detail, nil
}

func (r *mqlAlicloudPaiEasService) internetEndpoint() (string, error) {
	d, err := r.getDetail()
	if err != nil {
		return "", err
	}
	return tea.StringValue(d.InternetEndpoint), nil
}

func (r *mqlAlicloudPaiEasService) intranetEndpoint() (string, error) {
	d, err := r.getDetail()
	if err != nil {
		return "", err
	}
	return tea.StringValue(d.IntranetEndpoint), nil
}

func (r *mqlAlicloudPaiEasService) secondaryInternetEndpoint() (string, error) {
	d, err := r.getDetail()
	if err != nil {
		return "", err
	}
	return tea.StringValue(d.SecondaryInternetEndpoint), nil
}

func (r *mqlAlicloudPaiEasService) secondaryIntranetEndpoint() (string, error) {
	d, err := r.getDetail()
	if err != nil {
		return "", err
	}
	return tea.StringValue(d.SecondaryIntranetEndpoint), nil
}

func (r *mqlAlicloudPaiEasService) isPublic() (bool, error) {
	d, err := r.getDetail()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(tea.StringValue(d.InternetEndpoint)) != "", nil
}

func (r *mqlAlicloudPaiEasService) workspace() (*mqlAlicloudPaiWorkspace, error) {
	if r.cacheWorkspaceId == "" {
		r.Workspace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.pai.workspace", map[string]*llx.RawData{
		"workspaceId": llx.StringData(r.cacheWorkspaceId),
		"regionId":    llx.StringData(r.RegionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudPaiWorkspace), nil
}

func (r *mqlAlicloudPaiEasService) gateway() (*mqlAlicloudPaiEasGateway, error) {
	if r.cacheGatewayId == "" {
		r.Gateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.pai.easGateway", map[string]*llx.RawData{
		"gatewayId": llx.StringData(r.cacheGatewayId),
		"regionId":  llx.StringData(r.RegionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudPaiEasGateway), nil
}

// easNetworking is the VPC placement in an EAS service configuration, under
// cloud.networking.
type easNetworking struct {
	VpcId           string `json:"vpc_id"`
	VswitchId       string `json:"vswitch_id"`
	SecurityGroupId string `json:"security_group_id"`
}

// parseEasNetworking reads the VPC, vSwitch, and security group ids from an
// EAS service configuration document. Only cloud.networking is decoded, so no
// other part of the configuration (which may hold a service token) is kept.
// An empty or malformed document yields empty ids.
func parseEasNetworking(serviceConfig string) easNetworking {
	var doc struct {
		Cloud struct {
			Networking easNetworking `json:"networking"`
		} `json:"cloud"`
	}
	if strings.TrimSpace(serviceConfig) == "" {
		return easNetworking{}
	}
	if err := json.Unmarshal([]byte(serviceConfig), &doc); err != nil {
		return easNetworking{}
	}
	n := doc.Cloud.Networking
	n.VpcId = strings.TrimSpace(n.VpcId)
	n.VswitchId = strings.TrimSpace(n.VswitchId)
	n.SecurityGroupId = strings.TrimSpace(n.SecurityGroupId)
	return n
}

// networking returns the service's VPC placement, reading the configuration
// from the list record and falling back to DescribeService when the list did
// not carry it.
func (r *mqlAlicloudPaiEasService) networking() (easNetworking, error) {
	if r.cacheServiceConfig != "" {
		return parseEasNetworking(r.cacheServiceConfig), nil
	}
	d, err := r.getDetail()
	if err != nil {
		return easNetworking{}, err
	}
	return parseEasNetworking(tea.StringValue(d.ServiceConfig)), nil
}

func (r *mqlAlicloudPaiEasService) vpc() (*mqlAlicloudVpcNetwork, error) {
	n, err := r.networking()
	if err != nil {
		return nil, err
	}
	if n.VpcId == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.RegionId.Data, n.VpcId)
}

func (r *mqlAlicloudPaiEasService) vswitch() (*mqlAlicloudVpcVswitch, error) {
	n, err := r.networking()
	if err != nil {
		return nil, err
	}
	if n.VswitchId == "" {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcVswitch(r.MqlRuntime, r.RegionId.Data, n.VswitchId)
}

func (r *mqlAlicloudPaiEasService) securityGroup() (*mqlAlicloudEcsSecuritygroup, error) {
	n, err := r.networking()
	if err != nil {
		return nil, err
	}
	if n.SecurityGroupId == "" {
		r.SecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveEcsSecuritygroup(r.MqlRuntime, r.RegionId.Data, n.SecurityGroupId)
}

// ---------------------------------------------------------------------------
// EAS gateways
// ---------------------------------------------------------------------------

func (r *mqlAlicloudPai) easGateways() ([]any, error) {
	return paiRegional(r.MqlRuntime, "PAI-EAS gateway", func(region string) ([]any, error) {
		return listEasGateways(r.MqlRuntime, region, "")
	})
}

// listEasGateways lists the dedicated gateways in a region, or only the named
// one when gatewayID is set.
func listEasGateways(runtime *plugin.Runtime, region, gatewayID string) ([]any, error) {
	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.EasClient(region)
	if err != nil {
		return nil, err
	}
	items, err := paiPagedList(paiPageSize, func(page int) ([]*easclient.ListGatewayResponseBodyGateways, int64, error) {
		req := &easclient.ListGatewayRequest{
			PageNumber: tea.Int32(int32(page)),
			PageSize:   tea.Int32(paiPageSize),
		}
		if gatewayID != "" {
			req.GatewayId = new(gatewayID)
		}
		resp, err := client.ListGateway(req)
		if err != nil {
			return nil, 0, classifyAlicloudError(err, "eas:ListGateway")
		}
		if resp == nil || resp.Body == nil {
			return nil, 0, nil
		}
		return resp.Body.Gateways, tea.Int64Value(resp.Body.TotalCount), nil
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, g := range items {
		if g == nil || tea.StringValue(g.GatewayId) == "" {
			continue
		}
		mqlG, err := newEasGateway(runtime, region, g)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlG)
	}
	return res, nil
}

func newEasGateway(runtime *plugin.Runtime, region string, g *easclient.ListGatewayResponseBodyGateways) (*mqlAlicloudPaiEasGateway, error) {
	labels := map[string]any{}
	for _, l := range g.Labels {
		if l == nil || l.LabelKey == nil {
			continue
		}
		labels[*l.LabelKey] = tea.StringValue(l.LabelValue)
	}
	res, err := CreateResource(runtime, "alicloud.pai.easGateway", map[string]*llx.RawData{
		"__id":                  llx.StringData(region + "/" + tea.StringValue(g.GatewayId)),
		"regionId":              llx.StringData(region),
		"gatewayId":             llx.StringDataPtr(g.GatewayId),
		"name":                  llx.StringDataPtr(g.GatewayName),
		"status":                llx.StringDataPtr(g.Status),
		"instanceType":          llx.StringDataPtr(g.InstanceType),
		"replicas":              llx.IntData(int64(tea.Int32Value(g.Replicas))),
		"chargeType":            llx.StringDataPtr(g.ChargeType),
		"isDefault":             llx.BoolDataPtr(g.IsDefault),
		"internetEnabled":       llx.BoolDataPtr(g.InternetEnabled),
		"internetDomain":        llx.StringDataPtr(g.InternetDomain),
		"intranetEnabled":       llx.BoolDataPtr(g.IntranetEnabled),
		"intranetDomain":        llx.StringDataPtr(g.IntranetDomain),
		"sslRedirectionEnabled": llx.BoolDataPtr(g.SSLRedirectionEnabled),
		"labels":                llx.MapData(labels, types.String),
		"createTime":            llx.TimeDataPtr(parseAlicloudTime(g.CreateTime)),
		"updateTime":            llx.TimeDataPtr(parseAlicloudTime(g.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudPaiEasGateway), nil
}

// initAlicloudPaiEasGateway resolves a gateway by id within a region, reusing
// an already-listed gateway from the resource cache.
func initAlicloudPaiEasGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	gatewayID, err := requiredStringArg(args, "gatewayId", "alicloud.pai.easGateway")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.pai.easGateway")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.pai.easGateway\x00" + region + "/" + gatewayID); ok {
		return nil, x, nil
	}
	found, err := listEasGateways(runtime, region, gatewayID)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range found {
		if g := f.(*mqlAlicloudPaiEasGateway); g.GatewayId.Data == gatewayID {
			return nil, g, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.pai.easGateway %q not found in region %q", gatewayID, region)
}

func (r *mqlAlicloudPaiEasGateway) id() (string, error) {
	return r.RegionId.Data + "/" + r.GatewayId.Data, nil
}

func (r *mqlAlicloudPaiEasGateway) internetAcl() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.EasClient(r.RegionId.Data)
	if err != nil {
		return nil, err
	}
	resp, err := client.ListAclPolicy(new(r.RegionId.Data), new(r.GatewayId.Data), &easclient.ListAclPolicyRequest{})
	if err != nil {
		return nil, classifyAlicloudError(err, "eas:ListAclPolicy")
	}
	if resp == nil {
		return []any{}, nil
	}
	return easInternetAclEntries(resp.Body), nil
}

// easInternetAclEntries flattens a gateway's internet ACL policy lists into
// one entry per allowed CIDR block.
func easInternetAclEntries(body *easclient.ListAclPolicyResponseBody) []any {
	res := []any{}
	if body == nil {
		return res
	}
	for _, list := range body.InternetAclPolicyList {
		if list == nil {
			continue
		}
		for _, p := range list.AclPolicyList {
			if p == nil || strings.TrimSpace(tea.StringValue(p.Entry)) == "" {
				continue
			}
			res = append(res, map[string]any{
				"entry":   strings.TrimSpace(tea.StringValue(p.Entry)),
				"comment": tea.StringValue(p.Comment),
			})
		}
	}
	return res
}
