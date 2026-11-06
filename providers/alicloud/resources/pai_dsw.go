// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	dswclient "github.com/alibabacloud-go/pai-dsw-20220101/v2/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlAlicloudPai) dswInstances() ([]any, error) {
	return paiRegional(r.MqlRuntime, "PAI-DSW instance", func(region string) ([]any, error) {
		return listDswInstances(r.MqlRuntime, region, "")
	})
}

// listDswInstances lists the notebook instances in a region, or only the named
// one when instanceID is set.
func listDswInstances(runtime *plugin.Runtime, region, instanceID string) ([]any, error) {
	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.DswClient(region)
	if err != nil {
		return nil, err
	}
	items, err := paiPagedList(paiPageSize, func(page int) ([]*dswclient.ListInstancesResponseBodyInstances, int64, error) {
		req := &dswclient.ListInstancesRequest{
			PageNumber: tea.Int64(int64(page)),
			PageSize:   tea.Int64(paiPageSize),
		}
		if instanceID != "" {
			req.InstanceId = new(instanceID)
		}
		resp, err := client.ListInstances(req)
		if err != nil {
			return nil, 0, classifyAlicloudError(err, "paidsw:ListInstances")
		}
		if resp == nil || resp.Body == nil {
			return nil, 0, nil
		}
		return resp.Body.Instances, tea.Int64Value(resp.Body.TotalCount), nil
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, inst := range items {
		if inst == nil || tea.StringValue(inst.InstanceId) == "" {
			continue
		}
		mqlI, err := newDswInstance(runtime, region, inst)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlI)
	}
	return res, nil
}

// mqlAlicloudPaiDswInstanceInternal keeps the identifiers behind the typed
// references and the port forwards.
type mqlAlicloudPaiDswInstanceInternal struct {
	cacheWorkspaceId     string
	cacheVpcId           string
	cacheVswitchId       string
	cacheSecurityGroupId string
	cacheForwards        []*dswclient.ForwardInfoResponse
}

// dswRamRoleArns returns the role ARNs from an instance credential
// configuration, in order and without duplicates. Only RoleArn is read: the
// user info next to each role carries an access key ID and security token,
// which are never exposed.
func dswRamRoleArns(cfg *dswclient.CredentialConfig) []string {
	res := []string{}
	if cfg == nil {
		return res
	}
	for _, c := range cfg.Configs {
		if c == nil {
			continue
		}
		for _, role := range c.Roles {
			if role == nil {
				continue
			}
			arn := strings.TrimSpace(tea.StringValue(role.RoleArn))
			if arn != "" && !slices.Contains(res, arn) {
				res = append(res, arn)
			}
		}
	}
	return res
}

// envVarNames returns the sorted names of an environment variable map. The
// values are dropped.
func envVarNames(env map[string]*string) []string {
	res := make([]string, 0, len(env))
	for k := range env {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}

// dswForwardIsPublic reports whether an enabled port forward exposes the
// instance to the internet: a PUBLIC access type, an EIP, or a public connect
// endpoint.
func dswForwardIsPublic(f *dswclient.ForwardInfoResponse) bool {
	if f == nil || !tea.BoolValue(f.Enable) {
		return false
	}
	for _, t := range f.AccessType {
		if strings.EqualFold(strings.TrimSpace(tea.StringValue(t)), "PUBLIC") {
			return true
		}
	}
	if strings.TrimSpace(tea.StringValue(f.EipAllocationId)) != "" {
		return true
	}
	if f.ConnectInfo != nil && f.ConnectInfo.Internet != nil &&
		strings.TrimSpace(tea.StringValue(f.ConnectInfo.Internet.Endpoint)) != "" {
		return true
	}
	return false
}

func newDswInstance(runtime *plugin.Runtime, region string, inst *dswclient.ListInstancesResponseBodyInstances) (*mqlAlicloudPaiDswInstance, error) {
	instanceID := tea.StringValue(inst.InstanceId)

	labels := map[string]any{}
	for _, l := range inst.Labels {
		if l == nil || l.Key == nil {
			continue
		}
		labels[*l.Key] = tea.StringValue(l.Value)
	}
	tags := map[string]any{}
	for _, t := range inst.Tags {
		if t == nil || t.TagKey == nil {
			continue
		}
		tags[*t.TagKey] = tea.StringValue(t.TagValue)
	}

	vpcID, vswitchID, sgID, defaultRoute := "", "", "", ""
	extendedCidrs := []any{}
	var forwards []*dswclient.ForwardInfoResponse
	if v := inst.UserVpc; v != nil {
		vpcID = tea.StringValue(v.VpcId)
		vswitchID = tea.StringValue(v.VSwitchId)
		sgID = tea.StringValue(v.SecurityGroupId)
		defaultRoute = tea.StringValue(v.DefaultRoute)
		extendedCidrs = strPtrsToAny(v.ExtendedCIDRs)
		forwards = v.ForwardInfos
	}

	credentialEnabled := false
	if inst.CredentialConfig != nil {
		credentialEnabled = tea.BoolValue(inst.CredentialConfig.Enable)
	}

	// the culler is on when the API returns a culler with a positive maximum
	// idle time; an instance without one never stops for idleness
	var cullerMax, cullerCpu, cullerGpu int64
	if c := inst.IdleInstanceCuller; c != nil {
		cullerMax = int64(tea.Int32Value(c.MaxIdleTimeInMinutes))
		cullerCpu = int64(tea.Int32Value(c.CpuPercentThreshold))
		cullerGpu = int64(tea.Int32Value(c.GpuPercentThreshold))
	}

	var shutdownDue *string
	if t := inst.InstanceShutdownTimer; t != nil {
		shutdownDue = t.DueTime
	}

	res, err := CreateResource(runtime, "alicloud.pai.dswInstance", map[string]*llx.RawData{
		"__id":                           llx.StringData(region + "/" + instanceID),
		"regionId":                       llx.StringData(region),
		"instanceId":                     llx.StringData(instanceID),
		"name":                           llx.StringDataPtr(inst.InstanceName),
		"status":                         llx.StringDataPtr(inst.Status),
		"accessibility":                  llx.StringDataPtr(inst.Accessibility),
		"userName":                       llx.StringDataPtr(inst.UserName),
		"ecsSpec":                        llx.StringDataPtr(inst.EcsSpec),
		"acceleratorType":                llx.StringDataPtr(inst.AcceleratorType),
		"paymentType":                    llx.StringDataPtr(inst.PaymentType),
		"imageName":                      llx.StringDataPtr(inst.ImageName),
		"imageId":                        llx.StringDataPtr(inst.ImageId),
		"imageUrl":                       llx.StringDataPtr(inst.ImageUrl),
		"labels":                         llx.MapData(labels, types.String),
		"tags":                           llx.MapData(tags, types.String),
		"environmentVariableNames":       llx.ArrayData(stringsToAny(envVarNames(inst.EnvironmentVariables)), types.String),
		"createTime":                     llx.TimeDataPtr(parseAlicloudTime(inst.GmtCreateTime)),
		"modifiedTime":                   llx.TimeDataPtr(parseAlicloudTime(inst.GmtModifiedTime)),
		"defaultRoute":                   llx.StringData(defaultRoute),
		"extendedCidrs":                  llx.ArrayData(extendedCidrs, types.String),
		"credentialConfigEnabled":        llx.BoolData(credentialEnabled),
		"ramRoleArns":                    llx.ArrayData(stringsToAny(dswRamRoleArns(inst.CredentialConfig)), types.String),
		"idleCullerEnabled":              llx.BoolData(cullerMax > 0),
		"idleCullerMaxIdleTimeInMinutes": llx.IntData(cullerMax),
		"idleCullerCpuPercentThreshold":  llx.IntData(cullerCpu),
		"idleCullerGpuPercentThreshold":  llx.IntData(cullerGpu),
		"shutdownTime":                   llx.TimeDataPtr(parseAlicloudTime(shutdownDue)),
	})
	if err != nil {
		return nil, err
	}
	mqlI := res.(*mqlAlicloudPaiDswInstance)
	mqlI.cacheWorkspaceId = tea.StringValue(inst.WorkspaceId)
	mqlI.cacheVpcId = vpcID
	mqlI.cacheVswitchId = vswitchID
	mqlI.cacheSecurityGroupId = sgID
	mqlI.cacheForwards = forwards
	return mqlI, nil
}

// initAlicloudPaiDswInstance resolves an instance by id within a region,
// reusing an already-listed instance from the resource cache.
func initAlicloudPaiDswInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	instanceID, err := requiredStringArg(args, "instanceId", "alicloud.pai.dswInstance")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.pai.dswInstance")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.pai.dswInstance\x00" + region + "/" + instanceID); ok {
		return nil, x, nil
	}
	found, err := listDswInstances(runtime, region, instanceID)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range found {
		if i := f.(*mqlAlicloudPaiDswInstance); i.InstanceId.Data == instanceID {
			return nil, i, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.pai.dswInstance %q not found in region %q", instanceID, region)
}

func (r *mqlAlicloudPaiDswInstance) id() (string, error) {
	return r.RegionId.Data + "/" + r.InstanceId.Data, nil
}

func (r *mqlAlicloudPaiDswInstance) workspace() (*mqlAlicloudPaiWorkspace, error) {
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

func (r *mqlAlicloudPaiDswInstance) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcId == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.RegionId.Data, r.cacheVpcId)
}

func (r *mqlAlicloudPaiDswInstance) vswitch() (*mqlAlicloudVpcVswitch, error) {
	if r.cacheVswitchId == "" {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcVswitch(r.MqlRuntime, r.RegionId.Data, r.cacheVswitchId)
}

func (r *mqlAlicloudPaiDswInstance) securityGroup() (*mqlAlicloudEcsSecuritygroup, error) {
	if r.cacheSecurityGroupId == "" {
		r.SecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveEcsSecuritygroup(r.MqlRuntime, r.RegionId.Data, r.cacheSecurityGroupId)
}

func (r *mqlAlicloudPaiDswInstance) hasInternetForwarding() (bool, error) {
	return slices.ContainsFunc(r.cacheForwards, dswForwardIsPublic), nil
}

func (r *mqlAlicloudPaiDswInstance) ramRoles() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	account, err := conn.Identify()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, v := range r.RamRoleArns.Data {
		arn, _ := v.(string)
		name := ramRoleNameInAccount(arn, account)
		if name == "" {
			continue
		}
		role, err := resolveRamRole(r.MqlRuntime, name)
		if err != nil {
			return nil, err
		}
		if role != nil {
			res = append(res, role)
		}
	}
	return res, nil
}

// ramRoleNameInAccount returns the role name of a RAM role ARN
// (acs:ram::<account>:role/<name>) when the role belongs to account, and ""
// for a role in another account or a malformed ARN.
func ramRoleNameInAccount(arn, account string) string {
	parts := strings.SplitN(arn, ":", 5)
	if len(parts) != 5 || parts[0] != "acs" || parts[1] != "ram" || parts[3] != account {
		return ""
	}
	return ramRoleNameFromArn(arn)
}

func (r *mqlAlicloudPaiDswInstance) forwardInfos() ([]any, error) {
	res := []any{}
	for i, f := range r.cacheForwards {
		if f == nil {
			continue
		}
		var inetEndpoint, inetPort, intraEndpoint, intraPort, phase string
		if ci := f.ConnectInfo; ci != nil {
			phase = tea.StringValue(ci.Phase)
			if ci.Internet != nil {
				inetEndpoint = tea.StringValue(ci.Internet.Endpoint)
				inetPort = tea.StringValue(ci.Internet.Port)
			}
			if ci.Intranet != nil {
				intraEndpoint = tea.StringValue(ci.Intranet.Endpoint)
				intraPort = tea.StringValue(ci.Intranet.Port)
			}
		}
		key := tea.StringValue(f.Name)
		if key == "" {
			key = strconv.Itoa(i)
		}
		mqlF, err := CreateResource(r.MqlRuntime, "alicloud.pai.dswInstance.forwardInfo", map[string]*llx.RawData{
			"__id":             llx.StringData(r.RegionId.Data + "/" + r.InstanceId.Data + "/forward/" + key + "/" + tea.StringValue(f.ForwardPort)),
			"name":             llx.StringDataPtr(f.Name),
			"enabled":          llx.BoolDataPtr(f.Enable),
			"accessTypes":      llx.ArrayData(strPtrsToAny(f.AccessType), types.String),
			"forwardPort":      llx.StringDataPtr(f.ForwardPort),
			"externalPort":     llx.StringDataPtr(f.ExternalPort),
			"internetEndpoint": llx.StringData(inetEndpoint),
			"internetPort":     llx.StringData(inetPort),
			"intranetEndpoint": llx.StringData(intraEndpoint),
			"intranetPort":     llx.StringData(intraPort),
			"phase":            llx.StringData(phase),
		})
		if err != nil {
			return nil, err
		}
		fi := mqlF.(*mqlAlicloudPaiDswInstanceForwardInfo)
		fi.region = r.RegionId.Data
		fi.cacheNatGatewayId = strings.TrimSpace(tea.StringValue(f.NatGatewayId))
		fi.cacheEipAllocationId = strings.TrimSpace(tea.StringValue(f.EipAllocationId))
		res = append(res, fi)
	}
	return res, nil
}

type mqlAlicloudPaiDswInstanceForwardInfoInternal struct {
	region               string
	cacheNatGatewayId    string
	cacheEipAllocationId string
}

func (r *mqlAlicloudPaiDswInstanceForwardInfo) natGateway() (*mqlAlicloudVpcNatGateway, error) {
	if r.cacheNatGatewayId == "" {
		r.NatGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNatGateway(r.MqlRuntime, r.region, r.cacheNatGatewayId)
}

// eip resolves the forward's EIP against the account's EIP listing, so every
// forward in a scan shares one DescribeEipAddresses walk.
func (r *mqlAlicloudPaiDswInstanceForwardInfo) eip() (*mqlAlicloudVpcEipAddress, error) {
	if r.cacheEipAllocationId == "" {
		r.Eip.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if x, ok := r.MqlRuntime.Resources.Get("alicloud.vpc.eipAddress\x00" + r.region + "/" + r.cacheEipAllocationId); ok {
		return x.(*mqlAlicloudVpcEipAddress), nil
	}
	vpcRes, err := CreateResource(r.MqlRuntime, "alicloud.vpc", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	eips := vpcRes.(*mqlAlicloudVpc).GetEipAddresses()
	if eips.Error != nil {
		return nil, eips.Error
	}
	for _, e := range eips.Data {
		if eip, ok := e.(*mqlAlicloudVpcEipAddress); ok && eip.AllocationId.Data == r.cacheEipAllocationId {
			return eip, nil
		}
	}
	r.Eip.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
