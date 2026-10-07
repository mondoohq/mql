// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/IBM/vpc-go-sdk/vpcv1"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ibm/connection"
	"go.mondoo.com/mql/types"
)

// ---- regions ----

func (r *mqlIbm) vpcRegions() ([]any, error) {
	regions, err := conn(r.MqlRuntime).VpcRegions()
	if err != nil {
		return nil, classifyError(err, "is.region.region.read")
	}
	out := make([]any, 0, len(regions))
	for _, reg := range regions {
		m, err := CreateResource(r.MqlRuntime, "ibm.region", map[string]*llx.RawData{
			"__id":     llx.StringData("ibm.region/" + derefStr(reg.Name)),
			"name":     strData(reg.Name),
			"endpoint": strData(reg.Endpoint),
			"status":   strData(reg.Status),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// ---- VPCs ----

type mqlIbmVpcInternal struct {
	cacheResourceGroupID        string
	cacheDefaultSecurityGroupID string
	cacheDefaultNetworkAclID    string
}

func (r *mqlIbm) vpcs() ([]any, error) {
	items, err := listAllRegions(r.MqlRuntime, "is.vpc.vpc.list", func(c *vpcv1.VpcV1) ([]vpcv1.VPC, error) {
		pager, err := c.NewVpcsPager(&vpcv1.ListVpcsOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		v := it.item
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc", map[string]*llx.RawData{
			"__id":          llx.StringData("ibm.vpc/" + derefStr(v.CRN)),
			"id":            strData(v.ID),
			"crn":           strData(v.CRN),
			"name":          strData(v.Name),
			"region":        llx.StringData(it.region),
			"status":        strData(v.Status),
			"classicAccess": llx.BoolDataPtr(v.ClassicAccess),
			"createdAt":     dateTimeData(v.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmVpc)
		m.cacheResourceGroupID = resourceGroupID(v.ResourceGroup)
		if v.DefaultSecurityGroup != nil {
			m.cacheDefaultSecurityGroupID = derefStr(v.DefaultSecurityGroup.ID)
		}
		if v.DefaultNetworkACL != nil {
			m.cacheDefaultNetworkAclID = derefStr(v.DefaultNetworkACL.ID)
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmVpc) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

func (r *mqlIbmVpc) defaultSecurityGroup() (*mqlIbmVpcSecurityGroup, error) {
	return securityGroupByID(r.MqlRuntime, r.cacheDefaultSecurityGroupID, &r.DefaultSecurityGroup)
}

func (r *mqlIbmVpc) defaultNetworkAcl() (*mqlIbmVpcNetworkAcl, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return resolveOne(&r.DefaultNetworkAcl, ns.GetVpcNetworkAcls(), r.cacheDefaultNetworkAclID, func(a *mqlIbmVpcNetworkAcl) string { return a.Id.Data })
}

func (r *mqlIbmVpc) subnets() ([]any, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetVpcSubnets()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, e := range list.Data {
		if s := e.(*mqlIbmVpcSubnet); s.cacheVpcID == r.Id.Data {
			out = append(out, s)
		}
	}
	return out, nil
}

func vpcByID(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlIbmVpc]) (*mqlIbmVpc, error) {
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	return resolveOne(field, ns.GetVpcs(), id, func(v *mqlIbmVpc) string { return v.Id.Data })
}

// ---- subnets ----

type mqlIbmVpcSubnetInternal struct {
	cacheVpcID           string
	cacheNetworkAclID    string
	cachePublicGatewayID string
	cacheResourceGroupID string
}

func (r *mqlIbm) vpcSubnets() ([]any, error) {
	items, err := listAllRegions(r.MqlRuntime, "is.subnet.subnet.list", func(c *vpcv1.VpcV1) ([]vpcv1.Subnet, error) {
		pager, err := c.NewSubnetsPager(&vpcv1.ListSubnetsOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		s := it.item
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.subnet", map[string]*llx.RawData{
			"__id":                      llx.StringData("ibm.vpc.subnet/" + derefStr(s.CRN)),
			"id":                        strData(s.ID),
			"crn":                       strData(s.CRN),
			"name":                      strData(s.Name),
			"region":                    llx.StringData(it.region),
			"zone":                      llx.StringData(zoneName(s.Zone)),
			"ipv4CidrBlock":             strData(s.Ipv4CIDRBlock),
			"ipVersion":                 strData(s.IPVersion),
			"status":                    strData(s.Status),
			"availableIpv4AddressCount": intPtrData(s.AvailableIpv4AddressCount),
			"totalIpv4AddressCount":     intPtrData(s.TotalIpv4AddressCount),
			"createdAt":                 dateTimeData(s.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmVpcSubnet)
		m.cacheVpcID = vpcID(s.VPC)
		m.cacheResourceGroupID = resourceGroupID(s.ResourceGroup)
		if s.NetworkACL != nil {
			m.cacheNetworkAclID = derefStr(s.NetworkACL.ID)
		}
		if s.PublicGateway != nil {
			m.cachePublicGatewayID = derefStr(s.PublicGateway.ID)
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmVpcSubnet) vpc() (*mqlIbmVpc, error) {
	return vpcByID(r.MqlRuntime, r.cacheVpcID, &r.Vpc)
}

func (r *mqlIbmVpcSubnet) networkAcl() (*mqlIbmVpcNetworkAcl, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return resolveOne(&r.NetworkAcl, ns.GetVpcNetworkAcls(), r.cacheNetworkAclID, func(a *mqlIbmVpcNetworkAcl) string { return a.Id.Data })
}

func (r *mqlIbmVpcSubnet) publicGateway() (*mqlIbmVpcPublicGateway, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return resolveOne(&r.PublicGateway, ns.GetVpcPublicGateways(), r.cachePublicGatewayID, func(g *mqlIbmVpcPublicGateway) string { return g.Id.Data })
}

func (r *mqlIbmVpcSubnet) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

func subnetsByID(runtime *plugin.Runtime, ids []string) ([]any, error) {
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetVpcSubnets()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, ids, func(s *mqlIbmVpcSubnet) string { return s.Id.Data }), nil
}

// ---- instances ----

type mqlIbmVpcInstanceInternal struct {
	cacheVpcID           string
	cacheResourceGroupID string
	cacheVolumeIDs       []string
	cacheInterfaceIDs    []string
}

func (r *mqlIbmVpcInstance) id() (string, error) {
	return "ibm.vpc.instance/" + r.Crn.Data, nil
}

// vpcInstances is every instance, narrowed by --filters.
func (r *mqlIbm) vpcInstances() ([]any, error) {
	all, err := allVpcInstances(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return filterByTags(r.MqlRuntime, all, func(i *mqlIbmVpcInstance) string { return i.Crn.Data })
}

// allVpcInstances lists every instance once per connection, ignoring
// --filters: references from volumes and discovered assets resolve through it,
// and a filter must not hide what they point at.
func allVpcInstances(runtime *plugin.Runtime) ([]any, error) {
	v, err := conn(runtime).Memo("all/vpcInstances", func() (any, error) { return listVpcInstances(runtime) })
	if err != nil {
		return nil, err
	}
	return v.([]any), nil
}

func listVpcInstances(runtime *plugin.Runtime) ([]any, error) {
	items, err := listAllRegions(runtime, "is.instance.instance.list", func(c *vpcv1.VpcV1) ([]vpcv1.Instance, error) {
		pager, err := c.NewInstancesPager(&vpcv1.ListInstancesOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		res, err := CreateResource(runtime, "ibm.vpc.instance", instanceArgs(it.region, it.item))
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmVpcInstance)
		m.cacheVpcID = vpcID(it.item.VPC)
		m.cacheResourceGroupID = resourceGroupID(it.item.ResourceGroup)
		m.cacheInterfaceIDs = instanceInterfaceIDs(it.item)
		for _, a := range it.item.VolumeAttachments {
			if a.Volume != nil && a.Volume.ID != nil {
				m.cacheVolumeIDs = append(m.cacheVolumeIDs, *a.Volume.ID)
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func instanceArgs(region string, i vpcv1.Instance) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":                            llx.StringData("ibm.vpc.instance/" + derefStr(i.CRN)),
		"id":                              strData(i.ID),
		"crn":                             strData(i.CRN),
		"name":                            strData(i.Name),
		"region":                          llx.StringData(region),
		"zone":                            llx.StringData(zoneName(i.Zone)),
		"status":                          strData(i.Status),
		"lifecycleState":                  strData(i.LifecycleState),
		"profile":                         llx.NilData,
		"image":                           llx.NilData,
		"vcpuCount":                       llx.NilData,
		"memory":                          intPtrData(i.Memory),
		"enableSecureBoot":                llx.BoolDataPtr(i.EnableSecureBoot),
		"confidentialComputeMode":         strData(i.ConfidentialComputeMode),
		"metadataServiceEnabled":          llx.NilData,
		"metadataServiceProtocol":         llx.NilData,
		"metadataServiceResponseHopLimit": llx.NilData,
		"createdAt":                       dateTimeData(i.CreatedAt),
	}
	if i.Profile != nil {
		args["profile"] = strData(i.Profile.Name)
	}
	if i.Image != nil {
		args["image"] = strData(i.Image.Name)
	}
	if i.Vcpu != nil {
		args["vcpuCount"] = intPtrData(i.Vcpu.Count)
	}
	if ms := i.MetadataService; ms != nil {
		args["metadataServiceEnabled"] = llx.BoolDataPtr(ms.Enabled)
		args["metadataServiceProtocol"] = strData(ms.Protocol)
		args["metadataServiceResponseHopLimit"] = intPtrData(ms.ResponseHopLimit)
	}
	return args
}

// initIbmVpcInstance resolves an instance by id, or the instance a discovered
// asset is scoped to, from the listed instances.
func initIbmVpcInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	id := stringArg(args, "id")
	crn := ""
	if id == "" {
		crn = connection.AssetOption(conn(runtime).Conf, connection.OptionVpcInstance)
	}
	if id == "" && crn == "" {
		return nil, nil, errors.New(`ibm.vpc.instance requires an id, for example ibm.vpc.instance(id: "0717_...")`)
	}
	all, err := allVpcInstances(runtime)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range all {
		i := e.(*mqlIbmVpcInstance)
		if (id != "" && i.Id.Data == id) || (crn != "" && i.Crn.Data == crn) {
			return args, i, nil
		}
	}
	return nil, nil, fmt.Errorf("ibm.vpc.instance %q not found", id+crn)
}

func (r *mqlIbmVpcInstance) vpc() (*mqlIbmVpc, error) {
	return vpcByID(r.MqlRuntime, r.cacheVpcID, &r.Vpc)
}

func (r *mqlIbmVpcInstance) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

// instanceInterfaceIDs collects the ids a floating IP or a security group
// names when it targets the instance: legacy network interfaces, and network
// attachments with their virtual network interfaces. An instance on network
// attachments also lists read-only network interfaces carrying the attachment
// ids, so the set overlaps; duplicates are harmless.
func instanceInterfaceIDs(i vpcv1.Instance) []string {
	var out []string
	add := func(id *string) {
		if id != nil && *id != "" {
			out = append(out, *id)
		}
	}
	addAttachment := func(a *vpcv1.InstanceNetworkAttachmentReference) {
		if a == nil {
			return
		}
		add(a.ID)
		if a.VirtualNetworkInterface != nil {
			add(a.VirtualNetworkInterface.ID)
		}
	}
	if i.PrimaryNetworkInterface != nil {
		add(i.PrimaryNetworkInterface.ID)
	}
	for _, n := range i.NetworkInterfaces {
		add(n.ID)
	}
	addAttachment(i.PrimaryNetworkAttachment)
	for idx := range i.NetworkAttachments {
		addAttachment(&i.NetworkAttachments[idx])
	}
	return out
}

func (r *mqlIbmVpcInstance) securityGroups() ([]any, error) {
	all, err := allVpcSecurityGroups(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, e := range all {
		if sg := e.(*mqlIbmVpcSecurityGroup); sharesID(sg.cacheTargetIDs, r.cacheInterfaceIDs) {
			out = append(out, sg)
		}
	}
	return out, nil
}

func (r *mqlIbmVpcInstance) floatingIps() ([]any, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetVpcFloatingIps()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, e := range list.Data {
		if f := e.(*mqlIbmVpcFloatingIp); f.cacheTargetID != "" && slices.Contains(r.cacheInterfaceIDs, f.cacheTargetID) {
			out = append(out, f)
		}
	}
	return out, nil
}

// exposure combines the instance's floating IPs with the inbound rules of its
// security groups that admit any address.
func (r *mqlIbmVpcInstance) exposure() (*mqlIbmNetworkExposure, error) {
	fips := r.GetFloatingIps()
	if fips.Error != nil {
		return nil, fips.Error
	}
	sgs := r.GetSecurityGroups()
	if sgs.Error != nil {
		return nil, sgs.Error
	}
	openRules := []any{}
	for _, e := range sgs.Data {
		sg := e.(*mqlIbmVpcSecurityGroup)
		rules := sg.GetRules()
		if rules.Error != nil {
			return nil, rules.Error
		}
		for _, re := range rules.Data {
			rule := re.(*mqlIbmVpcSecurityGroupRule)
			if ruleOpenToInternet(rule.Direction.Data, rule.RemoteCidr.Data) {
				openRules = append(openRules, rule)
			}
		}
	}
	hasPublicIP := len(fips.Data) > 0
	sgAllows := len(openRules) > 0
	res, err := CreateResource(r.MqlRuntime, "ibm.network.exposure", map[string]*llx.RawData{
		"__id":                       llx.StringData("ibm.vpc.instance/" + r.Crn.Data + "/exposure"),
		"internetReachable":          llx.BoolData(hasPublicIP && sgAllows),
		"hasPublicIp":                llx.BoolData(hasPublicIP),
		"securityGroupAllowsIngress": llx.BoolData(sgAllows),
		"openIngressRules":           llx.ArrayData(openRules, types.Resource("ibm.vpc.securityGroup.rule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlIbmNetworkExposure), nil
}

// ruleOpenToInternet reports whether a security group rule admits inbound
// traffic from any address.
func ruleOpenToInternet(direction, remoteCidr string) bool {
	if direction != "inbound" {
		return false
	}
	c := strings.TrimSpace(remoteCidr)
	return c == "0.0.0.0/0" || c == "::/0"
}

func sharesID(a, b []string) bool {
	for _, x := range a {
		if x != "" && slices.Contains(b, x) {
			return true
		}
	}
	return false
}

func (r *mqlIbmVpcInstance) volumes() ([]any, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetVpcVolumes()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, r.cacheVolumeIDs, func(v *mqlIbmVpcVolume) string { return v.Id.Data }), nil
}

// ---- security groups ----

type mqlIbmVpcSecurityGroupInternal struct {
	cacheVpcID           string
	cacheResourceGroupID string
	cacheRules           []securityGroupRule
	cacheTargetIDs       []string
}

// securityGroupRule is every variant of a security group rule read through
// its JSON form: the SDK models TCP/UDP, ICMP, and "all" rules, and CIDR,
// address, and security group remotes, as separate types.
type securityGroupRule struct {
	ID        string `json:"id"`
	Direction string `json:"direction"`
	IPVersion string `json:"ip_version"`
	Protocol  string `json:"protocol"`
	PortMin   *int64 `json:"port_min"`
	PortMax   *int64 `json:"port_max"`
	Type      *int64 `json:"type"`
	Code      *int64 `json:"code"`
	Remote    struct {
		CIDRBlock string `json:"cidr_block"`
		Address   string `json:"address"`
		ID        string `json:"id"`
	} `json:"remote"`
}

func decodeSecurityGroupRules(rules []vpcv1.SecurityGroupRuleIntf) ([]securityGroupRule, error) {
	out := make([]securityGroupRule, 0, len(rules))
	for _, rule := range rules {
		var r securityGroupRule
		if err := asJSON(rule, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// securityGroupTargetIDs reads the ids of the network interfaces, virtual
// network interfaces, load balancers, and endpoint gateways a group is
// attached to, whatever their variant.
func securityGroupTargetIDs(targets []vpcv1.SecurityGroupTargetReferenceIntf) ([]string, error) {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		var ref targetRef
		if err := asJSON(t, &ref); err != nil {
			return nil, err
		}
		if ref.ID != "" {
			out = append(out, ref.ID)
		}
	}
	return out, nil
}

func (r *mqlIbmVpcSecurityGroup) id() (string, error) {
	return "ibm.vpc.securityGroup/" + r.Crn.Data, nil
}

// vpcSecurityGroups is every security group, narrowed by --filters.
func (r *mqlIbm) vpcSecurityGroups() ([]any, error) {
	all, err := allVpcSecurityGroups(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return filterByTags(r.MqlRuntime, all, func(sg *mqlIbmVpcSecurityGroup) string { return sg.Crn.Data })
}

// allVpcSecurityGroups lists every security group once per connection,
// ignoring --filters: rule remotes, load balancers, instances, and their
// exposure resolve through it, and a filter must not hide an open group.
func allVpcSecurityGroups(runtime *plugin.Runtime) ([]any, error) {
	v, err := conn(runtime).Memo("all/vpcSecurityGroups", func() (any, error) { return listVpcSecurityGroups(runtime) })
	if err != nil {
		return nil, err
	}
	return v.([]any), nil
}

func listVpcSecurityGroups(runtime *plugin.Runtime) ([]any, error) {
	items, err := listAllRegions(runtime, "is.security-group.security-group.list", func(c *vpcv1.VpcV1) ([]vpcv1.SecurityGroup, error) {
		pager, err := c.NewSecurityGroupsPager(&vpcv1.ListSecurityGroupsOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		sg := it.item
		rules, err := decodeSecurityGroupRules(sg.Rules)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(runtime, "ibm.vpc.securityGroup", map[string]*llx.RawData{
			"__id":        llx.StringData("ibm.vpc.securityGroup/" + derefStr(sg.CRN)),
			"id":          strData(sg.ID),
			"crn":         strData(sg.CRN),
			"name":        strData(sg.Name),
			"region":      llx.StringData(it.region),
			"createdAt":   dateTimeData(sg.CreatedAt),
			"targetCount": llx.IntData(int64(len(sg.Targets))),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmVpcSecurityGroup)
		m.cacheVpcID = vpcID(sg.VPC)
		m.cacheResourceGroupID = resourceGroupID(sg.ResourceGroup)
		m.cacheRules = rules
		if m.cacheTargetIDs, err = securityGroupTargetIDs(sg.Targets); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func initIbmVpcSecurityGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	id := stringArg(args, "id")
	crn := ""
	if id == "" {
		crn = connection.AssetOption(conn(runtime).Conf, connection.OptionVpcSecurityGroup)
	}
	if id == "" && crn == "" {
		return nil, nil, errors.New(`ibm.vpc.securityGroup requires an id, for example ibm.vpc.securityGroup(id: "r006-...")`)
	}
	all, err := allVpcSecurityGroups(runtime)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range all {
		sg := e.(*mqlIbmVpcSecurityGroup)
		if (id != "" && sg.Id.Data == id) || (crn != "" && sg.Crn.Data == crn) {
			return args, sg, nil
		}
	}
	return nil, nil, fmt.Errorf("ibm.vpc.securityGroup %q not found", id+crn)
}

func securityGroupByID(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlIbmVpcSecurityGroup]) (*mqlIbmVpcSecurityGroup, error) {
	if id == "" {
		nullResource(field)
		return nil, nil
	}
	all, err := allVpcSecurityGroups(runtime)
	if err != nil {
		return nil, err
	}
	return resolveIn(field, all, id, func(s *mqlIbmVpcSecurityGroup) string { return s.Id.Data })
}

func (r *mqlIbmVpcSecurityGroup) vpc() (*mqlIbmVpc, error) {
	return vpcByID(r.MqlRuntime, r.cacheVpcID, &r.Vpc)
}

func (r *mqlIbmVpcSecurityGroup) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

type mqlIbmVpcSecurityGroupRuleInternal struct {
	cacheRemoteSecurityGroupID string
}

func (r *mqlIbmVpcSecurityGroup) rules() ([]any, error) {
	out := make([]any, 0, len(r.cacheRules))
	for i, rule := range r.cacheRules {
		key := rule.ID
		if key == "" {
			key = r.Crn.Data + "/" + strconv.Itoa(i)
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.securityGroup.rule", securityGroupRuleArgs(key, rule))
		if err != nil {
			return nil, err
		}
		res.(*mqlIbmVpcSecurityGroupRule).cacheRemoteSecurityGroupID = rule.Remote.ID
		out = append(out, res)
	}
	return out, nil
}

func securityGroupRuleArgs(key string, rule securityGroupRule) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":          llx.StringData("ibm.vpc.securityGroup.rule/" + key),
		"id":            llx.StringData(rule.ID),
		"direction":     llx.StringData(rule.Direction),
		"ipVersion":     llx.StringData(rule.IPVersion),
		"protocol":      llx.StringData(rule.Protocol),
		"portMin":       llx.IntDataPtr(rule.PortMin),
		"portMax":       llx.IntDataPtr(rule.PortMax),
		"icmpType":      llx.IntDataPtr(rule.Type),
		"icmpCode":      llx.IntDataPtr(rule.Code),
		"remoteCidr":    llx.StringData(rule.Remote.CIDRBlock),
		"remoteAddress": llx.StringData(rule.Remote.Address),
	}
}

func (r *mqlIbmVpcSecurityGroupRule) remoteSecurityGroup() (*mqlIbmVpcSecurityGroup, error) {
	return securityGroupByID(r.MqlRuntime, r.cacheRemoteSecurityGroupID, &r.RemoteSecurityGroup)
}

func securityGroupsByID(runtime *plugin.Runtime, ids []string) ([]any, error) {
	all, err := allVpcSecurityGroups(runtime)
	if err != nil {
		return nil, err
	}
	return pickByID(all, ids, func(s *mqlIbmVpcSecurityGroup) string { return s.Id.Data }), nil
}

// ---- network ACLs ----

type mqlIbmVpcNetworkAclInternal struct {
	cacheVpcID           string
	cacheResourceGroupID string
	cacheSubnetIDs       []string
	cacheRules           []networkACLRule
}

// networkACLRule is every variant of a network ACL rule read through its JSON
// form.
type networkACLRule struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Action             string `json:"action"`
	Direction          string `json:"direction"`
	IPVersion          string `json:"ip_version"`
	Protocol           string `json:"protocol"`
	Source             string `json:"source"`
	Destination        string `json:"destination"`
	SourcePortMin      *int64 `json:"source_port_min"`
	SourcePortMax      *int64 `json:"source_port_max"`
	DestinationPortMin *int64 `json:"destination_port_min"`
	DestinationPortMax *int64 `json:"destination_port_max"`
	Type               *int64 `json:"type"`
	Code               *int64 `json:"code"`
}

func (r *mqlIbm) vpcNetworkAcls() ([]any, error) {
	items, err := listAllRegions(r.MqlRuntime, "is.network-acl.network-acl.list", func(c *vpcv1.VpcV1) ([]vpcv1.NetworkACL, error) {
		pager, err := c.NewNetworkAclsPager(&vpcv1.ListNetworkAclsOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		acl := it.item
		rules := make([]networkACLRule, 0, len(acl.Rules))
		for _, rule := range acl.Rules {
			var nr networkACLRule
			if err := asJSON(rule, &nr); err != nil {
				return nil, err
			}
			rules = append(rules, nr)
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.networkAcl", map[string]*llx.RawData{
			"__id":      llx.StringData("ibm.vpc.networkAcl/" + derefStr(acl.CRN)),
			"id":        strData(acl.ID),
			"crn":       strData(acl.CRN),
			"name":      strData(acl.Name),
			"region":    llx.StringData(it.region),
			"createdAt": dateTimeData(acl.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmVpcNetworkAcl)
		m.cacheVpcID = vpcID(acl.VPC)
		m.cacheResourceGroupID = resourceGroupID(acl.ResourceGroup)
		m.cacheRules = rules
		for _, s := range acl.Subnets {
			m.cacheSubnetIDs = append(m.cacheSubnetIDs, derefStr(s.ID))
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmVpcNetworkAcl) vpc() (*mqlIbmVpc, error) {
	return vpcByID(r.MqlRuntime, r.cacheVpcID, &r.Vpc)
}

func (r *mqlIbmVpcNetworkAcl) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

func (r *mqlIbmVpcNetworkAcl) subnets() ([]any, error) {
	return subnetsByID(r.MqlRuntime, r.cacheSubnetIDs)
}

// rules keeps the API order: network ACL rules are evaluated top to bottom.
func (r *mqlIbmVpcNetworkAcl) rules() ([]any, error) {
	out := make([]any, 0, len(r.cacheRules))
	for i, rule := range r.cacheRules {
		key := rule.ID
		if key == "" {
			key = r.Crn.Data + "/" + strconv.Itoa(i)
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.networkAcl.rule", map[string]*llx.RawData{
			"__id":               llx.StringData("ibm.vpc.networkAcl.rule/" + key),
			"id":                 llx.StringData(rule.ID),
			"name":               llx.StringData(rule.Name),
			"action":             llx.StringData(rule.Action),
			"direction":          llx.StringData(rule.Direction),
			"ipVersion":          llx.StringData(rule.IPVersion),
			"protocol":           llx.StringData(rule.Protocol),
			"source":             llx.StringData(rule.Source),
			"destination":        llx.StringData(rule.Destination),
			"sourcePortMin":      llx.IntDataPtr(rule.SourcePortMin),
			"sourcePortMax":      llx.IntDataPtr(rule.SourcePortMax),
			"destinationPortMin": llx.IntDataPtr(rule.DestinationPortMin),
			"destinationPortMax": llx.IntDataPtr(rule.DestinationPortMax),
			"icmpType":           llx.IntDataPtr(rule.Type),
			"icmpCode":           llx.IntDataPtr(rule.Code),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- floating IPs ----

type mqlIbmVpcFloatingIpInternal struct {
	cacheResourceGroupID string
	cacheTargetID        string
}

// targetRef is a polymorphic target reference read through its JSON form.
type targetRef struct {
	ID           string `json:"id"`
	ResourceType string `json:"resource_type"`
	Name         string `json:"name"`
}

func (r *mqlIbm) vpcFloatingIps() ([]any, error) {
	items, err := listAllRegions(r.MqlRuntime, "is.floating-ip.floating-ip.list", func(c *vpcv1.VpcV1) ([]vpcv1.FloatingIP, error) {
		pager, err := c.NewFloatingIpsPager(&vpcv1.ListFloatingIpsOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		f := it.item
		var target targetRef
		if f.Target != nil {
			if err := asJSON(f.Target, &target); err != nil {
				return nil, err
			}
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.floatingIp", map[string]*llx.RawData{
			"__id":               llx.StringData("ibm.vpc.floatingIp/" + derefStr(f.CRN)),
			"id":                 strData(f.ID),
			"crn":                strData(f.CRN),
			"name":               strData(f.Name),
			"address":            strData(f.Address),
			"region":             llx.StringData(it.region),
			"zone":               llx.StringData(zoneName(f.Zone)),
			"status":             strData(f.Status),
			"targetResourceType": llx.StringData(target.ResourceType),
			"targetName":         llx.StringData(target.Name),
			"createdAt":          dateTimeData(f.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmVpcFloatingIp)
		m.cacheResourceGroupID = resourceGroupID(f.ResourceGroup)
		m.cacheTargetID = target.ID
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlIbmVpcFloatingIp) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

// ---- public gateways ----

type mqlIbmVpcPublicGatewayInternal struct {
	cacheVpcID           string
	cacheResourceGroupID string
}

func (r *mqlIbm) vpcPublicGateways() ([]any, error) {
	items, err := listAllRegions(r.MqlRuntime, "is.public-gateway.public-gateway.list", func(c *vpcv1.VpcV1) ([]vpcv1.PublicGateway, error) {
		pager, err := c.NewPublicGatewaysPager(&vpcv1.ListPublicGatewaysOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		g := it.item
		address := ""
		if g.FloatingIP != nil {
			address = derefStr(g.FloatingIP.Address)
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.publicGateway", map[string]*llx.RawData{
			"__id":      llx.StringData("ibm.vpc.publicGateway/" + derefStr(g.CRN)),
			"id":        strData(g.ID),
			"crn":       strData(g.CRN),
			"name":      strData(g.Name),
			"region":    llx.StringData(it.region),
			"zone":      llx.StringData(zoneName(g.Zone)),
			"status":    strData(g.Status),
			"address":   llx.StringData(address),
			"createdAt": dateTimeData(g.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmVpcPublicGateway)
		m.cacheVpcID = vpcID(g.VPC)
		m.cacheResourceGroupID = resourceGroupID(g.ResourceGroup)
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmVpcPublicGateway) vpc() (*mqlIbmVpc, error) {
	return vpcByID(r.MqlRuntime, r.cacheVpcID, &r.Vpc)
}

func (r *mqlIbmVpcPublicGateway) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

// ---- load balancers ----

type mqlIbmVpcLoadBalancerInternal struct {
	cacheResourceGroupID  string
	cacheSecurityGroupIDs []string
	cacheSubnetIDs        []string
}

func (r *mqlIbm) vpcLoadBalancers() ([]any, error) {
	items, err := listAllRegions(r.MqlRuntime, "is.load-balancer.load-balancer.list", func(c *vpcv1.VpcV1) ([]vpcv1.LoadBalancer, error) {
		pager, err := c.NewLoadBalancersPager(&vpcv1.ListLoadBalancersOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		lb := it.item
		publicIPs := make([]string, 0, len(lb.PublicIps))
		for _, ip := range lb.PublicIps {
			publicIPs = append(publicIPs, derefStr(ip.Address))
		}
		args := map[string]*llx.RawData{
			"__id":                  llx.StringData("ibm.vpc.loadBalancer/" + derefStr(lb.CRN)),
			"id":                    strData(lb.ID),
			"crn":                   strData(lb.CRN),
			"name":                  strData(lb.Name),
			"region":                llx.StringData(it.region),
			"hostname":              strData(lb.Hostname),
			"isPublic":              llx.BoolDataPtr(lb.IsPublic),
			"isPrivatePath":         llx.BoolDataPtr(lb.IsPrivatePath),
			"profile":               llx.NilData,
			"operatingStatus":       strData(lb.OperatingStatus),
			"provisioningStatus":    strData(lb.ProvisioningStatus),
			"datapathLoggingActive": llx.NilData,
			"publicIps":             stringsData(publicIPs),
			"createdAt":             dateTimeData(lb.CreatedAt),
		}
		if lb.Profile != nil {
			args["profile"] = strData(lb.Profile.Name)
		}
		if lb.Logging != nil && lb.Logging.Datapath != nil {
			args["datapathLoggingActive"] = llx.BoolDataPtr(lb.Logging.Datapath.Active)
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.loadBalancer", args)
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmVpcLoadBalancer)
		m.cacheResourceGroupID = resourceGroupID(lb.ResourceGroup)
		for _, sg := range lb.SecurityGroups {
			m.cacheSecurityGroupIDs = append(m.cacheSecurityGroupIDs, derefStr(sg.ID))
		}
		for _, s := range lb.Subnets {
			m.cacheSubnetIDs = append(m.cacheSubnetIDs, derefStr(s.ID))
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmVpcLoadBalancer) securityGroups() ([]any, error) {
	return securityGroupsByID(r.MqlRuntime, r.cacheSecurityGroupIDs)
}

func (r *mqlIbmVpcLoadBalancer) subnets() ([]any, error) {
	return subnetsByID(r.MqlRuntime, r.cacheSubnetIDs)
}

func (r *mqlIbmVpcLoadBalancer) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

// ---- volumes ----

type mqlIbmVpcVolumeInternal struct {
	cacheResourceGroupID  string
	cacheInstanceIDs      []string
	cacheEncryptionKeyCRN string
}

func (r *mqlIbm) vpcVolumes() ([]any, error) {
	items, err := listAllRegions(r.MqlRuntime, "is.volume.volume.list", func(c *vpcv1.VpcV1) ([]vpcv1.Volume, error) {
		pager, err := c.NewVolumesPager(&vpcv1.ListVolumesOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		v := it.item
		args := map[string]*llx.RawData{
			"__id":            llx.StringData("ibm.vpc.volume/" + derefStr(v.CRN)),
			"id":              strData(v.ID),
			"crn":             strData(v.CRN),
			"name":            strData(v.Name),
			"region":          llx.StringData(it.region),
			"zone":            llx.StringData(zoneName(v.Zone)),
			"capacity":        intPtrData(v.Capacity),
			"iops":            intPtrData(v.Iops),
			"profile":         llx.NilData,
			"encryption":      strData(v.Encryption),
			"status":          strData(v.Status),
			"attachmentState": strData(v.AttachmentState),
			"createdAt":       dateTimeData(v.CreatedAt),
		}
		if v.Profile != nil {
			args["profile"] = strData(v.Profile.Name)
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.volume", args)
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmVpcVolume)
		m.cacheResourceGroupID = resourceGroupID(v.ResourceGroup)
		if v.EncryptionKey != nil {
			m.cacheEncryptionKeyCRN = derefStr(v.EncryptionKey.CRN)
		}
		for _, a := range v.VolumeAttachments {
			if a.Instance != nil && a.Instance.ID != nil {
				m.cacheInstanceIDs = append(m.cacheInstanceIDs, *a.Instance.ID)
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmVpcVolume) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

func (r *mqlIbmVpcVolume) encryptionKey() (*mqlIbmKmsKey, error) {
	return kmsKeyByCRN(r.MqlRuntime, r.cacheEncryptionKeyCRN, &r.EncryptionKey)
}

func (r *mqlIbmVpcVolume) instances() ([]any, error) {
	all, err := allVpcInstances(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return pickByID(all, r.cacheInstanceIDs, func(i *mqlIbmVpcInstance) string { return i.Id.Data }), nil
}

// ---- SSH keys ----

type mqlIbmVpcSshKeyInternal struct {
	cacheResourceGroupID string
}

func (r *mqlIbm) vpcSshKeys() ([]any, error) {
	items, err := listAllRegions(r.MqlRuntime, "is.key.key.list", func(c *vpcv1.VpcV1) ([]vpcv1.Key, error) {
		pager, err := c.NewKeysPager(&vpcv1.ListKeysOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		k := it.item
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.sshKey", map[string]*llx.RawData{
			"__id":        llx.StringData("ibm.vpc.sshKey/" + derefStr(k.CRN)),
			"id":          strData(k.ID),
			"crn":         strData(k.CRN),
			"name":        strData(k.Name),
			"region":      llx.StringData(it.region),
			"type":        strData(k.Type),
			"length":      intPtrData(k.Length),
			"fingerprint": strData(k.Fingerprint),
			"createdAt":   dateTimeData(k.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlIbmVpcSshKey).cacheResourceGroupID = resourceGroupID(k.ResourceGroup)
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlIbmVpcSshKey) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

// ---- flow log collectors ----

type mqlIbmVpcFlowLogCollectorInternal struct {
	cacheVpcID           string
	cacheResourceGroupID string
}

func (r *mqlIbm) vpcFlowLogCollectors() ([]any, error) {
	items, err := listAllRegions(r.MqlRuntime, "is.flow-log-collector.flow-log-collector.list", func(c *vpcv1.VpcV1) ([]vpcv1.FlowLogCollector, error) {
		pager, err := c.NewFlowLogCollectorsPager(&vpcv1.ListFlowLogCollectorsOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		f := it.item
		var target targetRef
		if f.Target != nil {
			if err := asJSON(f.Target, &target); err != nil {
				return nil, err
			}
		}
		bucket := ""
		if f.StorageBucket != nil {
			bucket = derefStr(f.StorageBucket.Name)
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.flowLogCollector", map[string]*llx.RawData{
			"__id":               llx.StringData("ibm.vpc.flowLogCollector/" + derefStr(f.CRN)),
			"id":                 strData(f.ID),
			"crn":                strData(f.CRN),
			"name":               strData(f.Name),
			"region":             llx.StringData(it.region),
			"active":             llx.BoolDataPtr(f.Active),
			"autoDelete":         llx.BoolDataPtr(f.AutoDelete),
			"lifecycleState":     strData(f.LifecycleState),
			"storageBucketName":  llx.StringData(bucket),
			"targetResourceType": llx.StringData(target.ResourceType),
			"targetName":         llx.StringData(target.Name),
			"createdAt":          dateTimeData(f.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmVpcFlowLogCollector)
		m.cacheVpcID = vpcID(f.VPC)
		m.cacheResourceGroupID = resourceGroupID(f.ResourceGroup)
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmVpcFlowLogCollector) vpc() (*mqlIbmVpc, error) {
	return vpcByID(r.MqlRuntime, r.cacheVpcID, &r.Vpc)
}

func (r *mqlIbmVpcFlowLogCollector) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}
