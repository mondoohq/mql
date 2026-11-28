// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/ibm/connection"
)

const (
	nsgStateActive   = "active"
	nsgStateInactive = "inactive"

	nsgRemoteDefaultAddressGroup = "default-network-address-group"
	nsgRemoteAddressGroup        = "network-address-group"
	nsgRemoteSecurityGroup       = "network-security-group"
)

// defaultAddressGroupCidr is the address range of the default network address
// group, which every workspace has and rules name without an ID.
const defaultAddressGroupCidr = "0.0.0.0/0"

// ---- workspace network security group fields ----

// powerWorkspaceDetails reads the workspace's own details once; the resource
// controller listing does not carry its network security group state.
func (r *mqlIbmPowerWorkspace) powerWorkspaceDetails() (*models.Workspace, error) {
	c := conn(r.MqlRuntime)
	v, err := c.Memo("power/workspace/"+r.Id.Data, func() (any, error) {
		sess, err := c.PowerSession(r.Zone.Data)
		if err != nil {
			return nil, err
		}
		return instance.NewIBMPIWorkspacesClient(connection.Context(), sess, r.Id.Data).Get(r.Id.Data)
	})
	if err != nil {
		return nil, classifyError(err, "power-iaas.cloud-instance.read")
	}
	return v.(*models.Workspace), nil
}

// nsgState is the state of network security groups on a workspace; a
// workspace that reports none has never had them enabled.
func nsgState(w *models.Workspace) string {
	if w == nil || w.Details == nil || w.Details.NetworkSecurityGroups == nil {
		return nsgStateInactive
	}
	s := strings.ToLower(derefStr(w.Details.NetworkSecurityGroups.State))
	if s == "" {
		return nsgStateInactive
	}
	return s
}

func (r *mqlIbmPowerWorkspace) networkSecurityGroupsState() (string, error) {
	w, err := r.powerWorkspaceDetails()
	if err != nil {
		return "", err
	}
	return nsgState(w), nil
}

func (r *mqlIbmPowerWorkspace) networkSecurityGroupsEnabled() (bool, error) {
	s, err := r.networkSecurityGroupsState()
	if err != nil {
		return false, err
	}
	return s == nsgStateActive, nil
}

func (r *mqlIbmPowerWorkspace) networkSecurityGroups() ([]any, error) {
	enabled, err := r.networkSecurityGroupsEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return []any{}, nil
	}
	c := conn(r.MqlRuntime)
	sess, err := c.PowerSession(r.Zone.Data)
	if err != nil {
		return nil, err
	}
	res, err := instance.NewIBMIPINetworkSecurityGroupClient(connection.Context(), sess, r.Id.Data).GetAll()
	if err != nil {
		return nil, classifyError(err, "power-iaas.network-security-group.read")
	}
	out := make([]any, 0, len(res.NetworkSecurityGroups))
	for _, g := range res.NetworkSecurityGroups {
		if g == nil {
			continue
		}
		m, err := CreateResource(r.MqlRuntime, "ibm.power.networkSecurityGroup", map[string]*llx.RawData{
			"__id":    llx.StringData("ibm.power.networkSecurityGroup/" + r.Id.Data + "/" + derefStr(g.ID)),
			"id":      strData(g.ID),
			"crn":     strData(g.Crn),
			"name":    strData(g.Name),
			"default": llx.BoolData(g.Default),
			"tags":    stringsData(g.UserTags),
		})
		if err != nil {
			return nil, err
		}
		nsg := m.(*mqlIbmPowerNetworkSecurityGroup)
		nsg.cacheWorkspace = r
		nsg.cacheGroup = g
		out = append(out, nsg)
	}
	return out, nil
}

func (r *mqlIbmPowerWorkspace) defaultNetworkSecurityGroup() (*mqlIbmPowerNetworkSecurityGroup, error) {
	list := r.GetNetworkSecurityGroups()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, e := range list.Data {
		if g := e.(*mqlIbmPowerNetworkSecurityGroup); g.Default.Data {
			return g, nil
		}
	}
	nullResource(&r.DefaultNetworkSecurityGroup)
	return nil, nil
}

func (r *mqlIbmPowerWorkspace) networkAddressGroups() ([]any, error) {
	enabled, err := r.networkSecurityGroupsEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return []any{}, nil
	}
	c := conn(r.MqlRuntime)
	sess, err := c.PowerSession(r.Zone.Data)
	if err != nil {
		return nil, err
	}
	res, err := instance.NewIBMPINetworkAddressGroupClient(connection.Context(), sess, r.Id.Data).GetAll()
	if err != nil {
		return nil, classifyError(err, "power-iaas.network-address-group.read")
	}
	out := make([]any, 0, len(res.NetworkAddressGroups))
	for _, g := range res.NetworkAddressGroups {
		if g == nil {
			continue
		}
		cidrs := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			if m != nil && derefStr(m.Cidr) != "" {
				cidrs = append(cidrs, *m.Cidr)
			}
		}
		m, err := CreateResource(r.MqlRuntime, "ibm.power.networkAddressGroup", map[string]*llx.RawData{
			"__id":  llx.StringData("ibm.power.networkAddressGroup/" + r.Id.Data + "/" + derefStr(g.ID)),
			"id":    strData(g.ID),
			"crn":   strData(g.Crn),
			"name":  strData(g.Name),
			"cidrs": stringsData(cidrs),
			"tags":  stringsData(g.UserTags),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// ---- network security groups ----

type mqlIbmPowerNetworkSecurityGroupInternal struct {
	cacheWorkspace *mqlIbmPowerWorkspace
	cacheGroup     *models.NetworkSecurityGroup
}

func (r *mqlIbmPowerNetworkSecurityGroup) rules() ([]any, error) {
	if r.cacheGroup == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(r.cacheGroup.Rules))
	for _, rule := range r.cacheGroup.Rules {
		if rule == nil {
			continue
		}
		args := nsgRuleArgs(rule)
		args["__id"] = llx.StringData("ibm.power.networkSecurityGroup.rule/" + r.Id.Data + "/" + derefStr(rule.ID))
		m, err := CreateResource(r.MqlRuntime, "ibm.power.networkSecurityGroup.rule", args)
		if err != nil {
			return nil, err
		}
		m.(*mqlIbmPowerNetworkSecurityGroupRule).cacheWorkspace = r.cacheWorkspace
		out = append(out, m)
	}
	return out, nil
}

// nsgRuleArgs maps a rule. A rule without a port range covers every port,
// which reads as 1 to 65535; ICMP has no ports.
func nsgRuleArgs(rule *models.NetworkSecurityGroupRule) map[string]*llx.RawData {
	protocol, icmpType := "", ""
	tcpFlags := []string{}
	if rule.Protocol != nil {
		protocol = rule.Protocol.Type
		icmpType = derefStr(rule.Protocol.IcmpType)
		for _, f := range rule.Protocol.TCPFlags {
			if f != nil && f.Flag != "" {
				tcpFlags = append(tcpFlags, f.Flag)
			}
		}
	}
	remoteType, remoteID := "", ""
	if rule.Remote != nil {
		remoteType, remoteID = rule.Remote.Type, rule.Remote.ID
	}
	dMin, dMax := nsgPortRange(protocol, rule.DestinationPort)
	sMin, sMax := nsgPortRange(protocol, rule.SourcePort)
	return map[string]*llx.RawData{
		"id":                 strData(rule.ID),
		"action":             strData(rule.Action),
		"protocol":           llx.StringData(protocol),
		"icmpType":           llx.StringData(icmpType),
		"tcpFlags":           stringsData(tcpFlags),
		"destinationPortMin": dMin,
		"destinationPortMax": dMax,
		"sourcePortMin":      sMin,
		"sourcePortMax":      sMax,
		"remoteType":         llx.StringData(remoteType),
		"remoteId":           llx.StringData(remoteID),
	}
}

// nsgPortRange is a rule's port range with its effective default: every port
// when the rule names none, and no ports for ICMP.
func nsgPortRange(protocol string, p *models.NetworkSecurityGroupRulePort) (*llx.RawData, *llx.RawData) {
	if protocol == "icmp" {
		return llx.NilData, llx.NilData
	}
	lo, hi := int64(1), int64(65535)
	if p != nil {
		if p.Minimum > 0 {
			lo = p.Minimum
		}
		if p.Maximum > 0 {
			hi = p.Maximum
		}
	}
	return llx.IntData(lo), llx.IntData(hi)
}

func (r *mqlIbmPowerNetworkSecurityGroup) openIngressRules() ([]any, error) {
	rules := r.GetRules()
	if rules.Error != nil {
		return nil, rules.Error
	}
	out := []any{}
	for _, e := range rules.Data {
		rule := e.(*mqlIbmPowerNetworkSecurityGroupRule)
		if rule.Action.Data != "allow" {
			continue
		}
		cidrs := rule.GetRemoteCidrs()
		if cidrs.Error != nil {
			return nil, cidrs.Error
		}
		for _, c := range cidrs.Data {
			if s, ok := c.(string); ok && isAnyAddress(s) {
				out = append(out, rule)
				break
			}
		}
	}
	return out, nil
}

// isAnyAddress reports a CIDR block that covers every address.
func isAnyAddress(cidr string) bool {
	c := strings.TrimSpace(cidr)
	return c == "0.0.0.0/0" || c == "::/0"
}

func (r *mqlIbmPowerNetworkSecurityGroup) members() ([]any, error) {
	if r.cacheGroup == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(r.cacheGroup.Members))
	for _, mem := range r.cacheGroup.Members {
		if mem == nil {
			continue
		}
		m, err := CreateResource(r.MqlRuntime, "ibm.power.networkSecurityGroup.member", map[string]*llx.RawData{
			"__id":       llx.StringData("ibm.power.networkSecurityGroup.member/" + r.Id.Data + "/" + derefStr(mem.ID)),
			"id":         strData(mem.ID),
			"type":       strData(mem.Type),
			"target":     strData(mem.Target),
			"macAddress": llx.StringData(mem.MacAddress),
			"networkId":  llx.StringData(mem.NetworkInterfaceNetworkID),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// ---- network security group rules ----

type mqlIbmPowerNetworkSecurityGroupRuleInternal struct {
	cacheWorkspace *mqlIbmPowerWorkspace
}

func (r *mqlIbmPowerNetworkSecurityGroupRule) remoteCidrs() ([]any, error) {
	switch r.RemoteType.Data {
	case nsgRemoteDefaultAddressGroup:
		return []any{defaultAddressGroupCidr}, nil
	case nsgRemoteAddressGroup:
		g, err := r.remoteNetworkAddressGroup()
		if err != nil || g == nil {
			return []any{}, err
		}
		return g.Cidrs.Data, nil
	}
	return []any{}, nil
}

func (r *mqlIbmPowerNetworkSecurityGroupRule) remoteNetworkAddressGroup() (*mqlIbmPowerNetworkAddressGroup, error) {
	if r.RemoteType.Data != nsgRemoteAddressGroup || r.cacheWorkspace == nil {
		nullResource(&r.RemoteNetworkAddressGroup)
		return nil, nil
	}
	return resolveOne(&r.RemoteNetworkAddressGroup, r.cacheWorkspace.GetNetworkAddressGroups(), r.RemoteId.Data,
		func(g *mqlIbmPowerNetworkAddressGroup) string { return g.Id.Data })
}

func (r *mqlIbmPowerNetworkSecurityGroupRule) remoteNetworkSecurityGroup() (*mqlIbmPowerNetworkSecurityGroup, error) {
	if r.RemoteType.Data != nsgRemoteSecurityGroup || r.cacheWorkspace == nil {
		nullResource(&r.RemoteNetworkSecurityGroup)
		return nil, nil
	}
	return resolveOne(&r.RemoteNetworkSecurityGroup, r.cacheWorkspace.GetNetworkSecurityGroups(), r.RemoteId.Data,
		func(g *mqlIbmPowerNetworkSecurityGroup) string { return g.Id.Data })
}
