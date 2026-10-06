// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"

	v3 "github.com/exoscale/egoscale/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/exoscale/connection"
)

// ---- security groups ----

type mqlExoscaleSecurityGroupInternal struct {
	cacheRules []v3.SecurityGroupRule
}

func (r *mqlExoscaleSecurityGroup) id() (string, error) {
	return "exoscale.securityGroup/" + r.Id.Data, nil
}

// securityGroups lists the organization's own security groups. Security
// groups are organization-wide, so any endpoint answers for all zones.
func (r *mqlExoscale) securityGroups() ([]any, error) {
	res, err := conn(r.MqlRuntime).Client().ListSecurityGroups(ctx(),
		v3.ListSecurityGroupsWithVisibility(v3.ListSecurityGroupsVisibilityPrivate))
	if err != nil {
		return nil, classifyError(err, "list-security-groups")
	}
	// Security groups carry no labels, so a label include filter drops them.
	// A group referenced by an instance still resolves: the init fetches a
	// group the list does not hold.
	filters := conn(r.MqlRuntime).Filters
	out := make([]any, 0, len(res.SecurityGroups))
	for _, sg := range res.SecurityGroups {
		if filters.IsFilteredOut(nil) {
			continue
		}
		m, err := newMqlExoscaleSecurityGroup(r.MqlRuntime, sg)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func newMqlExoscaleSecurityGroup(runtime *plugin.Runtime, sg v3.SecurityGroup) (*mqlExoscaleSecurityGroup, error) {
	res, err := CreateResource(runtime, "exoscale.securityGroup", map[string]*llx.RawData{
		"__id":            llx.StringData("exoscale.securityGroup/" + string(sg.ID)),
		"id":              llx.StringData(string(sg.ID)),
		"name":            llx.StringData(sg.Name),
		"description":     llx.StringData(sg.Description),
		"externalSources": stringArrayData(sg.ExternalSources),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlExoscaleSecurityGroup)
	m.cacheRules = sg.Rules
	return m, nil
}

// initExoscaleSecurityGroup resolves a security group by id: from the listed
// private groups, or, for a public group referenced by a rule, by fetching it
// once per connection.
func initExoscaleSecurityGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	id := stringArg(args, "id")
	if id == "" {
		id = connection.AssetOption(conn(runtime).Conf, connection.OptionSecurityGroup)
	}
	if id == "" {
		return nil, nil, fmt.Errorf("exoscale.securityGroup requires an id, for example exoscale.securityGroup(id: \"<uuid>\")")
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, nil, err
	}
	list := ns.GetSecurityGroups()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	if sg, ok := pickOneByID(list.Data, id, func(s *mqlExoscaleSecurityGroup) string { return s.Id.Data }); ok {
		return args, sg, nil
	}
	v, err := conn(runtime).Memo("security-group/"+id, func() (any, error) {
		return conn(runtime).Client().GetSecurityGroup(ctx(), v3.UUID(id))
	})
	if err != nil {
		return nil, nil, classifyError(err, "get-security-group")
	}
	sg := v.(*v3.SecurityGroup)
	if sg == nil {
		return nil, nil, fmt.Errorf("exoscale.securityGroup with id %q not found", id)
	}
	m, err := newMqlExoscaleSecurityGroup(runtime, *sg)
	return args, m, err
}

func (r *mqlExoscaleSecurityGroup) rules() ([]any, error) {
	out := make([]any, 0, len(r.cacheRules))
	for i, rule := range r.cacheRules {
		// A rule id is unique, but fall back to the group and position should
		// the API ever omit it, so two rules never share a cache entry.
		key := string(rule.ID)
		if key == "" {
			key = r.Id.Data + "/" + strconv.Itoa(i)
		}
		args := map[string]*llx.RawData{
			"__id":        llx.StringData("exoscale.securityGroup.rule/" + key),
			"id":          llx.StringData(string(rule.ID)),
			"description": llx.StringData(rule.Description),
			"direction":   llx.StringData(string(rule.FlowDirection)),
			"protocol":    llx.StringData(string(rule.Protocol)),
			"startPort":   llx.IntData(rule.StartPort),
			"endPort":     llx.IntData(rule.EndPort),
			"network":     llx.StringData(rule.Network),
			"icmpType":    llx.NilData,
			"icmpCode":    llx.NilData,
		}
		if rule.ICMP != nil {
			args["icmpType"] = llx.IntData(rule.ICMP.Type)
			args["icmpCode"] = llx.IntData(rule.ICMP.Code)
		}
		res, err := CreateResource(r.MqlRuntime, "exoscale.securityGroup.rule", args)
		if err != nil {
			return nil, err
		}
		m := res.(*mqlExoscaleSecurityGroupRule)
		if rule.SecurityGroup != nil {
			m.cachePeerSecurityGroupID = string(rule.SecurityGroup.ID)
		}
		out = append(out, m)
	}
	return out, nil
}

type mqlExoscaleSecurityGroupRuleInternal struct {
	cachePeerSecurityGroupID string
}

func (r *mqlExoscaleSecurityGroupRule) securityGroup() (*mqlExoscaleSecurityGroup, error) {
	if r.cachePeerSecurityGroupID == "" {
		nullResource(&r.SecurityGroup)
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "exoscale.securityGroup", map[string]*llx.RawData{
		"id": llx.StringData(r.cachePeerSecurityGroupID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlExoscaleSecurityGroup), nil
}

func securityGroupsByID(runtime *plugin.Runtime, ids []string) ([]any, error) {
	if len(ids) == 0 {
		return []any{}, nil
	}
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		// The init consults the listed groups first and only fetches a group
		// the list does not hold (a public one).
		res, err := NewResource(runtime, "exoscale.securityGroup", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- anti-affinity groups ----

type mqlExoscaleAntiAffinityGroupInternal struct {
	cacheInstanceIDs []string
}

func (r *mqlExoscale) antiAffinityGroups() ([]any, error) {
	res, err := conn(r.MqlRuntime).Client().ListAntiAffinityGroups(ctx())
	if err != nil {
		return nil, classifyError(err, "list-anti-affinity-groups")
	}
	out := make([]any, 0, len(res.AntiAffinityGroups))
	for _, g := range res.AntiAffinityGroups {
		m, err := CreateResource(r.MqlRuntime, "exoscale.antiAffinityGroup", map[string]*llx.RawData{
			"__id":        llx.StringData("exoscale.antiAffinityGroup/" + string(g.ID)),
			"id":          llx.StringData(string(g.ID)),
			"name":        llx.StringData(g.Name),
			"description": llx.StringData(g.Description),
		})
		if err != nil {
			return nil, err
		}
		m.(*mqlExoscaleAntiAffinityGroup).cacheInstanceIDs = uuidStrings(g.Instances, func(i v3.Instance) v3.UUID { return i.ID })
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlExoscaleAntiAffinityGroup) instances() ([]any, error) {
	return instancesByID(r.MqlRuntime, r.cacheInstanceIDs)
}

func antiAffinityGroupsByID(runtime *plugin.Runtime, ids []string) ([]any, error) {
	if len(ids) == 0 {
		return []any{}, nil
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetAntiAffinityGroups()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, ids, func(g *mqlExoscaleAntiAffinityGroup) string { return g.Id.Data }), nil
}

// ---- SSH keys ----

func (r *mqlExoscale) sshKeys() ([]any, error) {
	res, err := conn(r.MqlRuntime).Client().ListSSHKeys(ctx())
	if err != nil {
		return nil, classifyError(err, "list-ssh-keys")
	}
	out := make([]any, 0, len(res.SSHKeys))
	for _, k := range res.SSHKeys {
		m, err := CreateResource(r.MqlRuntime, "exoscale.sshKey", map[string]*llx.RawData{
			"__id":        llx.StringData("exoscale.sshKey/" + k.Name),
			"name":        llx.StringData(k.Name),
			"fingerprint": llx.StringData(k.Fingerprint),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func sshKeysByName(runtime *plugin.Runtime, names []string) ([]any, error) {
	if len(names) == 0 {
		return []any{}, nil
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetSshKeys()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, names, func(k *mqlExoscaleSshKey) string { return k.Name.Data }), nil
}

// ---- private networks ----

type mqlExoscalePrivateNetworkInternal struct {
	cacheInstanceIDs []string
}

func (r *mqlExoscale) privateNetworks() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-private-networks", func(c *v3.Client) ([]v3.PrivateNetwork, error) {
		res, err := c.ListPrivateNetworks(ctx())
		if err != nil {
			return nil, err
		}
		return res.PrivateNetworks, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		n := it.item
		var opts v3.PrivateNetworkOptions
		if n.Options != nil {
			opts = *n.Options
		}
		res, err := CreateResource(r.MqlRuntime, "exoscale.privateNetwork", map[string]*llx.RawData{
			"__id":         llx.StringData("exoscale.privateNetwork/" + string(n.ID)),
			"id":           llx.StringData(string(n.ID)),
			"zone":         llx.StringData(it.zone),
			"name":         llx.StringData(n.Name),
			"description":  llx.StringData(n.Description),
			"startIp":      llx.StringData(ipString(n.StartIP)),
			"endIp":        llx.StringData(ipString(n.EndIP)),
			"netmask":      llx.StringData(ipString(n.Netmask)),
			"vni":          llx.IntData(n.Vni),
			"labels":       labelData(n.Labels),
			"dnsServers":   ipArrayData(opts.DNSServers),
			"ntpServers":   ipArrayData(opts.NtpServers),
			"routers":      ipArrayData(opts.Routers),
			"domainSearch": stringArrayData(opts.DomainSearch),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlExoscalePrivateNetwork)
		m.cacheInstanceIDs = uuidStrings(n.Leases, func(l v3.PrivateNetworkLease) v3.UUID { return l.InstanceID })
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlExoscalePrivateNetwork) instances() ([]any, error) {
	return instancesByID(r.MqlRuntime, r.cacheInstanceIDs)
}

func privateNetworksByID(runtime *plugin.Runtime, ids []string) ([]any, error) {
	if len(ids) == 0 {
		return []any{}, nil
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetPrivateNetworks()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, ids, func(n *mqlExoscalePrivateNetwork) string { return n.Id.Data }), nil
}

// ---- elastic IPs ----

func (r *mqlExoscale) elasticIps() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-elastic-ips", func(c *v3.Client) ([]v3.ElasticIP, error) {
		res, err := c.ListElasticIPS(ctx())
		if err != nil {
			return nil, err
		}
		return res.ElasticIPS, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		e := it.item
		args := map[string]*llx.RawData{
			"__id":                     llx.StringData("exoscale.elasticIp/" + string(e.ID)),
			"id":                       llx.StringData(string(e.ID)),
			"zone":                     llx.StringData(it.zone),
			"ip":                       llx.StringData(e.IP),
			"cidr":                     llx.StringData(e.Cidr),
			"addressFamily":            llx.StringData(string(e.Addressfamily)),
			"description":              llx.StringData(e.Description),
			"labels":                   labelData(e.Labels),
			"healthcheckMode":          llx.StringData(""),
			"healthcheckPort":          llx.NilData,
			"healthcheckUri":           llx.StringData(""),
			"healthcheckInterval":      llx.NilData,
			"healthcheckTimeout":       llx.NilData,
			"healthcheckStrikesOk":     llx.NilData,
			"healthcheckStrikesFail":   llx.NilData,
			"healthcheckTlsSni":        llx.StringData(""),
			"healthcheckTlsSkipVerify": llx.NilData,
		}
		if h := e.Healthcheck; h != nil {
			args["healthcheckMode"] = llx.StringData(string(h.Mode))
			args["healthcheckPort"] = llx.IntData(h.Port)
			args["healthcheckUri"] = llx.StringData(h.URI)
			args["healthcheckInterval"] = llx.IntData(h.Interval)
			args["healthcheckTimeout"] = llx.IntData(h.Timeout)
			args["healthcheckStrikesOk"] = llx.IntData(h.StrikesOk)
			args["healthcheckStrikesFail"] = llx.IntData(h.StrikesFail)
			args["healthcheckTlsSni"] = llx.StringData(h.TlsSNI)
			args["healthcheckTlsSkipVerify"] = boolData(h.TlsSkipVerify)
		}
		res, err := CreateResource(r.MqlRuntime, "exoscale.elasticIp", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func elasticIpsByID(runtime *plugin.Runtime, ids []string) ([]any, error) {
	if len(ids) == 0 {
		return []any{}, nil
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetElasticIps()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, ids, func(e *mqlExoscaleElasticIp) string { return e.Id.Data }), nil
}
