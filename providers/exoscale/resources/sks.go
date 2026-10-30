// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	v3 "github.com/exoscale/egoscale/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/exoscale/connection"
	"go.mondoo.com/mql/types"
)

type mqlExoscaleSksClusterInternal struct {
	cacheDefaultSecurityGroupID string
	cacheNodepools              []v3.SKSNodepool
}

func (r *mqlExoscaleSksCluster) id() (string, error) {
	return "exoscale.sks.cluster/" + r.Id.Data, nil
}

func (r *mqlExoscale) sksClusters() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-sks-clusters", func(c *v3.Client) ([]v3.SKSCluster, error) {
		res, err := c.ListSKSClusters(ctx())
		if err != nil {
			return nil, err
		}
		return res.SKSClusters, nil
	})
	if err != nil {
		return nil, err
	}
	filters := conn(r.MqlRuntime).Filters
	out := make([]any, 0, len(items))
	for _, it := range items {
		if filters.IsFilteredOut(it.item.Labels) {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "exoscale.sks.cluster", sksClusterArgs(it.zone, it.item))
		if err != nil {
			return nil, err
		}
		m := res.(*mqlExoscaleSksCluster)
		if it.item.DefaultSecurityGroupID != nil {
			m.cacheDefaultSecurityGroupID = string(*it.item.DefaultSecurityGroupID)
		}
		m.cacheNodepools = it.item.Nodepools
		out = append(out, m)
	}
	return out, nil
}

func sksClusterArgs(zone string, c v3.SKSCluster) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":            llx.StringData("exoscale.sks.cluster/" + string(c.ID)),
		"id":              llx.StringData(string(c.ID)),
		"zone":            llx.StringData(zone),
		"name":            llx.StringData(c.Name),
		"description":     llx.StringData(c.Description),
		"version":         llx.StringData(c.Version),
		"state":           llx.StringData(string(c.State)),
		"created":         timeData(c.CreatedAT),
		"endpoint":        llx.StringData(c.Endpoint),
		"labels":          labelData(c.Labels),
		"level":           llx.StringData(string(c.Level)),
		"cni":             llx.StringData(string(c.Cni)),
		"autoUpgrade":     boolData(c.AutoUpgrade),
		"enableKubeProxy": boolData(c.EnableKubeProxy),
		"featureGates":    stringArrayData(c.FeatureGates),
		"addons":          stringArrayData(c.Addons),
		// A cluster created without an allow-list reports 0.0.0.0/0; an
		// absent list is null rather than an empty "nothing allowed".
		"allowedNetworks":    llx.NilData,
		"auditEnabled":       llx.BoolFalse,
		"auditEndpoint":      llx.StringData(""),
		"oidcIssuerUrl":      llx.StringData(""),
		"oidcClientId":       llx.StringData(""),
		"oidcUsernameClaim":  llx.StringData(""),
		"oidcUsernamePrefix": llx.StringData(""),
		"oidcGroupsClaim":    llx.StringData(""),
		"oidcGroupsPrefix":   llx.StringData(""),
		"oidcRequiredClaim":  llx.MapData(map[string]any{}, types.String),
	}
	if c.AllowedNetworks != nil {
		args["allowedNetworks"] = stringArrayData([]string(*c.AllowedNetworks))
	}
	if a := c.Audit; a != nil {
		// An audit block without the flag set reads as disabled.
		args["auditEnabled"] = llx.BoolData(a.Enabled != nil && *a.Enabled)
		args["auditEndpoint"] = llx.StringData(string(a.Endpoint))
	}
	if o := c.Oidc; o != nil {
		args["oidcIssuerUrl"] = llx.StringData(o.IssuerURL)
		args["oidcClientId"] = llx.StringData(o.ClientID)
		args["oidcUsernameClaim"] = llx.StringData(o.UsernameClaim)
		args["oidcUsernamePrefix"] = llx.StringData(o.UsernamePrefix)
		args["oidcGroupsClaim"] = llx.StringData(o.GroupsClaim)
		args["oidcGroupsPrefix"] = llx.StringData(o.GroupsPrefix)
		args["oidcRequiredClaim"] = labelData(o.RequiredClaim)
	}
	return args
}

func initExoscaleSksCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	id := stringArg(args, "id")
	if id == "" {
		id = connection.AssetOption(conn(runtime).Conf, connection.OptionSksCluster)
	}
	if id == "" {
		return nil, nil, fmt.Errorf("exoscale.sks.cluster requires an id, for example exoscale.sks.cluster(id: \"<uuid>\")")
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, nil, err
	}
	list := ns.GetSksClusters()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	if c, ok := pickOneByID(list.Data, id, func(c *mqlExoscaleSksCluster) string { return c.Id.Data }); ok {
		return args, c, nil
	}
	return nil, nil, fmt.Errorf("exoscale.sks.cluster with id %q not found", id)
}

func (r *mqlExoscaleSksCluster) defaultSecurityGroup() (*mqlExoscaleSecurityGroup, error) {
	if r.cacheDefaultSecurityGroupID == "" {
		nullResource(&r.DefaultSecurityGroup)
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "exoscale.securityGroup", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheDefaultSecurityGroupID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlExoscaleSecurityGroup), nil
}

type mqlExoscaleSksNodepoolInternal struct {
	cacheCluster              *mqlExoscaleSksCluster
	cacheInstanceType         *v3.InstanceType
	cacheTemplateID           string
	cacheInstancePoolID       string
	cacheSecurityGroupIDs     []string
	cachePrivateNetworkIDs    []string
	cacheAntiAffinityGroupIDs []string
}

func (r *mqlExoscaleSksCluster) nodepools() ([]any, error) {
	out := make([]any, 0, len(r.cacheNodepools))
	for _, np := range r.cacheNodepools {
		taints := make(map[string]any, len(np.Taints))
		for k, t := range np.Taints {
			taints[k] = t.Value + ":" + string(t.Effect)
		}
		args := map[string]*llx.RawData{
			"__id":               llx.StringData("exoscale.sks.nodepool/" + string(np.ID)),
			"id":                 llx.StringData(string(np.ID)),
			"zone":               llx.StringData(r.Zone.Data),
			"name":               llx.StringData(np.Name),
			"description":        llx.StringData(np.Description),
			"size":               llx.IntData(np.Size),
			"state":              llx.StringData(string(np.State)),
			"version":            llx.StringData(np.Version),
			"created":            timeData(np.CreatedAT),
			"labels":             labelData(np.Labels),
			"taints":             llx.MapData(taints, types.String),
			"diskSize":           llx.IntData(np.DiskSize),
			"instancePrefix":     llx.StringData(np.InstancePrefix),
			"publicIpAssignment": llx.StringData(string(np.PublicIPAssignment)),
			"kubeletMaxPods":     llx.IntDataPtr(np.KubeletMaxPods),
			"addons":             stringArrayData(np.Addons),
		}
		res, err := CreateResource(r.MqlRuntime, "exoscale.sks.nodepool", args)
		if err != nil {
			return nil, err
		}
		m := res.(*mqlExoscaleSksNodepool)
		m.cacheCluster = r
		m.cacheInstanceType = np.InstanceType
		if np.Template != nil {
			m.cacheTemplateID = string(np.Template.ID)
		}
		if np.InstancePool != nil {
			m.cacheInstancePoolID = string(np.InstancePool.ID)
		}
		m.cacheSecurityGroupIDs = uuidStrings(np.SecurityGroups, func(s v3.SecurityGroup) v3.UUID { return s.ID })
		m.cachePrivateNetworkIDs = uuidStrings(np.PrivateNetworks, func(n v3.PrivateNetwork) v3.UUID { return n.ID })
		m.cacheAntiAffinityGroupIDs = uuidStrings(np.AntiAffinityGroups, func(a v3.AntiAffinityGroup) v3.UUID { return a.ID })
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlExoscaleSksNodepool) cluster() (*mqlExoscaleSksCluster, error) {
	if r.cacheCluster == nil {
		nullResource(&r.Cluster)
		return nil, nil
	}
	return r.cacheCluster, nil
}

func (r *mqlExoscaleSksNodepool) instanceType() (*mqlExoscaleComputeInstanceType, error) {
	return resolveInstanceType(r.MqlRuntime, r.cacheInstanceType, &r.InstanceType)
}

func (r *mqlExoscaleSksNodepool) template() (*mqlExoscaleComputeTemplate, error) {
	return resolveTemplate(r.MqlRuntime, r.Zone.Data, r.cacheTemplateID, &r.Template)
}

func (r *mqlExoscaleSksNodepool) instancePool() (*mqlExoscaleComputeInstancePool, error) {
	return instancePoolByID(r.MqlRuntime, r.cacheInstancePoolID, &r.InstancePool)
}

func (r *mqlExoscaleSksNodepool) securityGroups() ([]any, error) {
	return securityGroupsByID(r.MqlRuntime, r.cacheSecurityGroupIDs)
}

func (r *mqlExoscaleSksNodepool) privateNetworks() ([]any, error) {
	return privateNetworksByID(r.MqlRuntime, r.cachePrivateNetworkIDs)
}

func (r *mqlExoscaleSksNodepool) antiAffinityGroups() ([]any, error) {
	return antiAffinityGroupsByID(r.MqlRuntime, r.cacheAntiAffinityGroupIDs)
}
