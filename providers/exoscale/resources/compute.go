// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"slices"

	v3 "github.com/exoscale/egoscale/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- instance types ----

func (r *mqlExoscale) instanceTypes() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-instance-types", func(c *v3.Client) ([]v3.InstanceType, error) {
		res, err := c.ListInstanceTypes(ctx())
		if err != nil {
			return nil, err
		}
		return res.InstanceTypes, nil
	})
	if err != nil {
		return nil, err
	}
	// Every zone lists the types it offers; the same type id appears in each.
	// Keep one entry per id and union the zones it was listed in.
	merged := mergeInstanceTypes(items)
	out := make([]any, 0, len(merged))
	for _, t := range merged {
		res, err := newMqlExoscaleComputeInstanceType(r.MqlRuntime, t)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func mergeInstanceTypes(items []zoned[v3.InstanceType]) []v3.InstanceType {
	var order []v3.UUID
	byID := map[v3.UUID]*v3.InstanceType{}
	for _, it := range items {
		t, ok := byID[it.item.ID]
		if !ok {
			cp := it.item
			cp.Zones = slices.Clone(cp.Zones)
			byID[cp.ID] = &cp
			order = append(order, cp.ID)
			t = &cp
		}
		if z := v3.ZoneName(it.zone); !slices.Contains(t.Zones, z) {
			t.Zones = append(t.Zones, z)
		}
	}
	out := make([]v3.InstanceType, 0, len(order))
	for _, id := range order {
		t := byID[id]
		slices.Sort(t.Zones)
		out = append(out, *t)
	}
	return out
}

func instanceTypeName(t *v3.InstanceType) string {
	if t.Family == "" && t.Size == "" {
		return ""
	}
	return string(t.Family) + "." + string(t.Size)
}

func newMqlExoscaleComputeInstanceType(runtime *plugin.Runtime, t v3.InstanceType) (*mqlExoscaleComputeInstanceType, error) {
	res, err := CreateResource(runtime, "exoscale.compute.instanceType", map[string]*llx.RawData{
		"__id":       llx.StringData("exoscale.compute.instanceType/" + string(t.ID)),
		"id":         llx.StringData(string(t.ID)),
		"name":       llx.StringData(instanceTypeName(&t)),
		"family":     llx.StringData(string(t.Family)),
		"size":       llx.StringData(string(t.Size)),
		"cpus":       llx.IntData(t.Cpus),
		"gpus":       llx.IntData(t.Gpus),
		"memory":     llx.IntData(t.Memory),
		"authorized": boolData(t.Authorized),
		"zones":      stringArrayData(t.Zones),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlExoscaleComputeInstanceType), nil
}

// resolveInstanceType finds an embedded instance type reference in the listed
// types. The embedded record usually carries only the id.
func resolveInstanceType(runtime *plugin.Runtime, ref *v3.InstanceType, field *plugin.TValue[*mqlExoscaleComputeInstanceType]) (*mqlExoscaleComputeInstanceType, error) {
	if ref == nil || ref.ID == "" {
		nullResource(field)
		return nil, nil
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetInstanceTypes()
	if list.Error != nil {
		return nil, list.Error
	}
	if t, ok := pickOneByID(list.Data, string(ref.ID), func(t *mqlExoscaleComputeInstanceType) string { return t.Id.Data }); ok {
		return t, nil
	}
	nullResource(field)
	return nil, nil
}

// ---- templates ----

func (r *mqlExoscaleComputeTemplate) id() (string, error) {
	return templateMqlID(r.Zone.Data, r.Id.Data), nil
}

func templateMqlID(zone, id string) string {
	return "exoscale.compute.template/" + zone + "/" + id
}

// templates lists the organization's own templates. The public catalog is
// large and identical for every organization; public templates are reachable
// through the instances and pools that use them.
func (r *mqlExoscale) templates() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-templates", func(c *v3.Client) ([]v3.Template, error) {
		res, err := c.ListTemplates(ctx(), v3.ListTemplatesWithVisibility(v3.ListTemplatesVisibilityPrivate))
		if err != nil {
			return nil, err
		}
		return res.Templates, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		res, err := newMqlExoscaleComputeTemplate(r.MqlRuntime, it.zone, it.item)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlExoscaleComputeTemplate(runtime *plugin.Runtime, zone string, t v3.Template) (*mqlExoscaleComputeTemplate, error) {
	res, err := CreateResource(runtime, "exoscale.compute.template", templateArgs(zone, t))
	if err != nil {
		return nil, err
	}
	return res.(*mqlExoscaleComputeTemplate), nil
}

func templateArgs(zone string, t v3.Template) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                                 llx.StringData(templateMqlID(zone, string(t.ID))),
		"id":                                   llx.StringData(string(t.ID)),
		"zone":                                 llx.StringData(zone),
		"name":                                 llx.StringData(t.Name),
		"description":                          llx.StringData(t.Description),
		"family":                               llx.StringData(t.Family),
		"version":                              llx.StringData(t.Version),
		"build":                                llx.StringData(t.Build),
		"maintainer":                           llx.StringData(t.Maintainer),
		"checksum":                             llx.StringData(t.Checksum),
		"url":                                  llx.StringData(t.URL),
		"defaultUser":                          llx.StringData(t.DefaultUser),
		"size":                                 llx.IntData(t.Size),
		"bootMode":                             llx.StringData(string(t.BootMode)),
		"visibility":                           llx.StringData(string(t.Visibility)),
		"passwordEnabled":                      boolData(t.PasswordEnabled),
		"sshKeyEnabled":                        boolData(t.SSHKeyEnabled),
		"applicationConsistentSnapshotEnabled": boolData(t.ApplicationConsistentSnapshotEnabled),
		"created":                              timeData(t.CreatedAT),
	}
}

// initExoscaleComputeTemplate resolves a template by id and zone. Private
// templates come from the listed collection; a public template is fetched
// once per connection, however many instances reference it.
func initExoscaleComputeTemplate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	id, zone := stringArg(args, "id"), stringArg(args, "zone")
	if id == "" || zone == "" {
		return nil, nil, fmt.Errorf("exoscale.compute.template requires an id and a zone, for example exoscale.compute.template(id: \"<uuid>\", zone: \"ch-gva-2\")")
	}

	ns, err := root(runtime)
	if err != nil {
		return nil, nil, err
	}
	list := ns.GetTemplates()
	if list.Error == nil {
		if t, ok := pickOneByID(list.Data, id, func(t *mqlExoscaleComputeTemplate) string {
			if t.Zone.Data != zone {
				return ""
			}
			return t.Id.Data
		}); ok {
			return args, t, nil
		}
	}

	z, ok, err := zoneByName(runtime, zone)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, fmt.Errorf("exoscale.compute.template: zone %q is not queried by this connection", zone)
	}
	v, err := conn(runtime).Memo("template/"+zone+"/"+id, func() (any, error) {
		return conn(runtime).ZoneClient(z).GetTemplate(ctx(), v3.UUID(id))
	})
	if err != nil {
		return nil, nil, classifyError(err, "get-template")
	}
	t := v.(*v3.Template)
	if t == nil {
		return nil, nil, fmt.Errorf("exoscale.compute.template with id %q not found in zone %s", id, zone)
	}
	return templateArgs(zone, *t), nil, nil
}

func resolveTemplate(runtime *plugin.Runtime, zone, id string, field *plugin.TValue[*mqlExoscaleComputeTemplate]) (*mqlExoscaleComputeTemplate, error) {
	if id == "" {
		nullResource(field)
		return nil, nil
	}
	res, err := NewResource(runtime, "exoscale.compute.template", map[string]*llx.RawData{
		"id":   llx.StringData(id),
		"zone": llx.StringData(zone),
	})
	if err != nil {
		// A template deleted after the instance was created can no longer be
		// read, which does not make the instance's other fields unreadable.
		if llx.KindOf(err) == llx.ErrorKind_ERROR_KIND_NOT_FOUND {
			nullResource(field)
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlExoscaleComputeTemplate), nil
}

// ---- instance pools ----

type mqlExoscaleComputeInstancePoolInternal struct {
	cacheInstanceType         *v3.InstanceType
	cacheTemplateID           string
	cacheInstanceIDs          []string
	cacheSecurityGroupIDs     []string
	cachePrivateNetworkIDs    []string
	cacheAntiAffinityGroupIDs []string
	cacheElasticIPIDs         []string
	cacheSSHKeyNames          []string
}

func (r *mqlExoscale) instancePools() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-instance-pools", func(c *v3.Client) ([]v3.InstancePool, error) {
		res, err := c.ListInstancePools(ctx())
		if err != nil {
			return nil, err
		}
		return res.InstancePools, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		p := it.item
		res, err := CreateResource(r.MqlRuntime, "exoscale.compute.instancePool", map[string]*llx.RawData{
			"__id":               llx.StringData("exoscale.compute.instancePool/" + string(p.ID)),
			"id":                 llx.StringData(string(p.ID)),
			"zone":               llx.StringData(it.zone),
			"name":               llx.StringData(p.Name),
			"description":        llx.StringData(p.Description),
			"state":              llx.StringData(string(p.State)),
			"size":               llx.IntData(p.Size),
			"minAvailable":       llx.IntData(p.MinAvailable),
			"labels":             labelData(p.Labels),
			"diskSize":           llx.IntData(p.DiskSize),
			"instancePrefix":     llx.StringData(p.InstancePrefix),
			"publicIpAssignment": llx.StringData(string(p.PublicIPAssignment)),
			"ipv6Enabled":        boolData(p.Ipv6Enabled),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlExoscaleComputeInstancePool)
		m.cacheInstanceType = p.InstanceType
		if p.Template != nil {
			m.cacheTemplateID = string(p.Template.ID)
		}
		m.cacheInstanceIDs = uuidStrings(p.Instances, func(i v3.Instance) v3.UUID { return i.ID })
		m.cacheSecurityGroupIDs = uuidStrings(p.SecurityGroups, func(s v3.SecurityGroup) v3.UUID { return s.ID })
		m.cachePrivateNetworkIDs = uuidStrings(p.PrivateNetworks, func(n v3.PrivateNetwork) v3.UUID { return n.ID })
		m.cacheAntiAffinityGroupIDs = uuidStrings(p.AntiAffinityGroups, func(a v3.AntiAffinityGroup) v3.UUID { return a.ID })
		m.cacheElasticIPIDs = uuidStrings(p.ElasticIPS, func(e v3.ElasticIP) v3.UUID { return e.ID })
		m.cacheSSHKeyNames = sshKeyNames(p.SSHKey, p.SSHKeys)
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlExoscaleComputeInstancePool) instanceType() (*mqlExoscaleComputeInstanceType, error) {
	return resolveInstanceType(r.MqlRuntime, r.cacheInstanceType, &r.InstanceType)
}

func (r *mqlExoscaleComputeInstancePool) template() (*mqlExoscaleComputeTemplate, error) {
	return resolveTemplate(r.MqlRuntime, r.Zone.Data, r.cacheTemplateID, &r.Template)
}

func (r *mqlExoscaleComputeInstancePool) instances() ([]any, error) {
	return instancesByID(r.MqlRuntime, r.cacheInstanceIDs)
}

func (r *mqlExoscaleComputeInstancePool) securityGroups() ([]any, error) {
	return securityGroupsByID(r.MqlRuntime, r.cacheSecurityGroupIDs)
}

func (r *mqlExoscaleComputeInstancePool) privateNetworks() ([]any, error) {
	return privateNetworksByID(r.MqlRuntime, r.cachePrivateNetworkIDs)
}

func (r *mqlExoscaleComputeInstancePool) antiAffinityGroups() ([]any, error) {
	return antiAffinityGroupsByID(r.MqlRuntime, r.cacheAntiAffinityGroupIDs)
}

func (r *mqlExoscaleComputeInstancePool) elasticIps() ([]any, error) {
	return elasticIpsByID(r.MqlRuntime, r.cacheElasticIPIDs)
}

func (r *mqlExoscaleComputeInstancePool) sshKeys() ([]any, error) {
	return sshKeysByName(r.MqlRuntime, r.cacheSSHKeyNames)
}

func instancePoolByID(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlExoscaleComputeInstancePool]) (*mqlExoscaleComputeInstancePool, error) {
	if id == "" {
		nullResource(field)
		return nil, nil
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetInstancePools()
	if list.Error != nil {
		return nil, list.Error
	}
	if p, ok := pickOneByID(list.Data, id, func(p *mqlExoscaleComputeInstancePool) string { return p.Id.Data }); ok {
		return p, nil
	}
	nullResource(field)
	return nil, nil
}

// ---- instance snapshots ----

type mqlExoscaleComputeSnapshotInternal struct {
	cacheInstanceID string
}

func (r *mqlExoscale) snapshots() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-snapshots", func(c *v3.Client) ([]v3.Snapshot, error) {
		res, err := c.ListSnapshots(ctx())
		if err != nil {
			return nil, err
		}
		return res.Snapshots, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		s := it.item
		res, err := CreateResource(r.MqlRuntime, "exoscale.compute.snapshot", map[string]*llx.RawData{
			"__id":                  llx.StringData("exoscale.compute.snapshot/" + string(s.ID)),
			"id":                    llx.StringData(string(s.ID)),
			"zone":                  llx.StringData(it.zone),
			"name":                  llx.StringData(s.Name),
			"size":                  llx.IntData(s.Size),
			"state":                 llx.StringData(string(s.State)),
			"created":               timeData(s.CreatedAT),
			"applicationConsistent": boolData(s.ApplicationConsistent),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlExoscaleComputeSnapshot)
		if s.Instance != nil {
			m.cacheInstanceID = string(s.Instance.ID)
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlExoscaleComputeSnapshot) instance() (*mqlExoscaleComputeInstance, error) {
	return instanceByID(r.MqlRuntime, r.cacheInstanceID, &r.Instance)
}
