// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"slices"
	"sync"

	v3 "github.com/exoscale/egoscale/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/exoscale/connection"
)

type mqlExoscaleComputeInstanceInternal struct {
	cacheInstanceType      *v3.InstanceType
	cacheTemplateID        string
	cacheSecurityGroupIDs  []string
	cachePrivateNetworkIDs []string
	cacheSSHKeyNames       []string

	// The list call returns a reduced record. The detail fields come from one
	// GetInstance call, shared by all of them.
	detailLock                sync.Mutex
	detailDone                bool
	detailErr                 error
	cacheElasticIPIDs         []string
	cacheAntiAffinityGroupIDs []string
	cacheSnapshotIDs          []string
}

func (r *mqlExoscaleComputeInstance) id() (string, error) {
	return "exoscale.compute.instance/" + r.Id.Data, nil
}

func (r *mqlExoscale) instances() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-instances", func(c *v3.Client) ([]v3.ListInstancesResponseInstances, error) {
		res, err := c.ListInstances(ctx())
		if err != nil {
			return nil, err
		}
		return res.Instances, nil
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
		res, err := newMqlExoscaleComputeInstance(r.MqlRuntime, it.zone, it.item)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// sshKeyNames merges the legacy single ssh-key and the ssh-keys list.
func sshKeyNames(single *v3.SSHKey, list []v3.SSHKey) []string {
	var out []string
	if single != nil && single.Name != "" {
		out = append(out, single.Name)
	}
	for _, k := range list {
		if k.Name != "" && !slices.Contains(out, k.Name) {
			out = append(out, k.Name)
		}
	}
	return out
}

func newMqlExoscaleComputeInstance(runtime *plugin.Runtime, zone string, i v3.ListInstancesResponseInstances) (*mqlExoscaleComputeInstance, error) {
	res, err := CreateResource(runtime, "exoscale.compute.instance", map[string]*llx.RawData{
		"__id":               llx.StringData("exoscale.compute.instance/" + string(i.ID)),
		"id":                 llx.StringData(string(i.ID)),
		"name":               llx.StringData(i.Name),
		"zone":               llx.StringData(zone),
		"state":              llx.StringData(string(i.State)),
		"created":            timeData(i.CreatedAT),
		"labels":             labelData(i.Labels),
		"publicIp":           llx.StringData(ipString(i.PublicIP)),
		"publicIpAssignment": llx.StringData(string(i.PublicIPAssignment)),
		"ipv6Address":        llx.StringData(i.Ipv6Address),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlExoscaleComputeInstance)
	m.cacheInstanceType = i.InstanceType
	if i.Template != nil {
		m.cacheTemplateID = string(i.Template.ID)
	}
	m.cacheSecurityGroupIDs = uuidStrings(i.SecurityGroups, func(s v3.SecurityGroup) v3.UUID { return s.ID })
	m.cachePrivateNetworkIDs = uuidStrings(i.PrivateNetworks, func(p v3.ListInstancesResponseInstancesPrivateNetworks) v3.UUID { return p.ID })
	m.cacheSSHKeyNames = sshKeyNames(i.SSHKey, i.SSHKeys)
	return m, nil
}

func initExoscaleComputeInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	id := stringArg(args, "id")
	if id == "" {
		// Fall back to a connected exoscale-compute-instance asset.
		id = connection.AssetOption(conn(runtime).Conf, connection.OptionInstance)
	}
	if id == "" {
		return nil, nil, fmt.Errorf("exoscale.compute.instance requires an id, for example exoscale.compute.instance(id: \"<uuid>\")")
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, nil, err
	}
	list := ns.GetInstances()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	if r, ok := pickOneByID(list.Data, id, func(r *mqlExoscaleComputeInstance) string { return r.Id.Data }); ok {
		return args, r, nil
	}
	return nil, nil, fmt.Errorf("exoscale.compute.instance with id %q not found", id)
}

func (r *mqlExoscaleComputeInstance) instanceType() (*mqlExoscaleComputeInstanceType, error) {
	return resolveInstanceType(r.MqlRuntime, r.cacheInstanceType, &r.InstanceType)
}

func (r *mqlExoscaleComputeInstance) template() (*mqlExoscaleComputeTemplate, error) {
	return resolveTemplate(r.MqlRuntime, r.Zone.Data, r.cacheTemplateID, &r.Template)
}

func (r *mqlExoscaleComputeInstance) securityGroups() ([]any, error) {
	return securityGroupsByID(r.MqlRuntime, r.cacheSecurityGroupIDs)
}

func (r *mqlExoscaleComputeInstance) privateNetworks() ([]any, error) {
	return privateNetworksByID(r.MqlRuntime, r.cachePrivateNetworkIDs)
}

func (r *mqlExoscaleComputeInstance) sshKeys() ([]any, error) {
	return sshKeysByName(r.MqlRuntime, r.cacheSSHKeyNames)
}

// instancePool finds the pool whose members include this instance. That
// covers both plain instance pools and the pools behind SKS node pools.
func (r *mqlExoscaleComputeInstance) instancePool() (*mqlExoscaleComputeInstancePool, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	pools := ns.GetInstancePools()
	if pools.Error != nil {
		return nil, pools.Error
	}
	for _, p := range pools.Data {
		pool := p.(*mqlExoscaleComputeInstancePool)
		if slices.Contains(pool.cacheInstanceIDs, r.Id.Data) {
			return pool, nil
		}
	}
	nullResource(&r.InstancePool)
	return nil, nil
}

// loadDetail reads the full instance record once and fills every field that
// only it carries.
func (r *mqlExoscaleComputeInstance) loadDetail() error {
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailDone {
		return r.detailErr
	}
	r.detailDone = true

	z, ok, err := zoneByName(r.MqlRuntime, r.Zone.Data)
	if err != nil {
		r.detailErr = err
		return err
	}
	if !ok {
		r.detailErr = fmt.Errorf("exoscale.compute.instance %s: zone %q is not queried by this connection", r.Id.Data, r.Zone.Data)
		return r.detailErr
	}
	d, err := conn(r.MqlRuntime).ZoneClient(z).GetInstance(ctx(), v3.UUID(r.Id.Data))
	if err != nil {
		r.detailErr = classifyError(err, "get-instance")
		return r.detailErr
	}

	// The list call leaves the MAC address empty; only the detail has it.
	r.MacAddress.Data, r.MacAddress.State = d.MACAddress, plugin.StateIsSet
	setInt(&r.DiskSize, d.DiskSize)
	setBool(&r.DiskEncrypted, d.DiskEncrypted)
	setBool(&r.SecurebootEnabled, d.SecurebootEnabled)
	setBool(&r.TpmEnabled, d.TpmEnabled)
	setBool(&r.IpForwarding, d.IPForwarding)
	setBool(&r.ApplicationConsistentSnapshotEnabled, d.ApplicationConsistentSnapshotEnabled)
	r.cacheElasticIPIDs = uuidStrings(d.ElasticIPS, func(e v3.ElasticIP) v3.UUID { return e.ID })
	r.cacheAntiAffinityGroupIDs = uuidStrings(d.AntiAffinityGroups, func(a v3.AntiAffinityGroup) v3.UUID { return a.ID })
	r.cacheSnapshotIDs = uuidStrings(d.Snapshots, func(s v3.Snapshot) v3.UUID { return s.ID })
	return nil
}

func (r *mqlExoscaleComputeInstance) macAddress() (string, error) {
	if err := r.loadDetail(); err != nil {
		return "", err
	}
	return r.MacAddress.Data, nil
}

func (r *mqlExoscaleComputeInstance) diskSize() (int64, error) {
	if err := r.loadDetail(); err != nil {
		return 0, err
	}
	return r.DiskSize.Data, nil
}

func (r *mqlExoscaleComputeInstance) diskEncrypted() (bool, error) {
	if err := r.loadDetail(); err != nil {
		return false, err
	}
	return r.DiskEncrypted.Data, nil
}

func (r *mqlExoscaleComputeInstance) securebootEnabled() (bool, error) {
	if err := r.loadDetail(); err != nil {
		return false, err
	}
	return r.SecurebootEnabled.Data, nil
}

func (r *mqlExoscaleComputeInstance) tpmEnabled() (bool, error) {
	if err := r.loadDetail(); err != nil {
		return false, err
	}
	return r.TpmEnabled.Data, nil
}

func (r *mqlExoscaleComputeInstance) ipForwarding() (bool, error) {
	if err := r.loadDetail(); err != nil {
		return false, err
	}
	return r.IpForwarding.Data, nil
}

func (r *mqlExoscaleComputeInstance) applicationConsistentSnapshotEnabled() (bool, error) {
	if err := r.loadDetail(); err != nil {
		return false, err
	}
	return r.ApplicationConsistentSnapshotEnabled.Data, nil
}

func (r *mqlExoscaleComputeInstance) elasticIps() ([]any, error) {
	if err := r.loadDetail(); err != nil {
		return nil, err
	}
	return elasticIpsByID(r.MqlRuntime, r.cacheElasticIPIDs)
}

func (r *mqlExoscaleComputeInstance) antiAffinityGroups() ([]any, error) {
	if err := r.loadDetail(); err != nil {
		return nil, err
	}
	return antiAffinityGroupsByID(r.MqlRuntime, r.cacheAntiAffinityGroupIDs)
}

func (r *mqlExoscaleComputeInstance) snapshots() ([]any, error) {
	if err := r.loadDetail(); err != nil {
		return nil, err
	}
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetSnapshots()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, r.cacheSnapshotIDs, func(s *mqlExoscaleComputeSnapshot) string { return s.Id.Data }), nil
}

// blockStorageVolumes scans the listed volumes for the ones attached here.
func (r *mqlExoscaleComputeInstance) blockStorageVolumes() ([]any, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetBlockStorageVolumes()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, v := range list.Data {
		if v.(*mqlExoscaleBlockStorageVolume).cacheInstanceID == r.Id.Data {
			out = append(out, v)
		}
	}
	return out, nil
}

// instancesByID resolves instance ids through the listed instances.
func instancesByID(runtime *plugin.Runtime, ids []string) ([]any, error) {
	if len(ids) == 0 {
		return []any{}, nil
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetInstances()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, ids, func(r *mqlExoscaleComputeInstance) string { return r.Id.Data }), nil
}

func instanceByID(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlExoscaleComputeInstance]) (*mqlExoscaleComputeInstance, error) {
	if id == "" {
		nullResource(field)
		return nil, nil
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetInstances()
	if list.Error != nil {
		return nil, list.Error
	}
	if r, ok := pickOneByID(list.Data, id, func(r *mqlExoscaleComputeInstance) string { return r.Id.Data }); ok {
		return r, nil
	}
	nullResource(field)
	return nil, nil
}
