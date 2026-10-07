// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"time"

	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"github.com/go-openapi/strfmt"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ibm/connection"
)

// powerServiceID is the catalog ID of the Power Virtual Server service. Its
// resource instances of type composite_instance are the workspaces; the
// service's images are separate power-iaas.image instances.
const powerServiceID = "abd259f0-9990-11e8-acc8-b9f54a8f1661"

// ---- workspaces ----

type mqlIbmPowerWorkspaceInternal struct {
	cacheResourceGroupID string
}

func (r *mqlIbmPowerWorkspace) id() (string, error) {
	return "ibm.power.workspace/" + r.Crn.Data, nil
}

// powerWorkspaces is every workspace, narrowed by --filters.
func (r *mqlIbm) powerWorkspaces() ([]any, error) {
	all, err := allPowerWorkspaces(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return filterByTags(r.MqlRuntime, all, func(w *mqlIbmPowerWorkspace) string { return w.Crn.Data })
}

// allPowerWorkspaces lists every workspace once per connection, ignoring
// --filters, for references that must not be hidden by a filter.
func allPowerWorkspaces(runtime *plugin.Runtime) ([]any, error) {
	v, err := conn(runtime).Memo("all/powerWorkspaces", func() (any, error) { return listPowerWorkspaces(runtime) })
	if err != nil {
		return nil, err
	}
	return v.([]any), nil
}

func listPowerWorkspaces(runtime *plugin.Runtime) ([]any, error) {
	items, err := listResourceInstances(runtime)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, ri := range items {
		if derefStr(ri.ResourceID) != powerServiceID {
			continue
		}
		res, err := CreateResource(runtime, "ibm.power.workspace", map[string]*llx.RawData{
			"__id":      llx.StringData("ibm.power.workspace/" + derefStr(ri.CRN)),
			"id":        strData(ri.GUID),
			"crn":       strData(ri.CRN),
			"name":      strData(ri.Name),
			"zone":      strData(ri.RegionID),
			"state":     strData(ri.State),
			"createdAt": dateTimeData(ri.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlIbmPowerWorkspace).cacheResourceGroupID = derefStr(ri.ResourceGroupID)
		out = append(out, res)
	}
	return out, nil
}

// initIbmPowerWorkspace resolves a workspace by CRN, or the workspace a
// discovered asset is scoped to, from the listed workspaces.
func initIbmPowerWorkspace(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	crn := stringArg(args, "crn")
	if crn == "" {
		crn = connection.AssetOption(conn(runtime).Conf, connection.OptionPowerWorkspace)
	}
	if crn == "" {
		return nil, nil, errors.New(`ibm.power.workspace requires a crn, for example ibm.power.workspace(crn: "crn:v1:bluemix:public:power-iaas:...")`)
	}
	all, err := allPowerWorkspaces(runtime)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range all {
		if w := e.(*mqlIbmPowerWorkspace); w.Crn.Data == crn {
			return args, w, nil
		}
	}
	return nil, nil, fmt.Errorf("ibm.power.workspace %q not found", crn)
}

func (r *mqlIbmPowerWorkspace) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

// pvmInstances lists the workspace's instances once; instances(), and every
// volume and network that refers to an instance, read from it.
func (r *mqlIbmPowerWorkspace) pvmInstances() ([]*models.PVMInstanceReference, error) {
	c := conn(r.MqlRuntime)
	v, err := c.Memo("power/instances/"+r.Id.Data, func() (any, error) {
		sess, err := c.PowerSession(r.Zone.Data)
		if err != nil {
			return nil, err
		}
		res, err := instance.NewIBMPIInstanceClient(connection.Context(), sess, r.Id.Data).GetAll()
		if err != nil {
			return nil, err
		}
		return res.PvmInstances, nil
	})
	if err != nil {
		return nil, classifyError(err, "power-iaas.cloud-instance.read")
	}
	return v.([]*models.PVMInstanceReference), nil
}

func (r *mqlIbmPowerWorkspace) instances() ([]any, error) {
	items, err := r.pvmInstances()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, p := range items {
		if p == nil {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.power.instance", powerInstanceArgs(p))
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmPowerInstance)
		m.cacheWorkspace = r
		m.cacheImageID = derefStr(p.ImageID)
		for _, n := range p.Networks {
			if n != nil && n.NetworkID != "" {
				m.cacheNetworkIDs = append(m.cacheNetworkIDs, n.NetworkID)
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmPowerWorkspace) networks() ([]any, error) {
	c := conn(r.MqlRuntime)
	sess, err := c.PowerSession(r.Zone.Data)
	if err != nil {
		return nil, err
	}
	res, err := instance.NewIBMPINetworkClient(connection.Context(), sess, r.Id.Data).GetAll()
	if err != nil {
		return nil, classifyError(err, "power-iaas.cloud-instance.read")
	}
	out := make([]any, 0, len(res.Networks))
	for _, n := range res.Networks {
		if n == nil {
			continue
		}
		args := map[string]*llx.RawData{
			"__id":        llx.StringData("ibm.power.network/" + r.Id.Data + "/" + derefStr(n.NetworkID)),
			"id":          strData(n.NetworkID),
			"crn":         llx.StringData(string(n.Crn)),
			"name":        strData(n.Name),
			"type":        strData(n.Type),
			"vlanId":      llx.NilData,
			"mtu":         intPtrData(n.Mtu),
			"dhcpManaged": llx.BoolData(n.DhcpManaged),
		}
		if n.VlanID != nil {
			args["vlanId"] = llx.IntData(int64(*n.VlanID))
		}
		m, err := CreateResource(r.MqlRuntime, "ibm.power.network", args)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmPowerWorkspace) volumes() ([]any, error) {
	c := conn(r.MqlRuntime)
	sess, err := c.PowerSession(r.Zone.Data)
	if err != nil {
		return nil, err
	}
	res, err := instance.NewIBMPIVolumeClient(connection.Context(), sess, r.Id.Data).GetAll()
	if err != nil {
		return nil, classifyError(err, "power-iaas.cloud-instance.read")
	}
	out := make([]any, 0, len(res.Volumes))
	for _, v := range res.Volumes {
		if v == nil {
			continue
		}
		m, err := CreateResource(r.MqlRuntime, "ibm.power.volume", map[string]*llx.RawData{
			"__id":               llx.StringData("ibm.power.volume/" + r.Id.Data + "/" + derefStr(v.VolumeID)),
			"id":                 strData(v.VolumeID),
			"crn":                llx.StringData(string(v.Crn)),
			"name":               strData(v.Name),
			"size":               llx.FloatDataPtr(v.Size),
			"state":              strData(v.State),
			"diskType":           strData(v.DiskType),
			"bootable":           llx.BoolDataPtr(v.Bootable),
			"shareable":          llx.BoolDataPtr(v.Shareable),
			"replicationEnabled": llx.BoolDataPtr(v.ReplicationEnabled),
			"createdAt":          dateTimeData(v.CreationDate),
		})
		if err != nil {
			return nil, err
		}
		vol := m.(*mqlIbmPowerVolume)
		vol.cacheWorkspace = r
		vol.cacheInstanceIDs = v.PvmInstanceIDs
		out = append(out, vol)
	}
	return out, nil
}

func (r *mqlIbmPowerWorkspace) images() ([]any, error) {
	c := conn(r.MqlRuntime)
	sess, err := c.PowerSession(r.Zone.Data)
	if err != nil {
		return nil, err
	}
	res, err := instance.NewIBMPIImageClient(connection.Context(), sess, r.Id.Data).GetAll()
	if err != nil {
		return nil, classifyError(err, "power-iaas.cloud-instance.read")
	}
	out := make([]any, 0, len(res.Images))
	for _, img := range res.Images {
		if img == nil {
			continue
		}
		os := ""
		if img.Specifications != nil {
			os = img.Specifications.OperatingSystem
		}
		m, err := CreateResource(r.MqlRuntime, "ibm.power.image", map[string]*llx.RawData{
			"__id":            llx.StringData("ibm.power.image/" + r.Id.Data + "/" + derefStr(img.ImageID)),
			"id":              strData(img.ImageID),
			"crn":             llx.StringData(string(img.Crn)),
			"name":            strData(img.Name),
			"operatingSystem": llx.StringData(os),
			"state":           strData(img.State),
			"storageType":     strData(img.StorageType),
			"createdAt":       dateTimeData(img.CreationDate),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// ---- instances ----

type mqlIbmPowerInstanceInternal struct {
	cacheWorkspace  *mqlIbmPowerWorkspace
	cacheImageID    string
	cacheNetworkIDs []string
}

func powerInstanceArgs(p *models.PVMInstanceReference) map[string]*llx.RawData {
	var ips, external []string
	for _, n := range p.Networks {
		if n == nil {
			continue
		}
		if n.IPAddress != "" {
			ips = append(ips, n.IPAddress)
		}
		if n.ExternalIP != "" {
			external = append(external, n.ExternalIP)
		}
	}
	return map[string]*llx.RawData{
		"__id":            llx.StringData("ibm.power.instance/" + string(p.Crn) + "/" + derefStr(p.PvmInstanceID)),
		"id":              strData(p.PvmInstanceID),
		"crn":             llx.StringData(string(p.Crn)),
		"name":            strData(p.ServerName),
		"status":          strData(p.Status),
		"osType":          strData(p.OsType),
		"operatingSystem": llx.StringData(p.OperatingSystem),
		"processors":      llx.FloatDataPtr(p.Processors),
		"processorType":   strData(p.ProcType),
		"memory":          llx.FloatDataPtr(p.Memory),
		"systemType":      llx.StringData(p.SysType),
		"storageType":     llx.StringData(p.StorageType),
		"ipAddresses":     stringsData(ips),
		"externalIps":     stringsData(external),
		"createdAt":       powerTime(p.CreationDate),
	}
}

// powerTime maps the Power client's non-pointer timestamp, zero when absent,
// to null.
func powerTime(t strfmt.DateTime) *llx.RawData {
	if time.Time(t).IsZero() {
		return llx.NilData
	}
	return llx.TimeData(time.Time(t))
}

func (r *mqlIbmPowerInstance) image() (*mqlIbmPowerImage, error) {
	if r.cacheWorkspace == nil || r.cacheImageID == "" {
		nullResource(&r.Image)
		return nil, nil
	}
	return resolveOne(&r.Image, r.cacheWorkspace.GetImages(), r.cacheImageID, func(i *mqlIbmPowerImage) string { return i.Id.Data })
}

func (r *mqlIbmPowerInstance) networks() ([]any, error) {
	if r.cacheWorkspace == nil {
		return []any{}, nil
	}
	list := r.cacheWorkspace.GetNetworks()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, r.cacheNetworkIDs, func(n *mqlIbmPowerNetwork) string { return n.Id.Data }), nil
}

// volumes scans the workspace's volumes for the ones attached here.
func (r *mqlIbmPowerInstance) volumes() ([]any, error) {
	if r.cacheWorkspace == nil {
		return []any{}, nil
	}
	list := r.cacheWorkspace.GetVolumes()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, e := range list.Data {
		v := e.(*mqlIbmPowerVolume)
		for _, id := range v.cacheInstanceIDs {
			if id == r.Id.Data {
				out = append(out, v)
				break
			}
		}
	}
	return out, nil
}

// ---- volumes ----

type mqlIbmPowerVolumeInternal struct {
	cacheWorkspace   *mqlIbmPowerWorkspace
	cacheInstanceIDs []string
}

func (r *mqlIbmPowerVolume) instances() ([]any, error) {
	if r.cacheWorkspace == nil {
		return []any{}, nil
	}
	list := r.cacheWorkspace.GetInstances()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, r.cacheInstanceIDs, func(i *mqlIbmPowerInstance) string { return i.Id.Data }), nil
}
