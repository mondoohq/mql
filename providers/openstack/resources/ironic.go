// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/nodes"
	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/ports"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// translateBaremetalError treats a 406 (microversion not supported by this
// cloud) as "no data", on top of the usual 401/403/404 handling. Ironic
// deployments older than the microversion we request answer 406; that means
// the capability is absent, not that the query failed.
func translateBaremetalError(err error) error {
	if err == nil {
		return nil
	}
	var resp gophercloud.ErrUnexpectedResponseCode
	if errors.As(err, &resp) && resp.Actual == 406 {
		return nil
	}
	return translateOpenstackError(err)
}

// ---- openstack.baremetal.node ----

type mqlOpenstackBaremetalNodeInternal struct {
	cacheOwner  string
	cacheLessee string
}

func (r *mqlOpenstackBaremetalNode) id() (string, error) {
	return "openstack.baremetal.node/" + r.Id.Data, nil
}

func initOpenstackBaremetalNode(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetBaremetalNodes()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		n := raw.(*mqlOpenstackBaremetalNode)
		if n.Id.Data == id {
			return args, n, nil
		}
	}
	initSyntheticID("openstack.baremetal.node", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) baremetalNodes() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.BareMetalClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := nodes.ListDetail(client, nodes.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateBaremetalError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := nodes.ExtractNodes(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		n := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.baremetal.node", map[string]*llx.RawData{
			"__id":                 llx.StringData("openstack.baremetal.node/" + n.UUID),
			"id":                   llx.StringData(n.UUID),
			"name":                 llx.StringData(n.Name),
			"powerState":           llx.StringData(n.PowerState),
			"targetPowerState":     llx.StringData(n.TargetPowerState),
			"provisionState":       llx.StringData(n.ProvisionState),
			"targetProvisionState": llx.StringData(n.TargetProvisionState),
			"maintenance":          llx.BoolData(n.Maintenance),
			"maintenanceReason":    llx.StringData(n.MaintenanceReason),
			"fault":                llx.StringData(n.Fault),
			"lastError":            llx.StringData(n.LastError),
			"driver":               llx.StringData(n.Driver),
			"resourceClass":        llx.StringData(n.ResourceClass),
			"conductorGroup":       llx.StringData(n.ConductorGroup),
			"conductor":            llx.StringData(n.Conductor),
			"protected":            llx.BoolData(n.Protected),
			"protectedReason":      llx.StringData(n.ProtectedReason),
			// AutomatedClean is *bool in the API: absent means the node defers to the
			// conductor default, which is neither on nor off, so it stays null.
			"automatedClean":   llx.BoolDataPtr(n.AutomatedClean),
			"retired":          llx.BoolData(n.Retired),
			"retiredReason":    llx.StringData(n.RetiredReason),
			"description":      llx.StringData(n.Description),
			"consoleEnabled":   llx.BoolData(n.ConsoleEnabled),
			"bootInterface":    llx.StringData(n.BootInterface),
			"deployInterface":  llx.StringData(n.DeployInterface),
			"networkInterface": llx.StringData(n.NetworkInterface),
			"traits":           stringSliceData(n.Traits),
			"instanceUuid":     llx.StringData(n.InstanceUUID),
			"createdAt":        llx.TimeDataPtr(timePtr(n.CreatedAt)),
			"updatedAt":        llx.TimeDataPtr(timePtr(n.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlNode := res.(*mqlOpenstackBaremetalNode)
		mqlNode.cacheOwner = n.Owner
		mqlNode.cacheLessee = n.Lessee
		out = append(out, mqlNode)
	}
	return out, nil
}

func (r *mqlOpenstackBaremetalNode) owner() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheOwner, &r.Owner)
}

func (r *mqlOpenstackBaremetalNode) lessee() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheLessee, &r.Lessee)
}

func (r *mqlOpenstackBaremetalNode) instance() (*mqlOpenstackComputeServer, error) {
	if r.InstanceUuid.Data == "" {
		r.Instance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.compute.server", map[string]*llx.RawData{
		"id": llx.StringData(r.InstanceUuid.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackComputeServer), nil
}

func (r *mqlOpenstackBaremetalNode) ports() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.BareMetalClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := ports.ListDetail(client, ports.ListOpts{Node: r.Id.Data}).AllPages(ctx())
	if err != nil {
		if translateBaremetalError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := ports.ExtractPorts(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		p := &items[i]
		res, err := CreateResource(r.MqlRuntime, "openstack.baremetal.port", map[string]*llx.RawData{
			"__id":                llx.StringData("openstack.baremetal.port/" + p.UUID),
			"id":                  llx.StringData(p.UUID),
			"address":             llx.StringData(p.Address),
			"nodeUuid":            llx.StringData(p.NodeUUID),
			"pxeEnabled":          llx.BoolData(p.PXEEnabled),
			"physicalNetwork":     llx.StringData(p.PhysicalNetwork),
			"portgroupUuid":       llx.StringData(p.PortGroupUUID),
			"isSmartNic":          llx.BoolData(p.IsSmartNIC),
			"localLinkConnection": llx.DictData(p.LocalLinkConnection),
			"createdAt":           llx.TimeDataPtr(timePtr(p.CreatedAt)),
			"updatedAt":           llx.TimeDataPtr(timePtr(p.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- openstack.baremetal.port ----

func (r *mqlOpenstackBaremetalPort) id() (string, error) {
	return "openstack.baremetal.port/" + r.Id.Data, nil
}

func (r *mqlOpenstackBaremetalPort) node() (*mqlOpenstackBaremetalNode, error) {
	if r.NodeUuid.Data == "" {
		r.Node.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.baremetal.node", map[string]*llx.RawData{
		"id": llx.StringData(r.NodeUuid.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackBaremetalNode), nil
}
