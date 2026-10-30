// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// ---------------------------------------------------------------------------
// node.pciDevices
// ---------------------------------------------------------------------------

func (r *mqlProxmoxNode) pciDevices() ([]any, error) {
	conn := nodeConn(r)
	devs, err := conn.GetNodePCIDevices(r.Name.Data)
	if err != nil {
		return nil, err
	}
	list := make([]any, len(devs))
	for i, d := range devs {
		res, err := CreateResource(r.MqlRuntime, "proxmox.node.pciDevice", map[string]*llx.RawData{
			"__id":          llx.StringData("proxmox.node.pciDevice/" + r.Name.Data + "/" + d.ID),
			"id":            llx.StringData(d.ID),
			"class":         llx.StringData(d.Class),
			"className":     llx.StringData(d.ClassName),
			"vendor":        llx.StringData(d.Vendor),
			"vendorName":    llx.StringData(d.VendorName),
			"device":        llx.StringData(d.Device),
			"deviceName":    llx.StringData(d.DeviceName),
			"subVendor":     llx.StringData(d.Subsystem.Vendor),
			"subVendorName": llx.StringData(d.Subsystem.VendorName),
			"subDevice":     llx.StringData(d.Subsystem.Device),
			"subDeviceName": llx.StringData(d.Subsystem.DeviceName),
			"iommuGroup":    llx.IntData(int64(d.IOMMUGroup)),
			"mdevSupported": llx.BoolData(d.MdevSupp == 1),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// node.usbDevices
// ---------------------------------------------------------------------------

func (r *mqlProxmoxNode) usbDevices() ([]any, error) {
	conn := nodeConn(r)
	devs, err := conn.GetNodeUSBDevices(r.Name.Data)
	if err != nil {
		return nil, err
	}
	list := make([]any, len(devs))
	for i, d := range devs {
		// USB devices don't have a single guaranteed-unique field — the
		// usbPath is the closest, but PVE occasionally emits empty values
		// on hubs. Fall back to bus+devnum so the cache key never collides.
		key := d.UsbPath
		if key == "" {
			key = d.BusNum + ":" + d.DevNum
		}
		res, err := CreateResource(r.MqlRuntime, "proxmox.node.usbDevice", map[string]*llx.RawData{
			"__id":         llx.StringData("proxmox.node.usbDevice/" + r.Name.Data + "/" + key),
			"vendorId":     llx.StringData(d.VendID),
			"productId":    llx.StringData(d.ProdID),
			"manufacturer": llx.StringData(d.Manufacturer),
			"product":      llx.StringData(d.Product),
			"serial":       llx.StringData(d.Serial),
			"busNum":       llx.StringData(d.BusNum),
			"devNum":       llx.StringData(d.DevNum),
			"port":         llx.StringData(d.Port),
			"level":        llx.StringData(d.Level),
			"class":        llx.StringData(d.Class),
			"speed":        llx.StringData(d.Speed),
			"usbPath":      llx.StringData(d.UsbPath),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// Firewall security groups
// ---------------------------------------------------------------------------

func (r *mqlProxmoxCluster) firewallGroups() ([]any, error) {
	conn := clusterConn(r)
	groups, err := conn.GetClusterFirewallGroups()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(groups))
	for i, g := range groups {
		res, err := CreateResource(r.MqlRuntime, "proxmox.firewall.group", map[string]*llx.RawData{
			"__id":    llx.StringData("proxmox.firewall.group/" + g.Group),
			"name":    llx.StringData(g.Group),
			"comment": llx.StringData(g.Comment),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxFirewallGroup) id() (string, error) {
	return "proxmox.firewall.group/" + r.Name.Data, nil
}

func firewallGroupConn(r *mqlProxmoxFirewallGroup) *connection.PveConnection {
	return r.MqlRuntime.Connection.(*connection.PveConnection)
}

func (r *mqlProxmoxFirewallGroup) rules() ([]any, error) {
	rules, err := firewallGroupConn(r).GetClusterFirewallGroupRules(r.Name.Data)
	if err != nil {
		return nil, err
	}
	return firewallRulesToResources(r.MqlRuntime, rules, "group/"+r.Name.Data)
}

// ---------------------------------------------------------------------------
// firewall.rule.group cross-ref
// ---------------------------------------------------------------------------

func (r *mqlProxmoxFirewallRule) group() (*mqlProxmoxFirewallGroup, error) {
	// PVE encodes the group name in `action` for type=group rules.
	if r.Type.Data != "group" {
		r.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	name := strings.TrimSpace(r.Action.Data)
	if name == "" {
		r.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.firewall.group", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxFirewallGroup), nil
}
