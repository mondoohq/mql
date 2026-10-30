// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25/mo"
	vimtypes "github.com/vmware/govmomi/vim25/types"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/vsphere/connection"
	"go.mondoo.com/mql/providers/vsphere/resources/resourceclient"
	"go.mondoo.com/mql/types"
)

type mqlVsphereHostInternal struct {
	host     *mo.HostSystem
	hostOnce sync.Once
}

// setHost stores the cached *mo.HostSystem if not already set. Multiple
// discovery paths (datacenter.hosts, cluster.hosts) can populate the same
// host resource concurrently; sync.Once ensures first-write-wins semantics
// rather than racing on the field.
func (v *mqlVsphereHost) setHost(h *mo.HostSystem) {
	v.hostOnce.Do(func() {
		v.host = h
	})
}

func (v *mqlVsphereHost) id() (string, error) {
	return v.Moid.Data, nil
}

// hostHardeningArgs extracts a few audit-relevant scalar fields from mo.HostSystem.
// firewallIncomingBlocked / firewallOutgoingBlocked reflect the host firewall's
// default policy; the firewall service itself is always running on ESXi.
// secureBootEnabled is reported by HostCapability.UefiSecureBoot, which requires
// vSphere 8.0.3+; on older hosts it's reported as false.
func hostHardeningArgs(hostInfo *mo.HostSystem) (lockdownMode string, firewallIncomingBlocked, firewallOutgoingBlocked, secureBootEnabled bool) {
	if hostInfo == nil {
		return
	}
	if hostInfo.Config != nil {
		lockdownMode = string(hostInfo.Config.LockdownMode)
		if fw := hostInfo.Config.Firewall; fw != nil {
			if fw.DefaultPolicy.IncomingBlocked != nil {
				firewallIncomingBlocked = *fw.DefaultPolicy.IncomingBlocked
			}
			if fw.DefaultPolicy.OutgoingBlocked != nil {
				firewallOutgoingBlocked = *fw.DefaultPolicy.OutgoingBlocked
			}
		}
	}
	if hostInfo.Capability != nil && hostInfo.Capability.UefiSecureBoot != nil {
		secureBootEnabled = *hostInfo.Capability.UefiSecureBoot
	}
	return
}

// hostRuntimeArgs extracts operational state from mo.HostSystem: the last-boot
// timestamp and maintenance-mode flag from HostRuntimeInfo, and the pending-reboot
// flag from the host summary (set when a staged patch or VIB install needs a reboot).
func hostRuntimeArgs(hostInfo *mo.HostSystem) (bootTime *time.Time, inMaintenanceMode, rebootRequired bool) {
	if hostInfo == nil {
		return
	}
	bootTime = hostInfo.Runtime.BootTime
	inMaintenanceMode = hostInfo.Runtime.InMaintenanceMode
	rebootRequired = hostInfo.Summary.RebootRequired
	return
}

func initVsphereHost(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.VsphereConnection)
	h, hostInfo, err := esxiHostProperties(conn)
	if err != nil {
		return nil, nil, err
	}

	props, err := resourceclient.HostProperties(hostInfo)
	if err != nil {
		return nil, nil, err
	}

	var name string
	if hostInfo != nil {
		name = hostInfo.Name
	}

	lockdownMode, firewallIncomingBlocked, firewallOutgoingBlocked, secureBootEnabled := hostHardeningArgs(hostInfo)
	bootTime, inMaintenanceMode, rebootRequired := hostRuntimeArgs(hostInfo)

	args["moid"] = llx.StringData(h.Reference().Encode())
	args["name"] = llx.StringData(name)
	args["properties"] = llx.DictData(props)
	args["inventoryPath"] = llx.StringData(h.InventoryPath)
	args["lockdownMode"] = llx.StringData(lockdownMode)
	args["firewallIncomingBlocked"] = llx.BoolData(firewallIncomingBlocked)
	args["firewallOutgoingBlocked"] = llx.BoolData(firewallOutgoingBlocked)
	args["secureBootEnabled"] = llx.BoolData(secureBootEnabled)
	args["bootTime"] = llx.TimeDataPtr(bootTime)
	args["inMaintenanceMode"] = llx.BoolData(inMaintenanceMode)
	args["rebootRequired"] = llx.BoolData(rebootRequired)

	return args, nil, nil
}

func (v *mqlVsphereHost) esxiClient() (*resourceclient.Esxi, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)

	if v.InventoryPath.Error != nil {
		return nil, v.InventoryPath.Error
	}
	path := v.InventoryPath.Data

	return esxiClient(conn, path)
}

// hostObject returns an *object.HostSystem for this host. Skips the
// `HostByInventoryPath` SOAP round-trip when the cached *mo.HostSystem is
// available (the common path — host resources hydrated by datacenter
// discovery), and falls back to the inventory-path lookup only when the
// resource was created via initVsphereHost without a cached handle.
func (v *mqlVsphereHost) hostObject() (*object.HostSystem, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	if v.host != nil {
		return object.NewHostSystem(conn.Client().Client, v.host.Reference()), nil
	}
	if v.InventoryPath.Error != nil {
		return nil, v.InventoryPath.Error
	}
	return getClientInstance(conn).HostByInventoryPath(v.InventoryPath.Data)
}

// pathAndHost returns the host's inventory path string (for stable __id
// construction in lazy accessors) plus a govmomi *object.HostSystem handle
// (for ESXCli / ConfigManager calls), propagating any InventoryPath error.
// Pulls together the common boilerplate of services / timezone / ntp /
// certificate.
func (v *mqlVsphereHost) pathAndHost() (string, *object.HostSystem, error) {
	if v.InventoryPath.Error != nil {
		return "", nil, v.InventoryPath.Error
	}
	host, err := v.hostObject()
	if err != nil {
		return "", nil, err
	}
	return v.InventoryPath.Data, host, nil
}

func (v *mqlVsphereHost) standardSwitch() ([]any, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}

	vswitches, err := esxiClient.VswitchStandard()
	if err != nil {
		return nil, err
	}

	// Index the host's cached HostVirtualSwitch records by name so we can
	// hydrate mtu / numPorts / numPortsAvailable without an extra SOAP call.
	vsByName := map[string]*vimtypes.HostVirtualSwitch{}
	if v.host != nil && v.host.Config != nil && v.host.Config.Network != nil {
		for i := range v.host.Config.Network.Vswitch {
			vsw := &v.host.Config.Network.Vswitch[i]
			vsByName[vsw.Name] = vsw
		}
	}

	mqlVswitches := make([]any, len(vswitches))
	for i, s := range vswitches {
		name, _ := s["Name"].(string)
		var mtu, numPorts, numPortsAvail int64
		if cached, ok := vsByName[name]; ok {
			mtu = int64(cached.Mtu)
			numPorts = int64(cached.NumPorts)
			numPortsAvail = int64(cached.NumPortsAvailable)
		}
		mqlVswitch, err := CreateResource(v.MqlRuntime, "vsphere.vswitch.standard", map[string]*llx.RawData{
			"__id":              llx.StringData(esxiClient.InventoryPath + "/" + name),
			"name":              llx.StringData(name),
			"properties":        llx.DictData(s),
			"mtu":               llx.IntData(mtu),
			"numPorts":          llx.IntData(numPorts),
			"numPortsAvailable": llx.IntData(numPortsAvail),
		})
		if err != nil {
			return nil, err
		}

		// store host inventory path, so that sub resources can use that to quickly query more
		r := mqlVswitch.(*mqlVsphereVswitchStandard)
		r.hostInventoryPath = esxiClient.InventoryPath
		r.parentResource = v

		mqlVswitches[i] = mqlVswitch
	}

	return mqlVswitches, nil
}

// portGroups enumerates the standard vSwitch port groups attached to this
// switch. Sourced from mo.HostSystem.Config.Network.Portgroup with a
// VswitchName filter; effective policy is the host-computed merge of the
// port-group override and the parent vSwitch's policy.
func (v *mqlVsphereVswitchStandard) portGroups() ([]any, error) {
	if v.parentResource == nil || v.parentResource.host == nil ||
		v.parentResource.host.Config == nil || v.parentResource.host.Config.Network == nil {
		return []any{}, nil
	}
	if v.parentResource.InventoryPath.Error != nil {
		return nil, v.parentResource.InventoryPath.Error
	}
	hostPath := v.parentResource.InventoryPath.Data
	switchName := v.Name.Data
	out := []any{}
	for i := range v.parentResource.host.Config.Network.Portgroup {
		pg := &v.parentResource.host.Config.Network.Portgroup[i]
		if pg.Spec.VswitchName != switchName {
			continue
		}
		id := hostPath + "/portgroup/" + pg.Spec.Name
		mqlPG, err := CreateResource(v.MqlRuntime, "vsphere.vswitch.standard.portgroup", map[string]*llx.RawData{
			"__id":        llx.StringData(id),
			"id":          llx.StringData(id),
			"name":        llx.StringData(pg.Spec.Name),
			"vSwitchName": llx.StringData(pg.Spec.VswitchName),
			"vlanId":      llx.IntData(int64(pg.Spec.VlanId)),
		})
		if err != nil {
			return nil, err
		}
		mqlPG.(*mqlVsphereVswitchStandardPortgroup).policy = &pg.ComputedPolicy
		mqlPG.(*mqlVsphereVswitchStandardPortgroup).parent = id
		out = append(out, mqlPG)
	}
	return out, nil
}

func (v *mqlVsphereHost) distributedSwitch() ([]any, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}

	vswitches, err := esxiClient.VswitchDvs()
	if err != nil {
		return nil, err
	}

	mqlVswitches := make([]any, len(vswitches))
	for i, s := range vswitches {
		name, _ := s["Name"].(string)
		mqlVswitch, err := CreateResource(v.MqlRuntime, "vsphere.vswitch.dvs", map[string]*llx.RawData{
			"__id":       llx.StringData(esxiClient.InventoryPath + "/" + name),
			"name":       llx.StringData(name),
			"properties": llx.DictData(s),
			// esxcli vswitch output carries no creation time; null marks it unknown.
			"createDate": llx.TimeDataPtr(nil),
			// esxcli carries no switch configuration; the typed settings are
			// only known for switches discovered through vCenter.
			"version":                llx.StringDataPtr(nil),
			"maxMtu":                 llx.IntDataPtr[int64](nil),
			"linkDiscoveryProtocol":  llx.StringDataPtr(nil),
			"linkDiscoveryOperation": llx.StringDataPtr(nil),
			"netflowEnabled":         llx.BoolDataPtr(nil),
			"netflowCollectorIp":     llx.StringDataPtr(nil),
			"healthCheckEnabled":     llx.BoolDataPtr(nil),
		})
		if err != nil {
			return nil, err
		}

		// store host inventory path, so that sub resources can use that to quickly query more
		r := mqlVswitch.(*mqlVsphereVswitchDvs)
		r.hostInventoryPath = esxiClient.InventoryPath
		r.parentResource = v

		mqlVswitches[i] = mqlVswitch
	}

	return mqlVswitches, nil
}

func (v *mqlVsphereHost) adapters() ([]any, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}
	adapters, err := esxiClient.Adapters()
	if err != nil {
		return nil, err
	}

	pParams, err := esxiClient.ListNicPauseParams()
	if err != nil {
		return nil, err
	}

	pauseParams := map[string]map[string]any{}
	// sort pause params by nic
	for i, p := range pParams {
		nicName, _ := pParams[i]["NIC"].(string)
		if nicName == "" {
			continue
		}
		pauseParams[nicName] = p
	}

	// Index PhysicalNic records from the cached host config so we can hydrate
	// MAC, link speed/duplex, driver, and Wake-on-LAN support without extra
	// SOAP calls.
	pnicByName := map[string]*vimtypes.PhysicalNic{}
	if v.host != nil && v.host.Config != nil && v.host.Config.Network != nil {
		for i := range v.host.Config.Network.Pnic {
			p := &v.host.Config.Network.Pnic[i]
			pnicByName[p.Device] = p
		}
	}

	mqlAdapters := make([]any, 0, len(adapters))
	for _, a := range adapters {
		nicName, _ := a["Name"].(string)
		if nicName == "" {
			continue
		}
		pParams := pauseParams[nicName]

		var (
			mac, driver         string
			linkSpeedMb         int64
			fullDuplex, wolSupp bool
		)
		if pn, ok := pnicByName[nicName]; ok {
			mac = pn.Mac
			driver = pn.Driver
			wolSupp = pn.WakeOnLanSupported
			if pn.LinkSpeed != nil {
				linkSpeedMb = int64(pn.LinkSpeed.SpeedMb)
				fullDuplex = pn.LinkSpeed.Duplex
			}
		}

		mqlAdapter, err := CreateResource(v.MqlRuntime, "vsphere.vmnic", map[string]*llx.RawData{
			"__id":               llx.StringData(esxiClient.InventoryPath + "/" + nicName),
			"name":               llx.StringData(nicName),
			"properties":         llx.DictData(a),
			"pauseParams":        llx.DictData(pParams),
			"mac":                llx.StringData(mac),
			"linkSpeedMb":        llx.IntData(linkSpeedMb),
			"fullDuplex":         llx.BoolData(fullDuplex),
			"driver":             llx.StringData(driver),
			"wakeOnLanSupported": llx.BoolData(wolSupp),
		})
		if err != nil {
			return nil, err
		}

		// set inventory path
		r := mqlAdapter.(*mqlVsphereVmnic)
		r.hostInventoryPath = esxiClient.InventoryPath
		r.parentResource = v

		mqlAdapters = append(mqlAdapters, mqlAdapter)
	}

	return mqlAdapters, nil
}

func (v *mqlVsphereVmnic) id() (string, error) {
	return v.Name.Data, nil
}

type mqlVsphereVmnicInternal struct {
	hostInventoryPath string
	parentResource    *mqlVsphereHost
}

type mqlVsphereVmknicInternal struct {
	parentResource *mqlVsphereHost
}

type mqlVsphereVswitchStandardPortgroupInternal struct {
	policy *vimtypes.HostNetworkPolicy
	parent string
}

func (v *mqlVsphereVmnic) esxiClient() (*resourceclient.Esxi, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	return esxiClient(conn, v.hostInventoryPath)
}

func (v *mqlVsphereVmnic) details() (map[string]any, error) {
	name := v.Name.Data

	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}

	return esxiClient.ListNicDetails(name)
}

func (v *mqlVsphereHost) vmknics() ([]any, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}
	vmknics, err := esxiClient.Vmknics()
	if err != nil {
		return nil, err
	}

	// Index HostVirtualNic records by device name and build a service →
	// vnic-keys lookup so we can attach MAC, MTU, TCP/IP stack, port group
	// binding, and the enabled-services list to each vmknic.
	vnicByDevice := map[string]*vimtypes.HostVirtualNic{}
	servicesByVnicKey := map[string][]any{}
	if v.host != nil && v.host.Config != nil {
		if v.host.Config.Network != nil {
			for i := range v.host.Config.Network.Vnic {
				vn := &v.host.Config.Network.Vnic[i]
				vnicByDevice[vn.Device] = vn
			}
		}
		if vn := v.host.Config.VirtualNicManagerInfo; vn != nil {
			// SelectedVnic entries are formatted "<nicType>.<vnicKey>"; strip
			// the prefix so the key matches HostVirtualNic.Key.
			for _, nc := range vn.NetConfig {
				prefix := nc.NicType + "."
				for _, sel := range nc.SelectedVnic {
					vnicKey := sel
					if strings.HasPrefix(sel, prefix) {
						vnicKey = sel[len(prefix):]
					}
					servicesByVnicKey[vnicKey] = append(servicesByVnicKey[vnicKey], nc.NicType)
				}
			}
		}
	}

	mqlVmknics := make([]any, len(vmknics))
	for i := range vmknics {
		entry := vmknics[i]
		nicName, _ := entry.Properties["Name"].(string)

		var (
			mac, tcpipStack string
			mtu             int64
			dhcp            bool
			pgName, pgMoid  string
			services        = []any{}
		)
		if vn, ok := vnicByDevice[nicName]; ok {
			mac = vn.Spec.Mac
			mtu = int64(vn.Spec.Mtu)
			tcpipStack = vn.Spec.NetStackInstanceKey
			pgName = vn.Portgroup
			if vn.Spec.DistributedVirtualPort != nil {
				pgMoid = vn.Spec.DistributedVirtualPort.PortgroupKey
			}
			if vn.Spec.Ip != nil {
				dhcp = vn.Spec.Ip.Dhcp
			}
			// Map host-internal vnic key to service names. Default to []any{}
			// rather than nil so the MQL output is `[]` instead of `null`.
			if mapped := servicesByVnicKey[vn.Key]; mapped != nil {
				services = mapped
			}
		}

		mqlVmknic, err := CreateResource(v.MqlRuntime, "vsphere.vmknic", map[string]*llx.RawData{
			"__id":          llx.StringData(esxiClient.InventoryPath + "/" + nicName),
			"name":          llx.StringData(nicName),
			"properties":    llx.DictData(entry.Properties),
			"ipv4":          llx.ArrayData(entry.Ipv4, types.Dict),
			"ipv6":          llx.ArrayData(entry.Ipv6, types.Dict),
			"tags":          llx.ArrayData(convert.SliceAnyToInterface(entry.Tags), types.String),
			"mac":           llx.StringData(mac),
			"mtu":           llx.IntData(mtu),
			"tcpipStack":    llx.StringData(tcpipStack),
			"dhcp":          llx.BoolData(dhcp),
			"portGroupName": llx.StringData(pgName),
			"portGroupMoid": llx.StringData(pgMoid),
			"services":      llx.ArrayData(services, types.String),
		})
		if err != nil {
			return nil, err
		}
		mqlVmknic.(*mqlVsphereVmknic).parentResource = v
		mqlVmknics[i] = mqlVmknic
	}

	return mqlVmknics, nil
}

// parseVibDate parses a VIB's date column (esxcli reports "2020-07-16"),
// returning nil for an empty or unparseable value. A single VIB with a missing
// date must not sink the whole host's package list, so we degrade that one
// field to null rather than erroring the accessor.
func parseVibDate(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil
	}
	return &t
}

func (v *mqlVsphereHost) packages() ([]any, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}
	vibs, err := esxiClient.Vibs()
	if err != nil {
		return nil, err
	}

	mqlPackages := make([]any, len(vibs))
	for i := range vibs {
		vib := vibs[i]

		mqlVib, err := CreateResource(v.MqlRuntime, "vsphere.host.vib", map[string]*llx.RawData{
			// __id must be host-scoped: a VIB ID is identical on every host
			// running the same ESXi build, so keying only on it would alias
			// (and clobber) the per-host installDate/status across hosts.
			"__id":            llx.StringData(esxiClient.InventoryPath + "/vib/" + vib.ID),
			"id":              llx.StringData(vib.ID),
			"name":            llx.StringData(vib.Name),
			"acceptanceLevel": llx.StringData(vib.AcceptanceLevel),
			"creationDate":    llx.TimeDataPtr(parseVibDate(vib.CreationDate)),
			"installDate":     llx.TimeDataPtr(parseVibDate(vib.InstallDate)),
			"status":          llx.StringData(vib.Status),
			"vendor":          llx.StringData(vib.Vendor),
			"version":         llx.StringData(vib.Version),
		})
		if err != nil {
			return nil, err
		}
		mqlPackages[i] = mqlVib
	}

	return mqlPackages, nil
}

func (v *mqlVsphereHost) acceptanceLevel() (string, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return "", err
	}
	return esxiClient.SoftwareAcceptance()
}

func (v *mqlVsphereHost) kernelModules() ([]any, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}
	modules, err := esxiClient.KernelModules()
	if err != nil {
		return nil, err
	}

	mqlModules := make([]any, len(modules))
	for i, m := range modules {
		mqlModule, err := CreateResource(v.MqlRuntime, "vsphere.host.kernelModule", map[string]*llx.RawData{
			"__id":                 llx.StringData(esxiClient.InventoryPath + "/" + m.Module),
			"name":                 llx.StringData(m.Module),
			"modulefile":           llx.StringData(m.ModuleFile),
			"version":              llx.StringData(m.Version),
			"loaded":               llx.BoolData(m.Loaded),
			"license":              llx.StringData(m.License),
			"enabled":              llx.BoolData(m.Enabled),
			"signedStatus":         llx.StringData(m.SignedStatus),
			"signatureDigest":      llx.StringData(m.SignatureDigest),
			"signatureFingerprint": llx.StringData(m.SignatureFingerPrint),
			"vibAcceptanceLevel":   llx.StringData(m.VIBAcceptanceLevel),
		})
		if err != nil {
			return nil, err
		}
		mqlModules[i] = mqlModule
	}

	return mqlModules, nil
}

func (v *mqlVsphereHost) advancedSettings() (map[string]any, error) {
	host, err := v.hostObject()
	if err != nil {
		return nil, err
	}
	return resourceclient.HostOptions(host)
}

// advancedSettingString looks up a single ESXi advanced (host option) value by
// key from the memoized advancedSettings map. The map stores every value as its
// fmt-formatted string, so callers parse from there. A missing key yields an
// empty string with ok=false, letting numeric resolvers fall back to a zero
// default rather than erroring on hosts that don't expose the setting.
func (v *mqlVsphereHost) advancedSettingString(key string) (value string, ok bool, err error) {
	settings := v.GetAdvancedSettings()
	if settings.Error != nil {
		return "", false, settings.Error
	}
	raw, found := settings.Data[key]
	if !found {
		return "", false, nil
	}
	s, _ := raw.(string)
	return s, true, nil
}

// advancedSettingInt resolves an integer-valued ESXi advanced setting, returning
// 0 when the key is absent or empty (the natural default for the lockout/timeout
// counters these back, where 0 already means "disabled").
func (v *mqlVsphereHost) advancedSettingInt(key string) (int64, error) {
	s, ok, err := v.advancedSettingString(key)
	if err != nil || !ok {
		return 0, err
	}
	return parseHostAdvancedSettingInt(key, s)
}

// parseHostAdvancedSettingInt converts a stringified ESXi advanced-setting value
// to an int64. An empty value (an unset option) reads as 0; a non-numeric value
// is a real error worth surfacing rather than silently zeroing.
func parseHostAdvancedSettingInt(key, s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("vsphere host advanced setting %q is not an integer %q: %w", key, s, err)
	}
	return n, nil
}

// parseHostBoolSetting interprets ESXi's stringified boolean options. vCenter
// renders the value as "true"/"false"; some builds surface "1"/"0".
func parseHostBoolSetting(s string) bool {
	return s == "true" || s == "1"
}

func (v *mqlVsphereHost) accountLockFailures() (int64, error) {
	return v.advancedSettingInt("Security.AccountLockFailures")
}

func (v *mqlVsphereHost) accountUnlockTime() (int64, error) {
	return v.advancedSettingInt("Security.AccountUnlockTime")
}

func (v *mqlVsphereHost) esxiShellInteractiveTimeOut() (int64, error) {
	return v.advancedSettingInt("UserVars.ESXiShellInteractiveTimeOut")
}

func (v *mqlVsphereHost) esxiShellTimeOut() (int64, error) {
	return v.advancedSettingInt("UserVars.ESXiShellTimeOut")
}

func (v *mqlVsphereHost) dcuiTimeOut() (int64, error) {
	return v.advancedSettingInt("UserVars.DcuiTimeOut")
}

func (v *mqlVsphereHost) memShareForceSalting() (int64, error) {
	return v.advancedSettingInt("Mem.ShareForceSalting")
}

// mobEnabled reports whether the Managed Object Browser is enabled. ESXi returns
// the option as a boolean, which advancedSettings stringifies to "true"/"false";
// older builds may surface "1"/"0", so both spellings are accepted.
func (v *mqlVsphereHost) mobEnabled() (bool, error) {
	s, ok, err := v.advancedSettingString("Config.HostAgent.plugins.solo.enableMob")
	if err != nil || !ok {
		return false, err
	}
	return parseHostBoolSetting(s), nil
}

func (v *mqlVsphereHost) syslogLogHost() (string, error) {
	s, _, err := v.advancedSettingString("Syslog.global.logHost")
	return s, err
}

func (v *mqlVsphereHost) syslogLogDir() (string, error) {
	s, _, err := v.advancedSettingString("Syslog.global.logDir")
	return s, err
}

func (v *mqlVsphereHost) dvFilterBindIpAddress() (string, error) {
	s, _, err := v.advancedSettingString("Net.DVFilterBindIpAddress")
	return s, err
}

func (v *mqlVsphereHost) services() ([]any, error) {
	path, host, err := v.pathAndHost()
	if err != nil {
		return nil, err
	}

	services, err := resourceclient.HostServices(host)
	if err != nil {
		return nil, err
	}
	mqlServices := make([]any, len(services))
	for i, s := range services {
		mqlService, err := CreateResource(v.MqlRuntime, "vsphere.host.service", map[string]*llx.RawData{
			"__id":     llx.StringData(path + "/" + s.Key),
			"key":      llx.StringData(s.Key),
			"label":    llx.StringData(s.Label),
			"required": llx.BoolData(s.Required),
			"running":  llx.BoolData(s.Running),
			"ruleset":  llx.ArrayData(convert.SliceAnyToInterface(s.Ruleset), types.String),
			"policy":   llx.StringData(s.Policy), // on, off, automatic
		})
		if err != nil {
			return nil, err
		}
		mqlServices[i] = mqlService
	}
	return mqlServices, nil
}

func (v *mqlVsphereHost) lockdownExceptions() ([]any, error) {
	_, host, err := v.pathAndHost()
	if err != nil {
		return nil, err
	}

	exceptions, err := resourceclient.HostLockdownExceptions(host)
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(exceptions), nil
}

func (v *mqlVsphereHost) timezone() (*mqlVsphereHostTimezone, error) {
	path, host, err := v.pathAndHost()
	if err != nil {
		return nil, err
	}

	datetimeinfo, err := resourceclient.HostDateTime(host)
	if err != nil {
		return nil, err
	}

	if datetimeinfo == nil {
		return nil, errors.New("vsphere does not return HostDateTimeSystem timezone information")
	}

	mqlTimezone, err := CreateResource(v.MqlRuntime, "vsphere.host.timezone", map[string]*llx.RawData{
		"__id":        llx.StringData(path + "/" + datetimeinfo.TimeZone.Key),
		"key":         llx.StringData(datetimeinfo.TimeZone.Key),
		"name":        llx.StringData(datetimeinfo.TimeZone.Name),
		"offset":      llx.IntData(int64(datetimeinfo.TimeZone.GmtOffset)),
		"description": llx.StringData(datetimeinfo.TimeZone.Description),
	})
	if err != nil {
		return nil, err
	}
	return mqlTimezone.(*mqlVsphereHostTimezone), nil
}

func (v *mqlVsphereHost) ntp() (*mqlVsphereHostNtpConfig, error) {
	path, host, err := v.pathAndHost()
	if err != nil {
		return nil, err
	}

	datetimeinfo, err := resourceclient.HostDateTime(host)
	if err != nil {
		return nil, err
	}

	var server []any
	var config []any

	if datetimeinfo != nil && datetimeinfo.NtpConfig != nil {
		server = convert.SliceAnyToInterface(datetimeinfo.NtpConfig.Server)
		config = convert.SliceAnyToInterface(datetimeinfo.NtpConfig.ConfigFile)
	}

	mqlNtpConfig, err := CreateResource(v.MqlRuntime, "vsphere.host.ntpConfig", map[string]*llx.RawData{
		"id":     llx.StringData("ntp/" + path),
		"server": llx.ArrayData(server, types.String),
		"config": llx.ArrayData(config, types.String),
	})
	if err != nil {
		return nil, err
	}

	return mqlNtpConfig.(*mqlVsphereHostNtpConfig), nil
}

func (v *mqlVsphereHost) snmp() (map[string]any, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}
	return esxiClient.Snmp()
}

func (v *mqlVsphereHost) security() (*mqlVsphereHostSecurity, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(v.MqlRuntime, "vsphere.host.security", map[string]*llx.RawData{
		"__id": llx.StringData(esxiClient.InventoryPath + "/security"),
	})
	if err != nil {
		return nil, err
	}

	security := res.(*mqlVsphereHostSecurity)
	security.hostInventoryPath = esxiClient.InventoryPath
	return security, nil
}

type mqlVsphereHostSecurityInternal struct {
	hostInventoryPath string
}

func (v *mqlVsphereHostSecurity) esxiClient() (*resourceclient.Esxi, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	return esxiClient(conn, v.hostInventoryPath)
}

func (v *mqlVsphereHostSecurity) keyPersistenceEnabled() (bool, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return false, err
	}
	return esxiClient.KeyPersistenceEnabled()
}

func (v *mqlVsphereHostSecurity) certificateStore() ([]any, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}

	store, err := esxiClient.CertificateStore()
	if err != nil {
		return nil, err
	}

	res := make([]any, len(store))
	for i := range store {
		res[i] = store[i]
	}
	return res, nil
}

func (v *mqlVsphereHost) ssh() (*mqlVsphereHostSsh, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(v.MqlRuntime, "vsphere.host.ssh", map[string]*llx.RawData{
		"__id": llx.StringData(esxiClient.InventoryPath + "/ssh"),
	})
	if err != nil {
		return nil, err
	}

	ssh := res.(*mqlVsphereHostSsh)
	ssh.hostInventoryPath = esxiClient.InventoryPath
	return ssh, nil
}

func (v *mqlVsphereHost) tlsServerProfile() (string, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return "", err
	}
	return esxiClient.TlsServerProfile()
}

type mqlVsphereHostSshInternal struct {
	hostInventoryPath string
}

func (v *mqlVsphereHostSsh) esxiClient() (*resourceclient.Esxi, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	return esxiClient(conn, v.hostInventoryPath)
}

func (v *mqlVsphereHostSsh) serverConfig() (map[string]any, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}
	config, err := esxiClient.SshServerConfig()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(config), nil
}

func (v *mqlVsphereHostSsh) clientConfig() (map[string]any, error) {
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}
	config, err := esxiClient.SshClientConfig()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(config), nil
}

// firewallRulesets exposes the per-service ESXi firewall ruleset definitions
// from mo.HostSystem.Config.Firewall (already fetched via HostInfo). Each
// ruleset bundles a per-service rule list, an enabled flag, and the
// allowed-IP scope; the global default-deny posture lives on
// vsphere.host.firewallIncomingBlocked / firewallOutgoingBlocked.
func (v *mqlVsphereHost) firewallRulesets() ([]any, error) {
	if v.host == nil || v.host.Config == nil || v.host.Config.Firewall == nil {
		return []any{}, nil
	}
	// Prefer the readable inventory path, but fall back to the host moid (always
	// unique) so the sub-resource __ids can never collapse to "/..." and alias
	// across hosts if InventoryPath is unset.
	hostPath := v.Moid.Data
	if v.InventoryPath.Error == nil && v.InventoryPath.Data != "" {
		hostPath = v.InventoryPath.Data
	}

	mqlRulesets := make([]any, 0, len(v.host.Config.Firewall.Ruleset))
	for _, rs := range v.host.Config.Firewall.Ruleset {
		rsId := hostPath + "/firewall/" + rs.Key

		allIp := false
		allowedIPs := []any{}
		allowedNetworks := []any{}
		if rs.AllowedHosts != nil {
			allIp = rs.AllowedHosts.AllIp
			for _, ip := range rs.AllowedHosts.IpAddress {
				allowedIPs = append(allowedIPs, ip)
			}
			for _, n := range rs.AllowedHosts.IpNetwork {
				allowedNetworks = append(allowedNetworks, map[string]any{
					"network":      n.Network,
					"prefixLength": int64(n.PrefixLength),
				})
			}
		}

		mqlRules := make([]any, len(rs.Rule))
		for i, r := range rs.Rule {
			// Build a stable key from the rule's natural fields rather than
			// the slice index — vCenter doesn't guarantee Config.Firewall.Ruleset[].Rule
			// ordering across calls, and an index-based __id would
			// re-create resources on every refetch. Two rules with an
			// identical (port, endPort, protocol, direction, portType) tuple
			// describe the same firewall opening — collapsing them onto a
			// single cached resource is the desired behavior, not a bug.
			ruleKey := strconv.Itoa(int(r.Port)) + "-" + strconv.Itoa(int(r.EndPort)) +
				"-" + r.Protocol + "-" + string(r.Direction) + "-" + string(r.PortType)
			ruleId := rsId + "/" + ruleKey
			mqlRule, err := CreateResource(v.MqlRuntime, "vsphere.host.firewallRule", map[string]*llx.RawData{
				"__id":      llx.StringData(ruleId),
				"id":        llx.StringData(ruleId),
				"port":      llx.IntData(int64(r.Port)),
				"endPort":   llx.IntData(int64(r.EndPort)),
				"direction": llx.StringData(string(r.Direction)),
				"portType":  llx.StringData(string(r.PortType)),
				"protocol":  llx.StringData(r.Protocol),
			})
			if err != nil {
				return nil, err
			}
			mqlRules[i] = mqlRule
		}

		mqlRs, err := CreateResource(v.MqlRuntime, "vsphere.host.firewallRuleset", map[string]*llx.RawData{
			"__id":               llx.StringData(rsId),
			"id":                 llx.StringData(rsId),
			"key":                llx.StringData(rs.Key),
			"label":              llx.StringData(rs.Label),
			"enabled":            llx.BoolData(rs.Enabled),
			"required":           llx.BoolData(rs.Required),
			"service":            llx.StringData(rs.Service),
			"allIpsAllowed":      llx.BoolData(allIp),
			"allowedIpAddresses": llx.ArrayData(allowedIPs, types.String),
			"allowedIpNetworks":  llx.ArrayData(allowedNetworks, types.Dict),
			"rules":              llx.ArrayData(mqlRules, types.Resource("vsphere.host.firewallRule")),
		})
		if err != nil {
			return nil, err
		}
		mqlRulesets = append(mqlRulesets, mqlRs)
	}
	return mqlRulesets, nil
}

// iscsiAdapters lists iSCSI host bus adapters from
// mo.HostSystem.Config.StorageDevice.HostBusAdapter, exposing the IQN and
// CHAP authentication posture. The CHAP secret itself is intentionally NOT
// exposed — only the policy and the username.
func (v *mqlVsphereHost) iscsiAdapters() ([]any, error) {
	if v.host == nil || v.host.Config == nil || v.host.Config.StorageDevice == nil {
		return []any{}, nil
	}
	// Prefer the readable inventory path, but fall back to the host moid (always
	// unique) so the sub-resource __ids can never collapse to "/..." and alias
	// across hosts if InventoryPath is unset.
	hostPath := v.Moid.Data
	if v.InventoryPath.Error == nil && v.InventoryPath.Data != "" {
		hostPath = v.InventoryPath.Data
	}

	mqlAdapters := []any{}
	for _, ba := range v.host.Config.StorageDevice.HostBusAdapter {
		hba, ok := ba.(*vimtypes.HostInternetScsiHba)
		if !ok || hba == nil {
			continue
		}
		auth := hba.AuthenticationProperties
		id := hostPath + "/iscsi/" + hba.Device
		mqlAdapter, err := CreateResource(v.MqlRuntime, "vsphere.host.iscsiAdapter", map[string]*llx.RawData{
			"__id":                         llx.StringData(id),
			"id":                           llx.StringData(id),
			"device":                       llx.StringData(hba.Device),
			"iScsiName":                    llx.StringData(hba.IScsiName),
			"iScsiAlias":                   llx.StringData(hba.IScsiAlias),
			"chapAuthEnabled":              llx.BoolData(auth.ChapAuthEnabled),
			"chapAuthenticationType":       llx.StringData(auth.ChapAuthenticationType),
			"chapName":                     llx.StringData(auth.ChapName),
			"mutualChapAuthenticationType": llx.StringData(auth.MutualChapAuthenticationType),
			"mutualChapName":               llx.StringData(auth.MutualChapName),
		})
		if err != nil {
			return nil, err
		}
		mqlAdapters = append(mqlAdapters, mqlAdapter)
	}
	return mqlAdapters, nil
}

func (v *mqlVsphereHost) certificate() (*mqlVsphereHostCertificate, error) {
	path, host, err := v.pathAndHost()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	certMgr, err := host.ConfigManager().CertificateManager(ctx)
	if err != nil {
		return nil, err
	}
	// Older ESXi versions (and some host states) don't expose a
	// HostCertificateManager; CertificateManager returns (nil, nil).
	// Mark the field resolved-and-null so the runtime doesn't panic
	// or re-fetch.
	if certMgr == nil {
		v.Certificate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	info, err := certMgr.CertificateInfo(ctx)
	if err != nil {
		return nil, err
	}

	id := "cert/" + path
	if info.Kind != "" {
		id += "/" + info.Kind
	}
	args := map[string]*llx.RawData{
		"__id":    llx.StringData(id),
		"id":      llx.StringData(id),
		"kind":    llx.StringData(info.Kind),
		"subject": llx.StringData(info.Subject),
		"issuer":  llx.StringData(info.Issuer),
		"status":  llx.StringData(info.Status),
	}
	if info.NotBefore != nil {
		args["notBefore"] = llx.TimeData(*info.NotBefore)
	} else {
		args["notBefore"] = llx.TimeData(time.Time{})
	}
	if info.NotAfter != nil {
		args["notAfter"] = llx.TimeData(*info.NotAfter)
	} else {
		args["notAfter"] = llx.TimeData(time.Time{})
	}

	mqlCert, err := CreateResource(v.MqlRuntime, "vsphere.host.certificate", args)
	if err != nil {
		return nil, err
	}
	return mqlCert.(*mqlVsphereHostCertificate), nil
}
