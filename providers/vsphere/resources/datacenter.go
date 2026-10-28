// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25/mo"
	vimtypes "github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/vsphere/connection"
	"go.mondoo.com/mql/providers/vsphere/resources/resourceclient"
	"go.mondoo.com/mql/types"
	"golang.org/x/sync/errgroup"
)

// mqlVsphereClusterInternal caches the underlying ClusterComputeResource so
// cross-reference accessors (e.g. cluster.hosts()) can avoid redundant fetches.
// `clusterOnce` makes the post-CreateResource population race-free when the
// same cluster resource is reached via multiple discovery paths.
type mqlVsphereClusterInternal struct {
	cluster     *mo.ClusterComputeResource
	clusterOnce sync.Once
}

func (v *mqlVsphereCluster) setCluster(c *mo.ClusterComputeResource) {
	v.clusterOnce.Do(func() {
		v.cluster = c
	})
}

// mqlVsphereDatastoreInternal caches the Datastore mo so cross-reference
// accessors (datastore.vms(), datastore.hosts()) can resolve typed refs from
// already-fetched property data. `dsOnce` is the same first-write-wins guard
// described on mqlVsphereClusterInternal.
type mqlVsphereDatastoreInternal struct {
	ds     *mo.Datastore
	dsOnce sync.Once
}

func (v *mqlVsphereDatastore) setDs(d *mo.Datastore) {
	v.dsOnce.Do(func() {
		v.ds = d
	})
}

// countSnapshots returns the total snapshot count in a VM's snapshot tree
// (including nested children). 0 if info is nil.
func countSnapshots(info *vimtypes.VirtualMachineSnapshotInfo) int {
	if info == nil {
		return 0
	}
	var walk func(nodes []vimtypes.VirtualMachineSnapshotTree) int
	walk = func(nodes []vimtypes.VirtualMachineSnapshotTree) int {
		n := len(nodes)
		for i := range nodes {
			n += walk(nodes[i].ChildSnapshotList)
		}
		return n
	}
	return walk(info.RootSnapshotList)
}

// discoveryConcurrency caps the number of concurrent per-asset SOAP calls we
// fan out during host/VM enumeration. Higher = lower wall-clock for a single
// discovery, but vCenter rate-limits concurrent sessions and the gain
// flattens past ~16 workers.
const discoveryConcurrency = 16

// stagedHost holds the per-host data fetched in the concurrent stage of
// newVsphereHostResources, before the sequential CreateResource pass.
type stagedHost struct {
	hostInfo                *mo.HostSystem
	props                   map[string]any
	name                    string
	tags                    []string
	lockdownMode            string
	firewallIncomingBlocked bool
	firewallOutgoingBlocked bool
	secureBootEnabled       bool
	bootTime                *time.Time
	inMaintenanceMode       bool
	rebootRequired          bool
	vendor                  string
	model                   string
	cpuMhz                  int64
	numCpuCores             int64
}

func newVsphereHostResources(vClient *resourceclient.Client, runtime *plugin.Runtime, vhosts []*object.HostSystem) ([]any, error) {
	conn := runtime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()

	hostRefs := make([]mo.Reference, len(vhosts))
	for i, h := range vhosts {
		hostRefs[i] = h.Reference()
	}
	vapiTagsByMoid := BatchGetTags(ctx, hostRefs, conn)

	// Stage 1 — concurrent fetch of per-host data (SOAP + JSON marshaling).
	// CreateResource is held back to stage 2 because it touches the runtime
	// resource cache, which we keep single-threaded.
	staged := make([]stagedHost, len(vhosts))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(discoveryConcurrency)
	for i, h := range vhosts {
		g.Go(func() error {
			hostInfo, err := resourceclient.HostInfo(gctx, h)
			if err != nil {
				return err
			}
			props, err := resourceclient.HostProperties(hostInfo)
			if err != nil {
				return err
			}

			s := stagedHost{hostInfo: hostInfo, props: props}
			if hostInfo != nil {
				s.name = hostInfo.Name
			}
			if vapi := vapiTagsByMoid[h.Reference().Value]; len(vapi) > 0 {
				s.tags = vapi
			} else if hostInfo != nil {
				s.tags = extractTagKeys(hostInfo.Tag)
			}
			s.lockdownMode, s.firewallIncomingBlocked, s.firewallOutgoingBlocked, s.secureBootEnabled = hostHardeningArgs(hostInfo)
			s.bootTime, s.inMaintenanceMode, s.rebootRequired = hostRuntimeArgs(hostInfo)
			if hostInfo != nil {
				hw := hostInfo.Summary.Hardware
				if hw != nil {
					s.vendor = hw.Vendor
					s.model = hw.Model
					s.cpuMhz = int64(hw.CpuMhz)
					s.numCpuCores = int64(hw.NumCpuCores)
				}
			}
			staged[i] = s
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Stage 2 — sequential CreateResource pass.
	mqlHosts := make([]any, len(vhosts))
	for i, s := range staged {
		h := vhosts[i]
		mqlHost, err := CreateResource(runtime, "vsphere.host", map[string]*llx.RawData{
			"moid":                    llx.StringData(h.Reference().Encode()),
			"name":                    llx.StringData(s.name),
			"properties":              llx.DictData(s.props),
			"inventoryPath":           llx.StringData(h.InventoryPath),
			"tags":                    llx.ArrayData(convert.SliceAnyToInterface(s.tags), types.String),
			"lockdownMode":            llx.StringData(s.lockdownMode),
			"firewallIncomingBlocked": llx.BoolData(s.firewallIncomingBlocked),
			"firewallOutgoingBlocked": llx.BoolData(s.firewallOutgoingBlocked),
			"secureBootEnabled":       llx.BoolData(s.secureBootEnabled),
			"bootTime":                llx.TimeDataPtr(s.bootTime),
			"inMaintenanceMode":       llx.BoolData(s.inMaintenanceMode),
			"rebootRequired":          llx.BoolData(s.rebootRequired),
			"vendor":                  llx.StringData(s.vendor),
			"model":                   llx.StringData(s.model),
			"cpuMhz":                  llx.IntData(s.cpuMhz),
			"numCpuCores":             llx.IntData(s.numCpuCores),
		})
		if err != nil {
			return nil, err
		}
		mqlHost.(*mqlVsphereHost).setHost(s.hostInfo)
		mqlHosts[i] = mqlHost
	}
	return mqlHosts, nil
}

func (v *mqlVsphereDatacenter) id() (string, error) {
	return v.Moid.Data, nil
}

func (v *mqlVsphereDatacenter) hosts() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	client := getClientInstance(conn)

	if v.InventoryPath.Error != nil {
		return nil, v.InventoryPath.Error
	}
	path := v.InventoryPath.Data

	dc, err := client.Datacenter(path)
	if err != nil {
		return nil, err
	}

	vhosts, err := client.ListHosts(dc, nil)
	if err != nil {
		return nil, fmt.Errorf("error listing hosts for datacenter %s: %w", dc.InventoryPath, err)
	}
	return newVsphereHostResources(client, v.MqlRuntime, vhosts)
}

func (v *mqlVsphereDatacenter) clusters() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	client := getClientInstance(conn)

	if v.InventoryPath.Error != nil {
		return nil, v.InventoryPath.Error
	}
	path := v.InventoryPath.Data

	dc, err := client.Datacenter(path)
	if err != nil {
		return nil, err
	}

	vCluster, err := client.ListClusters(dc)
	if err != nil {
		return nil, err
	}

	mqlClusters := make([]any, len(vCluster))
	for i, c := range vCluster {
		moc, err := resourceclient.ClusterInfo(context.Background(), c)
		if err != nil {
			return nil, err
		}

		props, err := resourceclient.PropertiesToDict(moc)
		if err != nil {
			return nil, err
		}

		vsanEnabled, haEnabled, drsEnabled := false, false, false
		if cfg, ok := moc.ConfigurationEx.(*vimtypes.ClusterConfigInfoEx); ok && cfg != nil {
			if cfg.VsanConfigInfo != nil && cfg.VsanConfigInfo.Enabled != nil {
				vsanEnabled = *cfg.VsanConfigInfo.Enabled
			}
			if cfg.DasConfig.Enabled != nil {
				haEnabled = *cfg.DasConfig.Enabled
			}
			if cfg.DrsConfig.Enabled != nil {
				drsEnabled = *cfg.DrsConfig.Enabled
			}
		}
		evcMode := ""
		if sum, ok := moc.Summary.(*vimtypes.ClusterComputeResourceSummary); ok && sum != nil {
			evcMode = sum.CurrentEVCModeKey
		}

		mqlCluster, err := CreateResource(v.MqlRuntime, "vsphere.cluster", map[string]*llx.RawData{
			"moid":          llx.StringData(c.Reference().Encode()),
			"name":          llx.StringData(c.Name()),
			"properties":    llx.DictData(props),
			"inventoryPath": llx.StringData(c.InventoryPath),
			"vsanEnabled":   llx.BoolData(vsanEnabled),
			"haEnabled":     llx.BoolData(haEnabled),
			"drsEnabled":    llx.BoolData(drsEnabled),
			"evcMode":       llx.StringData(evcMode),
		})
		if err != nil {
			return nil, err
		}
		mqlCluster.(*mqlVsphereCluster).setCluster(moc)

		mqlClusters[i] = mqlCluster
	}

	return mqlClusters, nil
}

func (v *mqlVsphereCluster) id() (string, error) {
	return v.Moid.Data, nil
}

func (v *mqlVsphereCluster) hosts() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	client := getClientInstance(conn)

	if v.InventoryPath.Error != nil {
		return nil, v.InventoryPath.Error
	}
	path := v.InventoryPath.Data

	cluster, err := client.Cluster(path)
	if err != nil {
		return nil, err
	}

	vhosts, err := client.ListHosts(nil, cluster)
	if err != nil {
		return nil, err
	}
	return newVsphereHostResources(client, v.MqlRuntime, vhosts)
}

func (v *mqlVsphereDatacenter) vms() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	vClient := getClientInstance(conn)

	if v.InventoryPath.Error != nil {
		return nil, v.InventoryPath.Error
	}
	path := v.InventoryPath.Data

	dc, err := vClient.Datacenter(path)
	if err != nil {
		return nil, err
	}

	vms, err := vClient.ListVirtualMachines(dc)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	vmRefs := make([]mo.Reference, len(vms))
	for i, vm := range vms {
		vmRefs[i] = vm.Reference()
	}
	vapiTagsByMoid := BatchGetTags(ctx, vmRefs, conn)

	// Stage 1 — concurrent VmInfo + VmProperties for each VM.
	type stagedVm struct {
		vmInfo *mo.VirtualMachine
		props  map[string]any
		tags   []string
	}
	staged := make([]stagedVm, len(vms))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(discoveryConcurrency)
	for i, vm := range vms {
		g.Go(func() error {
			vmInfo, err := resourceclient.VmInfo(gctx, vm)
			if err != nil {
				return err
			}
			props, err := resourceclient.VmProperties(vmInfo)
			if err != nil {
				return err
			}

			s := stagedVm{vmInfo: vmInfo, props: props}
			if vapi := vapiTagsByMoid[vm.Reference().Value]; len(vapi) > 0 {
				s.tags = vapi
			} else if vmInfo != nil {
				s.tags = extractTagKeys(vmInfo.Tag)
			}
			staged[i] = s
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Stage 2 — sequential CreateResource pass.
	mqlVms := make([]any, len(vms))
	for i, s := range staged {
		vm := vms[i]
		var (
			name                                  string
			bootFirmware                          string
			secureBootEnabled, vbsEnabled         bool
			cpuHotAddEnabled, memoryHotAddEnabled bool
			numCpu, memoryMB                      int64
			powerState                            string
			annotation                            string
			createDate                            time.Time
			numSnapshots                          int64
			vmwareToolsRunning                    bool
			vmwareToolsVersion                    string
			guestIpAddress                        string
			guestHostname                         string
			encrypted, vtpmPresent                bool
			encryptionKeyId                       string
			instanceUuid, biosUuid                string
			template                              bool
		)
		if s.vmInfo != nil {
			powerState = string(s.vmInfo.Runtime.PowerState)
			numSnapshots = int64(countSnapshots(s.vmInfo.Snapshot))
			if s.vmInfo.Guest != nil {
				vmwareToolsRunning = s.vmInfo.Guest.ToolsRunningStatus == string(vimtypes.VirtualMachineToolsRunningStatusGuestToolsRunning)
				vmwareToolsVersion = s.vmInfo.Guest.ToolsVersion
				guestIpAddress = s.vmInfo.Guest.IpAddress
				guestHostname = s.vmInfo.Guest.HostName
			}
			if s.vmInfo.Config != nil {
				cfg := s.vmInfo.Config
				name = cfg.Name
				annotation = cfg.Annotation
				if cfg.CreateDate != nil {
					createDate = *cfg.CreateDate
				}
				bootFirmware = cfg.Firmware
				if cfg.BootOptions != nil && cfg.BootOptions.EfiSecureBootEnabled != nil {
					secureBootEnabled = *cfg.BootOptions.EfiSecureBootEnabled
				}
				if cfg.Flags.VbsEnabled != nil {
					vbsEnabled = *cfg.Flags.VbsEnabled
				}
				if cfg.CpuHotAddEnabled != nil {
					cpuHotAddEnabled = *cfg.CpuHotAddEnabled
				}
				if cfg.MemoryHotAddEnabled != nil {
					memoryHotAddEnabled = *cfg.MemoryHotAddEnabled
				}
				numCpu = int64(cfg.Hardware.NumCPU)
				memoryMB = int64(cfg.Hardware.MemoryMB)
				if cfg.KeyId != nil {
					encrypted = true
					encryptionKeyId = cfg.KeyId.KeyId
				}
				instanceUuid = cfg.InstanceUuid
				biosUuid = cfg.Uuid
				template = cfg.Template
				for _, dev := range cfg.Hardware.Device {
					if _, ok := dev.(*vimtypes.VirtualTPM); ok {
						vtpmPresent = true
						break
					}
				}
			}
		}
		var cfgSettings vmConfigSettings
		if s.vmInfo != nil {
			cfgSettings = vmConfigSettingsFrom(s.vmInfo.Config)
		}
		mqlVm, err := CreateResource(v.MqlRuntime, "vsphere.vm", map[string]*llx.RawData{
			"moid":                llx.StringData(vm.Reference().Encode()),
			"name":                llx.StringData(name),
			"properties":          llx.DictData(s.props),
			"inventoryPath":       llx.StringData(vm.InventoryPath),
			"tags":                llx.ArrayData(convert.SliceAnyToInterface(s.tags), types.String),
			"bootFirmware":        llx.StringData(bootFirmware),
			"secureBootEnabled":   llx.BoolData(secureBootEnabled),
			"vbsEnabled":          llx.BoolData(vbsEnabled),
			"encrypted":           llx.BoolData(encrypted),
			"encryptionKeyId":     llx.StringData(encryptionKeyId),
			"vtpmPresent":         llx.BoolData(vtpmPresent),
			"numCpu":              llx.IntData(numCpu),
			"memoryMB":            llx.IntData(memoryMB),
			"cpuHotAddEnabled":    llx.BoolData(cpuHotAddEnabled),
			"memoryHotAddEnabled": llx.BoolData(memoryHotAddEnabled),
			"powerState":          llx.StringData(powerState),
			"annotation":          llx.StringData(annotation),
			"createDate":          llx.TimeData(createDate),
			"numSnapshots":        llx.IntData(numSnapshots),
			"vmwareToolsRunning":  llx.BoolData(vmwareToolsRunning),
			"vmwareToolsVersion":  llx.StringData(vmwareToolsVersion),
			"guestIpAddress":      llx.StringData(guestIpAddress),
			"guestHostname":       llx.StringData(guestHostname),
			"instanceUuid":        llx.StringData(instanceUuid),
			"biosUuid":            llx.StringData(biosUuid),
			"template":            llx.BoolData(template),
			"hardwareVersion":     llx.StringDataPtr(cfgSettings.hardwareVersion),
			"guestId":             llx.StringDataPtr(cfgSettings.guestId),
			"migrateEncryption":   llx.StringDataPtr(cfgSettings.migrateEncryption),
			"ftEncryptionMode":    llx.StringDataPtr(cfgSettings.ftEncryptionMode),
			"loggingEnabled":      llx.BoolDataPtr(cfgSettings.loggingEnabled),
			"toolsUpgradePolicy":  llx.StringDataPtr(cfgSettings.toolsUpgradePolicy),
		})
		if err != nil {
			return nil, err
		}
		mqlVm.(*mqlVsphereVm).setVm(s.vmInfo)
		mqlVms[i] = mqlVm
	}
	return mqlVms, nil
}

func (v *mqlVsphereDatacenter) distributedSwitches() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	client := getClientInstance(conn)

	if v.InventoryPath.Error != nil {
		return nil, v.InventoryPath.Error
	}
	path := v.InventoryPath.Data
	if path == "" {
		path = "/"
	}

	vswitches, err := client.GetDistributedVirtualSwitches(context.Background(), path)
	if err != nil {
		return nil, err
	}

	mqlVswitches := make([]any, len(vswitches))
	for i, s := range vswitches {

		config, err := client.GetDistributedVirtualSwitchConfig(context.Background(), s)
		if err != nil {
			return nil, err
		}
		configMap, err := resourceclient.DistributedVirtualSwitchConfig(config)
		if err != nil {
			return nil, err
		}

		var createDate *time.Time
		if config.Config != nil {
			t := config.Config.GetDVSConfigInfo().CreateTime
			createDate = &t
		}

		settings := dvsSettingsFrom(config.Config, config.Summary.ProductInfo)

		mqlVswitch, err := CreateResource(v.MqlRuntime, "vsphere.vswitch.dvs", map[string]*llx.RawData{
			"moid":                   llx.StringData(s.Reference().Encode()),
			"name":                   llx.StringData(s.Name()),
			"properties":             llx.DictData(configMap),
			"createDate":             llx.TimeDataPtr(createDate),
			"version":                llx.StringDataPtr(settings.version),
			"maxMtu":                 llx.IntDataPtr(settings.maxMtu),
			"linkDiscoveryProtocol":  llx.StringDataPtr(settings.linkDiscoveryProtocol),
			"linkDiscoveryOperation": llx.StringDataPtr(settings.linkDiscoveryOperation),
			"netflowEnabled":         llx.BoolDataPtr(settings.netflowEnabled),
			"netflowCollectorIp":     llx.StringDataPtr(settings.netflowCollectorIp),
			"healthCheckEnabled":     llx.BoolDataPtr(settings.healthCheckEnabled),
		})
		if err != nil {
			return nil, err
		}

		// store host inventory path, so that sub resources can use that to quickly query more
		r := mqlVswitch.(*mqlVsphereVswitchDvs)
		r.hostInventoryPath = s.InventoryPath
		r.cacheVspanSessions = resourceclient.VspanSessions(config)
		r.cacheDefaultSecurityPolicy = settings.defaultSecurityPolicy

		mqlVswitches[i] = mqlVswitch
	}

	return mqlVswitches, nil
}

func (v *mqlVsphereDatacenter) distributedPortGroups() ([]any, error) {
	if v.InventoryPath.Error != nil {
		return nil, v.InventoryPath.Error
	}
	path := v.InventoryPath.Data
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	client := resourceclient.New(conn.Client())

	distPGs, err := client.GetDistributedVirtualPortgroups(context.Background(), path)
	if err != nil {
		return nil, err
	}

	mqlPGs := make([]any, len(distPGs))
	for i, distPG := range distPGs {
		config, err := client.GetDistributedVirtualPortgroupConfig(context.Background(), distPG)
		if err != nil {
			return nil, err
		}

		configMap, err := resourceclient.DistributedVirtualPortgroupConfig(config)
		if err != nil {
			return nil, err
		}

		// Extract a single VLAN ID for the simple-tag case. Trunked /
		// private-VLAN configurations leave vlanId at 0 — callers can
		// inspect `properties` for the full VLAN spec.
		var vlanId int64
		var portCfgPtr *vimtypes.VMwareDVSPortSetting
		if portCfg, ok := config.Config.DefaultPortConfig.(*vimtypes.VMwareDVSPortSetting); ok && portCfg != nil {
			portCfgPtr = portCfg
			if vlan, ok := portCfg.Vlan.(*vimtypes.VmwareDistributedVirtualSwitchVlanIdSpec); ok && vlan != nil {
				vlanId = int64(vlan.VlanId)
			}
		}

		// PortConfigResetAtDisconnect comes from the port group's policy
		// (Config.Policy), not its DefaultPortConfig.
		var portConfigResetAtDisconnect bool
		if config.Config.Policy != nil {
			portConfigResetAtDisconnect = config.Config.Policy.GetDVPortgroupPolicy().PortConfigResetAtDisconnect
		}

		pgSettings := dvPortgroupSettingsFrom(&config.Config)

		name := distPG.Name()
		mqlDistPG, err := NewResource(v.MqlRuntime, "vsphere.vswitch.portgroup", map[string]*llx.RawData{
			"moid":                          llx.StringData(distPG.Reference().Encode()),
			"name":                          llx.StringData(name),
			"properties":                    llx.DictData(configMap),
			"vlanId":                        llx.IntData(vlanId),
			"portConfigResetAtDisconnect":   llx.BoolData(portConfigResetAtDisconnect),
			"portBinding":                   llx.StringData(pgSettings.portBinding),
			"blocked":                       llx.BoolDataPtr(pgSettings.blocked),
			"vlanTrunkRanges":               llx.ArrayData(stringsToAny(pgSettings.vlanTrunkRanges), types.String),
			"securityPolicyOverrideAllowed": llx.BoolDataPtr(pgSettings.securityPolicyOverrideAllowed),
			"vlanOverrideAllowed":           llx.BoolDataPtr(pgSettings.vlanOverrideAllowed),
			"macManagementOverrideAllowed":  llx.BoolDataPtr(pgSettings.macManagementOverrideAllowed),
			"uplinkTeamingOverrideAllowed":  llx.BoolDataPtr(pgSettings.uplinkTeamingOverrideAllowed),
		})
		if err != nil {
			return nil, err
		}

		pg := mqlDistPG.(*mqlVsphereVswitchPortgroup)
		pg.defaultPortConfig = portCfgPtr
		mqlPGs[i] = pg
	}

	return mqlPGs, nil
}

func (v *mqlVsphereDatacenter) datastores() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	vClient := getClientInstance(conn)

	if v.InventoryPath.Error != nil {
		return nil, v.InventoryPath.Error
	}
	path := v.InventoryPath.Data

	dc, err := vClient.Datacenter(path)
	if err != nil {
		return nil, err
	}

	finder := find.NewFinder(vClient.Client.Client, true)
	finder.SetDatacenter(dc)
	ctx := context.Background()
	dsList, err := finder.DatastoreList(ctx, "*")
	if err != nil {
		if resourceclient.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("error listing datastores for datacenter %s: %w", dc.InventoryPath, err)
	}

	mqlDss := make([]any, len(dsList))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(discoveryConcurrency)
	type stagedDs struct {
		moid        string
		props       *mo.Datastore
		path        string
		vmfsVersion string
		ssd         bool
	}
	staged := make([]stagedDs, len(dsList))
	for i, ds := range dsList {
		g.Go(func() error {
			// "vm" and "host" power the datastore.vms()/hosts() cross-references;
			// they're cheap to include in the same property fetch.
			var props mo.Datastore
			if err := ds.Properties(gctx, ds.Reference(), []string{"summary", "info", "vm", "host"}, &props); err != nil {
				return err
			}
			vmfsVersion := ""
			ssd := false
			if vmfsInfo, ok := props.Info.(*vimtypes.VmfsDatastoreInfo); ok && vmfsInfo != nil && vmfsInfo.Vmfs != nil {
				vmfsVersion = vmfsInfo.Vmfs.Version
				if vmfsInfo.Vmfs.Ssd != nil {
					ssd = *vmfsInfo.Vmfs.Ssd
				}
			}
			staged[i] = stagedDs{
				moid:        ds.Reference().Encode(),
				props:       &props,
				path:        ds.InventoryPath,
				vmfsVersion: vmfsVersion,
				ssd:         ssd,
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	for i, s := range staged {
		multi := false
		summary := s.props.Summary
		if summary.MultipleHostAccess != nil {
			multi = *summary.MultipleHostAccess
		}
		mqlDs, err := CreateResource(v.MqlRuntime, "vsphere.datastore", map[string]*llx.RawData{
			"moid":               llx.StringData(s.moid),
			"name":               llx.StringData(summary.Name),
			"type":               llx.StringData(summary.Type),
			"capacity":           llx.IntData(summary.Capacity),
			"freeSpace":          llx.IntData(summary.FreeSpace),
			"uncommitted":        llx.IntData(summary.Uncommitted),
			"accessible":         llx.BoolData(summary.Accessible),
			"multipleHostAccess": llx.BoolData(multi),
			"maintenanceMode":    llx.StringData(summary.MaintenanceMode),
			"url":                llx.StringData(summary.Url),
			"inventoryPath":      llx.StringData(s.path),
			"vmfsVersion":        llx.StringData(s.vmfsVersion),
			"ssd":                llx.BoolData(s.ssd),
		})
		if err != nil {
			return nil, err
		}
		mqlDs.(*mqlVsphereDatastore).setDs(s.props)
		mqlDss[i] = mqlDs
	}
	return mqlDss, nil
}

func (v *mqlVsphereDatacenter) resourcePools() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	vClient := getClientInstance(conn)

	if v.InventoryPath.Error != nil {
		return nil, v.InventoryPath.Error
	}
	dc, err := vClient.Datacenter(v.InventoryPath.Data)
	if err != nil {
		return nil, err
	}

	finder := find.NewFinder(vClient.Client.Client, true)
	finder.SetDatacenter(dc)
	ctx := context.Background()
	pools, err := finder.ResourcePoolList(ctx, "*")
	if err != nil {
		if resourceclient.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("error listing resource pools for datacenter %s: %w", dc.InventoryPath, err)
	}

	mqlPools := make([]any, len(pools))
	for i, p := range pools {
		pctx, cancel := context.WithTimeout(context.Background(), resourceclient.DefaultAPITimeout)
		var props mo.ResourcePool
		err := p.Properties(pctx, p.Reference(), []string{"config"}, &props)
		cancel()
		if err != nil {
			return nil, err
		}
		cfg := props.Config

		// Translate the SharesInfo. SDK has Shares.Level (string-typed enum)
		// and Shares.Shares (int32, only meaningful when Level == "custom").
		cpuShareLevel, cpuShares := "", int64(0)
		if cfg.CpuAllocation.Shares != nil {
			cpuShareLevel = string(cfg.CpuAllocation.Shares.Level)
			cpuShares = int64(cfg.CpuAllocation.Shares.Shares)
		}
		memShareLevel, memShares := "", int64(0)
		if cfg.MemoryAllocation.Shares != nil {
			memShareLevel = string(cfg.MemoryAllocation.Shares.Level)
			memShares = int64(cfg.MemoryAllocation.Shares.Shares)
		}
		cpuExpandable := false
		if cfg.CpuAllocation.ExpandableReservation != nil {
			cpuExpandable = *cfg.CpuAllocation.ExpandableReservation
		}
		memExpandable := false
		if cfg.MemoryAllocation.ExpandableReservation != nil {
			memExpandable = *cfg.MemoryAllocation.ExpandableReservation
		}
		var cpuReservation, cpuLimit, memReservation, memLimit int64
		if cfg.CpuAllocation.Reservation != nil {
			cpuReservation = *cfg.CpuAllocation.Reservation
		}
		if cfg.CpuAllocation.Limit != nil {
			cpuLimit = *cfg.CpuAllocation.Limit
		}
		if cfg.MemoryAllocation.Reservation != nil {
			memReservation = *cfg.MemoryAllocation.Reservation
		}
		if cfg.MemoryAllocation.Limit != nil {
			memLimit = *cfg.MemoryAllocation.Limit
		}

		mqlPool, err := CreateResource(v.MqlRuntime, "vsphere.resourcepool", map[string]*llx.RawData{
			"moid":                        llx.StringData(p.Reference().Encode()),
			"name":                        llx.StringData(p.Name()),
			"inventoryPath":               llx.StringData(p.InventoryPath),
			"cpuReservationMhz":           llx.IntData(cpuReservation),
			"cpuLimitMhz":                 llx.IntData(cpuLimit),
			"cpuExpandableReservation":    llx.BoolData(cpuExpandable),
			"cpuShareLevel":               llx.StringData(cpuShareLevel),
			"cpuShares":                   llx.IntData(cpuShares),
			"memoryReservationMB":         llx.IntData(memReservation),
			"memoryLimitMB":               llx.IntData(memLimit),
			"memoryExpandableReservation": llx.BoolData(memExpandable),
			"memoryShareLevel":            llx.StringData(memShareLevel),
			"memoryShares":                llx.IntData(memShares),
		})
		if err != nil {
			return nil, err
		}
		mqlPools[i] = mqlPool
	}
	return mqlPools, nil
}
