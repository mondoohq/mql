// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"reflect"

	vimtypes "github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vsphere/connection"
	"go.mondoo.com/mql/providers/vsphere/resources/resourceclient"
)

type mqlVsphereVswitchStandardInternal struct {
	hostInventoryPath string
	parentResource    *mqlVsphereHost
}

func (v *mqlVsphereVswitchStandard) id() (string, error) {
	return v.Name.Data, v.Name.Error
}

func (v *mqlVsphereVswitchStandard) esxiClient() (*resourceclient.Esxi, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	return esxiClient(conn, v.hostInventoryPath)
}

// failoverPolicy is the legacy ESXCli-sourced dict view of the vSwitch's NIC
// teaming policy. Superseded by failoverSettings() which returns a typed
// resource sourced directly from the cached host config.
func (v *mqlVsphereVswitchStandard) failoverPolicy() (map[string]any, error) {
	if v.Name.Error != nil {
		return nil, v.Name.Error
	}
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}
	return esxiClient.VswitchStandardFailoverPolicy(v.Name.Data)
}

// securityPolicy is the legacy ESXCli-sourced dict view of the vSwitch's
// layer-2 security policy. Superseded by securitySettings().
func (v *mqlVsphereVswitchStandard) securityPolicy() (map[string]any, error) {
	if v.Name.Error != nil {
		return nil, v.Name.Error
	}
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}
	return esxiClient.VswitchStandardSecurityPolicy(v.Name.Data)
}

// shapingPolicy is the legacy ESXCli-sourced dict view of the vSwitch's
// traffic shaping policy. Superseded by shapingSettings().
func (v *mqlVsphereVswitchStandard) shapingPolicy() (map[string]any, error) {
	if v.Name.Error != nil {
		return nil, v.Name.Error
	}
	esxiClient, err := v.esxiClient()
	if err != nil {
		return nil, err
	}
	return esxiClient.VswitchStandardShapingPolicy(v.Name.Data)
}

func (v *mqlVsphereVswitchStandard) uplinks() ([]any, error) {
	props := v.GetProperties()
	if props.Error != nil {
		return nil, props.Error
	}

	properties, ok := props.Data.(map[string]any)
	if !ok {
		return nil, errors.New("unexpected properties structure for vsphere switch")
	}

	// if no properties are set, we have no uplinks for the switch
	if properties == nil {
		return []any{}, nil
	}

	uplinksRaw := properties["Uplinks"]
	if uplinksRaw == nil {
		return []any{}, nil
	}

	uplinkNames, ok := uplinksRaw.([]any)
	if !ok {
		return nil, errors.New("unexpected type for vsphere switch uplinks " + reflect.ValueOf(uplinksRaw).Type().Name())
	}

	// get the esxi.host parent resource
	if v.parentResource == nil {
		return nil, errors.New("cannot get esxi host inventory path")
	}

	// get all host adapter
	return findHostAdapter(v.parentResource, uplinkNames)
}

func findHostAdapter(host *mqlVsphereHost, uplinkNames []any) ([]any, error) {
	adapters := host.GetAdapters()
	if adapters.Error != nil {
		return nil, errors.New("cannot retrieve esxi host adapters")
	}

	// gather all adapters on that host so that we can find the adapter by name
	mqlUplinks := []any{}
	for i := range adapters.Data {
		adapter := adapters.Data[i].(*mqlVsphereVmnic)

		if adapter.Name.Error != nil {
			return nil, errors.New("cannot retrieve esxi adapter name")
		}
		name := adapter.Name.Data

		for i := range uplinkNames {
			uplinkName, ok := uplinkNames[i].(string)
			if !ok {
				continue
			}
			if name == uplinkName {
				mqlUplinks = append(mqlUplinks, adapter)
			}
		}
	}

	return mqlUplinks, nil
}

type mqlVsphereVswitchDvsInternal struct {
	hostInventoryPath string
	parentResource    *mqlVsphereHost
	// cacheVspanSessions captured during vCenter discovery; nil for host-observed switches
	cacheVspanSessions []vimtypes.VMwareVspanSession
	// cacheDefaultSecurityPolicy captured during vCenter discovery; nil for host-observed switches
	cacheDefaultSecurityPolicy *vimtypes.DVSSecurityPolicy
}

// dvsSettings holds the typed switch-level configuration read from a
// VMwareDVSConfigInfo. A nil pointer means the switch did not report the
// value, which surfaces as null.
type dvsSettings struct {
	version                *string
	maxMtu                 *int32
	linkDiscoveryProtocol  *string
	linkDiscoveryOperation *string
	netflowEnabled         *bool
	netflowCollectorIp     *string
	healthCheckEnabled     *bool
	defaultSecurityPolicy  *vimtypes.DVSSecurityPolicy
}

// dvsSettingsFrom extracts dvsSettings from a switch's config and summary.
// The product version is read from the config, falling back to the summary
// when the config carries none.
func dvsSettingsFrom(config vimtypes.BaseDVSConfigInfo, summaryProduct *vimtypes.DistributedVirtualSwitchProductSpec) dvsSettings {
	out := dvsSettings{}
	if config == nil {
		return out
	}
	base := config.GetDVSConfigInfo()
	if base == nil {
		return out
	}

	version := base.ProductInfo.Version
	if version == "" && summaryProduct != nil {
		version = summaryProduct.Version
	}
	if version != "" {
		out.version = &version
	}

	healthCheckEnabled := false
	for _, hc := range base.HealthCheckConfig {
		if hc == nil {
			continue
		}
		if c := hc.GetDVSHealthCheckConfig(); c != nil && c.Enable != nil && *c.Enable {
			healthCheckEnabled = true
			break
		}
	}
	out.healthCheckEnabled = &healthCheckEnabled

	if portCfg, ok := base.DefaultPortConfig.(*vimtypes.VMwareDVSPortSetting); ok && portCfg != nil {
		if portCfg.IpfixEnabled != nil && portCfg.IpfixEnabled.Value != nil {
			enabled := *portCfg.IpfixEnabled.Value
			out.netflowEnabled = &enabled
		}
		out.defaultSecurityPolicy = portCfg.SecurityPolicy
	}

	vmwareCfg, ok := config.(*vimtypes.VMwareDVSConfigInfo)
	if !ok || vmwareCfg == nil {
		return out
	}
	maxMtu := vmwareCfg.MaxMtu
	out.maxMtu = &maxMtu
	if ldp := vmwareCfg.LinkDiscoveryProtocolConfig; ldp != nil {
		protocol, operation := ldp.Protocol, ldp.Operation
		out.linkDiscoveryProtocol = &protocol
		out.linkDiscoveryOperation = &operation
	}
	if ipfix := vmwareCfg.IpfixConfig; ipfix != nil {
		collector := ipfix.CollectorIpAddress
		out.netflowCollectorIp = &collector
	}
	return out
}

func (v *mqlVsphereVswitchDvs) defaultPortSecurityPolicy() (*mqlVsphereVswitchSecurityPolicy, error) {
	if v.cacheDefaultSecurityPolicy == nil {
		v.DefaultPortSecurityPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return buildDvsSecurityPolicy(v.MqlRuntime, v.Moid.Data+"/policy/defaultSecurity", v.cacheDefaultSecurityPolicy)
}

func (v *mqlVsphereVswitchDvs) id() (string, error) {
	return v.Name.Data, v.Name.Error
}

func (v *mqlVsphereVswitchDvs) vspanSessions() ([]any, error) {
	moid := ""
	if v.Moid.IsSet() {
		moid = v.Moid.Data
	}

	res := make([]any, 0, len(v.cacheVspanSessions))
	for i := range v.cacheVspanSessions {
		s := v.cacheVspanSessions[i]
		mqlSession, err := CreateResource(v.MqlRuntime, "vsphere.vswitch.dvs.vspanSession", map[string]*llx.RawData{
			"__id":                 llx.StringData(moid + "/vspan/" + s.Key),
			"key":                  llx.StringData(s.Key),
			"name":                 llx.StringData(s.Name),
			"description":          llx.StringData(s.Description),
			"enabled":              llx.BoolData(s.Enabled),
			"sessionType":          llx.StringData(s.SessionType),
			"normalTrafficAllowed": llx.BoolData(s.NormalTrafficAllowed),
			"stripOriginalVlan":    llx.BoolData(s.StripOriginalVlan),
			"encapsulationVlanId":  llx.IntData(int64(s.EncapsulationVlanId)),
			"mirroredPacketLength": llx.IntData(int64(s.MirroredPacketLength)),
			"samplingRate":         llx.IntData(int64(s.SamplingRate)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSession)
	}
	return res, nil
}

func (v *mqlVsphereVswitchDvs) uplinks() ([]any, error) {
	props := v.GetProperties()
	if props.Error != nil {
		return nil, props.Error
	}

	properties, ok := props.Data.(map[string]any)
	if !ok {
		return nil, errors.New("unexpected properties structure for vsphere switch")
	}

	// if no properties are set, we have no uplinks for the dvs
	if properties == nil {
		return []any{}, nil
	}

	uplinksRaw, ok := properties["Uplinks"]
	if !ok || uplinksRaw == nil {
		return []any{}, nil
	}

	uplinkNames, ok := uplinksRaw.([]any)
	if !ok {
		return nil, errors.New("unexpected type for vsphere switch uplinks " + reflect.ValueOf(uplinksRaw).Type().Name())
	}

	// get the esxi.host parent resource
	if v.parentResource == nil {
		return nil, errors.New("cannot get esxi host inventory path")
	}

	// get all host adapter
	return findHostAdapter(v.parentResource, uplinkNames)
}

func (v *mqlVsphereVswitchPortgroup) id() (string, error) {
	return v.Name.Data, v.Name.Error
}
