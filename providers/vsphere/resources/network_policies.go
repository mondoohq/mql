// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	mqltypes "go.mondoo.com/mql/types"
)

// ---------- standard vSwitch policies (sourced from cached *mo.HostSystem) ----------

func (v *mqlVsphereVswitchStandard) findStandardSwitchSpec() *types.HostVirtualSwitchSpec {
	if v.parentResource == nil || v.parentResource.host == nil ||
		v.parentResource.host.Config == nil || v.parentResource.host.Config.Network == nil {
		return nil
	}
	for i := range v.parentResource.host.Config.Network.Vswitch {
		vsw := &v.parentResource.host.Config.Network.Vswitch[i]
		if vsw.Name == v.Name.Data {
			return &vsw.Spec
		}
	}
	return nil
}

func (v *mqlVsphereVswitchStandard) securityPolicySettings() (*mqlVsphereVswitchSecurityPolicy, error) {
	spec := v.findStandardSwitchSpec()
	if spec == nil || spec.Policy == nil {
		v.SecurityPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	id := standardSwitchPolicyID(v, "security")
	res, err := buildHostSecurityPolicy(v.MqlRuntime, id, spec.Policy.Security)
	if err != nil {
		return nil, err
	}
	if res == nil {
		v.SecurityPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

func (v *mqlVsphereVswitchStandard) failoverPolicySettings() (*mqlVsphereVswitchFailoverPolicy, error) {
	spec := v.findStandardSwitchSpec()
	if spec == nil || spec.Policy == nil {
		v.FailoverPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	id := standardSwitchPolicyID(v, "failover")
	res, err := buildHostFailoverPolicy(v.MqlRuntime, id, spec.Policy.NicTeaming)
	if err != nil {
		return nil, err
	}
	if res == nil {
		v.FailoverPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

func (v *mqlVsphereVswitchStandard) shapingPolicySettings() (*mqlVsphereVswitchShapingPolicy, error) {
	spec := v.findStandardSwitchSpec()
	if spec == nil || spec.Policy == nil {
		v.ShapingPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	id := standardSwitchPolicyID(v, "shaping")
	res, err := buildHostShapingPolicy(v.MqlRuntime, id, spec.Policy.ShapingPolicy)
	if err != nil {
		return nil, err
	}
	if res == nil {
		v.ShapingPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

func standardSwitchPolicyID(v *mqlVsphereVswitchStandard, kind string) string {
	host := ""
	if v.parentResource != nil {
		host = v.parentResource.InventoryPath.Data
	}
	return host + "/vswitch/" + v.Name.Data + "/policy/" + kind
}

func buildHostSecurityPolicy(runtime *plugin.Runtime, id string, p *types.HostNetworkSecurityPolicy) (*mqlVsphereVswitchSecurityPolicy, error) {
	if p == nil {
		return nil, nil
	}
	res, err := CreateResource(runtime, "vsphere.vswitch.securityPolicy", map[string]*llx.RawData{
		"__id":                 llx.StringData(id),
		"allowPromiscuous":     llx.BoolData(boolPtrOr(p.AllowPromiscuous, false)),
		"allowForgedTransmits": llx.BoolData(boolPtrOr(p.ForgedTransmits, false)),
		"allowMacChanges":      llx.BoolData(boolPtrOr(p.MacChanges, false)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereVswitchSecurityPolicy), nil
}

func buildHostFailoverPolicy(runtime *plugin.Runtime, id string, p *types.HostNicTeamingPolicy) (*mqlVsphereVswitchFailoverPolicy, error) {
	if p == nil {
		return nil, nil
	}
	var active, standby []any
	if p.NicOrder != nil {
		active = stringsToAny(p.NicOrder.ActiveNic)
		standby = stringsToAny(p.NicOrder.StandbyNic)
	}
	checkBeacon := false
	if p.FailureCriteria != nil && p.FailureCriteria.CheckBeacon != nil {
		checkBeacon = *p.FailureCriteria.CheckBeacon
	}
	res, err := CreateResource(runtime, "vsphere.vswitch.failoverPolicy", map[string]*llx.RawData{
		"__id":           llx.StringData(id),
		"policy":         llx.StringData(p.Policy),
		"reversePolicy":  llx.BoolData(boolPtrOr(p.ReversePolicy, false)),
		"notifySwitches": llx.BoolData(boolPtrOr(p.NotifySwitches, false)),
		"rollingOrder":   llx.BoolData(boolPtrOr(p.RollingOrder, false)),
		"checkBeacon":    llx.BoolData(checkBeacon),
		"activeNic":      llx.ArrayData(active, mqltypes.String),
		"standbyNic":     llx.ArrayData(standby, mqltypes.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereVswitchFailoverPolicy), nil
}

func buildHostShapingPolicy(runtime *plugin.Runtime, id string, p *types.HostNetworkTrafficShapingPolicy) (*mqlVsphereVswitchShapingPolicy, error) {
	if p == nil {
		return nil, nil
	}
	res, err := CreateResource(runtime, "vsphere.vswitch.shapingPolicy", map[string]*llx.RawData{
		"__id":             llx.StringData(id),
		"enabled":          llx.BoolData(boolPtrOr(p.Enabled, false)),
		"averageBandwidth": llx.IntData(p.AverageBandwidth),
		"peakBandwidth":    llx.IntData(p.PeakBandwidth),
		"burstSize":        llx.IntData(p.BurstSize),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereVswitchShapingPolicy), nil
}

// ---------- DVS port group policies (sourced from cached DefaultPortConfig) ----------

type mqlVsphereVswitchPortgroupInternal struct {
	defaultPortConfig *types.VMwareDVSPortSetting
}

func (p *mqlVsphereVswitchPortgroup) securityPolicySettings() (*mqlVsphereVswitchSecurityPolicy, error) {
	if p.defaultPortConfig == nil || p.defaultPortConfig.SecurityPolicy == nil {
		p.SecurityPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return buildDvsSecurityPolicy(p.MqlRuntime, p.Moid.Data+"/policy/security", p.defaultPortConfig.SecurityPolicy)
}

// buildDvsSecurityPolicy creates a vsphere.vswitch.securityPolicy from a
// distributed switch security policy (switch or port group default port
// config).
func buildDvsSecurityPolicy(runtime *plugin.Runtime, id string, sp *types.DVSSecurityPolicy) (*mqlVsphereVswitchSecurityPolicy, error) {
	res, err := CreateResource(runtime, "vsphere.vswitch.securityPolicy", map[string]*llx.RawData{
		"__id":                 llx.StringData(id),
		"allowPromiscuous":     llx.BoolData(boolPolicyValue(sp.AllowPromiscuous)),
		"allowForgedTransmits": llx.BoolData(boolPolicyValue(sp.ForgedTransmits)),
		"allowMacChanges":      llx.BoolData(boolPolicyValue(sp.MacChanges)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereVswitchSecurityPolicy), nil
}

// dvPortgroupSettings holds the typed port group configuration read from a
// DVPortgroupConfigInfo. A nil pointer means the port group did not report
// the value, which surfaces as null.
type dvPortgroupSettings struct {
	portBinding                   string
	blocked                       *bool
	vlanTrunkRanges               []string
	securityPolicyOverrideAllowed *bool
	vlanOverrideAllowed           *bool
	macManagementOverrideAllowed  *bool
	uplinkTeamingOverrideAllowed  *bool
}

func dvPortgroupSettingsFrom(cfg *types.DVPortgroupConfigInfo) dvPortgroupSettings {
	out := dvPortgroupSettings{vlanTrunkRanges: []string{}}
	if cfg == nil {
		return out
	}
	out.portBinding = cfg.Type

	if portCfg, ok := cfg.DefaultPortConfig.(*types.VMwareDVSPortSetting); ok && portCfg != nil {
		if portCfg.Blocked != nil && portCfg.Blocked.Value != nil {
			blocked := *portCfg.Blocked.Value
			out.blocked = &blocked
		}
		if trunk, ok := portCfg.Vlan.(*types.VmwareDistributedVirtualSwitchTrunkVlanSpec); ok && trunk != nil {
			for _, r := range trunk.VlanId {
				out.vlanTrunkRanges = append(out.vlanTrunkRanges, strconv.Itoa(int(r.Start))+"-"+strconv.Itoa(int(r.End)))
			}
		}
	}

	if policy, ok := cfg.Policy.(*types.VMwareDVSPortgroupPolicy); ok && policy != nil {
		securityOverride := policy.SecurityPolicyOverrideAllowed
		vlanOverride := policy.VlanOverrideAllowed
		teamingOverride := policy.UplinkTeamingOverrideAllowed
		out.securityPolicyOverrideAllowed = &securityOverride
		out.vlanOverrideAllowed = &vlanOverride
		out.uplinkTeamingOverrideAllowed = &teamingOverride
		out.macManagementOverrideAllowed = policy.MacManagementOverrideAllowed
	}
	return out
}

func (p *mqlVsphereVswitchPortgroup) failoverPolicySettings() (*mqlVsphereVswitchFailoverPolicy, error) {
	if p.defaultPortConfig == nil || p.defaultPortConfig.UplinkTeamingPolicy == nil {
		p.FailoverPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	tp := p.defaultPortConfig.UplinkTeamingPolicy

	var active, standby []any
	if tp.UplinkPortOrder != nil {
		active = stringsToAny(tp.UplinkPortOrder.ActiveUplinkPort)
		standby = stringsToAny(tp.UplinkPortOrder.StandbyUplinkPort)
	}
	checkBeacon := false
	if tp.FailureCriteria != nil {
		checkBeacon = boolPolicyValue(tp.FailureCriteria.CheckBeacon)
	}
	id := p.Moid.Data + "/policy/failover"
	res, err := CreateResource(p.MqlRuntime, "vsphere.vswitch.failoverPolicy", map[string]*llx.RawData{
		"__id":           llx.StringData(id),
		"policy":         llx.StringData(stringPolicyValue(tp.Policy)),
		"reversePolicy":  llx.BoolData(boolPolicyValue(tp.ReversePolicy)),
		"notifySwitches": llx.BoolData(boolPolicyValue(tp.NotifySwitches)),
		"rollingOrder":   llx.BoolData(boolPolicyValue(tp.RollingOrder)),
		"checkBeacon":    llx.BoolData(checkBeacon),
		"activeNic":      llx.ArrayData(active, mqltypes.String),
		"standbyNic":     llx.ArrayData(standby, mqltypes.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereVswitchFailoverPolicy), nil
}

func (p *mqlVsphereVswitchPortgroup) shapingPolicySettings() (*mqlVsphereVswitchShapingPolicy, error) {
	if p.defaultPortConfig == nil || p.defaultPortConfig.InShapingPolicy == nil {
		p.ShapingPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	sp := p.defaultPortConfig.InShapingPolicy
	id := p.Moid.Data + "/policy/shaping"
	res, err := CreateResource(p.MqlRuntime, "vsphere.vswitch.shapingPolicy", map[string]*llx.RawData{
		"__id":             llx.StringData(id),
		"enabled":          llx.BoolData(boolPolicyValue(sp.Enabled)),
		"averageBandwidth": llx.IntData(longPolicyValue(sp.AverageBandwidth)),
		"peakBandwidth":    llx.IntData(longPolicyValue(sp.PeakBandwidth)),
		"burstSize":        llx.IntData(longPolicyValue(sp.BurstSize)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereVswitchShapingPolicy), nil
}

func (p *mqlVsphereVswitchPortgroup) macManagementPolicySettings() (*mqlVsphereVswitchMacManagementPolicy, error) {
	if p.defaultPortConfig == nil || p.defaultPortConfig.MacManagementPolicy == nil {
		p.MacManagementPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mp := p.defaultPortConfig.MacManagementPolicy

	var (
		learningEnabled, learningFlooding bool
		learningLimit                     int64
		learningLimitPolicy               string
	)
	if mp.MacLearningPolicy != nil {
		lp := mp.MacLearningPolicy
		learningEnabled = lp.Enabled
		learningFlooding = boolPtrOr(lp.AllowUnicastFlooding, false)
		if lp.Limit != nil {
			learningLimit = int64(*lp.Limit)
		}
		learningLimitPolicy = lp.LimitPolicy
	}

	id := p.Moid.Data + "/policy/macManagement"
	res, err := CreateResource(p.MqlRuntime, "vsphere.vswitch.macManagementPolicy", map[string]*llx.RawData{
		"__id":                            llx.StringData(id),
		"allowPromiscuous":                llx.BoolData(boolPtrOr(mp.AllowPromiscuous, false)),
		"allowForgedTransmits":            llx.BoolData(boolPtrOr(mp.ForgedTransmits, false)),
		"allowMacChanges":                 llx.BoolData(boolPtrOr(mp.MacChanges, false)),
		"macLearningEnabled":              llx.BoolData(learningEnabled),
		"macLearningAllowUnicastFlooding": llx.BoolData(learningFlooding),
		"macLearningLimit":                llx.IntData(learningLimit),
		"macLearningLimitPolicy":          llx.StringData(learningLimitPolicy),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereVswitchMacManagementPolicy), nil
}

// ---------- helpers for the *Policy wrappers and *bool ----------

func boolPtrOr(b *bool, fallback bool) bool {
	if b == nil {
		return fallback
	}
	return *b
}

func boolPolicyValue(p *types.BoolPolicy) bool {
	if p == nil || p.Value == nil {
		return false
	}
	return *p.Value
}

func longPolicyValue(p *types.LongPolicy) int64 {
	if p == nil {
		return 0
	}
	return p.Value
}

func stringPolicyValue(p *types.StringPolicy) string {
	if p == nil {
		return ""
	}
	return p.Value
}

// ---------- standard vSwitch port group policies ----------

func (p *mqlVsphereVswitchStandardPortgroup) securityPolicySettings() (*mqlVsphereVswitchSecurityPolicy, error) {
	if p.policy == nil {
		p.SecurityPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := buildHostSecurityPolicy(p.MqlRuntime, p.parent+"/policy/security", p.policy.Security)
	if err != nil {
		return nil, err
	}
	if res == nil {
		p.SecurityPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

func (p *mqlVsphereVswitchStandardPortgroup) failoverPolicySettings() (*mqlVsphereVswitchFailoverPolicy, error) {
	if p.policy == nil {
		p.FailoverPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := buildHostFailoverPolicy(p.MqlRuntime, p.parent+"/policy/failover", p.policy.NicTeaming)
	if err != nil {
		return nil, err
	}
	if res == nil {
		p.FailoverPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

func (p *mqlVsphereVswitchStandardPortgroup) shapingPolicySettings() (*mqlVsphereVswitchShapingPolicy, error) {
	if p.policy == nil {
		p.ShapingPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := buildHostShapingPolicy(p.MqlRuntime, p.parent+"/policy/shaping", p.policy.ShapingPolicy)
	if err != nil {
		return nil, err
	}
	if res == nil {
		p.ShapingPolicySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}
