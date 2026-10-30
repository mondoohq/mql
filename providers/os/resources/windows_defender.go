// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// enabled reports whether the Defender service and its real-time antivirus and
// antispyware protection are all active. It resolves to false (not an error)
// when Defender is unavailable on the target.
func (d *mqlWindowsDefender) enabled() (bool, error) {
	statusRes := d.GetStatus()
	if statusRes.Error != nil {
		if errors.Is(statusRes.Error, windows.ErrDefenderUnavailable) {
			return false, nil
		}
		return false, statusRes.Error
	}
	s := statusRes.Data
	if s == nil {
		return false, nil
	}
	return s.AmServiceEnabled.Data && s.AntivirusEnabled.Data && s.AntispywareEnabled.Data, nil
}

// windows.defender.status and windows.defender.preferences are reachable by
// dotted paths that are also their own registered resource names: the field
// `status` on `windows.defender` and the resource `windows.defender.status`
// occupy the same path. The compiler resolves the longest matching resource
// name before it considers a field, so `windows.defender.status` instantiates
// the sub-resource directly and the parent's status() accessor never runs.
// Every field is a plain schema field that only the parent populates, so all of
// them stay unset and report "provider returned no data and no error", then
// convert as primitives carrying no type information:
//
//	windows.defender.status.antivirusEnabled           -> null
//	windows.defender { status { antivirusEnabled } }   -> true
//
// A check reading "antivirus is enabled" off the dotted form therefore reports
// null on a host where Defender is running. Delegating to the parent's accessor
// fills the resource in. When the parent creates the resource normally it
// carries an __id and these are a no-op.
func initWindowsDefenderChild[T plugin.Resource](
	runtime *plugin.Runtime,
	args map[string]*llx.RawData,
	field string,
	get func(*mqlWindowsDefender) *plugin.TValue[T],
) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	parent, err := CreateResource(runtime, "windows.defender", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	v := get(parent.(*mqlWindowsDefender))
	if v.Error != nil {
		return nil, nil, v.Error
	}
	if v.IsNull() {
		// Defender is not installed. Falling through would build the resource
		// out of the empty args and report null for every field, which reads as
		// "not configured" rather than "not present".
		return nil, nil, fmt.Errorf("cannot read windows.defender.%s: %w", field, windows.ErrDefenderUnavailable)
	}
	return args, v.Data, nil
}

func initWindowsDefenderStatus(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsDefenderChild(runtime, args, "status", (*mqlWindowsDefender).GetStatus)
}

func initWindowsDefenderPreferences(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsDefenderChild(runtime, args, "preferences", (*mqlWindowsDefender).GetPreferences)
}

func (d *mqlWindowsDefender) status() (*mqlWindowsDefenderStatus, error) {
	conn := d.MqlRuntime.Connection.(shared.Connection)

	status, err := windows.GetDefenderComputerStatus(conn)
	if err != nil {
		if errors.Is(err, windows.ErrDefenderUnavailable) {
			d.Status.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	res, err := CreateResource(d.MqlRuntime, "windows.defender.status", map[string]*llx.RawData{
		"__id":                             llx.StringData("windows.defender.status"),
		"amEngineVersion":                  llx.StringData(status.AMEngineVersion),
		"amProductVersion":                 llx.StringData(status.AMProductVersion),
		"amRunningMode":                    llx.StringData(status.AMRunningMode),
		"amServiceEnabled":                 llx.BoolData(status.AMServiceEnabled),
		"amServiceVersion":                 llx.StringData(status.AMServiceVersion),
		"antispywareEnabled":               llx.BoolData(status.AntispywareEnabled),
		"antispywareSignatureAge":          llx.IntDataPtr(windows.DefenderAge(status.AntispywareSignatureAge)),
		"antispywareSignatureLastUpdated":  llx.TimeDataPtr(windows.DefenderTime(status.AntispywareSignatureLastUpdated)),
		"antispywareSignatureVersion":      llx.StringData(status.AntispywareSignatureVersion),
		"antivirusEnabled":                 llx.BoolData(status.AntivirusEnabled),
		"antivirusSignatureAge":            llx.IntDataPtr(windows.DefenderAge(status.AntivirusSignatureAge)),
		"antivirusSignatureLastUpdated":    llx.TimeDataPtr(windows.DefenderTime(status.AntivirusSignatureLastUpdated)),
		"antivirusSignatureVersion":        llx.StringData(status.AntivirusSignatureVersion),
		"behaviorMonitorEnabled":           llx.BoolData(status.BehaviorMonitorEnabled),
		"computerID":                       llx.StringData(status.ComputerID),
		"computerState":                    llx.IntData(status.ComputerState),
		"defenderSignaturesOutOfDate":      llx.BoolData(status.DefenderSignaturesOutOfDate),
		"deviceControlDefaultEnforcement":  llx.StringDataPtr(status.DeviceControlDefaultEnforcement),
		"deviceControlPoliciesLastUpdated": llx.TimeDataPtr(windows.DefenderTime(status.DeviceControlPoliciesLastUpdated)),
		"deviceControlState":               llx.StringData(status.DeviceControlState),
		"fullScanAge":                      llx.IntDataPtr(windows.DefenderAge(status.FullScanAge)),
		"fullScanStartTime":                llx.TimeDataPtr(windows.DefenderTime(status.FullScanStartTime)),
		"fullScanEndTime":                  llx.TimeDataPtr(windows.DefenderTime(status.FullScanEndTime)),
		"fullScanOverdue":                  llx.BoolData(status.FullScanOverdue),
		"fullScanRequired":                 llx.BoolData(status.FullScanRequired),
		"fullScanSignatureVersion":         llx.StringData(status.FullScanSignatureVersion),
		"ioavProtectionEnabled":            llx.BoolData(status.IoavProtectionEnabled),
		"isTamperProtected":                llx.BoolData(status.IsTamperProtected),
		"isVirtualMachine":                 llx.BoolData(status.IsVirtualMachine),
		"lastFullScanSource":               llx.IntData(status.LastFullScanSource),
		"lastQuickScanSource":              llx.IntData(status.LastQuickScanSource),
		"nisEnabled":                       llx.BoolData(status.NISEnabled),
		"nisEngineVersion":                 llx.StringData(status.NISEngineVersion),
		"nisSignatureAge":                  llx.IntDataPtr(windows.DefenderAge(status.NISSignatureAge)),
		"nisSignatureLastUpdated":          llx.TimeDataPtr(windows.DefenderTime(status.NISSignatureLastUpdated)),
		"nisSignatureVersion":              llx.StringData(status.NISSignatureVersion),
		"onAccessProtectionEnabled":        llx.BoolData(status.OnAccessProtectionEnabled),
		"productStatus":                    llx.IntData(status.ProductStatus),
		"quickScanAge":                     llx.IntDataPtr(windows.DefenderAge(status.QuickScanAge)),
		"quickScanStartTime":               llx.TimeDataPtr(windows.DefenderTime(status.QuickScanStartTime)),
		"quickScanEndTime":                 llx.TimeDataPtr(windows.DefenderTime(status.QuickScanEndTime)),
		"quickScanOverdue":                 llx.BoolData(status.QuickScanOverdue),
		"quickScanSignatureVersion":        llx.StringData(status.QuickScanSignatureVersion),
		"realTimeProtectionEnabled":        llx.BoolData(status.RealTimeProtectionEnabled),
		"realTimeScanDirection":            llx.IntData(status.RealTimeScanDirection),
		"rebootRequired":                   llx.BoolData(status.RebootRequired),
		"smartAppControlState":             llx.StringData(status.SmartAppControlState),
		"smartAppControlExpiration":        llx.TimeDataPtr(windows.DefenderTime(status.SmartAppControlExpiration)),
		"tamperProtectionSource":           llx.StringData(status.TamperProtectionSource),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlWindowsDefenderStatus), nil
}

func (d *mqlWindowsDefender) preferences() (*mqlWindowsDefenderPreferences, error) {
	conn := d.MqlRuntime.Connection.(shared.Connection)

	// Fetch Get-MpPreference up front so we can resolve the whole preferences
	// resource to null when Defender is unavailable, rather than letting each
	// sub-accessor surface a raw ErrDefenderUnavailable.
	prefs, err := windows.GetDefenderPreferences(conn)
	if err != nil {
		if errors.Is(err, windows.ErrDefenderUnavailable) {
			d.Preferences.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	res, err := CreateResource(d.MqlRuntime, "windows.defender.preferences", map[string]*llx.RawData{
		"__id": llx.StringData("windows.defender.preferences"),
	})
	if err != nil {
		return nil, err
	}

	// Seed the cache so the grouped sub-accessors reuse this result instead of
	// running Get-MpPreference a second time.
	p := res.(*mqlWindowsDefenderPreferences)
	p.seedPrefs(prefs)
	return p, nil
}

func (d *mqlWindowsDefender) threats() ([]any, error) {
	conn := d.MqlRuntime.Connection.(shared.Connection)

	threats, err := windows.GetDefenderThreats(conn)
	if err != nil {
		if errors.Is(err, windows.ErrDefenderUnavailable) {
			// An empty list would make threats.none(...) and threats.all(...)
			// pass on a host that has no antivirus recording threats at all.
			// Null says the history could not be read, matching how status and
			// preferences resolve on the same host.
			d.Threats.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(threats))
	for i := range threats {
		t := threats[i]
		mqlThreat, err := CreateResource(d.MqlRuntime, "windows.defender.threat", map[string]*llx.RawData{
			"__id":             llx.StringData("windows.defender.threat/" + strconv.FormatInt(t.ThreatID, 10)),
			"threatId":         llx.IntData(t.ThreatID),
			"name":             llx.StringData(t.ThreatName),
			"severityID":       llx.IntData(t.SeverityID),
			"categoryID":       llx.IntData(t.CategoryID),
			"isActive":         llx.BoolData(t.IsActive),
			"didThreatExecute": llx.BoolData(t.DidThreatExecute),
			"rollupStatus":     llx.IntData(t.RollupStatus),
			"resources":        llx.ArrayData(convert.SliceAnyToInterface(t.Resources), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlThreat)
	}
	return res, nil
}

func (d *mqlWindowsDefender) threatDetections() ([]any, error) {
	conn := d.MqlRuntime.Connection.(shared.Connection)

	detections, err := windows.GetDefenderThreatDetections(conn)
	if err != nil {
		if errors.Is(err, windows.ErrDefenderUnavailable) {
			d.ThreatDetections.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(detections))
	for i := range detections {
		det := detections[i]
		mqlDet, err := CreateResource(d.MqlRuntime, "windows.defender.threatDetection", map[string]*llx.RawData{
			"__id":                           llx.StringData("windows.defender.threatDetection/" + det.DetectionID),
			"detectionId":                    llx.StringData(det.DetectionID),
			"threatId":                       llx.IntData(det.ThreatID),
			"processName":                    llx.StringData(det.ProcessName),
			"domainUser":                     llx.StringData(det.DomainUser),
			"detectionSourceTypeId":          llx.IntData(det.DetectionSourceTypeID),
			"currentThreatExecutionStatusID": llx.IntData(det.CurrentThreatExecutionStatusID),
			"threatStatusID":                 llx.IntData(det.ThreatStatusID),
			"cleaningActionID":               llx.IntData(det.CleaningActionID),
			"actionSuccess":                  llx.BoolData(det.ActionSuccess),
			"initialDetectionTime":           llx.TimeDataPtr(windows.DefenderTime(det.InitialDetectionTime)),
			"lastThreatStatusChangeTime":     llx.TimeDataPtr(windows.DefenderTime(det.LastThreatStatusChangeTime)),
			"remediationTime":                llx.TimeDataPtr(windows.DefenderTime(det.RemediationTime)),
			"resources":                      llx.ArrayData(convert.SliceAnyToInterface(det.Resources), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDet)
	}
	return res, nil
}

// mqlWindowsDefenderPreferencesInternal caches the Get-MpPreference result so
// that the grouped accessors (scan, cloudProtection, ...) share a single query.
type mqlWindowsDefenderPreferencesInternal struct {
	lock    sync.Mutex
	fetched bool
	prefs   *windows.MpPreference
	err     error

	policyLock    sync.Mutex
	policyFetched bool
	policy        *defenderPolicy
	policyErr     error
}

// defenderPolicyKey is the Group Policy root for Microsoft Defender Antivirus,
// as defined by WindowsDefender.admx. The ADMX-backed MDM policies
// (ADMX_MicrosoftDefenderAntivirus) write to the same keys.
const defenderPolicyKey = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`

// defenderPolicy holds the Defender Group Policy values that Get-MpPreference
// does not report, keyed by lower-cased value name per subkey. A key that does
// not exist is an empty map, so every value under it reads as not configured.
type defenderPolicy struct {
	root      map[string]registry.RegistryKeyItem
	realTime  map[string]registry.RegistryKeyItem
	spynet    map[string]registry.RegistryKeyItem
	scan      map[string]registry.RegistryKeyItem
	reporting map[string]registry.RegistryKeyItem
	features  map[string]registry.RegistryKeyItem
}

// readRegistryValues reads one registry key into a map keyed by lower-cased
// value name. A missing key is an empty map, not an error.
func readRegistryValues(runtime *plugin.Runtime, path string) (map[string]registry.RegistryKeyItem, error) {
	o, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return map[string]registry.RegistryKeyItem{}, nil
		}
		return nil, err
	}
	res := make(map[string]registry.RegistryKeyItem, len(entries))
	for i := range entries {
		res[strings.ToLower(entries[i].Key)] = entries[i]
	}
	return res, nil
}

// getPolicy reads the Defender Group Policy keys once and caches the result.
func (p *mqlWindowsDefenderPreferences) getPolicy() (*defenderPolicy, error) {
	p.policyLock.Lock()
	defer p.policyLock.Unlock()
	if p.policyFetched {
		return p.policy, p.policyErr
	}
	pol := &defenderPolicy{}
	reads := []struct {
		subkey string
		dst    *map[string]registry.RegistryKeyItem
	}{
		{``, &pol.root},
		{`Real-Time Protection`, &pol.realTime},
		{`Spynet`, &pol.spynet},
		{`Scan`, &pol.scan},
		{`Reporting`, &pol.reporting},
		{`Features`, &pol.features},
	}
	for _, rd := range reads {
		path := defenderPolicyKey
		if rd.subkey != "" {
			path += `\` + rd.subkey
		}
		items, err := readRegistryValues(p.MqlRuntime, path)
		if err != nil {
			p.policyFetched = true
			p.policyErr = err
			return nil, err
		}
		*rd.dst = items
	}
	p.policy = pol
	p.policyFetched = true
	return pol, nil
}

// prefOrPolicy returns the Get-MpPreference value when the platform reports
// one, otherwise the Group Policy DWORD (non-zero is true), otherwise nil.
func prefOrPolicy(pref *bool, items map[string]registry.RegistryKeyItem, name string) *bool {
	if pref != nil {
		return pref
	}
	return regBoolPtr(items, name)
}

// defenderOverrides are the windows.defender.localSettingOverrides values.
type defenderOverrides struct {
	spynetReporting                  *bool
	realtimeMonitoring               *bool
	disableBehaviorMonitoring        *bool
	disableIOAVProtection            *bool
	disableIntrusionPreventionSystem *bool
	disableOnAccessProtection        *bool
	scanParameters                   *bool
	scanScheduleDay                  *bool
	avgCPULoadFactor                 *bool
}

// resolveLocalSettingOverrides combines the LocalSettingOverride* preferences
// with their Group Policy values. Current Defender platforms no longer report
// these properties through Get-MpPreference, so the policy is the only source
// there. The value names are the ones WindowsDefender.admx defines. The ADMX has
// no override policy for the intrusion prevention system, so that one can only
// come from Get-MpPreference.
func resolveLocalSettingOverrides(prefs *windows.MpPreference, pol *defenderPolicy) defenderOverrides {
	return defenderOverrides{
		spynetReporting:                  prefOrPolicy(prefs.LocalSettingOverrideSpynetReporting, pol.spynet, "LocalSettingOverrideSpynetReporting"),
		realtimeMonitoring:               prefOrPolicy(prefs.LocalSettingOverrideRealtimeMonitoring, pol.realTime, "LocalSettingOverrideDisableRealtimeMonitoring"),
		disableBehaviorMonitoring:        prefOrPolicy(prefs.LocalSettingOverrideDisableBehaviorMonitoring, pol.realTime, "LocalSettingOverrideDisableBehaviorMonitoring"),
		disableIOAVProtection:            prefOrPolicy(prefs.LocalSettingOverrideDisableIOAVProtection, pol.realTime, "LocalSettingOverrideDisableIOAVProtection"),
		disableIntrusionPreventionSystem: prefs.LocalSettingOverrideDisableIntrusionPreventionSystem,
		disableOnAccessProtection:        prefOrPolicy(prefs.LocalSettingOverrideDisableOnAccessProtection, pol.realTime, "LocalSettingOverrideDisableOnAccessProtection"),
		scanParameters:                   prefOrPolicy(prefs.LocalSettingOverrideScanParameters, pol.scan, "LocalSettingOverrideScanParameters"),
		scanScheduleDay:                  prefOrPolicy(prefs.LocalSettingOverrideScanScheduleDay, pol.scan, "LocalSettingOverrideScheduleDay"),
		avgCPULoadFactor:                 prefOrPolicy(prefs.LocalSettingOverrideAvgCPULoadFactor, pol.scan, "LocalSettingOverrideAvgCPULoadFactor"),
	}
}

// defenderPolicyOnly are the Defender Group Policy values that Get-MpPreference
// does not report at all, so the policy is their only source. Each is nil when
// the policy is not configured.
type defenderPolicyOnly struct {
	disableRoutinelyTakingAction        *bool
	disableScanOnRealtimeEnable         *bool
	disablePackedExeScanning            *bool
	daysUntilAggressiveCatchupQuickScan *int64
	passiveRemediation                  *int64
}

// resolveDefenderPolicyOnly reads the policy-only values. The subkeys and value
// names are the ones WindowsDefender.admx defines:
//
//	DisableRoutinelyTakingAction         Windows Defender
//	DisableScanOnRealtimeEnable          Windows Defender\Real-Time Protection
//	DisablePackedExeScanning             Windows Defender\Scan
//	DaysUntilAggressiveCatchupQuickScan  Windows Defender\Scan
//	PassiveRemediation                   Windows Defender\Features
//
// PassiveRemediation is a bitmask in the Defender CSP, so it stays an integer.
func resolveDefenderPolicyOnly(pol *defenderPolicy) defenderPolicyOnly {
	return defenderPolicyOnly{
		disableRoutinelyTakingAction:        regBoolPtr(pol.root, "DisableRoutinelyTakingAction"),
		disableScanOnRealtimeEnable:         regBoolPtr(pol.realTime, "DisableScanOnRealtimeEnable"),
		disablePackedExeScanning:            regBoolPtr(pol.scan, "DisablePackedExeScanning"),
		daysUntilAggressiveCatchupQuickScan: regIntPtr(pol.scan, "DaysUntilAggressiveCatchupQuickScan"),
		passiveRemediation:                  regIntPtr(pol.features, "PassiveRemediation"),
	}
}

// seedPrefs installs an already-fetched Get-MpPreference result.
//
// It must take the same lock getPrefs uses. CreateResource looks the __id up in
// the runtime cache and returns the existing resource when it finds one, so the
// instance handed back here may already be published and in use by another
// goroutine reading these fields under the lock. Writing them unlocked is a
// data race, and without the happens-before edge the lock provides a reader can
// observe fetched as true while prefs is still nil, which makes getPrefs return
// (nil, nil) and every grouped accessor dereference it.
//
// The fetched guard keeps a second seeder from replacing a result that has
// already been handed out.
func (p *mqlWindowsDefenderPreferences) seedPrefs(prefs *windows.MpPreference) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.fetched {
		return
	}
	p.prefs = prefs
	p.fetched = true
}

// peekPrefs reports the cached Get-MpPreference result without fetching. The
// third return value is false when nothing has been cached yet. It exists so a
// test can observe the seeded state under the lock.
func (p *mqlWindowsDefenderPreferences) peekPrefs() (*windows.MpPreference, error, bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.prefs, p.err, p.fetched
}

// getPrefs fetches Get-MpPreference once and caches the result.
func (p *mqlWindowsDefenderPreferences) getPrefs() (*windows.MpPreference, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.fetched {
		return p.prefs, p.err
	}
	conn := p.MqlRuntime.Connection.(shared.Connection)
	p.prefs, p.err = windows.GetDefenderPreferences(conn)
	p.fetched = true
	return p.prefs, p.err
}

func (p *mqlWindowsDefenderPreferences) scan() (*mqlWindowsDefenderScanSettings, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(p.MqlRuntime, "windows.defender.scanSettings", map[string]*llx.RawData{
		"__id":                                          llx.StringData("windows.defender.scanSettings"),
		"scanParameters":                                llx.IntData(prefs.ScanParameters),
		"scanScheduleDay":                               llx.IntData(prefs.ScanScheduleDay),
		"scanScheduleTime":                              llx.StringData(prefs.ScanScheduleTimeString()),
		"scanScheduleQuickScanTime":                     llx.StringData(prefs.ScanScheduleQuickScanTimeString()),
		"scanScheduleOffset":                            llx.IntData(prefs.ScanScheduleOffset),
		"scanAvgCPULoadFactor":                          llx.IntData(prefs.ScanAvgCPULoadFactor),
		"scanOnlyIfIdleEnabled":                         llx.BoolData(prefs.ScanOnlyIfIdleEnabled),
		"checkForSignaturesBeforeRunningScan":           llx.BoolData(prefs.CheckForSignaturesBeforeRunningScan),
		"disableArchiveScanning":                        llx.BoolData(prefs.DisableArchiveScanning),
		"disableEmailScanning":                          llx.BoolData(prefs.DisableEmailScanning),
		"disableRemovableDriveScanning":                 llx.BoolData(prefs.DisableRemovableDriveScanning),
		"disableScanningMappedNetworkDrivesForFullScan": llx.BoolData(prefs.DisableScanningMappedNetworkDrivesForFullScan),
		"disableScanningNetworkFiles":                   llx.BoolData(prefs.DisableScanningNetworkFiles),
		"disableCatchupFullScan":                        llx.BoolData(prefs.DisableCatchupFullScan),
		"disableCatchupQuickScan":                       llx.BoolData(prefs.DisableCatchupQuickScan),
		"disableCpuThrottleOnIdleScans":                 llx.BoolData(prefs.DisableCpuThrottleOnIdleScans),
		"enableFullScanOnBatteryPower":                  llx.BoolData(prefs.EnableFullScanOnBatteryPower),
		"enableLowCpuPriority":                          llx.BoolData(prefs.EnableLowCpuPriority),
		"quickScanIncludeExclusions":                    llx.IntDataPtr(prefs.QuickScanIncludeExclusions),
	})
	if err != nil {
		return nil, err
	}
	r := res.(*mqlWindowsDefenderScanSettings)
	r.preferences.Store(p)
	return r, nil
}

func (p *mqlWindowsDefenderPreferences) realTimeProtection() (*mqlWindowsDefenderRealTimeSettings, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(p.MqlRuntime, "windows.defender.realTimeSettings", map[string]*llx.RawData{
		"__id":                             llx.StringData("windows.defender.realTimeSettings"),
		"disableRealtimeMonitoring":        llx.BoolData(prefs.DisableRealtimeMonitoring),
		"disableBehaviorMonitoring":        llx.BoolData(prefs.DisableBehaviorMonitoring),
		"disableIOAVProtection":            llx.BoolData(prefs.DisableIOAVProtection),
		"disableScriptScanning":            llx.BoolData(prefs.DisableScriptScanning),
		"disableIntrusionPreventionSystem": llx.BoolDataPtr(prefs.DisableIntrusionPreventionSystem),
		"realTimeScanDirection":            llx.IntData(prefs.RealTimeScanDirection),
		"enableFileHashComputation":        llx.BoolData(prefs.EnableFileHashComputation),
		"oobeEnableRtpAndSigUpdate":        llx.BoolDataPtr(prefs.OobeEnableRtpAndSigUpdate),
	})
	if err != nil {
		return nil, err
	}
	r := res.(*mqlWindowsDefenderRealTimeSettings)
	r.preferences.Store(p)
	return r, nil
}

func (p *mqlWindowsDefenderPreferences) cloudProtection() (*mqlWindowsDefenderCloudSettings, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(p.MqlRuntime, "windows.defender.cloudSettings", map[string]*llx.RawData{
		"__id":                    llx.StringData("windows.defender.cloudSettings"),
		"mapsReporting":           llx.IntData(prefs.MAPSReporting),
		"submitSamplesConsent":    llx.IntData(prefs.SubmitSamplesConsent),
		"cloudBlockLevel":         llx.IntData(prefs.CloudBlockLevel),
		"cloudExtendedTimeout":    llx.IntData(prefs.CloudExtendedTimeout),
		"disableBlockAtFirstSeen": llx.BoolData(prefs.DisableBlockAtFirstSeen),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlWindowsDefenderCloudSettings), nil
}

func (p *mqlWindowsDefenderPreferences) signatureUpdates() (*mqlWindowsDefenderSignatureSettings, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(p.MqlRuntime, "windows.defender.signatureSettings", map[string]*llx.RawData{
		"__id":                                         llx.StringData("windows.defender.signatureSettings"),
		"signatureScheduleDay":                         llx.IntData(prefs.SignatureScheduleDay),
		"signatureScheduleTime":                        llx.StringData(prefs.SignatureScheduleTimeString()),
		"signatureUpdateInterval":                      llx.IntData(prefs.SignatureUpdateInterval),
		"signatureUpdateCatchupInterval":               llx.IntData(prefs.SignatureUpdateCatchupInterval),
		"signatureFallbackOrder":                       llx.StringData(prefs.SignatureFallbackOrder),
		"signatureDefinitionUpdateFileSharesSources":   llx.StringData(prefs.SignatureDefinitionUpdateFileSharesSources),
		"signatureDisableUpdateOnStartupWithoutEngine": llx.BoolData(prefs.SignatureDisableUpdateOnStartupWithoutEngine),
		"signatureFirstAuGracePeriod":                  llx.IntData(prefs.SignatureFirstAuGracePeriod),
		"signatureAuGracePeriod":                       llx.IntData(prefs.SignatureAuGracePeriod),
		"definitionUpdatesChannel":                     llx.IntData(prefs.DefinitionUpdatesChannel),
		"engineUpdatesChannel":                         llx.IntData(prefs.EngineUpdatesChannel),
		"platformUpdatesChannel":                       llx.IntData(prefs.PlatformUpdatesChannel),
		"meteredConnectionUpdates":                     llx.BoolData(prefs.MeteredConnectionUpdates),
		"reportDynamicSignatureDroppedEvent":           llx.BoolDataPtr(prefs.ReportDynamicSignatureDroppedEvent),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlWindowsDefenderSignatureSettings), nil
}

func (p *mqlWindowsDefenderPreferences) threatActions() (*mqlWindowsDefenderThreatActionSettings, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(p.MqlRuntime, "windows.defender.threatActionSettings", map[string]*llx.RawData{
		"__id":                        llx.StringData("windows.defender.threatActionSettings"),
		"severeThreatDefaultAction":   llx.IntData(prefs.SevereThreatDefaultAction),
		"highThreatDefaultAction":     llx.IntData(prefs.HighThreatDefaultAction),
		"moderateThreatDefaultAction": llx.IntData(prefs.ModerateThreatDefaultAction),
		"lowThreatDefaultAction":      llx.IntData(prefs.LowThreatDefaultAction),
		"unknownThreatDefaultAction":  llx.IntData(prefs.UnknownThreatDefaultAction),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlWindowsDefenderThreatActionSettings)
	mqlRes.cacheIds = prefs.ThreatIDDefaultAction_Ids
	mqlRes.cacheActions = prefs.ThreatIDDefaultAction_Actions
	return mqlRes, nil
}

func (p *mqlWindowsDefenderPreferences) controlledFolderAccess() (*mqlWindowsDefenderControlledFolderAccess, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(p.MqlRuntime, "windows.defender.controlledFolderAccess", map[string]*llx.RawData{
		"__id":                llx.StringData("windows.defender.controlledFolderAccess"),
		"enabled":             llx.IntData(prefs.EnableControlledFolderAccess),
		"allowedApplications": llx.ArrayData(convert.SliceAnyToInterface(prefs.ControlledFolderAccessAllowedApplications), types.String),
		"protectedFolders":    llx.ArrayData(convert.SliceAnyToInterface(prefs.ControlledFolderAccessProtectedFolders), types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlWindowsDefenderControlledFolderAccess), nil
}

func (p *mqlWindowsDefenderPreferences) networkProtection() (*mqlWindowsDefenderNetworkProtectionSettings, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(p.MqlRuntime, "windows.defender.networkProtectionSettings", map[string]*llx.RawData{
		"__id":                               llx.StringData("windows.defender.networkProtectionSettings"),
		"enableNetworkProtection":            llx.IntData(prefs.EnableNetworkProtection),
		"allowNetworkProtectionOnWinServer":  llx.BoolData(prefs.AllowNetworkProtectionOnWinServer),
		"allowNetworkProtectionDownLevel":    llx.BoolData(prefs.AllowNetworkProtectionDownLevel),
		"allowDatagramProcessingOnWinServer": llx.BoolData(prefs.AllowDatagramProcessingOnWinServer),
		"enableDnsSinkhole":                  llx.BoolData(prefs.EnableDnsSinkhole),
		"enableConvertWarnToBlock":           llx.BoolDataPtr(prefs.EnableConvertWarnToBlock),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlWindowsDefenderNetworkProtectionSettings), nil
}

func (p *mqlWindowsDefenderPreferences) behavioralNetworkBlocks() (*mqlWindowsDefenderBehavioralNetworkBlockSettings, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(p.MqlRuntime, "windows.defender.behavioralNetworkBlockSettings", map[string]*llx.RawData{
		"__id":                                      llx.StringData("windows.defender.behavioralNetworkBlockSettings"),
		"bruteForceProtectionConfiguredState":       llx.IntData(prefs.BruteForceProtectionConfiguredState),
		"bruteForceProtectionAggressiveness":        llx.IntData(prefs.BruteForceProtectionAggressiveness),
		"bruteForceProtectionMaxBlockTime":          llx.IntData(prefs.BruteForceProtectionMaxBlockTime),
		"remoteEncryptionProtectionConfiguredState": llx.IntData(prefs.RemoteEncryptionProtectionConfiguredState),
		"remoteEncryptionProtectionAggressiveness":  llx.IntData(prefs.RemoteEncryptionProtectionAggressiveness),
		"remoteEncryptionProtectionMaxBlockTime":    llx.IntData(prefs.RemoteEncryptionProtectionMaxBlockTime),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlWindowsDefenderBehavioralNetworkBlockSettings), nil
}

func (p *mqlWindowsDefenderPreferences) localSettingOverrides() (*mqlWindowsDefenderLocalSettingOverrides, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}
	pol, err := p.getPolicy()
	if err != nil {
		return nil, err
	}
	o := resolveLocalSettingOverrides(prefs, pol)
	res, err := CreateResource(p.MqlRuntime, "windows.defender.localSettingOverrides", map[string]*llx.RawData{
		"__id":                             llx.StringData("windows.defender.localSettingOverrides"),
		"spynetReporting":                  llx.BoolDataPtr(o.spynetReporting),
		"realtimeMonitoring":               llx.BoolDataPtr(o.realtimeMonitoring),
		"disableBehaviorMonitoring":        llx.BoolDataPtr(o.disableBehaviorMonitoring),
		"disableIOAVProtection":            llx.BoolDataPtr(o.disableIOAVProtection),
		"disableIntrusionPreventionSystem": llx.BoolDataPtr(o.disableIntrusionPreventionSystem),
		"disableOnAccessProtection":        llx.BoolDataPtr(o.disableOnAccessProtection),
		"scanParameters":                   llx.BoolDataPtr(o.scanParameters),
		"scanScheduleDay":                  llx.BoolDataPtr(o.scanScheduleDay),
		"avgCPULoadFactor":                 llx.BoolDataPtr(o.avgCPULoadFactor),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlWindowsDefenderLocalSettingOverrides), nil
}

func (p *mqlWindowsDefenderPreferences) remediation() (*mqlWindowsDefenderRemediationSettings, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(p.MqlRuntime, "windows.defender.remediationSettings", map[string]*llx.RawData{
		"__id":                           llx.StringData("windows.defender.remediationSettings"),
		"remediationScheduleDay":         llx.IntData(prefs.RemediationScheduleDay),
		"remediationScheduleTime":        llx.StringData(prefs.RemediationScheduleTimeString()),
		"quarantinePurgeItemsAfterDelay": llx.IntData(prefs.QuarantinePurgeItemsAfterDelay),
		"disableRestorePoint":            llx.BoolData(prefs.DisableRestorePoint),
	})
	if err != nil {
		return nil, err
	}
	r := res.(*mqlWindowsDefenderRemediationSettings)
	r.preferences.Store(p)
	return r, nil
}

func (p *mqlWindowsDefenderPreferences) exclusions() (*mqlWindowsDefenderExclusions, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(p.MqlRuntime, "windows.defender.exclusions", map[string]*llx.RawData{
		"__id":               llx.StringData("windows.defender.exclusions"),
		"paths":              llx.ArrayData(convert.SliceAnyToInterface(prefs.ExclusionPath), types.String),
		"extensions":         llx.ArrayData(convert.SliceAnyToInterface(prefs.ExclusionExtension), types.String),
		"processes":          llx.ArrayData(convert.SliceAnyToInterface(prefs.ExclusionProcess), types.String),
		"ipAddresses":        llx.ArrayData(convert.SliceAnyToInterface(prefs.ExclusionIpAddress), types.String),
		"hideFromLocalUsers": llx.BoolDataPtr(prefs.HideExclusionsFromLocalUsers),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlWindowsDefenderExclusions), nil
}

func (p *mqlWindowsDefenderPreferences) attackSurfaceReductionRules() ([]any, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return nil, err
	}

	ids := prefs.AttackSurfaceReductionRules_Ids
	actions := prefs.AttackSurfaceReductionRules_Actions

	res := make([]any, 0, len(ids))
	for i := range ids {
		var action int64
		if i < len(actions) {
			action = actions[i]
		}
		mqlRule, err := CreateResource(p.MqlRuntime, "windows.defender.asrRule", map[string]*llx.RawData{
			"__id":   llx.StringData("windows.defender.asrRule/" + ids[i]),
			"id":     llx.StringData(ids[i]),
			"name":   llx.StringData(windows.AttackSurfaceReductionRuleNames[ids[i]]),
			"action": llx.IntData(action),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func (p *mqlWindowsDefenderPreferences) puaProtection() (int64, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return 0, err
	}
	return prefs.PUAProtection, nil
}

func (p *mqlWindowsDefenderPreferences) uiLockdown() (bool, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return false, err
	}
	return prefs.UILockdown, nil
}

func (p *mqlWindowsDefenderPreferences) randomizeScheduleTaskTimes() (bool, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return false, err
	}
	return prefs.RandomizeScheduleTaskTimes, nil
}

func (p *mqlWindowsDefenderPreferences) disableAutoExclusions() (bool, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return false, err
	}
	return prefs.DisableAutoExclusions, nil
}

func (p *mqlWindowsDefenderPreferences) disableGenericReports() (bool, error) {
	prefs, err := p.getPrefs()
	if err != nil {
		return false, err
	}
	v := prefs.DisableGenericReports
	if v == nil {
		// Current platforms dropped this preference from Get-MpPreference; the
		// Group Policy value is what remains.
		pol, err := p.getPolicy()
		if err != nil {
			return false, err
		}
		v = regBoolPtr(pol.reporting, "DisableGenericRePorts")
	}
	if v == nil {
		p.DisableGenericReports.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *v, nil
}

// mqlWindowsDefenderThreatActionSettingsInternal caches the per-threat-ID
// action arrays so idActions() can zip them into typed resources.
type mqlWindowsDefenderThreatActionSettingsInternal struct {
	cacheIds     []string
	cacheActions []int64
}

func (t *mqlWindowsDefenderThreatActionSettings) idActions() ([]any, error) {
	res := make([]any, 0, len(t.cacheIds))
	for i := range t.cacheIds {
		var action int64
		if i < len(t.cacheActions) {
			action = t.cacheActions[i]
		}
		mqlAction, err := CreateResource(t.MqlRuntime, "windows.defender.threatIdAction", map[string]*llx.RawData{
			"__id":     llx.StringData("windows.defender.threatIdAction/" + t.cacheIds[i]),
			"threatId": llx.StringData(t.cacheIds[i]),
			"action":   llx.IntData(action),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAction)
	}
	return res, nil
}

// The scan, real-time and remediation settings each carry Group Policy values
// that Get-MpPreference does not report. Reading the policy costs registry
// reads, so those fields are computed on demand from the policy that the
// preferences resource reads and caches once. The settings resource keeps a
// pointer to the preferences resource that created it; it is atomic because
// CreateResource may hand back a cached instance another goroutine is reading.
type mqlWindowsDefenderScanSettingsInternal struct {
	preferences atomic.Pointer[mqlWindowsDefenderPreferences]
}

type mqlWindowsDefenderRealTimeSettingsInternal struct {
	preferences atomic.Pointer[mqlWindowsDefenderPreferences]
}

type mqlWindowsDefenderRemediationSettingsInternal struct {
	preferences atomic.Pointer[mqlWindowsDefenderPreferences]
}

// defenderPolicyOnlyFor resolves the policy-only values for a settings
// resource. A settings resource created by its own name rather than through
// windows.defender.preferences has no preferences pointer, so it is looked up
// through windows.defender. The second return value is false when Defender is
// not installed.
func defenderPolicyOnlyFor(runtime *plugin.Runtime, prefs *mqlWindowsDefenderPreferences) (defenderPolicyOnly, bool, error) {
	if prefs == nil {
		parent, err := CreateResource(runtime, "windows.defender", map[string]*llx.RawData{})
		if err != nil {
			return defenderPolicyOnly{}, false, err
		}
		v := parent.(*mqlWindowsDefender).GetPreferences()
		if v.Error != nil {
			return defenderPolicyOnly{}, false, v.Error
		}
		if v.IsNull() || v.Data == nil {
			return defenderPolicyOnly{}, false, nil
		}
		prefs = v.Data
	}
	pol, err := prefs.getPolicy()
	if err != nil {
		return defenderPolicyOnly{}, false, err
	}
	return resolveDefenderPolicyOnly(pol), true, nil
}

// policyBool returns a policy-only boolean, marking the field null when the
// policy is not configured or Defender is not installed.
func policyBool(field *plugin.TValue[bool], v *bool, ok bool, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	if !ok || v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *v, nil
}

// policyInt is policyBool for integer values.
func policyInt(field *plugin.TValue[int64], v *int64, ok bool, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	if !ok || v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *v, nil
}

func (s *mqlWindowsDefenderScanSettings) disablePackedExeScanning() (bool, error) {
	pol, ok, err := defenderPolicyOnlyFor(s.MqlRuntime, s.preferences.Load())
	return policyBool(&s.DisablePackedExeScanning, pol.disablePackedExeScanning, ok, err)
}

func (s *mqlWindowsDefenderScanSettings) daysUntilAggressiveCatchupQuickScan() (int64, error) {
	pol, ok, err := defenderPolicyOnlyFor(s.MqlRuntime, s.preferences.Load())
	return policyInt(&s.DaysUntilAggressiveCatchupQuickScan, pol.daysUntilAggressiveCatchupQuickScan, ok, err)
}

func (r *mqlWindowsDefenderRealTimeSettings) disableScanOnRealtimeEnable() (bool, error) {
	pol, ok, err := defenderPolicyOnlyFor(r.MqlRuntime, r.preferences.Load())
	return policyBool(&r.DisableScanOnRealtimeEnable, pol.disableScanOnRealtimeEnable, ok, err)
}

func (r *mqlWindowsDefenderRemediationSettings) disableRoutinelyTakingAction() (bool, error) {
	pol, ok, err := defenderPolicyOnlyFor(r.MqlRuntime, r.preferences.Load())
	return policyBool(&r.DisableRoutinelyTakingAction, pol.disableRoutinelyTakingAction, ok, err)
}

func (r *mqlWindowsDefenderRemediationSettings) passiveRemediation() (int64, error) {
	pol, ok, err := defenderPolicyOnlyFor(r.MqlRuntime, r.preferences.Load())
	return policyInt(&r.PassiveRemediation, pol.passiveRemediation, ok, err)
}
