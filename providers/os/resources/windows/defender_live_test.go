// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The defender_*_win<version>.json fixtures were captured with
// `Get-MpComputerStatus | ConvertTo-Json -Compress` and
// `Get-MpPreference | ConvertTo-Json -Compress -Depth 3` from live Windows
// Server 2016, 2019, 2022 and 2025 hosts, all running Defender platform
// 4.18.26070.9. Only the machine identifier was replaced with a synthetic
// value and the CIM metadata wrappers (CimClass, CimInstanceProperties,
// CimSystemProperties) that ConvertTo-Json emits alongside the properties were
// removed; every reported property is verbatim.
//
// Both cmdlets return the properties of a CIM instance, so their shapes come
// from the Defender platform rather than the Windows build. The platform
// updates itself independently of the OS, which is why all three versions
// agree.
var defenderLiveVersions = []string{"2016", "2019", "2022", "2025"}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return data
}

// TestMpComputerStatusLiveDecodes guards against the field types drifting away
// from what Defender actually returns. A single mismatched type aborts the
// whole json.Unmarshal, so one wrong tag takes down every field of
// windows.defender.status, not just its own.
func TestMpComputerStatusLiveDecodes(t *testing.T) {
	for _, v := range defenderLiveVersions {
		t.Run(v, func(t *testing.T) {
			status, err := ParseMpComputerStatus(readFixture(t, "defender_computer_status_win"+v+".json"))
			require.NoError(t, err)

			assert.True(t, status.AMServiceEnabled)
			assert.True(t, status.AntivirusEnabled)
			assert.True(t, status.AntispywareEnabled)
			assert.True(t, status.RealTimeProtectionEnabled)
			assert.True(t, status.BehaviorMonitorEnabled)
			assert.True(t, status.NISEnabled)
			assert.True(t, status.OnAccessProtectionEnabled)
			assert.True(t, status.IoavProtectionEnabled)
			assert.True(t, status.IsVirtualMachine)
			assert.False(t, status.IsTamperProtected)
			assert.False(t, status.RebootRequired)
			assert.Equal(t, "4.18.26070.9", status.AMProductVersion)

			// "Normal" means Defender is the active antivirus. A passive-mode
			// host still reports amServiceEnabled and antivirusEnabled true, so
			// this is what separates "protected" from "installed".
			assert.Equal(t, "Normal", status.AMRunningMode)
			assert.Equal(t, "Off", status.SmartAppControlState)

			// Device control reports names, not numbers. Defender leaves the
			// default enforcement unset on a host with no device-control
			// policy, so it must not read as a number either.
			assert.Equal(t, "Disabled", status.DeviceControlState)
			assert.Nil(t, status.DeviceControlDefaultEnforcement)

			// A host that has never run a scan reports uint32 max for the scan
			// age and leaves the scan times null. The age must read as null,
			// not as 11.7 million days.
			assert.Equal(t, int64(4294967295), status.FullScanAge)
			assert.Nil(t, DefenderAge(status.FullScanAge))
			assert.Nil(t, DefenderAge(status.QuickScanAge))
			assert.Nil(t, DefenderTime(status.FullScanStartTime))
			assert.Nil(t, DefenderTime(status.QuickScanEndTime))
			assert.Nil(t, DefenderTime(status.SmartAppControlExpiration))

			// Signature timestamps arrive in the PowerShell 5.1 "/Date(ms)/"
			// form and must parse.
			assert.NotNil(t, DefenderTime(status.AntivirusSignatureLastUpdated))
		})
	}
}

// TestMpPreferenceLiveDecodes is the Get-MpPreference counterpart.
func TestMpPreferenceLiveDecodes(t *testing.T) {
	for _, v := range defenderLiveVersions {
		t.Run(v, func(t *testing.T) {
			pref, err := ParseMpPreference(readFixture(t, "defender_preference_win"+v+".json"))
			require.NoError(t, err)

			// Defender reports this as a boolean, not as the 0/1/2 enum the
			// Set-MpPreference documentation once implied.
			assert.False(t, pref.CheckForSignaturesBeforeRunningScan)

			assert.Equal(t, int64(1), pref.ScanParameters)
			assert.Equal(t, int64(50), pref.ScanAvgCPULoadFactor)
			assert.Equal(t, int64(2), pref.MAPSReporting)
			assert.Equal(t, int64(1), pref.SubmitSamplesConsent)
			assert.Equal(t, int64(90), pref.QuarantinePurgeItemsAfterDelay)
			assert.Equal(t, "MicrosoftUpdateServer|MMPC", pref.SignatureFallbackOrder)
			assert.True(t, pref.EnableDnsSinkhole)
			assert.True(t, pref.DisableEmailScanning)
			assert.False(t, pref.DisableRealtimeMonitoring)

			// Reported by the platform on every version, at their defaults
			// except HideExclusionsFromLocalUsers, which Defender turns on.
			require.NotNil(t, pref.HideExclusionsFromLocalUsers)
			assert.True(t, *pref.HideExclusionsFromLocalUsers)
			require.NotNil(t, pref.OobeEnableRtpAndSigUpdate)
			assert.False(t, *pref.OobeEnableRtpAndSigUpdate)
			require.NotNil(t, pref.QuickScanIncludeExclusions)
			assert.Equal(t, int64(0), *pref.QuickScanIncludeExclusions)
			require.NotNil(t, pref.ReportDynamicSignatureDroppedEvent)
			assert.False(t, *pref.ReportDynamicSignatureDroppedEvent)
			require.NotNil(t, pref.EnableConvertWarnToBlock)
			assert.False(t, *pref.EnableConvertWarnToBlock)

			// Nothing is configured on these hosts, so every list preference
			// comes back as a JSON null rather than an empty array.
			assert.Empty(t, pref.ExclusionPath)
			assert.Empty(t, pref.ExclusionExtension)
			assert.Empty(t, pref.ExclusionProcess)
			assert.Empty(t, pref.ExclusionIpAddress)
			assert.Empty(t, pref.AttackSurfaceReductionRules_Ids)
			assert.Empty(t, pref.AttackSurfaceReductionRules_Actions)
			assert.Empty(t, pref.ThreatIDDefaultAction_Ids)
			assert.Empty(t, pref.ThreatIDDefaultAction_Actions)
			assert.Empty(t, pref.ControlledFolderAccessAllowedApplications)
			assert.Empty(t, pref.ControlledFolderAccessProtectedFolders)

			// The Defender platform on these hosts does not report these
			// preferences at all. They must stay nil rather than decoding to
			// false, which would claim a hardened configuration that nothing
			// verified.
			assert.Nil(t, pref.DisableIntrusionPreventionSystem)
			assert.Nil(t, pref.DisableGenericReports)
			assert.Nil(t, pref.LocalSettingOverrideSpynetReporting)
			assert.Nil(t, pref.LocalSettingOverrideRealtimeMonitoring)
			assert.Nil(t, pref.LocalSettingOverrideDisableBehaviorMonitoring)
			assert.Nil(t, pref.LocalSettingOverrideDisableIOAVProtection)
			assert.Nil(t, pref.LocalSettingOverrideDisableIntrusionPreventionSystem)
			assert.Nil(t, pref.LocalSettingOverrideDisableOnAccessProtection)
			assert.Nil(t, pref.LocalSettingOverrideScanParameters)
			assert.Nil(t, pref.LocalSettingOverrideScanScheduleDay)
			assert.Nil(t, pref.LocalSettingOverrideAvgCPULoadFactor)
		})
	}
}

// TestDefenderFixturesAgreeAcrossVersions pins the observation that the
// property set is identical across all four Windows Server versions, so a
// future divergence shows up as a test failure with the differing names rather
// than as a field that quietly reads zero on one version.
func TestDefenderFixturesAgreeAcrossVersions(t *testing.T) {
	for _, prefix := range []string{"defender_computer_status_win", "defender_preference_win"} {
		t.Run(prefix, func(t *testing.T) {
			var base map[string]json.RawMessage
			for _, v := range defenderLiveVersions {
				var got map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(readFixture(t, prefix+v+".json"), &got))
				if base == nil {
					base = got
					continue
				}
				assert.ElementsMatch(t, keysOf(base), keysOf(got),
					fmt.Sprintf("%s%s reports a different property set", prefix, v))
			}
		})
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestScheduleTime covers every serialization a Defender schedule preference
// has been observed to arrive in. Windows PowerShell 5.1, which is what ships
// on Windows Server, sends a whole TimeSpan object.
func TestScheduleTime(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"powershell 5.1 TimeSpan object", `{"Ticks":72000000000,"Days":0,"Hours":2,"Minutes":0,"Seconds":0,"TotalHours":2}`, "02:00:00"},
		{"TimeSpan object at midnight", `{"Ticks":0,"Days":0,"Hours":0,"Minutes":0,"Seconds":0}`, "00:00:00"},
		{"TimeSpan object with minutes", `{"Ticks":63000000000,"Hours":1,"Minutes":45}`, "01:45:00"},
		{"iso duration hours", `"PT2H"`, "02:00:00"},
		{"iso duration hours and minutes", `"PT1H45M"`, "01:45:00"},
		{"iso duration seconds", `"PT30S"`, "00:00:30"},
		{"already formatted", `"02:00:00"`, "02:00:00"},
		{"powershell date form", `"/Date(1705276800000)/"`, "00:00:00"},
		{"null", `null`, ""},
		{"empty", ``, ""},
		{"unrecognized string is preserved", `"whenever"`, "whenever"},
		{"trailing number with no unit is not a duration", `"PT2"`, "PT2"},
		{"no unit at all is not a duration", `"PTX"`, "PTX"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ScheduleTime(json.RawMessage(tt.raw)))
		})
	}
}

// TestLiveScheduleTimes pins the schedule preferences read off the live hosts.
func TestLiveScheduleTimes(t *testing.T) {
	for _, v := range defenderLiveVersions {
		t.Run(v, func(t *testing.T) {
			pref, err := ParseMpPreference(readFixture(t, "defender_preference_win"+v+".json"))
			require.NoError(t, err)

			assert.Equal(t, "02:00:00", pref.ScanScheduleTimeString())
			assert.Equal(t, "00:00:00", pref.ScanScheduleQuickScanTimeString())
			assert.Equal(t, "01:45:00", pref.SignatureScheduleTimeString())
			assert.Equal(t, "02:00:00", pref.RemediationScheduleTimeString())
		})
	}
}
