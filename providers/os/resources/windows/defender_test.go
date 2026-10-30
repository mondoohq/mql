// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMpComputerStatus(t *testing.T) {
	data, err := os.ReadFile("testdata/defender_computer_status.json")
	require.NoError(t, err)

	status, err := ParseMpComputerStatus(data)
	require.NoError(t, err)

	assert.True(t, status.AMServiceEnabled)
	assert.True(t, status.AntivirusEnabled)
	assert.True(t, status.AntispywareEnabled)
	assert.True(t, status.RealTimeProtectionEnabled)
	assert.True(t, status.BehaviorMonitorEnabled)
	assert.True(t, status.IsTamperProtected)
	assert.Equal(t, "Signatures", status.TamperProtectionSource)
	assert.Equal(t, "1.405.319.0", status.AntivirusSignatureVersion)
	assert.Equal(t, "Off", status.SmartAppControlState)

	// time parsing of the "/Date(ms)/" form
	ts := DefenderTime(status.AntivirusSignatureLastUpdated)
	require.NotNil(t, ts)
	assert.Equal(t, int64(1705334400), ts.Unix())

	// null time fields resolve to nil
	assert.Nil(t, DefenderTime(status.FullScanStartTime))
	assert.Nil(t, DefenderTime(status.SmartAppControlExpiration))
}

func TestParseMpPreference(t *testing.T) {
	data, err := os.ReadFile("testdata/defender_preference.json")
	require.NoError(t, err)

	pref, err := ParseMpPreference(data)
	require.NoError(t, err)

	// scan
	assert.Equal(t, int64(1), pref.ScanParameters)
	assert.True(t, pref.DisableEmailScanning)
	assert.False(t, pref.DisableArchiveScanning)

	// cloud
	assert.Equal(t, int64(2), pref.MAPSReporting)
	assert.Equal(t, int64(1), pref.SubmitSamplesConsent)
	assert.Equal(t, int64(2), pref.CloudBlockLevel)

	// threat actions
	assert.Equal(t, int64(2), pref.SevereThreatDefaultAction)

	// per-threat-ID overrides: large unsigned ids preserved as strings
	require.Len(t, pref.ThreatIDDefaultAction_Ids, 2)
	assert.Equal(t, "2147519003", pref.ThreatIDDefaultAction_Ids[0])
	require.Len(t, pref.ThreatIDDefaultAction_Actions, 2)
	assert.Equal(t, int64(6), pref.ThreatIDDefaultAction_Actions[0])

	// controlled folder access
	assert.Equal(t, int64(1), pref.EnableControlledFolderAccess)
	require.Len(t, pref.ControlledFolderAccessProtectedFolders, 1)

	// network protection
	assert.Equal(t, int64(1), pref.EnableNetworkProtection)
	assert.True(t, pref.AllowNetworkProtectionOnWinServer)

	// exclusions: array form
	require.Len(t, pref.ExclusionPath, 2)
	assert.Equal(t, "C:\\Temp", pref.ExclusionPath[0])
	// exclusions: scalar form coerced into a single-element slice
	require.Len(t, pref.ExclusionExtension, 1)
	assert.Equal(t, ".log", pref.ExclusionExtension[0])
	// exclusions: null resolves to an empty slice
	assert.Empty(t, pref.ExclusionIpAddress)

	// ASR rules
	require.Len(t, pref.AttackSurfaceReductionRules_Ids, 2)
	assert.Equal(t, "56a863a9-875e-4185-98a7-b882c64b5ce5", pref.AttackSurfaceReductionRules_Ids[0])
	assert.Equal(t, int64(1), pref.AttackSurfaceReductionRules_Actions[0])
	assert.Equal(t,
		"Block abuse of exploited vulnerable signed drivers",
		AttackSurfaceReductionRuleNames[pref.AttackSurfaceReductionRules_Ids[0]],
	)

	// schedule time fields preserved as raw strings across PowerShell versions
	assert.Equal(t, "00:00:00", pref.ScanScheduleQuickScanTimeString())
	assert.NotEmpty(t, pref.ScanScheduleTimeString())

	// behavioral network blocks
	assert.Equal(t, int64(1), pref.BruteForceProtectionConfiguredState)
	assert.Equal(t, int64(2), pref.BruteForceProtectionAggressiveness)
	assert.Equal(t, int64(1), pref.RemoteEncryptionProtectionConfiguredState)

	// local setting overrides
	require.NotNil(t, pref.LocalSettingOverrideSpynetReporting)
	assert.False(t, *pref.LocalSettingOverrideSpynetReporting)
	require.NotNil(t, pref.LocalSettingOverrideRealtimeMonitoring)
	assert.False(t, *pref.LocalSettingOverrideRealtimeMonitoring)

	// misc
	assert.Equal(t, int64(1), pref.PUAProtection)
	assert.True(t, pref.RandomizeScheduleTaskTimes)
	// the "RePorts" casing is matched via the explicit json tag
	require.NotNil(t, pref.DisableGenericReports)
	assert.True(t, *pref.DisableGenericReports)

	// preferences configured away from their defaults
	require.NotNil(t, pref.QuickScanIncludeExclusions)
	assert.Equal(t, int64(1), *pref.QuickScanIncludeExclusions)
	require.NotNil(t, pref.OobeEnableRtpAndSigUpdate)
	assert.True(t, *pref.OobeEnableRtpAndSigUpdate)
	require.NotNil(t, pref.ReportDynamicSignatureDroppedEvent)
	assert.True(t, *pref.ReportDynamicSignatureDroppedEvent)
	require.NotNil(t, pref.EnableConvertWarnToBlock)
	assert.True(t, *pref.EnableConvertWarnToBlock)
	require.NotNil(t, pref.HideExclusionsFromLocalUsers)
	assert.False(t, *pref.HideExclusionsFromLocalUsers)
}

// A Defender platform that predates a preference does not report it. It must
// decode to nil, so the field reads null rather than claiming the default.
func TestParseMpPreference_AbsentPreferencesAreNil(t *testing.T) {
	pref, err := ParseMpPreference([]byte(`{"ScanParameters":1}`))
	require.NoError(t, err)
	assert.Nil(t, pref.QuickScanIncludeExclusions)
	assert.Nil(t, pref.OobeEnableRtpAndSigUpdate)
	assert.Nil(t, pref.ReportDynamicSignatureDroppedEvent)
	assert.Nil(t, pref.EnableConvertWarnToBlock)
	assert.Nil(t, pref.HideExclusionsFromLocalUsers)
}

func TestParseMpThreats(t *testing.T) {
	data, err := os.ReadFile("testdata/defender_threats.json")
	require.NoError(t, err)

	threats, err := ParseMpThreats(data)
	require.NoError(t, err)
	require.Len(t, threats, 2)

	assert.Equal(t, int64(2147519003), threats[0].ThreatID)
	assert.Equal(t, "Virus:DOS/EICAR_Test_File", threats[0].ThreatName)
	assert.False(t, threats[0].IsActive)
	require.Len(t, threats[0].Resources, 1)

	assert.True(t, threats[1].IsActive)
	assert.True(t, threats[1].DidThreatExecute)
	require.Len(t, threats[1].Resources, 2)
}

func TestParseMpThreats_Single(t *testing.T) {
	// PowerShell emits a bare object when there is exactly one result.
	single := `{"ThreatID":2147519003,"ThreatName":"Virus:DOS/EICAR_Test_File","SeverityID":5,"IsActive":false,"Resources":"file:_C:\\eicar.com"}`
	threats, err := ParseMpThreats([]byte(single))
	require.NoError(t, err)
	require.Len(t, threats, 1)
	assert.Equal(t, int64(2147519003), threats[0].ThreatID)
	require.Len(t, threats[0].Resources, 1)
}

func TestParseMpThreats_Empty(t *testing.T) {
	threats, err := ParseMpThreats([]byte(""))
	require.NoError(t, err)
	assert.Empty(t, threats)
}

func TestIsDefenderUnavailable(t *testing.T) {
	assert.True(t, isDefenderUnavailable("The term 'Get-MpComputerStatus' is not recognized as the name of a cmdlet"))
	assert.True(t, isDefenderUnavailable("CommandNotFoundException"))
	assert.False(t, isDefenderUnavailable("Access is denied"))
}

// defenderUnavailable must work on non-English Windows. The localized "command
// not recognized" stderr text is not reliable, so the sentinel exit code set by
// the Get-Command guard is the primary, language-independent signal.
func TestDefenderUnavailable(t *testing.T) {
	t.Run("sentinel exit code, no stderr", func(t *testing.T) {
		// The Get-Command guard exits before emitting any (localized) text.
		assert.True(t, defenderUnavailable(defenderUnavailableExitCode, ""))
	})

	t.Run("sentinel exit code on a non-English host", func(t *testing.T) {
		// Worst case: fully localized prose with no English phrase and no cmdlet
		// token to fall back on. The heuristic alone cannot detect it, but the
		// sentinel exit code still flags it correctly.
		german := "Die Benennung wurde nicht als Name eines Cmdlets erkannt. Überprüfen Sie die Schreibweise des Namens."
		assert.False(t, isDefenderUnavailable(german), "heuristic cannot match fully localized text")
		assert.True(t, defenderUnavailable(defenderUnavailableExitCode, german))
	})

	t.Run("English stderr fallback without the sentinel", func(t *testing.T) {
		// Older path: a command-not-found surfaced via stderr on an English host.
		assert.True(t, defenderUnavailable(1, "The term 'Get-MpComputerStatus' is not recognized"))
	})

	t.Run("genuine error is not treated as unavailable", func(t *testing.T) {
		// A real failure (e.g. access denied) on a non-sentinel exit code must be
		// surfaced, not swallowed as "Defender not installed".
		assert.False(t, defenderUnavailable(1, "Zugriff verweigert"))
		assert.False(t, defenderUnavailable(1, "Access is denied"))
	})
}

// Every Defender script must carry the locale-independent availability guard so
// a missing cmdlet exits with the sentinel before any localized error text.
func TestDefenderScriptsHaveAvailabilityGuard(t *testing.T) {
	cases := map[string]struct {
		script string
		cmdlet string
	}{
		"computer status":  {defenderComputerStatusScript, "Get-MpComputerStatus"},
		"preferences":      {defenderPreferenceScript, "Get-MpPreference"},
		"threats":          {defenderThreatScript, "Get-MpThreat"},
		"threat detection": {defenderThreatDetectionScript, "Get-MpThreatDetection"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Contains(t, tc.script, "Get-Command "+tc.cmdlet, "guard must probe the cmdlet")
			assert.Contains(t, tc.script, "exit 200", "guard must exit with the sentinel code")
			// The pipeline itself is still present after the guard.
			assert.Contains(t, tc.script, tc.cmdlet+" | ConvertTo-Json")
		})
	}
}

func TestDefenderTime(t *testing.T) {
	t.Run("PowerShell 5.1 /Date(ms)/ form", func(t *testing.T) {
		ts := DefenderTime(`/Date(1705334400000)/`)
		require.NotNil(t, ts)
		assert.Equal(t, int64(1705334400), ts.Unix())
	})

	t.Run("ISO 8601 form", func(t *testing.T) {
		ts := DefenderTime("2026-03-01T08:30:00Z")
		require.NotNil(t, ts)
		assert.Equal(t, "2026-03-01T08:30:00Z", ts.UTC().Format(time.RFC3339))
	})

	// Get-MpComputerStatus on Windows 11 25H2 reports SmartAppControlExpiration
	// as a preformatted string. With no expiration set it reads
	// "(null) (1601-01-01T00:00:00Z)".
	t.Run("preformatted string with no expiration", func(t *testing.T) {
		assert.Nil(t, DefenderTime("(null) (1601-01-01T00:00:00Z)"))
	})

	t.Run("preformatted string with an expiration", func(t *testing.T) {
		ts := DefenderTime("134087040000000000 (2025-11-28T00:00:00Z)")
		require.NotNil(t, ts)
		assert.Equal(t, "2025-11-28T00:00:00Z", ts.UTC().Format(time.RFC3339))
	})

	t.Run("FILETIME epoch is unset", func(t *testing.T) {
		assert.Nil(t, DefenderTime("1601-01-01T00:00:00Z"))
		assert.Nil(t, DefenderTime(`/Date(-11644473600000)/`))
	})

	t.Run("empty and unparseable", func(t *testing.T) {
		assert.Nil(t, DefenderTime(""))
		assert.Nil(t, DefenderTime("(null)"))
		assert.Nil(t, DefenderTime("not a date"))
	})
}

func TestDefenderAge(t *testing.T) {
	// Get-MpComputerStatus reports FullScanAge and QuickScanAge as the UINT32
	// maximum on a host that has never completed a scan.
	assert.Nil(t, DefenderAge(4294967295))
	assert.Nil(t, DefenderAge(-1))

	for _, v := range []int64{0, 1, 392, 65535} {
		got := DefenderAge(v)
		require.NotNil(t, got, "age %d", v)
		assert.Equal(t, v, *got)
	}
}
