// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// Microsoft Defender Antivirus is queried through the Defender PowerShell
// module (the Defender cmdlets). `Get-MpComputerStatus` reports the live engine,
// signature, and protection state; `Get-MpPreference` reports the configurable
// policy; and `Get-MpThreat` / `Get-MpThreatDetection` report the recorded
// threat history.
//
// On systems where the Defender module is not present (for example a server
// running a third-party antivirus, where the Windows Defender feature is not
// installed) these cmdlets are not recognized. We detect that case and return
// ErrDefenderUnavailable so callers can resolve the resource to null rather
// than failing the entire query.
//
// Availability detection must work on non-English Windows. The "command not
// recognized" error text PowerShell writes to stderr is localized, so we do not
// rely on it as the primary signal. Instead each script is guarded with
// Get-Command and, when the cmdlet is missing, exits with a fixed sentinel code
// (defenderUnavailableExitCode) before any localized text is emitted. The
// stderr heuristic is kept only as a secondary fallback.
//
// References:
// https://learn.microsoft.com/en-us/powershell/module/defender/

// defenderUnavailableExitCode is the process exit code our scripts use to
// signal, locale-independently, that the Defender cmdlet is not present. It is a
// distinctive value (not the common 0/1/2) so it is unlikely to collide with an
// exit code PowerShell or Windows would return for an unrelated failure.
const defenderUnavailableExitCode = 200

// defenderScript wraps a Defender cmdlet pipeline with a locale-independent
// availability guard: if the cmdlet is not present, PowerShell exits with
// defenderUnavailableExitCode before running (or emitting any localized error
// for) the pipeline.
func defenderScript(cmdlet, pipeline string) string {
	return fmt.Sprintf(
		"if (-not (Get-Command %s -ErrorAction SilentlyContinue)) { exit %d }; %s",
		cmdlet, defenderUnavailableExitCode, pipeline,
	)
}

var (
	defenderComputerStatusScript  = defenderScript("Get-MpComputerStatus", `Get-MpComputerStatus | ConvertTo-Json -Compress`)
	defenderPreferenceScript      = defenderScript("Get-MpPreference", `Get-MpPreference | ConvertTo-Json -Compress -Depth 3`)
	defenderThreatScript          = defenderScript("Get-MpThreat", `Get-MpThreat | ConvertTo-Json -Compress -Depth 3`)
	defenderThreatDetectionScript = defenderScript("Get-MpThreatDetection", `Get-MpThreatDetection | ConvertTo-Json -Compress -Depth 3`)
)

// ErrDefenderUnavailable indicates the Defender PowerShell module is not
// available on the target (for example a non-Windows host or a Windows
// installation without the Defender feature).
var ErrDefenderUnavailable = errors.New("microsoft defender is not available on this system")

// isDefenderUnavailable reports whether command stderr indicates that the
// Defender cmdlets are missing rather than a genuine runtime failure. It is a
// best-effort fallback: the English "is not recognized" phrases only match on
// English hosts, so the locale-independent exit-code check in defenderUnavailable
// is the primary signal. The cmdlet names and the (non-localized) .NET exception
// type still match here on non-English hosts.
func isDefenderUnavailable(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "is not recognized") ||
		strings.Contains(s, "not recognized as the name") ||
		strings.Contains(s, "commandnotfoundexception") ||
		strings.Contains(s, "get-mpcomputerstatus") ||
		strings.Contains(s, "get-mppreference") ||
		strings.Contains(s, "get-mpthreat") ||
		strings.Contains(s, "get-mpthreatdetection")
}

// defenderUnavailable reports whether a non-zero command result indicates the
// Defender cmdlets are missing rather than a genuine runtime failure. The
// sentinel exit code set by the Get-Command guard is the primary,
// locale-independent signal; the stderr heuristic is a fallback.
func defenderUnavailable(exitStatus int, stderr string) bool {
	if exitStatus == defenderUnavailableExitCode {
		return true
	}
	return isDefenderUnavailable(stderr)
}

// runDefenderCommand executes a Defender cmdlet and returns its stdout. It
// returns ErrDefenderUnavailable when the cmdlet is not recognized.
func runDefenderCommand(p shared.Connection, script string) ([]byte, error) {
	c, err := p.RunCommand(powershell.Encode(script))
	if err != nil {
		return nil, err
	}

	if c.ExitStatus != 0 {
		stderr, rerr := io.ReadAll(c.Stderr)
		if rerr != nil {
			return nil, rerr
		}
		if defenderUnavailable(c.ExitStatus, string(stderr)) {
			return nil, ErrDefenderUnavailable
		}
		return nil, errors.New("failed to query microsoft defender: " + string(stderr))
	}

	return io.ReadAll(c.Stdout)
}

// DefenderTime parses a Defender JSON date, handling both the PowerShell 5.1
// "/Date(ms)/" form and the ISO-8601 form emitted by PowerShell 7+.
//
// Some properties (SmartAppControlExpiration) arrive as a preformatted string
// "<raw> (<ISO-8601>)", for example "(null) (1601-01-01T00:00:00Z)"; the
// parenthesized tail is the timestamp.
//
// Defender reports an unset timestamp as the FILETIME epoch, 1601-01-01, and
// that resolves to nil rather than to a date four centuries ago.
func DefenderTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.HasSuffix(s, ")") {
		if i := strings.LastIndex(s, " ("); i >= 0 {
			s = strings.TrimSpace(s[i+2 : len(s)-1])
		}
	}
	if t := powershell.PSJsonTimestamp(s); t != nil {
		return notFiletimeEpoch(t)
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return notFiletimeEpoch(&t)
		}
	}
	return nil
}

// notFiletimeEpoch returns nil for a timestamp at or before the FILETIME epoch
// (1601-01-01), which Windows uses for "never".
func notFiletimeEpoch(t *time.Time) *time.Time {
	if t.Year() <= 1601 {
		return nil
	}
	return t
}

// defenderUnsetAge is the value Get-MpComputerStatus reports for an age in days
// when the event it counts from never happened, for example FullScanAge on a
// host that has never completed a full scan. It is the UINT32 maximum.
const defenderUnsetAge = 4294967295

// DefenderAge returns an age in days reported by Get-MpComputerStatus, or nil
// when Defender reports it as unset.
func DefenderAge(v int64) *int64 {
	if v < 0 || v >= defenderUnsetAge {
		return nil
	}
	return &v
}

// flexStrings unmarshals a JSON value that PowerShell may emit either as a
// string array or, when there is a single element, as a bare scalar string.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" {
		return nil
	}
	if s[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*f = arr
		return nil
	}
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*f = []string{v}
	return nil
}

// flexInts behaves like flexStrings for integer arrays.
type flexInts []int64

func (f *flexInts) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" {
		return nil
	}
	if s[0] == '[' {
		var arr []int64
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*f = arr
		return nil
	}
	var v int64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*f = []int64{v}
	return nil
}

// flexNumStrings unmarshals a JSON value that PowerShell may emit either as a
// number array or a bare scalar number, preserving each value as a decimal
// string so large unsigned identifiers do not overflow.
type flexNumStrings []string

func (f *flexNumStrings) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" {
		return nil
	}
	if s[0] == '[' {
		var arr []json.Number
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		out := make([]string, len(arr))
		for i := range arr {
			out[i] = arr[i].String()
		}
		*f = out
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = []string{n.String()}
	return nil
}

// ScheduleTime normalizes a Defender schedule preference to a "HH:MM:SS"
// time of day.
//
// These preferences are CIM datetime values, and how PowerShell serializes
// them depends on the host. Windows PowerShell 5.1 emits a whole TimeSpan
// object, so the field arrives as
// {"Ticks":72000000000,"Days":0,"Hours":2,...}; PowerShell 7+ emits an ISO
// 8601 duration such as "PT2H"; and some builds emit the "/Date(ms)/" form or
// an already-formatted "02:00:00". All four describe 02:00 and must read the
// same way.
//
// An unrecognized value is returned trimmed rather than dropped, so an
// unfamiliar serialization surfaces as itself instead of as an empty string
// that would read as "no schedule".
func ScheduleTime(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return ""
	}

	// PowerShell 5.1: a serialized TimeSpan object.
	if s[0] == '{' {
		var ts struct {
			Ticks *int64 `json:"Ticks"`
		}
		if err := json.Unmarshal(raw, &ts); err == nil && ts.Ticks != nil {
			// A .NET tick is 100 nanoseconds, and time.Duration counts
			// nanoseconds, so the tick count scales by 100.
			return formatTimeOfDay(time.Duration(*ts.Ticks) * 100)
		}
		return s
	}

	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var v string
		if err := json.Unmarshal(raw, &v); err == nil {
			return normalizeScheduleString(v)
		}
	}
	return s
}

// normalizeScheduleString converts the string serializations of a schedule
// preference to "HH:MM:SS".
func normalizeScheduleString(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	// The "/Date(ms)/" form carries a full timestamp whose time of day is the
	// scheduled time.
	if t := powershell.PSJsonTimestamp(v); t != nil {
		return t.UTC().Format("15:04:05")
	}
	if d, ok := parseISODuration(v); ok {
		return formatTimeOfDay(d)
	}
	return v
}

// parseISODuration parses the time-only ISO 8601 durations PowerShell 7+ emits
// for a TimeSpan, for example "PT2H" or "PT1H45M". Durations carrying a date
// component are rejected, since a schedule preference never has one.
func parseISODuration(v string) (time.Duration, bool) {
	rest, ok := strings.CutPrefix(strings.ToUpper(v), "PT")
	if !ok || rest == "" {
		return 0, false
	}
	var total time.Duration
	// start indexes the first byte of the number currently being read. Slicing
	// rest keeps the digits where they already are instead of rebuilding them a
	// character at a time, which would allocate once per digit on every
	// schedule field of every scan.
	start := -1
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if (c >= '0' && c <= '9') || c == '.' {
			if start < 0 {
				start = i
			}
			continue
		}
		if start < 0 {
			return 0, false
		}
		f, err := strconv.ParseFloat(rest[start:i], 64)
		if err != nil {
			return 0, false
		}
		switch c {
		case 'H':
			total += time.Duration(f * float64(time.Hour))
		case 'M':
			total += time.Duration(f * float64(time.Minute))
		case 'S':
			total += time.Duration(f * float64(time.Second))
		default:
			return 0, false
		}
		start = -1
	}
	// A trailing number with no unit, for example "PT2".
	if start >= 0 {
		return 0, false
	}
	return total, true
}

// formatTimeOfDay renders a duration since midnight as "HH:MM:SS".
func formatTimeOfDay(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	secs := int64(d / time.Second)
	return fmt.Sprintf("%02d:%02d:%02d", (secs/3600)%24, (secs/60)%60, secs%60)
}

// MpComputerStatus mirrors the relevant fields of Get-MpComputerStatus.
type MpComputerStatus struct {
	AMEngineVersion                  string
	AMProductVersion                 string
	AMRunningMode                    string
	AMServiceEnabled                 bool
	AMServiceVersion                 string
	AntispywareEnabled               bool
	AntispywareSignatureAge          int64
	AntispywareSignatureLastUpdated  string
	AntispywareSignatureVersion      string
	AntivirusEnabled                 bool
	AntivirusSignatureAge            int64
	AntivirusSignatureLastUpdated    string
	AntivirusSignatureVersion        string
	BehaviorMonitorEnabled           bool
	ComputerID                       string
	ComputerState                    int64
	DefenderSignaturesOutOfDate      bool
	DeviceControlDefaultEnforcement  *string
	DeviceControlPoliciesLastUpdated string
	DeviceControlState               string
	FullScanAge                      int64
	FullScanStartTime                string
	FullScanEndTime                  string
	FullScanOverdue                  bool
	FullScanRequired                 bool
	FullScanSignatureVersion         string
	IoavProtectionEnabled            bool
	IsTamperProtected                bool
	IsVirtualMachine                 bool
	LastFullScanSource               int64
	LastQuickScanSource              int64
	NISEnabled                       bool
	NISEngineVersion                 string
	NISSignatureAge                  int64
	NISSignatureLastUpdated          string
	NISSignatureVersion              string
	OnAccessProtectionEnabled        bool
	ProductStatus                    int64
	QuickScanAge                     int64
	QuickScanStartTime               string
	QuickScanEndTime                 string
	QuickScanOverdue                 bool
	QuickScanSignatureVersion        string
	RealTimeProtectionEnabled        bool
	RealTimeScanDirection            int64
	RebootRequired                   bool
	SmartAppControlState             string
	SmartAppControlExpiration        string
	TamperProtectionSource           string
}

// MpPreference mirrors the relevant fields of Get-MpPreference.
type MpPreference struct {
	// scan
	ScanParameters                                int64
	ScanScheduleDay                               int64
	ScanScheduleTime                              json.RawMessage
	ScanScheduleQuickScanTime                     json.RawMessage
	ScanScheduleOffset                            int64
	ScanAvgCPULoadFactor                          int64
	ScanOnlyIfIdleEnabled                         bool
	CheckForSignaturesBeforeRunningScan           bool
	DisableArchiveScanning                        bool
	DisableEmailScanning                          bool
	DisableRemovableDriveScanning                 bool
	DisableScanningMappedNetworkDrivesForFullScan bool
	DisableScanningNetworkFiles                   bool
	DisableCatchupFullScan                        bool
	DisableCatchupQuickScan                       bool
	DisableCpuThrottleOnIdleScans                 bool
	EnableFullScanOnBatteryPower                  bool
	EnableLowCpuPriority                          bool
	QuickScanIncludeExclusions                    *int64

	// real-time
	DisableRealtimeMonitoring        bool
	DisableBehaviorMonitoring        bool
	DisableIOAVProtection            bool
	DisableScriptScanning            bool
	DisableIntrusionPreventionSystem *bool
	RealTimeScanDirection            int64
	EnableFileHashComputation        bool
	OobeEnableRtpAndSigUpdate        *bool

	// cloud / MAPS
	MAPSReporting           int64
	SubmitSamplesConsent    int64
	CloudBlockLevel         int64
	CloudExtendedTimeout    int64
	DisableBlockAtFirstSeen bool

	// signature updates
	SignatureScheduleDay                         int64
	SignatureScheduleTime                        json.RawMessage
	SignatureUpdateInterval                      int64
	SignatureUpdateCatchupInterval               int64
	SignatureFallbackOrder                       string
	SignatureDefinitionUpdateFileSharesSources   string
	SignatureDisableUpdateOnStartupWithoutEngine bool
	SignatureFirstAuGracePeriod                  int64
	SignatureAuGracePeriod                       int64
	DefinitionUpdatesChannel                     int64
	EngineUpdatesChannel                         int64
	PlatformUpdatesChannel                       int64
	MeteredConnectionUpdates                     bool
	ReportDynamicSignatureDroppedEvent           *bool

	// threat actions
	SevereThreatDefaultAction     int64
	HighThreatDefaultAction       int64
	ModerateThreatDefaultAction   int64
	LowThreatDefaultAction        int64
	UnknownThreatDefaultAction    int64
	ThreatIDDefaultAction_Ids     flexNumStrings
	ThreatIDDefaultAction_Actions flexInts

	// controlled folder access
	EnableControlledFolderAccess              int64
	ControlledFolderAccessAllowedApplications flexStrings
	ControlledFolderAccessProtectedFolders    flexStrings

	// network protection
	EnableNetworkProtection            int64
	AllowNetworkProtectionOnWinServer  bool
	AllowNetworkProtectionDownLevel    bool
	AllowDatagramProcessingOnWinServer bool
	EnableDnsSinkhole                  bool
	EnableConvertWarnToBlock           *bool

	// behavioral network blocks (brute-force and remote-encryption protection)
	BruteForceProtectionConfiguredState       int64
	BruteForceProtectionAggressiveness        int64
	BruteForceProtectionMaxBlockTime          int64
	RemoteEncryptionProtectionConfiguredState int64
	RemoteEncryptionProtectionAggressiveness  int64
	RemoteEncryptionProtectionMaxBlockTime    int64

	// local setting overrides (whether a local preference may override policy)
	LocalSettingOverrideSpynetReporting                  *bool
	LocalSettingOverrideRealtimeMonitoring               *bool
	LocalSettingOverrideDisableBehaviorMonitoring        *bool
	LocalSettingOverrideDisableIOAVProtection            *bool
	LocalSettingOverrideDisableIntrusionPreventionSystem *bool
	LocalSettingOverrideDisableOnAccessProtection        *bool
	LocalSettingOverrideScanParameters                   *bool
	LocalSettingOverrideScanScheduleDay                  *bool
	LocalSettingOverrideAvgCPULoadFactor                 *bool

	// remediation
	RemediationScheduleDay         int64
	RemediationScheduleTime        json.RawMessage
	QuarantinePurgeItemsAfterDelay int64
	DisableRestorePoint            bool

	// exclusions
	ExclusionPath      flexStrings
	ExclusionExtension flexStrings
	ExclusionProcess   flexStrings
	ExclusionIpAddress flexStrings
	// HideExclusionsFromLocalUsers hides the exclusion lists from users who
	// are not administrators.
	HideExclusionsFromLocalUsers *bool

	// attack surface reduction
	AttackSurfaceReductionRules_Ids     flexStrings
	AttackSurfaceReductionRules_Actions flexInts

	// misc
	PUAProtection              int64
	UILockdown                 bool
	RandomizeScheduleTaskTimes bool
	DisableAutoExclusions      bool
	// Defender uses the historical "RePorts" casing for this preference; the
	// json tag matches it explicitly so the field is populated regardless of how
	// the cmdlet serializes it.
	DisableGenericReports *bool `json:"DisableGenericRePorts"`
}

// ScanScheduleTimeString returns the scheduled-scan time of day.
func (p *MpPreference) ScanScheduleTimeString() string { return ScheduleTime(p.ScanScheduleTime) }

// ScanScheduleQuickScanTimeString returns the scheduled quick-scan time of day.
func (p *MpPreference) ScanScheduleQuickScanTimeString() string {
	return ScheduleTime(p.ScanScheduleQuickScanTime)
}

// SignatureScheduleTimeString returns the scheduled signature-update time of day.
func (p *MpPreference) SignatureScheduleTimeString() string {
	return ScheduleTime(p.SignatureScheduleTime)
}

// RemediationScheduleTimeString returns the scheduled-remediation time of day.
func (p *MpPreference) RemediationScheduleTimeString() string {
	return ScheduleTime(p.RemediationScheduleTime)
}

// MpThreat mirrors the relevant fields of Get-MpThreat.
type MpThreat struct {
	ThreatID         int64
	ThreatName       string
	SeverityID       int64
	CategoryID       int64
	IsActive         bool
	DidThreatExecute bool
	RollupStatus     int64
	Resources        flexStrings
}

// MpThreatDetection mirrors the relevant fields of Get-MpThreatDetection.
type MpThreatDetection struct {
	DetectionID                    string
	ThreatID                       int64
	ProcessName                    string
	DomainUser                     string
	DetectionSourceTypeID          int64
	CurrentThreatExecutionStatusID int64
	ThreatStatusID                 int64
	CleaningActionID               int64
	ActionSuccess                  bool
	InitialDetectionTime           string
	LastThreatStatusChangeTime     string
	RemediationTime                string
	Resources                      flexStrings
}

// GetDefenderComputerStatus runs Get-MpComputerStatus and parses the result.
func GetDefenderComputerStatus(p shared.Connection) (*MpComputerStatus, error) {
	data, err := runDefenderCommand(p, defenderComputerStatusScript)
	if err != nil {
		return nil, err
	}
	return ParseMpComputerStatus(data)
}

func ParseMpComputerStatus(data []byte) (*MpComputerStatus, error) {
	var status MpComputerStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// GetDefenderPreferences runs Get-MpPreference and parses the result.
func GetDefenderPreferences(p shared.Connection) (*MpPreference, error) {
	data, err := runDefenderCommand(p, defenderPreferenceScript)
	if err != nil {
		return nil, err
	}
	return ParseMpPreference(data)
}

func ParseMpPreference(data []byte) (*MpPreference, error) {
	var pref MpPreference
	if err := json.Unmarshal(data, &pref); err != nil {
		return nil, err
	}
	return &pref, nil
}

// GetDefenderThreats runs Get-MpThreat and parses the result.
func GetDefenderThreats(p shared.Connection) ([]MpThreat, error) {
	data, err := runDefenderCommand(p, defenderThreatScript)
	if err != nil {
		return nil, err
	}
	return ParseMpThreats(data)
}

func ParseMpThreats(data []byte) ([]MpThreat, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return []MpThreat{}, nil
	}
	return decodeJSONObjectOrArray[MpThreat](data)
}

// GetDefenderThreatDetections runs Get-MpThreatDetection and parses the result.
func GetDefenderThreatDetections(p shared.Connection) ([]MpThreatDetection, error) {
	data, err := runDefenderCommand(p, defenderThreatDetectionScript)
	if err != nil {
		return nil, err
	}
	return ParseMpThreatDetections(data)
}

func ParseMpThreatDetections(data []byte) ([]MpThreatDetection, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return []MpThreatDetection{}, nil
	}
	return decodeJSONObjectOrArray[MpThreatDetection](data)
}

// decodeJSONObjectOrArray decodes a JSON payload that PowerShell may emit as a
// single object (one result) or an array (multiple results).
func decodeJSONObjectOrArray[T any](data []byte) ([]T, error) {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		return []T{}, nil
	}
	if s[0] == '[' {
		var arr []T
		if err := json.Unmarshal(data, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var item T
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, err
	}
	return []T{item}, nil
}

// AttackSurfaceReductionRuleNames maps the well-known ASR rule GUIDs to their
// friendly names. Unknown GUIDs resolve to an empty name.
//
// https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
var AttackSurfaceReductionRuleNames = map[string]string{
	"56a863a9-875e-4185-98a7-b882c64b5ce5": "Block abuse of exploited vulnerable signed drivers",
	"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Block Adobe Reader from creating child processes",
	"d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block all Office applications from creating child processes",
	"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Block credential stealing from the Windows local security authority subsystem (lsass.exe)",
	"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable content from email client and webmail",
	"01443614-cd74-433a-b99e-2ecdc07bfc25": "Block executable files from running unless they meet a prevalence, age, or trusted list criterion",
	"5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Block execution of potentially obfuscated scripts",
	"d3e037e1-3eb8-44c8-a917-57927947596d": "Block JavaScript or VBScript from launching downloaded executable content",
	"3b576869-a4ec-4529-8536-b80a7769e899": "Block Office applications from creating executable content",
	"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Block Office applications from injecting code into other processes",
	"26190899-1602-49e8-8b27-eb1d0a1ce869": "Block Office communication application from creating child processes",
	"e6db77e5-3df2-4cf1-b95a-636979351e5b": "Block persistence through WMI event subscription",
	"d1e49aac-8f56-4280-b9ba-993a6d77406c": "Block process creations originating from PSExec and WMI commands",
	"33ddedf1-c6e0-47cb-833e-de6133960387": "Block rebooting machine in Safe Mode",
	"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Block untrusted and unsigned processes that run from USB",
	"c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": "Block use of copied or impersonated system tools",
	"a8f5898e-1dc8-49a9-9878-85004b8a61e6": "Block Webshell creation for Servers",
	"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Block Win32 API calls from Office macros",
	"c1db55ab-c21a-4637-bb3f-a12568109d35": "Use advanced protection against ransomware",
}
