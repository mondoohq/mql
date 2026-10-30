// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// Windows Update Agent history operation codes (IUpdateHistoryEntry.Operation).
const (
	UpdateOperationInstallation   = 1
	UpdateOperationUninstallation = 2
)

// Windows Update Agent history result codes (IUpdateHistoryEntry.ResultCode /
// OperationResultCode). 2 == orcSucceeded.
const (
	UpdateResultSucceeded = 2
)

// CBSStateInstalled is the Component Based Servicing CurrentState value (0x70)
// that marks a package as installed. Other states (staged, superseded,
// resolved, …) use different values and are not considered installed.
const CBSStateInstalled = 112

var kbIDRegexp = regexp.MustCompile(`(?i)KB\d+`)

// ParseKBID extracts the first knowledge base article ID (e.g. "KB5034441")
// from a string such as an update title or a CBS package name. It returns an
// empty string when no KB ID is present (common for driver and Defender
// definition updates). The returned ID is upper-cased ("KB" + digits).
func ParseKBID(s string) string {
	m := kbIDRegexp.FindString(s)
	if m == "" {
		return ""
	}
	return "KB" + strings.TrimPrefix(strings.ToUpper(m), "KB")
}

// windowsUpdateHistoryMaxEntries caps how many history records
// WINDOWS_QUERY_UPDATE_HISTORY asks the Windows Update Agent for.
// IUpdateSearcher.QueryHistory returns records in descending chronological
// order (newest first: see IUpdateSearcher::QueryHistory on Microsoft Learn),
// so the cap keeps the newest entries and only drops history older than that.
// Both consumers (os.lastUpdate and windows.update.installed) only care about
// the newest install per KB, so a host that has accumulated more than this
// many history events over its lifetime loses nothing they read; on a host
// with years of updates, unbounded QueryHistory is the expensive part of this
// query, run over records nothing downstream can still use once a newer
// install for the same KB has already been seen.
const windowsUpdateHistoryMaxEntries = 1000

// WINDOWS_QUERY_UPDATE_HISTORY enumerates the Windows Update Agent install
// history via the COM API, capped to the most recent windowsUpdateHistoryMaxEntries
// records and pre-filtered in PowerShell to succeeded installations
// (Operation == Installation, ResultCode == Succeeded) so that only those
// entries are turned into objects and serialized — uninstalls, failures, and
// aborted/in-progress entries are dropped before the expensive per-entry
// work. The per-entry loop is a `foreach` building `[pscustomobject]`
// records rather than `Where-Object` / `ForEach-Object` / `New-Object
// psobject`: the pipeline cmdlets are markedly slower in PowerShell,
// which matters here because history can run into the thousands of
// entries on a long-lived host. Go's FilterInstalledHistory re-applies the
// same predicate (and de-duplicates by KB), so the two must stay in sync;
// see TestUpdateHistoryQueryFilterMatchesGo. Dates serialize as PowerShell
// "/Date(ms)/" strings. Classification is the name of the one category whose
// Type is UpdateClassification; Categories also carries product names, in no
// fixed order.
//
// $ErrorActionPreference is Stop so a failed COM call exits non-zero. Without
// it GetTotalHistoryCount failing leaves $count null, the $count -gt 0 guard is
// false, and the caller is handed an empty history: a host whose update agent
// could not be reached reports that nothing has ever been installed.
var WINDOWS_QUERY_UPDATE_HISTORY = fmt.Sprintf(`
$ErrorActionPreference='Stop';
$ProgressPreference='SilentlyContinue';
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$count = $searcher.GetTotalHistoryCount()
$history = @()
if ($count -gt 0) {
  $take = [Math]::Min($count, %d)
  $history = foreach ($entry in $searcher.QueryHistory(0, $take)) {
    if ($entry.Operation -eq %d -and $entry.ResultCode -eq %d) {
      $classification = $null
      foreach ($category in $entry.Categories) {
        if ($category.Type -eq 'UpdateClassification') { $classification = $category.Name; break }
      }
      [pscustomobject]@{
        "Title" = $entry.Title
        "Date" = $entry.Date
        "Operation" = [int]$entry.Operation
        "ResultCode" = [int]$entry.ResultCode
        "SupportUrl" = $entry.SupportUrl
        "UpdateID" = $entry.UpdateIdentity.UpdateID
        "RevisionNumber" = [int]$entry.UpdateIdentity.RevisionNumber
        "Categories" = @($entry.Categories | ForEach-Object { $_.Name })
        "Classification" = $classification
      }
    }
  }
}
@($history) | ConvertTo-Json -Depth 3`, windowsUpdateHistoryMaxEntries, UpdateOperationInstallation, UpdateResultSucceeded)

// WindowsUpdateHistoryEntry is a single Windows Update Agent history record.
type WindowsUpdateHistoryEntry struct {
	Title          string   `json:"Title"`
	Date           string   `json:"Date"`
	Operation      int      `json:"Operation"`
	ResultCode     int      `json:"ResultCode"`
	SupportUrl     string   `json:"SupportUrl"`
	UpdateID       string   `json:"UpdateID"`
	RevisionNumber int      `json:"RevisionNumber"`
	Categories     []string `json:"Categories"`
	Classification string   `json:"Classification"`
}

func ParseWindowsUpdateHistory(input io.Reader) ([]WindowsUpdateHistoryEntry, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return []WindowsUpdateHistoryEntry{}, nil
	}

	return powershell.UnmarshalList[WindowsUpdateHistoryEntry](data)
}

// FilterInstalledHistory returns the succeeded installation entries from a
// Windows Update Agent history, de-duplicated by KB ID (falling back to the
// update identity when no KB is present). Uninstallations, failed operations,
// and entries with neither a KB nor an update identity are dropped. The first
// entry seen for each update is kept; QueryHistory returns history
// newest-first, so this keeps the most recent.
func FilterInstalledHistory(entries []WindowsUpdateHistoryEntry) []WindowsUpdateHistoryEntry {
	seen := map[string]struct{}{}
	res := []WindowsUpdateHistoryEntry{}
	for i := range entries {
		e := entries[i]
		if e.Operation != UpdateOperationInstallation || e.ResultCode != UpdateResultSucceeded {
			continue
		}

		key := ParseKBID(e.Title)
		if key == "" {
			key = e.UpdateID
		}
		// An entry with neither a KB nor an update identity can't be
		// deduplicated and isn't usefully identifiable, so drop it.
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		res = append(res, e)
	}
	return res
}

// OperationName maps a Windows Update Agent operation code to a label.
func OperationName(op int) string {
	switch op {
	case UpdateOperationInstallation:
		return "Installation"
	case UpdateOperationUninstallation:
		return "Uninstallation"
	default:
		return ""
	}
}

// ClassifyUpdate derives a best-effort classification for an update. It
// prefers the agent-reported classification (the category typed
// UpdateClassification, never a product category) and otherwise infers one
// from the title (Windows Update history entries frequently report no
// categories).
func ClassifyUpdate(classification string, title string) string {
	if classification != "" {
		return classification
	}
	return inferClassificationFromTitle(title)
}

func inferClassificationFromTitle(title string) string {
	t := strings.ToLower(title)
	switch {
	case strings.Contains(t, "security update"):
		return "Security Updates"
	case strings.Contains(t, "definition update"), strings.Contains(t, "security intelligence update"):
		return "Definition Updates"
	case strings.Contains(t, "servicing stack update"):
		return "Servicing Stack Updates"
	case strings.Contains(t, "cumulative update"), strings.Contains(t, "rollup"):
		return "Update Rollups"
	case strings.Contains(t, "feature update"):
		return "Feature Packs"
	case strings.Contains(t, "driver"):
		return "Drivers"
	case strings.Contains(t, "critical update"):
		return "Critical Updates"
	default:
		return ""
	}
}

// nonOSProductMarkers name products that the Windows Update Agent services
// alongside the operating system but that are not the operating system. A
// .NET Framework or an Office security update is a real update; counting it
// would report a host years behind on Windows as patched this morning, which is
// the same failure the Definition Updates filter exists to prevent.
//
// The Defender entries matter beyond the signature stream the classification
// already drops: the antimalware platform ships its own "Update for Windows
// Defender Antivirus antimalware platform" entries, whose title would otherwise
// pass the Windows product test below.
var nonOSProductMarkers = []string{
	".net",
	"office",
	"visual studio",
	"visual c++",
	"sql server",
	"exchange server",
	"silverlight",
	"microsoft edge",
	"defender",
	"malicious software removal tool",
	"security intelligence",
	"skype",
	"onedrive",
	"developer tools, runtimes, and redistributables",
}

// IsOperatingSystemUpdate reports whether a Windows Update Agent history entry
// is a patch to the operating system itself.
//
// The agent reports a product alongside the classification, but history entries
// frequently carry no categories at all (see ClassifyUpdate), so the title is
// the signal that has to hold on its own. Titles name the product they patch
// after "Update for ", and the first such product is the one being patched:
//
//	"2026-08 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5063878)"
//	                             -> "Windows 11 Version 24H2"          operating system
//	"Security Update for Microsoft .NET Framework 4.8 for Windows Server 2019 (KB5034619)"
//	                    -> "Microsoft .NET Framework 4.8"              not the operating system
//
// That second title is why a plain search for "Windows" in the title is wrong:
// a .NET update names the Windows release it targets, and matching it would
// count every .NET servicing entry as an operating system patch.
//
// classification is the agent-reported classification, "" when there is none.
func IsOperatingSystemUpdate(categories []string, classification string, title string) bool {
	if slices.ContainsFunc(categories, namesNonOSProduct) {
		return false
	}
	if namesNonOSProduct(title) {
		return false
	}

	switch ClassifyUpdate(classification, title) {
	case "Definition Updates", "Drivers":
		// Definition data lands daily and a driver is firmware for one device,
		// so neither says anything about operating system patch state.
		return false
	}

	// The servicing stack ships only for the operating system, and its titles
	// do not always follow the "Update for <product>" shape.
	if strings.Contains(strings.ToLower(title), "servicing stack update") {
		return true
	}
	// A feature update is a whole operating system version move, titled
	// "Feature update to Windows 11, version 24H2" with no "for" clause.
	if strings.Contains(strings.ToLower(title), "feature update to windows") {
		return true
	}

	return strings.HasPrefix(strings.ToLower(titleProduct(title)), "windows")
}

// namesNonOSProduct reports whether s names one of the products the agent
// services that are not the operating system.
func namesNonOSProduct(s string) bool {
	lower := strings.ToLower(s)
	for _, marker := range nonOSProductMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// titleProduct returns the product an update title says it patches: the text
// after the first " for ", cut at the next " for " (which introduces the
// architecture clause) or at the KB parenthetical. Returns "" for a title that
// names no product.
func titleProduct(title string) string {
	const sep = " for "
	_, rest, ok := strings.Cut(title, sep)
	if !ok {
		return ""
	}
	if product, _, ok := strings.Cut(rest, sep); ok {
		rest = product
	}
	if product, _, ok := strings.Cut(rest, " ("); ok {
		rest = product
	}
	return strings.TrimSpace(rest)
}

// wuaResultsTimeFormat is the layout WINDOWS_QUERY_WUA_RESULTS formats dates
// with and ParseWUAResults reads them back in. The value is UTC.
const wuaResultsTimeFormat = "2006-01-02 15:04:05"

// Service IDs of the update services that deliver the operating system's own
// updates, as the WindowsUpdateClient event log records them in the
// serviceGuid field: Windows Update, Microsoft Update and WSUS or Configuration
// Manager (see "How Windows Update works" on Microsoft Learn). Other IDs, such
// as the Store and OS flighting channels, are not the operating system's
// updates and are left out.
const (
	WUServiceWindowsUpdate   = "9482f4b4-e343-43b6-b170-9a65bc822c77"
	WUServiceMicrosoftUpdate = "7971f918-a847-4430-9279-4a52d1efe18d"
	WUServiceManagedWSUS     = "3da21691-e39d-4da6-8a4b-b43877bcb1b7"
	wuaScanSuccessEventID    = 26
	wuaScanFailureEventID    = 25
)

// WINDOWS_QUERY_WUA_RESULTS reads IAutomaticUpdatesResults from the Windows
// Update Agent (Microsoft.Update.AutoUpdate) and the newest successful and the
// newest failed scan of an OS update service from the WindowsUpdateClient
// Operational event log.
//
// The COM dates are documented as UTC, but the COM DateTime can come back with
// Kind=Unspecified, so no ToUniversalTime/ToLocalTime call is made on them:
// converting would shift the value by the host's offset. A value of $null or a
// "never" sentinel (DateTime.MinValue, 1601, the 1899-12-30 OLE zero) is
// emitted as null. A COM failure exits non-zero.
//
// Update Orchestrator scans and online IUpdateSearcher searches do not update
// the COM values on Windows 10 and later; they log event 26 ("Windows Update
// successfully found N updates") with the scanned service in serviceGuid.
// TimeCreated of an event is a local DateTime, so it is converted with
// ToUniversalTime. Event 25 ("Windows Update failed to check for updates with
// error 0x...") carries the code in errorCode. Each event is found with one
// server-side filtered lookup of the newest match; no events are looped over.
// A missing log, no match or a failure reading it yields null scan fields and
// does not fail the query.
var WINDOWS_QUERY_WUA_RESULTS = fmt.Sprintf(`
$ErrorActionPreference='Stop';
$ProgressPreference='SilentlyContinue';
try {
  $results = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results
  $fmt = 'yyyy-MM-dd HH:mm:ss'
  $inv = [System.Globalization.CultureInfo]::InvariantCulture
  $search = $null
  $install = $null
  $d = $results.LastSearchSuccessDate
  if ($d -ne $null -and ([datetime]$d).Year -ge 1980) { $search = ([datetime]$d).ToString($fmt, $inv) }
  $d = $results.LastInstallationSuccessDate
  if ($d -ne $null -and ([datetime]$d).Year -ge 1980) { $install = ([datetime]$d).ToString($fmt, $inv) }
  $scan = $null
  $fail = $null
  $failCode = ''
  try {
    $log = 'Microsoft-Windows-WindowsUpdateClient/Operational'
    $e = Get-WinEvent -LogName $log -FilterXPath "%s" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($e) { $scan = $e.TimeCreated.ToUniversalTime().ToString($fmt, $inv) }
    $e = Get-WinEvent -LogName $log -FilterXPath "%s" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($e) {
      $fail = $e.TimeCreated.ToUniversalTime().ToString($fmt, $inv)
      $code = ''
      foreach ($data in ([xml]$e.ToXml()).Event.EventData.Data) {
        if ($data.Name -eq 'errorCode') { $code = ([string]$data.'#text').Trim() }
      }
      if ($code -match '^(0[xX])?([0-9a-fA-F]+)$') { $failCode = '0x' + $Matches[2].ToUpperInvariant() }
    }
  } catch { $scan = $null; $fail = $null; $failCode = '' }
  [pscustomobject]@{
    "LastSearchSuccessDate" = $search
    "LastInstallationSuccessDate" = $install
    "LastScanSuccess" = $scan
    "LastScanFailure" = $fail
    "LastScanFailureCode" = $failCode
  } | ConvertTo-Json -Compress
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}`, wuaScanXPath(wuaScanSuccessEventID), wuaScanXPath(wuaScanFailureEventID))

// wuaScanXPath selects the events with the given id whose serviceGuid is one of
// the OS update services. XPath string comparison is case-sensitive and the
// log writes the GUID lower-case in braces, so the upper-case form is matched
// too. The server-side filter plus -MaxEvents 1 keeps the read to one event.
func wuaScanXPath(eventID int) string {
	var conds []string
	for _, g := range []string{WUServiceWindowsUpdate, WUServiceMicrosoftUpdate, WUServiceManagedWSUS} {
		for _, v := range []string{strings.ToLower(g), strings.ToUpper(g)} {
			conds = append(conds, fmt.Sprintf("Data[@Name='serviceGuid']='{%s}'", v))
		}
	}
	return fmt.Sprintf("*[System[EventID=%d]] and *[EventData[%s]]", eventID, strings.Join(conds, " or "))
}

// WUAResults holds the Windows Update Agent's last successful search and
// installation times and the newest successful scan the event log records for
// an OS update service, in UTC. A nil field means none was reported.
type WUAResults struct {
	LastSearchSuccess       *time.Time
	LastInstallationSuccess *time.Time
	LastScanSuccess         *time.Time
	// LastScanFailure is the newest failed scan (event 25) of an OS update
	// service and LastScanFailureCode its error code ("0x80240438"), empty
	// when the event carried none.
	LastScanFailure     *time.Time
	LastScanFailureCode string
}

type wuaResultsJSON struct {
	LastSearchSuccessDate       *string `json:"LastSearchSuccessDate"`
	LastInstallationSuccessDate *string `json:"LastInstallationSuccessDate"`
	LastScanSuccess             *string `json:"LastScanSuccess"`
	LastScanFailure             *string `json:"LastScanFailure"`
	LastScanFailureCode         *string `json:"LastScanFailureCode"`
}

// ParseWUAResults parses the output of WINDOWS_QUERY_WUA_RESULTS. Missing or
// null fields yield nil times; empty output is an error, as is malformed JSON
// or a date that does not match the format.
func ParseWUAResults(input io.Reader) (*WUAResults, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	// json.Unmarshal accepts surrounding whitespace but not a UTF-8 byte order
	// mark, which some PowerShell hosts put in front of the output.
	data = bytes.TrimPrefix(bytes.TrimSpace(data), []byte("\xef\xbb\xbf"))
	var raw wuaResultsJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse windows update agent results: %w", err)
	}
	search, err := parseWUAResultsTime(raw.LastSearchSuccessDate)
	if err != nil {
		return nil, err
	}
	install, err := parseWUAResultsTime(raw.LastInstallationSuccessDate)
	if err != nil {
		return nil, err
	}
	scan, err := parseWUAResultsTime(raw.LastScanSuccess)
	if err != nil {
		return nil, err
	}
	failure, err := parseWUAResultsTime(raw.LastScanFailure)
	if err != nil {
		return nil, err
	}
	code := ""
	if raw.LastScanFailureCode != nil {
		code = strings.TrimSpace(*raw.LastScanFailureCode)
	}
	return &WUAResults{
		LastSearchSuccess:       search,
		LastInstallationSuccess: install,
		LastScanSuccess:         scan,
		LastScanFailure:         failure,
		LastScanFailureCode:     code,
	}, nil
}

func parseWUAResultsTime(s *string) (*time.Time, error) {
	if s == nil || strings.TrimSpace(*s) == "" {
		return nil, nil
	}
	t, err := time.ParseInLocation(wuaResultsTimeFormat, strings.TrimSpace(*s), time.UTC)
	if err != nil {
		return nil, fmt.Errorf("failed to parse windows update agent time %q: %w", *s, err)
	}
	return &t, nil
}
