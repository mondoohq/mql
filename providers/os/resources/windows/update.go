// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
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

// WINDOWS_QUERY_UPDATE_HISTORY enumerates the Windows Update Agent install
// history via the COM API, pre-filtering in PowerShell to succeeded
// installations (Operation == Installation, ResultCode == Succeeded) so that
// only those entries are turned into objects and serialized — uninstalls,
// failures, and aborted/in-progress entries are dropped before the expensive
// per-entry work. Go's FilterInstalledHistory re-applies the same predicate
// (and de-duplicates by KB), so the two must stay in sync; see
// TestUpdateHistoryQueryFilterMatchesGo. Dates serialize as PowerShell
// "/Date(ms)/" strings.
var WINDOWS_QUERY_UPDATE_HISTORY = `
$ProgressPreference='SilentlyContinue';
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$count = $searcher.GetTotalHistoryCount()
$history = @()
if ($count -gt 0) {
  $history = $searcher.QueryHistory(0, $count) |
    Where-Object { $_.Operation -eq 1 -and $_.ResultCode -eq 2 } |
    ForEach-Object {
    New-Object psobject -Property @{
      "Title" = $_.Title
      "Date" = $_.Date
      "Operation" = [int]$_.Operation
      "ResultCode" = [int]$_.ResultCode
      "SupportUrl" = $_.SupportUrl
      "UpdateID" = $_.UpdateIdentity.UpdateID
      "Categories" = @($_.Categories | ForEach-Object { $_.Name })
    }
  }
}
@($history) | ConvertTo-Json -Depth 3`

// WindowsUpdateHistoryEntry is a single Windows Update Agent history record.
type WindowsUpdateHistoryEntry struct {
	Title      string   `json:"Title"`
	Date       string   `json:"Date"`
	Operation  int      `json:"Operation"`
	ResultCode int      `json:"ResultCode"`
	SupportUrl string   `json:"SupportUrl"`
	UpdateID   string   `json:"UpdateID"`
	Categories []string `json:"Categories"`
}

func ParseWindowsUpdateHistory(input io.Reader) ([]WindowsUpdateHistoryEntry, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return []WindowsUpdateHistoryEntry{}, nil
	}

	return unmarshalJSONArrayOrObject[WindowsUpdateHistoryEntry](data)
}

// unmarshalJSONArrayOrObject decodes a JSON array of T, tolerating PowerShell's
// ConvertTo-Json behavior of emitting a bare object (not a single-element
// array) when the source collection has exactly one element.
func unmarshalJSONArrayOrObject[T any](data []byte) ([]T, error) {
	var arr []T
	arrErr := json.Unmarshal(data, &arr)
	if arrErr == nil {
		return arr, nil
	}

	var single T
	if err := json.Unmarshal(data, &single); err != nil {
		// report the array error, which is the expected shape
		return nil, arrErr
	}
	return []T{single}, nil
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

// FirstCategory returns the first non-empty category name, or "".
func FirstCategory(categories []string) string {
	for _, c := range categories {
		if c != "" {
			return c
		}
	}
	return ""
}

// ClassifyUpdate derives a best-effort classification for an update. It
// prefers the agent-reported category and otherwise infers one from the title
// (Windows Update history entries frequently report no categories).
func ClassifyUpdate(categories []string, title string) string {
	if c := FirstCategory(categories); c != "" {
		return c
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
func IsOperatingSystemUpdate(categories []string, title string) bool {
	for _, c := range categories {
		if namesNonOSProduct(c) {
			return false
		}
	}
	if namesNonOSProduct(title) {
		return false
	}

	switch ClassifyUpdate(categories, title) {
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
