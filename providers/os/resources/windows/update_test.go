// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateHistoryQueryFilterMatchesGo guards that the PowerShell-side
// per-entry pre-filter uses the same Operation/ResultCode codes that the
// Go-side FilterInstalledHistory enforces. If the constants change, the
// embedded query must change with them or installed updates would silently
// disappear.
func TestUpdateHistoryQueryFilterMatchesGo(t *testing.T) {
	want := fmt.Sprintf("$entry.Operation -eq %d -and $entry.ResultCode -eq %d",
		UpdateOperationInstallation, UpdateResultSucceeded)
	assert.Contains(t, WINDOWS_QUERY_UPDATE_HISTORY, want,
		"PowerShell pre-filter must match the Go install/succeeded predicate")
}

// TestUpdateHistoryQueryCapsCount guards that the embedded query caps
// QueryHistory at windowsUpdateHistoryMaxEntries rather than asking for the
// whole history every time. QueryHistory returns records newest-first, so
// the cap bounds how much history-older-than-any-still-useful-KB the query
// pays to enumerate, not which updates are found.
func TestUpdateHistoryQueryCapsCount(t *testing.T) {
	want := fmt.Sprintf("[Math]::Min($count, %d)", windowsUpdateHistoryMaxEntries)
	assert.Contains(t, WINDOWS_QUERY_UPDATE_HISTORY, want)
	assert.Equal(t, 1000, windowsUpdateHistoryMaxEntries)
}

// TestUpdateHistoryQueryUsesForeachNotPipeline pins the performance-motivated
// rewrite away from Where-Object/ForEach-Object/New-Object psobject: those
// pipeline cmdlets are markedly slower than a foreach statement building
// [pscustomobject] records, and history can run into the thousands of
// entries on a long-lived host.
func TestUpdateHistoryQueryUsesForeachNotPipeline(t *testing.T) {
	assert.Contains(t, WINDOWS_QUERY_UPDATE_HISTORY, "foreach (")
	assert.Contains(t, WINDOWS_QUERY_UPDATE_HISTORY, "[pscustomobject]@{")
	assert.NotContains(t, WINDOWS_QUERY_UPDATE_HISTORY, "Where-Object")
	assert.NotContains(t, WINDOWS_QUERY_UPDATE_HISTORY, "New-Object psobject")

	// the output field names must not move: ParseWindowsUpdateHistory and
	// downstream consumers both depend on them
	for _, field := range []string{`"Title"`, `"Date"`, `"Operation"`, `"ResultCode"`, `"SupportUrl"`, `"UpdateID"`, `"Categories"`, `"RevisionNumber"`, `"Classification"`} {
		assert.Contains(t, WINDOWS_QUERY_UPDATE_HISTORY, field)
	}
	assert.Contains(t, WINDOWS_QUERY_UPDATE_HISTORY, "$category.Type -eq 'UpdateClassification'")
}

func TestParseWindowsUpdateHistory(t *testing.T) {
	r, err := os.Open("./testdata/update_history.json")
	require.NoError(t, err)
	defer r.Close()

	entries, err := ParseWindowsUpdateHistory(r)
	require.NoError(t, err)
	assert.Len(t, entries, 6)
	assert.Equal(t, "https://support.microsoft.com/help/5034441", entries[0].SupportUrl)
	assert.Equal(t, 1, entries[0].Operation)
	assert.Equal(t, 2, entries[0].ResultCode)
}

func TestParseWindowsUpdateHistory_Empty(t *testing.T) {
	entries, err := ParseWindowsUpdateHistory(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestFilterInstalledHistory(t *testing.T) {
	r, err := os.Open("./testdata/update_history.json")
	require.NoError(t, err)
	defer r.Close()

	entries, err := ParseWindowsUpdateHistory(r)
	require.NoError(t, err)

	installed := FilterInstalledHistory(entries)

	// Of the 6 history records: one failed (ResultCode 4) and one uninstall
	// (Operation 2) are dropped, and KB5034441 appears twice (de-duped). That
	// leaves KB5034441, KB5034763, and the Defender definition update.
	require.Len(t, installed, 3)

	kbs := make([]string, 0, len(installed))
	for _, e := range installed {
		kbs = append(kbs, ParseKBID(e.Title))
	}
	assert.Contains(t, kbs, "KB5034441")
	assert.Contains(t, kbs, "KB5034763")
	assert.Contains(t, kbs, "KB2267602")

	// the kept KB5034441 entry is the newest (first seen)
	for _, e := range installed {
		if ParseKBID(e.Title) == "KB5034441" {
			assert.Equal(t, "/Date(1705334400000)/", e.Date)
		}
	}
}

func TestParseWindowsUpdateHistory_SingleObject(t *testing.T) {
	// PowerShell ConvertTo-Json emits a bare object (not an array) when the
	// collection has exactly one element.
	single := `{"Title":"2024-01 Cumulative Update (KB5034441)","Date":"/Date(1705334400000)/","Operation":1,"ResultCode":2,"UpdateID":"11111111-1111-1111-1111-111111111111","Categories":["Security Updates"]}`
	entries, err := ParseWindowsUpdateHistory(strings.NewReader(single))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "KB5034441", ParseKBID(entries[0].Title))
}

func TestParseWindowsUpdateHistoryClassificationAndRevision(t *testing.T) {
	record := `[{"Title":"2026-10 Cumulative Update for Windows 11 Version 25H2 for x64-based Systems (KB5127648)",` +
		`"Date":"/Date(1705334400000)/","Operation":1,"ResultCode":2,"UpdateID":"43f0fc0f-a617-48ba-9bb1-0a4995bd53af",` +
		`"RevisionNumber":3,"Categories":["Windows 11","Security Updates"],"Classification":"Security Updates"}]`
	entries, err := ParseWindowsUpdateHistory(strings.NewReader(record))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, 3, entries[0].RevisionNumber)
	assert.Equal(t, "Security Updates", entries[0].Classification)
}

func TestParseKBID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"2024-01 Cumulative Update for Windows Server 2022 (KB5034441)", "KB5034441"},
		{"Security Intelligence Update ... - KB2267602 (Version 1.405.0.0)", "KB2267602"},
		{"kb1234567 lower case", "KB1234567"},
		{"Intel - Display - 27.20.100.9466", ""},
		{"", ""},
	}
	for _, tt := range tests {
		assert.Equalf(t, tt.want, ParseKBID(tt.input), "ParseKBID(%q)", tt.input)
	}
}

func TestClassifyUpdate(t *testing.T) {
	// a reported category wins
	assert.Equal(t, "Security Updates", ClassifyUpdate("Security Updates", "anything"))
	// The agent's classification wins over the title.
	assert.Equal(t, "Update Rollups", ClassifyUpdate("Update Rollups", "Windows Malicious Software Removal Tool x64 - v5.146 (KB890830)"))
	// empty categories fall back to title inference
	assert.Equal(t, "Update Rollups", ClassifyUpdate("", "2024-02 Cumulative Update for .NET Framework (KB5034763)"))
	assert.Equal(t, "Security Updates", ClassifyUpdate("", "2024-01 Security Update for Windows (KB5030219)"))
	assert.Equal(t, "Servicing Stack Updates", ClassifyUpdate("", "Servicing Stack Update for Windows (KB5031234)"))
	assert.Equal(t, "Drivers", ClassifyUpdate("", "Intel - Display driver"))
	assert.Equal(t, "", ClassifyUpdate("", "Some unrecognized update"))
}

func TestOperationName(t *testing.T) {
	assert.Equal(t, "Installation", OperationName(UpdateOperationInstallation))
	assert.Equal(t, "Uninstallation", OperationName(UpdateOperationUninstallation))
	assert.Equal(t, "", OperationName(0))
}

// IsOperatingSystemUpdate is what makes os.lastUpdate mean patch state on
// Windows. A .NET or Office entry counted as an operating system update reports
// a host years behind on Windows as patched, and an operating system update
// rejected reports a patched host as unknown.
func TestIsOperatingSystemUpdate(t *testing.T) {
	tests := []struct {
		name           string
		title          string
		categories     []string
		classification string
		want           bool
	}{
		{
			name:  "cumulative update",
			title: "2026-08 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5063878)",
			want:  true,
		},
		{
			name:  "security update for the OS",
			title: "2024-01 Security Update for Windows Server 2022 for x64-based Systems (KB5034439)",
			want:  true,
		},
		{
			name:  "servicing stack update",
			title: "2024-01 Servicing Stack Update for Windows Server 2022 for x64-based Systems (KB5034865)",
			want:  true,
		},
		{
			name:  "feature update names no product clause",
			title: "Feature update to Windows 11, version 24H2",
			want:  true,
		},
		{
			// The title names the Windows release it targets, which is why a
			// plain search for "Windows" in the title is the wrong test.
			name:  "dotnet framework names Windows but patches dotnet",
			title: "Security Update for Microsoft .NET Framework 4.8 for Windows Server 2019 (KB5034619)",
			want:  false,
		},
		{
			name:  "dotnet core",
			title: "Microsoft .NET Core 3.1.32 Update for x64 Client (KB5013624)",
			want:  false,
		},
		{
			name:  "office",
			title: "Update for Microsoft Office 2019 (KB4484552)",
			want:  false,
		},
		{
			// Not the signature stream the classification drops: this is the
			// engine, and its title would otherwise pass the Windows test.
			name:  "defender platform update",
			title: "Update for Windows Defender Antivirus antimalware platform - KB4052623",
			want:  false,
		},
		{
			name:  "malicious software removal tool",
			title: "Windows Malicious Software Removal Tool x64 - v5.121 (KB890830)",
			want:  false,
		},
		{
			name:           "definition update by classification",
			title:          "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602",
			categories:     []string{"Definition Updates"},
			classification: "Definition Updates",
			want:           false,
		},
		{
			name:           "driver",
			title:          "Intel - System - 10.1.1.38",
			categories:     []string{"Drivers"},
			classification: "Drivers",
			want:           false,
		},
		{
			// The title alone passes the Windows product test; only the
			// classification marks it as a driver, and the product category
			// listed first must not hide it.
			name:           "driver whose first category is a product",
			title:          "2026-10 Update for Windows 11 Version 25H2 for x64-based Systems",
			categories:     []string{"Windows 11", "Drivers"},
			classification: "Drivers",
			want:           false,
		},
		{
			name:  "edge",
			title: "Microsoft Edge-Stable Channel Version 120 Update",
			want:  false,
		},
		{
			// The product category rejects it even when the title alone would
			// have passed.
			name:       "product category overrides a passing title",
			title:      "2024-01 Security Update for Windows Server 2022 for x64-based Systems (KB5034439)",
			categories: []string{"Security Updates", "Microsoft .NET Framework"},
			want:       false,
		},
		{
			name:       "os product category alongside a classification",
			title:      "2026-08 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5063878)",
			categories: []string{"Security Updates", "Windows 11"},
			want:       true,
		},
		{
			name:  "title naming no product",
			title: "Some vendor tool 1.2.3",
			want:  false,
		},
		{
			name:  "empty title",
			title: "",
			want:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, IsOperatingSystemUpdate(test.categories, test.classification, test.title))
		})
	}
}

func TestTitleProduct(t *testing.T) {
	tests := []struct{ title, want string }{
		{"2026-08 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5063878)", "Windows 11 Version 24H2"},
		{"Security Update for Microsoft .NET Framework 4.8 for Windows Server 2019 (KB5034619)", "Microsoft .NET Framework 4.8"},
		{"Update for Microsoft Office 2019 (KB4484552)", "Microsoft Office 2019"},
		{"Feature update to Windows 11, version 24H2", ""},
		{"", ""},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			assert.Equal(t, test.want, titleProduct(test.title))
		})
	}
}

func TestUpdateHistoryQueryStopsOnError(t *testing.T) {
	// GetTotalHistoryCount failing without this leaves $count null, the
	// $count -gt 0 guard false, and an empty history: a host whose update
	// agent could not be reached reports that nothing was ever installed.
	assert.Contains(t, WINDOWS_QUERY_UPDATE_HISTORY, "$ErrorActionPreference='Stop'")
}

func TestParseWUAResults(t *testing.T) {
	t.Run("both dates set", func(t *testing.T) {
		res, err := ParseWUAResults(strings.NewReader(`{"LastSearchSuccessDate":"2026-10-19 06:25:42","LastInstallationSuccessDate":"2026-10-19 06:25:56"}`))
		require.NoError(t, err)
		require.NotNil(t, res.LastSearchSuccess)
		require.NotNil(t, res.LastInstallationSuccess)
		assert.Equal(t, time.Date(2026, 10, 19, 6, 25, 42, 0, time.UTC), *res.LastSearchSuccess)
		assert.Equal(t, time.Date(2026, 10, 19, 6, 25, 56, 0, time.UTC), *res.LastInstallationSuccess)
		assert.Equal(t, time.UTC, res.LastSearchSuccess.Location())
	})
	t.Run("null dates", func(t *testing.T) {
		res, err := ParseWUAResults(strings.NewReader(`{"LastSearchSuccessDate":null,"LastInstallationSuccessDate":null}`))
		require.NoError(t, err)
		assert.Nil(t, res.LastSearchSuccess)
		assert.Nil(t, res.LastInstallationSuccess)
	})
	t.Run("one null one set", func(t *testing.T) {
		res, err := ParseWUAResults(strings.NewReader(`{"LastSearchSuccessDate":"2026-01-02 03:04:05","LastInstallationSuccessDate":null}`))
		require.NoError(t, err)
		require.NotNil(t, res.LastSearchSuccess)
		assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), *res.LastSearchSuccess)
		assert.Nil(t, res.LastInstallationSuccess)
	})
	t.Run("missing keys", func(t *testing.T) {
		res, err := ParseWUAResults(strings.NewReader(`{}`))
		require.NoError(t, err)
		assert.Nil(t, res.LastSearchSuccess)
		assert.Nil(t, res.LastInstallationSuccess)
	})
	t.Run("byte order mark and CRLF", func(t *testing.T) {
		res, err := ParseWUAResults(strings.NewReader("\xef\xbb\xbf{\"LastSearchSuccessDate\":\"2026-10-19 06:25:42\",\"LastInstallationSuccessDate\":null}\r\n"))
		require.NoError(t, err)
		require.NotNil(t, res.LastSearchSuccess)
		assert.Equal(t, time.Date(2026, 10, 19, 6, 25, 42, 0, time.UTC), *res.LastSearchSuccess)
		assert.Nil(t, res.LastInstallationSuccess)
	})
	t.Run("scan success from event log", func(t *testing.T) {
		res, err := ParseWUAResults(strings.NewReader("\xef\xbb\xbf{\"LastSearchSuccessDate\":null,\"LastInstallationSuccessDate\":null,\"LastScanSuccess\":\"2026-10-20 08:09:10\"}\r\n"))
		require.NoError(t, err)
		assert.Nil(t, res.LastSearchSuccess)
		require.NotNil(t, res.LastScanSuccess)
		assert.Equal(t, time.Date(2026, 10, 20, 8, 9, 10, 0, time.UTC), *res.LastScanSuccess)
	})
	t.Run("scan success null or absent", func(t *testing.T) {
		res, err := ParseWUAResults(strings.NewReader(`{"LastSearchSuccessDate":"2026-01-02 03:04:05","LastScanSuccess":null}`))
		require.NoError(t, err)
		assert.Nil(t, res.LastScanSuccess)
		res, err = ParseWUAResults(strings.NewReader(`{"LastSearchSuccessDate":"2026-01-02 03:04:05"}`))
		require.NoError(t, err)
		assert.Nil(t, res.LastScanSuccess)
	})
	t.Run("unparseable scan time", func(t *testing.T) {
		_, err := ParseWUAResults(strings.NewReader(`{"LastScanSuccess":"soon"}`))
		assert.Error(t, err)
	})
	t.Run("scan failure fields", func(t *testing.T) {
		res, err := ParseWUAResults(strings.NewReader("\xef\xbb\xbf{\"LastScanFailure\":\"2026-10-20 09:10:11\",\"LastScanFailureCode\":\"0x80240438\"}\r\n"))
		require.NoError(t, err)
		require.NotNil(t, res.LastScanFailure)
		assert.Equal(t, time.Date(2026, 10, 20, 9, 10, 11, 0, time.UTC), *res.LastScanFailure)
		assert.Equal(t, "0x80240438", res.LastScanFailureCode)
	})
	t.Run("scan failure null or absent", func(t *testing.T) {
		res, err := ParseWUAResults(strings.NewReader(`{"LastScanFailure":null,"LastScanFailureCode":null}`))
		require.NoError(t, err)
		assert.Nil(t, res.LastScanFailure)
		assert.Equal(t, "", res.LastScanFailureCode)
		res, err = ParseWUAResults(strings.NewReader(`{}`))
		require.NoError(t, err)
		assert.Nil(t, res.LastScanFailure)
		assert.Equal(t, "", res.LastScanFailureCode)
	})
	t.Run("unparseable scan failure time", func(t *testing.T) {
		_, err := ParseWUAResults(strings.NewReader(`{"LastScanFailure":"later"}`))
		assert.Error(t, err)
	})
	t.Run("malformed json", func(t *testing.T) {
		_, err := ParseWUAResults(strings.NewReader(`{"LastSearchSuccessDate":`))
		assert.Error(t, err)
	})
	t.Run("empty output", func(t *testing.T) {
		_, err := ParseWUAResults(strings.NewReader(""))
		assert.Error(t, err)
	})
	t.Run("unparseable date", func(t *testing.T) {
		_, err := ParseWUAResults(strings.NewReader(`{"LastSearchSuccessDate":"yesterday"}`))
		assert.Error(t, err)
	})
}

// The COM dates must not be converted: a COM DateTime with Kind=Unspecified
// would be shifted by the host offset. Event log times are local DateTimes and
// must be converted, exactly once.
func TestWUAResultsQueryTimeZones(t *testing.T) {
	assert.NotContains(t, WINDOWS_QUERY_WUA_RESULTS, "ToLocalTime")
	assert.Contains(t, WINDOWS_QUERY_WUA_RESULTS, "'yyyy-MM-dd HH:mm:ss'")
	// one conversion for the success time, one for the failure time
	assert.Equal(t, 2, strings.Count(WINDOWS_QUERY_WUA_RESULTS, "ToUniversalTime"))
	assert.Equal(t, 2, strings.Count(WINDOWS_QUERY_WUA_RESULTS, "$e.TimeCreated.ToUniversalTime()"))
}

// Only scans of the OS update services count; Store and flighting channels
// log event 26 too.
func TestWUAResultsQueryFiltersOSServices(t *testing.T) {
	q := WINDOWS_QUERY_WUA_RESULTS
	for _, guid := range []string{
		"9482f4b4-e343-43b6-b170-9a65bc822c77",
		"7971f918-a847-4430-9279-4a52d1efe18d",
		"3da21691-e39d-4da6-8a4b-b43877bcb1b7",
	} {
		// the log writes the GUID lower-case in braces; XPath compares case-sensitively
		assert.Contains(t, q, "Data[@Name='serviceGuid']='{"+guid+"}'")
		assert.Contains(t, q, "Data[@Name='serviceGuid']='{"+strings.ToUpper(guid)+"}'")
	}
	assert.NotContains(t, q, "855e8a7c-ecb4-4ca3-b045-1dfa50104289")
	assert.NotContains(t, q, "8b24b027-1dee-babb-9a95-3517dfb9c552")
	assert.NotContains(t, q, "855E8A7C-ECB4-4CA3-B045-1DFA50104289")
	assert.NotContains(t, q, "8B24B027-1DEE-BABB-9A95-3517DFB9C552")
	assert.Contains(t, q, "Microsoft-Windows-WindowsUpdateClient/Operational")
	// one server-side filtered lookup per event id, newest match only
	assert.Equal(t, 2, strings.Count(q, "Get-WinEvent"))
	assert.Equal(t, 2, strings.Count(q, "-MaxEvents 1 "))
	assert.Equal(t, 2, strings.Count(q, "-FilterXPath"))
	assert.Contains(t, q, "*[System[EventID=26]] and *[EventData[")
	assert.Contains(t, q, "*[System[EventID=25]] and *[EventData[")
	assert.NotContains(t, q, "-MaxEvents 200")
	assert.NotContains(t, q, "FilterHashtable")
	// no loop over events, and the event XML is read once, for the failure code only
	assert.NotContains(t, q, "foreach ($e ")
	assert.Equal(t, 1, strings.Count(q, "ToXml()"))
	assert.Contains(t, q, "'errorCode'")
	assert.Contains(t, q, `"LastScanFailure" = $fail`)
	assert.Contains(t, q, `"LastScanFailureCode" = $failCode`)
	assert.Contains(t, q, "-ErrorAction SilentlyContinue")
	for _, r := range q {
		assert.Less(t, r, rune(128), "script must be ASCII")
	}
}
