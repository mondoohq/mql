// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateHistoryQueryFilterMatchesGo guards that the PowerShell-side
// Where-Object pre-filter uses the same Operation/ResultCode codes that the
// Go-side FilterInstalledHistory enforces. If the constants change, the
// embedded query must change with them or installed updates would silently
// disappear.
func TestUpdateHistoryQueryFilterMatchesGo(t *testing.T) {
	want := fmt.Sprintf("$_.Operation -eq %d -and $_.ResultCode -eq %d",
		UpdateOperationInstallation, UpdateResultSucceeded)
	assert.Contains(t, WINDOWS_QUERY_UPDATE_HISTORY, want,
		"PowerShell pre-filter must match the Go install/succeeded predicate")
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
	assert.Equal(t, "Security Updates", ClassifyUpdate([]string{"Security Updates"}, "anything"))
	// empty categories fall back to title inference
	assert.Equal(t, "Update Rollups", ClassifyUpdate(nil, "2024-02 Cumulative Update for .NET Framework (KB5034763)"))
	assert.Equal(t, "Security Updates", ClassifyUpdate([]string{}, "2024-01 Security Update for Windows (KB5030219)"))
	assert.Equal(t, "Servicing Stack Updates", ClassifyUpdate(nil, "Servicing Stack Update for Windows (KB5031234)"))
	assert.Equal(t, "Drivers", ClassifyUpdate(nil, "Intel - Display driver"))
	assert.Equal(t, "", ClassifyUpdate(nil, "Some unrecognized update"))
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
		name       string
		title      string
		categories []string
		want       bool
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
			name:       "definition update by category",
			title:      "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602",
			categories: []string{"Definition Updates"},
			want:       false,
		},
		{
			name:       "driver",
			title:      "Intel - System - 10.1.1.38",
			categories: []string{"Drivers"},
			want:       false,
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
			assert.Equal(t, test.want, IsOperatingSystemUpdate(test.categories, test.title))
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
