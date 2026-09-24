// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWindowsUpdates(t *testing.T) {
	r, err := os.Open("./testdata/updates_win.json")
	require.NoError(t, err)
	defer r.Close()

	updates, err := ParseWindowsUpdates(r)
	require.NoError(t, err)
	assert.Equal(t, 6, len(updates), "detected the right amount of updates")

	u, err := findUpdate(updates, "4537759")
	require.NoError(t, err)
	assert.Equal(t, "2020-02 Security Update for Adobe Flash Player for Windows Server 2019 for x64-based Systems (KB4537759)", u.Title)
	assert.Equal(t, "Critical", u.MsrcSeverity)
	assert.Equal(t, "https://support.microsoft.com/help/4537759", u.SupportUrl)
	assert.Equal(t, []string{"CVE-2020-0001"}, u.CveIDs)
	assert.Equal(t, []string{"Security Updates"}, u.Categories)

	// empty input
	updates, err = ParseWindowsUpdates(strings.NewReader(""))
	require.NoError(t, err)
	assert.Equal(t, 0, len(updates))
}

func TestParseWindowsUpdates_SingleObject(t *testing.T) {
	// ConvertTo-Json emits a bare object when the search returns one update.
	single := `{"UpdateID":"abc","Title":"Update (KB4538461)","MsrcSeverity":"Important","KBArticleIDs":["4538461"],"RebootRequired":true}`
	updates, err := ParseWindowsUpdates(strings.NewReader(single))
	require.NoError(t, err)
	require.Len(t, updates, 1)
	assert.Equal(t, "4538461", updates[0].KBArticleIDs[0])
	assert.True(t, updates[0].RebootRequired)
}

func TestWindowsUpdateToOperatingSystemUpdate(t *testing.T) {
	u := WindowsUpdate{
		UpdateID:       "0b669361-bcf2-4c1c-b4fb-e5629cfdc3c0",
		Title:          "2020-02 Security Update (KB4537759)",
		MsrcSeverity:   "Critical",
		RebootRequired: true,
		KBArticleIDs:   []string{"4537759"},
	}
	osUpdate, ok := u.toOperatingSystemUpdate()
	require.True(t, ok)
	assert.Equal(t, "4537759", osUpdate.Name, "KB becomes the os.update name")
	assert.Equal(t, "0b669361-bcf2-4c1c-b4fb-e5629cfdc3c0", osUpdate.ID)
	assert.Equal(t, "2020-02 Security Update (KB4537759)", osUpdate.Description)
	assert.Equal(t, "Critical", osUpdate.Severity)
	assert.Equal(t, "windows/updates", osUpdate.Format)
	assert.True(t, osUpdate.Restart)

	// updates without a KB are dropped from os.update
	_, ok = WindowsUpdate{UpdateID: "x", Title: "Driver update"}.toOperatingSystemUpdate()
	assert.False(t, ok)
}

func findUpdate(updates []WindowsUpdate, kb string) (WindowsUpdate, error) {
	for i := range updates {
		if slices.Contains(updates[i].KBArticleIDs, kb) {
			return updates[i], nil
		}
	}
	return WindowsUpdate{}, errors.New("not found")
}

// findKb is shared with the other update-manager tests in this package.
func findKb(pkgs []OperatingSystemUpdate, name string) (OperatingSystemUpdate, error) {
	for i := range pkgs {
		if pkgs[i].Name == name {
			return pkgs[i], nil
		}
	}
	return OperatingSystemUpdate{}, errors.New("not found")
}

func TestParseWindowsUpdatesDropsBlankRecords(t *testing.T) {
	// What a failed Windows Update Agent search leaves on stdout: $searcher is
	// null, so $searcher.Updates is null, and piping null to ForEach-Object
	// still runs the block once. Counting that as an outstanding update is
	// wrong, and so is counting it as a clean scan.
	updates, err := ParseWindowsUpdates(strings.NewReader(`{"UpdateID": null, "Title": null}`))
	require.NoError(t, err)
	assert.Empty(t, updates)

	updates, err = ParseWindowsUpdates(strings.NewReader(`[{"UpdateID": null, "Title": null}]`))
	require.NoError(t, err)
	assert.Empty(t, updates)

	// A real update alongside a blank one keeps the real one.
	updates, err = ParseWindowsUpdates(strings.NewReader(
		`[{"UpdateID": null, "Title": null},{"UpdateID":"0f1e-2d3c","Title":"2026-08 Cumulative Update (KB5120242)","KBArticleIDs":["5120242"]}]`))
	require.NoError(t, err)
	require.Len(t, updates, 1)
	assert.Equal(t, "0f1e-2d3c", updates[0].UpdateID)

	// An update with a title but no identity is still an update.
	updates, err = ParseWindowsUpdates(strings.NewReader(`[{"UpdateID":"","Title":"Some driver"}]`))
	require.NoError(t, err)
	require.Len(t, updates, 1)
}

func TestWindowsUpdateSearchQueryStopsOnError(t *testing.T) {
	// Without this the COM failure is a non-terminating error, powershell.exe
	// exits 0, the ExitStatus check never fires, and a host that could not be
	// reached reports itself fully patched.
	q := windowsUpdateSearchQuery(WindowsUpdateCriteriaAvailable, true)
	assert.Contains(t, q, "$ErrorActionPreference='Stop'")
	assert.Contains(t, q, WindowsUpdateCriteriaAvailable)
}

// TestWindowsUpdateSearchQueryOnlineFlag pins that the online/offline switch
// only ever changes $searcher.Online, and that it is always set before
// Search() runs -- setting IUpdateSearcher.Online after the search has
// already started has no effect.
func TestWindowsUpdateSearchQueryOnlineFlag(t *testing.T) {
	online := windowsUpdateSearchQuery(WindowsUpdateCriteriaSoftware, true)
	assert.Contains(t, online, "$searcher.Online = $true")
	assert.NotContains(t, online, "$searcher.Online = $false")

	offline := windowsUpdateSearchQuery(WindowsUpdateCriteriaAvailable, false)
	assert.Contains(t, offline, "$searcher.Online = $false")
	assert.NotContains(t, offline, "$searcher.Online = $true")

	onlineIdx := strings.Index(offline, "$searcher.Online")
	searchIdx := strings.Index(offline, ".Search(")
	require.GreaterOrEqual(t, onlineIdx, 0)
	require.GreaterOrEqual(t, searchIdx, 0)
	assert.Less(t, onlineIdx, searchIdx, "Online must be set on the searcher before Search() runs")
}

// TestWindowsUpdateSearchQueryUsesForeachNotPipeline pins the
// performance-motivated rewrite away from ForEach-Object/New-Object psobject
// for the per-update record, and confirms the output field names used by
// ParseWindowsUpdates did not move.
func TestWindowsUpdateSearchQueryUsesForeachNotPipeline(t *testing.T) {
	q := windowsUpdateSearchQuery(WindowsUpdateCriteriaAvailable, false)
	assert.Contains(t, q, "foreach (")
	assert.Contains(t, q, "[pscustomobject]@{")
	assert.NotContains(t, q, "New-Object psobject")

	for _, field := range []string{`"UpdateID"`, `"Title"`, `"MsrcSeverity"`, `"SupportUrl"`, `"RebootRequired"`, `"KBArticleIDs"`, `"CveIDs"`, `"Categories"`} {
		assert.Contains(t, q, field)
	}
}

func TestDropEmptyWindowsUpdatesKeepsTheInputWhenNothingIsBlank(t *testing.T) {
	in := []WindowsUpdate{{UpdateID: "a", Title: "A"}, {UpdateID: "b", Title: "B"}}
	got := dropEmptyWindowsUpdates(in)
	require.Len(t, got, 2)
	assert.Equal(t, in, got)

	// Nothing is copied when there is nothing to drop, which is every
	// successful search.
	assert.Equal(t, &in[0], &got[0])
}

func TestDropEmptyWindowsUpdatesPreservesOrder(t *testing.T) {
	in := []WindowsUpdate{
		{UpdateID: "a", Title: "A"},
		{},
		{UpdateID: "b", Title: "B"},
		{},
		{UpdateID: "c", Title: "C"},
	}
	got := dropEmptyWindowsUpdates(in)
	require.Len(t, got, 3)
	assert.Equal(t, "a", got[0].UpdateID)
	assert.Equal(t, "b", got[1].UpdateID)
	assert.Equal(t, "c", got[2].UpdateID)
}
