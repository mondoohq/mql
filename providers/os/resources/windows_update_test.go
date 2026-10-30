// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

// regItems builds a name->item map mirroring readRegistryKey output (keys are
// lower-cased) from a set of REG_DWORD name/value pairs.
func regItems(values map[string]int64) map[string]registry.RegistryKeyItem {
	items := map[string]registry.RegistryKeyItem{}
	for name, v := range values {
		items[lower(name)] = registry.RegistryKeyItem{
			Key:   name,
			Value: registry.RegistryKeyValue{Number: v},
		}
	}
	return items
}

func TestUpdateEntryID(t *testing.T) {
	const id = "740c4b6c-bcfa-4f97-ae49-7bcc6933e696"
	installed := updateEntryID(updateEntryInstalled, id, 1)
	available := updateEntryID(updateEntryAvailable, id, 1)
	assert.NotEqual(t, installed, available,
		"an update both installed and still offered must not share one cached entry")
	assert.NotEqual(t, installed, updateEntryID(updateEntryInstalled, id, 2),
		"two revisions of one update are two entries")
	assert.Equal(t, installed, updateEntryID(updateEntryInstalled, id, 1))
}

func TestComputeWindowsUpdatePolicy(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		v := computeWindowsUpdatePolicy(nil, nil)
		assert.False(t, v.automaticUpdatesEnabled)
		assert.Nil(t, v.noAutoUpdate)
		assert.Nil(t, v.scheduledInstallDay)
		assert.Nil(t, v.deferQualityUpdatesPeriodInDays)
		assert.Nil(t, v.disablePauseUXAccess)
	})

	t.Run("automatic updates enabled (NoAutoUpdate=0)", func(t *testing.T) {
		au := regItems(map[string]int64{"NoAutoUpdate": 0, "ScheduledInstallDay": 0})
		v := computeWindowsUpdatePolicy(nil, au)
		assert.True(t, v.automaticUpdatesEnabled)
		require.NotNil(t, v.noAutoUpdate)
		assert.False(t, *v.noAutoUpdate)
		// ScheduledInstallDay=0 ("every day") must be distinguishable from absent.
		require.NotNil(t, v.scheduledInstallDay)
		assert.Equal(t, int64(0), *v.scheduledInstallDay)
	})

	t.Run("automatic updates disabled (NoAutoUpdate=1)", func(t *testing.T) {
		au := regItems(map[string]int64{"NoAutoUpdate": 1})
		v := computeWindowsUpdatePolicy(nil, au)
		assert.False(t, v.automaticUpdatesEnabled)
		require.NotNil(t, v.noAutoUpdate)
		assert.True(t, *v.noAutoUpdate)
	})

	t.Run("case-insensitive value names", func(t *testing.T) {
		// readRegistryKey lower-cases names; ensure lookups still resolve.
		au := map[string]registry.RegistryKeyItem{
			"noautoupdate": {Key: "noautoupdate", Value: registry.RegistryKeyValue{Number: 0}},
		}
		v := computeWindowsUpdatePolicy(nil, au)
		assert.True(t, v.automaticUpdatesEnabled)
	})

	t.Run("windows update for business deferrals", func(t *testing.T) {
		policy := regItems(map[string]int64{
			"ManagePreviewBuildsPolicyValue":         0,
			"DeferFeatureUpdates":                    1,
			"DeferFeatureUpdatesPeriodInDays":        180,
			"DeferQualityUpdates":                    1,
			"DeferQualityUpdatesPeriodInDays":        0,
			"AllowTemporaryEnterpriseFeatureControl": 0,
			"SetAllowOptionalContent":                0,
			"SetDisablePauseUXAccess":                1,
		})
		au := regItems(map[string]int64{"NoAutoRebootWithLoggedOnUsers": 0})
		v := computeWindowsUpdatePolicy(policy, au)

		require.NotNil(t, v.managePreviewBuilds)
		assert.Equal(t, int64(0), *v.managePreviewBuilds)
		require.NotNil(t, v.deferFeatureUpdatesPeriodInDays)
		assert.Equal(t, int64(180), *v.deferFeatureUpdatesPeriodInDays)
		// 0-day quality deferral must not collapse to "not configured".
		require.NotNil(t, v.deferQualityUpdatesPeriodInDays)
		assert.Equal(t, int64(0), *v.deferQualityUpdatesPeriodInDays)
		require.NotNil(t, v.disablePauseUXAccess)
		assert.True(t, *v.disablePauseUXAccess)
		require.NotNil(t, v.noAutoRebootWithLoggedOnUsers)
		assert.False(t, *v.noAutoRebootWithLoggedOnUsers)
	})
}

func TestDeriveCatalogSource(t *testing.T) {
	tests := []struct {
		name           string
		read           bool
		useWUServer    bool
		wsusServerURL  string
		auOptions      int64
		noAutoUpdate   bool
		wufbConfigured bool
		want           string
	}{
		{name: "registry unreadable", read: false, want: "unknown"},
		{name: "automatic updates disabled, legacy AUOptions encoding", read: true, auOptions: 1, want: "disabled"},
		// The shape every host running a modern Windows carries: AUOptions
		// holds a live value and NoAutoUpdate is what switches updates off.
		{name: "automatic updates disabled by NoAutoUpdate", read: true, auOptions: 2, noAutoUpdate: true, want: "disabled"},
		{name: "NoAutoUpdate wins over a configured WSUS server", read: true, useWUServer: true, wsusServerURL: "http://wsus.local:8530", auOptions: 4, noAutoUpdate: true, want: "disabled"},
		{name: "wsus managed", read: true, useWUServer: true, wsusServerURL: "http://wsus.local:8530", auOptions: 4, want: "wsus"},
		{name: "wsus url without UseWUServer falls through", read: true, useWUServer: false, wsusServerURL: "http://wsus.local:8530", auOptions: 4, want: "windowsUpdate"},
		{name: "windows update for business", read: true, wufbConfigured: true, auOptions: 0, want: "windowsUpdateForBusiness"},
		{name: "direct windows update", read: true, auOptions: 4, want: "windowsUpdate"},
		// The PolicyState key exists on every Windows Server since 2019 with
		// IsWUfBConfigured set to 0; its presence alone must not read as
		// enrollment.
		{name: "PolicyState present but WUfB not configured", read: true, wufbConfigured: false, auOptions: 4, want: "windowsUpdate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveCatalogSource(tt.read, tt.useWUServer, tt.wsusServerURL, tt.auOptions, tt.noAutoUpdate, tt.wufbConfigured)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseWULastSuccessTime(t *testing.T) {
	got := parseWULastSuccessTime("2024-01-15 10:30:00")
	require.NotNil(t, got)
	assert.Equal(t, time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC), got.UTC())

	assert.Nil(t, parseWULastSuccessTime(""))
	assert.Nil(t, parseWULastSuccessTime("not a timestamp"))
}

func TestFormatWULastError(t *testing.T) {
	assert.Equal(t, "", formatWULastError(0))
	assert.Equal(t, "0x80244022", formatWULastError(0x80244022))
	assert.Equal(t, "0xD", formatWULastError(13))
}

func TestCBSEntryArgs(t *testing.T) {
	installed := time.Date(2026, 8, 10, 15, 49, 51, 0, time.UTC)
	args := cbsEntryArgs(windows.CBSUpdate{
		KB:          "KB5120228",
		ReleaseType: "Security Update",
		InstalledOn: &installed,
		PackageName: "Package_for_HotpatchFix_33222~31bf3856ad364e35~amd64~~26100.33222.1.16",
	})
	assert.Equal(t, "KB5120228", args["kbId"].Value)
	assert.Equal(t, "Package_for_HotpatchFix_33222~31bf3856ad364e35~amd64~~26100.33222.1.16", args["updateId"].Value)
	assert.Equal(t, "Security Update (KB5120228)", args["title"].Value)
	assert.Equal(t, "Security Updates", args["classification"].Value)
	assert.Equal(t, &installed, args["date"].Value)

	// a plain "Update" has no classification, and no install time stays null
	args = cbsEntryArgs(windows.CBSUpdate{KB: "KB5120708", ReleaseType: "Update"})
	assert.Equal(t, "", args["classification"].Value)
	assert.Nil(t, args["date"].Value)
}

func TestWUResultTimes(t *testing.T) {
	comDetect := time.Date(2026, 10, 19, 6, 25, 42, 0, time.UTC)
	comInstall := time.Date(2026, 10, 19, 6, 25, 56, 0, time.UTC)
	regDetect := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	regInstall := time.Date(2025, 3, 2, 0, 0, 0, 0, time.UTC)

	t.Run("agent answered", func(t *testing.T) {
		d, i := wuResultTimes(&windows.WUAResults{LastSearchSuccess: &comDetect, LastInstallationSuccess: &comInstall}, &regDetect, &regInstall)
		assert.Equal(t, &comDetect, d)
		assert.Equal(t, &comInstall, i)
	})

	t.Run("agent reports never, stale registry value is not used", func(t *testing.T) {
		d, i := wuResultTimes(&windows.WUAResults{LastInstallationSuccess: &comInstall}, &regDetect, &regInstall)
		assert.Nil(t, d)
		assert.Equal(t, &comInstall, i)
	})

	t.Run("event log scan newer than agent search", func(t *testing.T) {
		scan := comDetect.Add(time.Hour)
		d, _ := wuResultTimes(&windows.WUAResults{LastSearchSuccess: &comDetect, LastScanSuccess: &scan}, &regDetect, &regInstall)
		assert.Equal(t, &scan, d)
	})

	t.Run("agent search newer than event log scan", func(t *testing.T) {
		scan := comDetect.Add(-time.Hour)
		d, _ := wuResultTimes(&windows.WUAResults{LastSearchSuccess: &comDetect, LastScanSuccess: &scan}, &regDetect, &regInstall)
		assert.Equal(t, &comDetect, d)
	})

	t.Run("only the event log scan present", func(t *testing.T) {
		scan := comDetect.Add(time.Hour)
		d, _ := wuResultTimes(&windows.WUAResults{LastScanSuccess: &scan}, &regDetect, &regInstall)
		assert.Equal(t, &scan, d)
	})

	t.Run("neither present, registry is not used", func(t *testing.T) {
		d, _ := wuResultTimes(&windows.WUAResults{}, &regDetect, &regInstall)
		assert.Nil(t, d)
	})

	t.Run("agent unavailable, registry fallback", func(t *testing.T) {
		d, i := wuResultTimes(nil, &regDetect, &regInstall)
		assert.Equal(t, &regDetect, d)
		assert.Equal(t, &regInstall, i)
	})
}

func TestWUDetectionError(t *testing.T) {
	success := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	later := success.Add(time.Hour)
	earlier := success.Add(-time.Hour)

	t.Run("failure newer than agent search", func(t *testing.T) {
		assert.Equal(t, "0x80240438", wuDetectionError(&windows.WUAResults{LastSearchSuccess: &success, LastScanFailure: &later, LastScanFailureCode: "0x80240438"}, "0x1"))
	})
	t.Run("failure newer than agent search but older than event scan", func(t *testing.T) {
		assert.Equal(t, "", wuDetectionError(&windows.WUAResults{LastSearchSuccess: &earlier, LastScanSuccess: &later, LastScanFailure: &success, LastScanFailureCode: "0x80240438"}, "0x1"))
	})
	t.Run("failure older than success", func(t *testing.T) {
		assert.Equal(t, "", wuDetectionError(&windows.WUAResults{LastScanSuccess: &success, LastScanFailure: &earlier, LastScanFailureCode: "0x80240438"}, "0x1"))
	})
	t.Run("failure at the same time as success is not an error", func(t *testing.T) {
		assert.Equal(t, "", wuDetectionError(&windows.WUAResults{LastScanSuccess: &success, LastScanFailure: &success, LastScanFailureCode: "0x80240438"}, ""))
	})
	t.Run("failure without any success", func(t *testing.T) {
		assert.Equal(t, "0x80072EE2", wuDetectionError(&windows.WUAResults{LastScanFailure: &success, LastScanFailureCode: "0x80072EE2"}, ""))
	})
	t.Run("no failure, stale registry error is not used", func(t *testing.T) {
		assert.Equal(t, "", wuDetectionError(&windows.WUAResults{LastScanSuccess: &success}, "0x80244022"))
	})
	t.Run("query failed, registry fallback", func(t *testing.T) {
		assert.Equal(t, "0x80244022", wuDetectionError(nil, "0x80244022"))
	})
}
