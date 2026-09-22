// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package edr

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every literal in this file is written out by hand from the signals the
// shipped mondoo-edr-policy (v1.6.4) checks and from the vendors' own
// component names. Nothing is read back out of Catalog, so a catalog entry
// that is edited to the wrong package or service name fails these tests
// instead of moving the expectation with it.

func pkg(name, version string) Package {
	return Package{Name: name, Version: version}
}

func svc(name string, running, enabled bool) Service {
	return Service{Name: name, Installed: true, Running: running, Enabled: enabled}
}

func proc(executable, state string) Process {
	return Process{Executable: executable, State: state}
}

func ext(identifier string, enabled, active bool) SystemExtension {
	return SystemExtension{Identifier: identifier, Enabled: enabled, Active: active}
}

func paths(present ...string) func(string) bool {
	return func(p string) bool {
		for _, want := range present {
			if p == want {
				return true
			}
		}
		return false
	}
}

func byID(detections []Detection) map[string]Detection {
	out := make(map[string]Detection, len(detections))
	for _, d := range detections {
		out[d.Product.ID] = d
	}
	return out
}

func detectOne(t *testing.T, inv Inventory, id string) Detection {
	t.Helper()
	d, ok := byID(Detect(inv))[id]
	require.True(t, ok, "expected %q to be detected", id)
	return d
}

// --- every product, on every platform it ships on, fully healthy ---

func TestDetectHealthy(t *testing.T) {
	tests := []struct {
		name string
		id   string
		inv  Inventory
	}{
		{
			name: "CrowdStrike Falcon on macOS",
			id:   "crowdstrike-falcon",
			inv: Inventory{
				Platform:         PlatformMacOS,
				Packages:         []Package{pkg("Falcon", "7.20.0")},
				SystemExtensions: []SystemExtension{ext("com.crowdstrike.falcon.Agent", true, true)},
			},
		},
		{
			name: "CrowdStrike Falcon on Linux",
			id:   "crowdstrike-falcon",
			inv: Inventory{
				Platform: PlatformLinux,
				Packages: []Package{pkg("falcon-sensor", "7.20.0-17106")},
				Services: []Service{svc("falcon-sensor", true, true)},
			},
		},
		{
			name: "CrowdStrike Falcon on Windows",
			id:   "crowdstrike-falcon",
			inv: Inventory{
				Platform: PlatformWindows,
				Packages: []Package{pkg("CrowdStrike Sensor Platform", "7.20")},
				Services: []Service{svc("CSFalconService", true, true)},
			},
		},
		{
			name: "SentinelOne on macOS",
			id:   "sentinelone",
			inv: Inventory{
				Platform: PlatformMacOS,
				Packages: []Package{pkg("SentinelOne Extensions", "24.2.3")},
				Services: []Service{
					svc("com.sentinelone.sentineld", true, true),
					svc("com.sentinelone.sentineld-helper", true, true),
					svc("com.sentinelone.sentineld-guard", true, true),
					svc("com.sentinelone.sentinel-extensions", true, true),
					// Started on demand: the policy asserts only that it is
					// loaded, never that it is running.
					svc("com.sentinelone.sentineld-shell", false, true),
				},
			},
		},
		{
			name: "SentinelOne on Linux",
			id:   "sentinelone",
			inv: Inventory{
				Platform: PlatformLinux,
				Packages: []Package{pkg("SentinelAgent", "23.4.2.5")},
				Services: []Service{svc("sentinelone", true, true)},
			},
		},
		{
			name: "SentinelOne on Linux, lowercase package name",
			id:   "sentinelone",
			inv: Inventory{
				Platform: PlatformLinux,
				Packages: []Package{pkg("sentinelagent", "23.4.2.5")},
				Services: []Service{svc("sentinelone", true, true)},
			},
		},
		{
			name: "SentinelOne on Windows",
			id:   "sentinelone",
			inv: Inventory{
				Platform: PlatformWindows,
				Packages: []Package{pkg("Sentinel Agent", "23.4.2.5")},
				Services: []Service{svc("SentinelAgent", true, true)},
			},
		},
		{
			name: "ESET on macOS",
			id:   "eset",
			inv: Inventory{
				Platform: PlatformMacOS,
				Packages: []Package{pkg("ESET Endpoint Security", "7.3.3000.0")},
				Services: []Service{svc("com.eset.endpoint", true, true)},
			},
		},
		{
			name: "ESET on Linux",
			id:   "eset",
			inv: Inventory{
				Platform:   PlatformLinux,
				Services:   []Service{svc("eraagent", true, true)},
				PathExists: paths("/opt/eset/RemoteAdministrator/Agent"),
			},
		},
		{
			name: "ESET on Windows",
			id:   "eset",
			inv: Inventory{
				Platform: PlatformWindows,
				Packages: []Package{pkg("ESET Server Security", "9.0.12013.0")},
				Services: []Service{svc("ekrn", true, true)},
			},
		},
		{
			name: "Microsoft Defender on Windows",
			id:   "microsoft-defender",
			inv: Inventory{
				Platform: PlatformWindows,
				Services: []Service{svc("WinDefend", true, true)},
			},
		},
		{
			name: "Wazuh on macOS",
			id:   "wazuh",
			inv: Inventory{
				Platform:   PlatformMacOS,
				Services:   []Service{svc("com.wazuh.agent", true, true)},
				PathExists: paths("/Library/Ossec"),
			},
		},
		{
			name: "Wazuh on Linux",
			id:   "wazuh",
			inv: Inventory{
				Platform: PlatformLinux,
				Packages: []Package{pkg("wazuh-agent", "4.9.0")},
				Services: []Service{svc("wazuh-agent", true, true)},
			},
		},
		{
			name: "Wazuh on Windows",
			id:   "wazuh",
			inv: Inventory{
				Platform: PlatformWindows,
				Packages: []Package{pkg("Wazuh Agent", "4.9.0")},
				Services: []Service{svc("WazuhSvc", true, true)},
			},
		},
		{
			name: "Sophos on Windows",
			id:   "sophos",
			inv: Inventory{
				Platform: PlatformWindows,
				Packages: []Package{
					pkg("Sophos Endpoint Defense", "2.28.10"),
					pkg("Sophos Endpoint Agent", "2.28.10"),
				},
				Services: []Service{
					svc("Sophos Endpoint Defense Service", true, true),
					svc("Sophos MCS Agent", true, true),
				},
			},
		},
		{
			name: "Cortex XDR on macOS",
			id:   "cortex-xdr",
			inv: Inventory{
				Platform: PlatformMacOS,
				Packages: []Package{pkg("Cortex XDR", "8.4.0")},
				Services: []Service{svc("com.paloaltonetworks.cortex.agent", true, true)},
			},
		},
		{
			name: "Cortex XDR on Linux",
			id:   "cortex-xdr",
			inv: Inventory{
				Platform: PlatformLinux,
				Packages: []Package{pkg("cortex-agent", "8.4.0")},
				Services: []Service{svc("traps_pmd", true, true)},
			},
		},
		{
			name: "Cortex XDR on Windows, versioned package name",
			id:   "cortex-xdr",
			inv: Inventory{
				Platform: PlatformWindows,
				Packages: []Package{pkg("Cortex XDR 8.4.0.106603", "8.4.0")},
				Services: []Service{svc("cyserver", true, true)},
			},
		},
		{
			name: "WatchGuard EPDR on Windows",
			id:   "watchguard-epdr",
			inv: Inventory{
				Platform: PlatformWindows,
				Packages: []Package{pkg("WatchGuard EPDR", "8.00.24.0000")},
				Services: []Service{svc("PandaAetherAgent", true, true)},
			},
		},
		{
			name: "Malwarebytes on macOS",
			id:   "malwarebytes",
			inv: Inventory{
				Platform:   PlatformMacOS,
				Processes:  []Process{proc("/Applications/Malwarebytes.app/Contents/MacOS/Malwarebytes", "sleeping")},
				PathExists: paths("/Library/Application Support/Malwarebytes"),
			},
		},
		{
			name: "Malwarebytes on Windows",
			id:   "malwarebytes",
			inv: Inventory{
				Platform: PlatformWindows,
				Packages: []Package{pkg("Malwarebytes Endpoint Agent", "1.2.0.1131")},
				Services: []Service{svc("MBEndpointAgent", true, true)},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := detectOne(t, tc.inv, tc.id)
			assert.True(t, d.Running, "running")
			assert.True(t, d.Healthy, "healthy")
		})
	}
}

// Every product above must be exercised on every platform it claims. A new
// catalog entry with no happy-path case fails here rather than shipping
// unproven.
func TestEveryCatalogEntryHasAHealthyCase(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range healthyCoverage() {
		covered[tc] = true
	}
	for _, product := range Catalog {
		for platform := range product.Platforms {
			key := product.ID + "/" + platform
			assert.True(t, covered[key], "no TestDetectHealthy case for %s", key)
		}
	}
}

// healthyCoverage lists what TestDetectHealthy actually asserts, written out
// separately so the coverage check cannot be satisfied by the catalog itself.
func healthyCoverage() []string {
	return []string{
		"crowdstrike-falcon/macos", "crowdstrike-falcon/linux", "crowdstrike-falcon/windows",
		"sentinelone/macos", "sentinelone/linux", "sentinelone/windows",
		"eset/macos", "eset/linux", "eset/windows",
		"microsoft-defender/windows",
		"wazuh/macos", "wazuh/linux", "wazuh/windows",
		"sophos/windows",
		"cortex-xdr/macos", "cortex-xdr/linux", "cortex-xdr/windows",
		"watchguard-epdr/windows",
		"malwarebytes/macos", "malwarebytes/windows",
	}
}

// --- installed but not healthy ---

func TestStoppedServiceIsInstalledButNotHealthy(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformLinux,
		Packages: []Package{pkg("falcon-sensor", "7.20.0-17106")},
		Services: []Service{svc("falcon-sensor", false, true)},
	}, "crowdstrike-falcon")

	assert.Contains(t, d.DetectedBy, SignalPackage)
	assert.False(t, d.Running)
	assert.False(t, d.Healthy)
}

func TestDisabledServiceIsRunningButNotHealthy(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformWindows,
		Packages: []Package{pkg("CrowdStrike Sensor Platform", "7.20")},
		Services: []Service{svc("CSFalconService", true, false)},
	}, "crowdstrike-falcon")

	assert.True(t, d.Running)
	assert.True(t, d.EnabledReported)
	assert.False(t, d.Enabled)
	assert.False(t, d.Healthy, "a sensor that does not start at boot stops protecting at the next reboot")
}

func TestMissingServiceCannotProveRunning(t *testing.T) {
	// Sophos runs two services. Only one is present, so nothing establishes
	// that the other component is up.
	d := detectOne(t, Inventory{
		Platform: PlatformWindows,
		Packages: []Package{pkg("Sophos Endpoint Defense", "2.28.10")},
		Services: []Service{svc("Sophos Endpoint Defense Service", true, true)},
	}, "sophos")

	assert.False(t, d.Running)
	assert.False(t, d.Healthy)
}

func TestPackageInstalledWithNoServiceAtAll(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformWindows,
		Packages: []Package{pkg("Malwarebytes Endpoint Agent", "1.2.0.1131")},
	}, "malwarebytes")

	assert.Equal(t, []string{SignalPackage}, d.DetectedBy)
	assert.False(t, d.Running)
	assert.False(t, d.Healthy)
}

// --- boot-start is not reported on launchd ---

func TestMacOSLaunchdProductsDoNotReportBootStart(t *testing.T) {
	// launchd reports every loaded label as enabled, so enabled would read
	// true on a Mac whatever the asset does at boot. Healthy must therefore
	// rest on running alone for these products.
	d := detectOne(t, Inventory{
		Platform:   PlatformMacOS,
		Services:   []Service{svc("com.wazuh.agent", true, false)},
		PathExists: paths("/Library/Ossec"),
	}, "wazuh")

	assert.False(t, d.EnabledReported)
	assert.True(t, d.Running)
	assert.True(t, d.Healthy, "healthy must not depend on a value launchd does not report")
}

func TestCrowdStrikeMacOSReportsBootStartFromTheSystemExtension(t *testing.T) {
	// The extension's own enabled flag is real, unlike launchd's, so this one
	// product does report boot start on macOS.
	d := detectOne(t, Inventory{
		Platform:         PlatformMacOS,
		Packages:         []Package{pkg("Falcon", "7.20.0")},
		SystemExtensions: []SystemExtension{ext("com.crowdstrike.falcon.Agent", true, true)},
	}, "crowdstrike-falcon")

	assert.True(t, d.EnabledReported)
	assert.True(t, d.Enabled)
}

// --- system extension states ---

func TestSystemExtensionStates(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		active      bool
		wantRunning bool
	}{
		{"enabled and active", true, true, true},
		{"enabled but not active", true, false, false},
		{"active but not enabled", false, true, false},
		{"neither", false, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := detectOne(t, Inventory{
				Platform:         PlatformMacOS,
				Packages:         []Package{pkg("Falcon", "7.20.0")},
				SystemExtensions: []SystemExtension{ext("com.crowdstrike.falcon.Agent", tc.enabled, tc.active)},
			}, "crowdstrike-falcon")

			assert.Equal(t, tc.wantRunning, d.Running)
			assert.Equal(t, tc.wantRunning, d.Healthy)
		})
	}
}

func TestFalconPackageWithoutItsSystemExtension(t *testing.T) {
	// The sensor is installed but its endpoint security extension was never
	// approved, which is the common macOS deployment failure.
	d := detectOne(t, Inventory{
		Platform: PlatformMacOS,
		Packages: []Package{pkg("Falcon", "7.20.0")},
	}, "crowdstrike-falcon")

	assert.Equal(t, []string{SignalPackage}, d.DetectedBy)
	assert.False(t, d.Running)
	assert.False(t, d.Healthy)
}

// --- processes ---

func TestZombieProcessDoesNotProveRunning(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform:   PlatformMacOS,
		Processes:  []Process{proc("/Applications/Malwarebytes.app/Contents/MacOS/Malwarebytes", "zombie")},
		PathExists: paths("/Library/Application Support/Malwarebytes"),
	}, "malwarebytes")

	assert.False(t, d.Running)
	assert.False(t, d.Healthy)
}

// Agents that install outside the package database are recognized by a path
// alone. Each such path is asserted on its own, because a co-installed service
// would otherwise cover for a path that no longer matches anything.

func TestWazuhOnMacOSIsRecognizedByItsPathAlone(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform:   PlatformMacOS,
		PathExists: paths("/Library/Ossec"),
	}, "wazuh")

	assert.Equal(t, []string{SignalPath}, d.DetectedBy)
	assert.False(t, d.Running)
}

func TestESETOnLinuxIsRecognizedByItsPathAlone(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform:   PlatformLinux,
		PathExists: paths("/opt/eset/RemoteAdministrator/Agent"),
	}, "eset")

	assert.Equal(t, []string{SignalPath}, d.DetectedBy)
	assert.False(t, d.Running)
}

func TestInstallPathWithNoProcess(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform:   PlatformMacOS,
		PathExists: paths("/Library/Application Support/Malwarebytes"),
	}, "malwarebytes")

	assert.Equal(t, []string{SignalPath}, d.DetectedBy)
	assert.False(t, d.Running)
}

// --- service families matched by pattern ---

func TestServicePatternNeedsOnlyOneRunningMember(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformWindows,
		Packages: []Package{pkg("Sentinel Agent", "23.4.2.5")},
		Services: []Service{
			svc("SentinelAgent", true, true),
			svc("SentinelStaticEngine", false, false),
			svc("SentinelAgentWatchdog", false, true),
		},
	}, "sentinelone")

	assert.True(t, d.Running)
	assert.True(t, d.Healthy)
}

func TestServicePatternWithNoRunningMember(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformWindows,
		Packages: []Package{pkg("Sentinel Agent", "23.4.2.5")},
		Services: []Service{
			svc("SentinelAgent", false, true),
			svc("SentinelAgentWatchdog", false, true),
		},
	}, "sentinelone")

	assert.False(t, d.Running)
	assert.False(t, d.Healthy)
}

func TestServicePatternWithNoMatchAtAll(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformWindows,
		Packages: []Package{pkg("Sentinel Agent", "23.4.2.5")},
		Services: []Service{svc("Spooler", true, true)},
	}, "sentinelone")

	assert.False(t, d.Running)
}

func TestESETServicePatternIsAnchored(t *testing.T) {
	// com.eset. must be the start of the label; a third-party service that
	// merely contains the string must not stand in for ESET being up.
	d := detectOne(t, Inventory{
		Platform: PlatformMacOS,
		Packages: []Package{pkg("ESET Endpoint Security", "7.3.3000.0")},
		Services: []Service{svc("io.example.com.eset.shim", true, true)},
	}, "eset")

	assert.False(t, d.Running, "an unanchored match would report ESET as running")
}

// --- package matching precision ---

func TestPackageNamesDoNotMatchOnSubstrings(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		packages []Package
	}{
		{"FalconView is not CrowdStrike Falcon", PlatformMacOS, []Package{pkg("FalconView", "4.5")}},
		{"Falcon Proxy is not the sensor", PlatformMacOS, []Package{pkg("Falcon Proxy", "1.0")}},
		{"CortexTools is not Cortex XDR", PlatformWindows, []Package{pkg("CortexTools", "1.0")}},
		{"a Sophos utility is not the endpoint agent", PlatformWindows, []Package{pkg("Sophos Connect", "2.3")}},
		{"Wazuh Manager is not the agent", PlatformWindows, []Package{pkg("Wazuh Manager", "4.9.0")}},
		{"an unrelated sensor package", PlatformLinux, []Package{pkg("falcon-sensor-config", "1.0")}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found := Detect(Inventory{Platform: tc.platform, Packages: tc.packages})
			assert.Empty(t, found, "detected %v", byID(found))
		})
	}
}

func TestCortexPackagePatternIsCaseInsensitive(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformWindows,
		Packages: []Package{pkg("CORTEX XDR AGENT", "8.4.0")},
	}, "cortex-xdr")

	assert.Contains(t, d.DetectedBy, SignalPackage)
}

func TestPackageNameMatchIgnoresCase(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformWindows,
		Packages: []Package{pkg("crowdstrike sensor platform", "7.20")},
	}, "crowdstrike-falcon")

	assert.Contains(t, d.DetectedBy, SignalPackage)
}

// --- service name normalization ---

func TestServiceNamesMatchWithAndWithoutTheSystemdSuffix(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformLinux,
		Packages: []Package{pkg("falcon-sensor", "7.20.0-17106")},
		Services: []Service{svc("falcon-sensor.service", true, true)},
	}, "crowdstrike-falcon")

	assert.True(t, d.Healthy)
}

func TestServicePatternsSeeTheNormalizedName(t *testing.T) {
	// No shipped pattern is anchored at the end, so this asserts on the
	// helper directly: a pattern written with $ must still match a systemd
	// unit spelled with its optional suffix.
	sig := Signature{ServicePattern: regexp.MustCompile(`^falcon-sensor$`)}
	inv := Inventory{Services: []Service{
		svc("unrelated.service", true, true),
		svc("falcon-sensor.service", true, true),
	}}

	assert.Equal(t, []int{1}, matchPatternedServices(sig, inv))
}

func TestWindowsServiceNamesAreNotCaseSensitive(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformWindows,
		Services: []Service{svc("windefend", true, true)},
	}, "microsoft-defender")

	assert.True(t, d.Healthy)
}

func TestLinuxServiceNamesAreCaseSensitive(t *testing.T) {
	// systemd unit names are case sensitive, so a unit spelled differently is
	// not the sensor's unit and cannot prove it is running.
	d := detectOne(t, Inventory{
		Platform: PlatformLinux,
		Packages: []Package{pkg("falcon-sensor", "7.20.0")},
		Services: []Service{svc("Falcon-Sensor", true, true)},
	}, "crowdstrike-falcon")

	assert.False(t, d.Running)
	assert.False(t, d.Healthy)
}

// --- platform isolation ---

func TestWindowsSignalsAreIgnoredOnOtherPlatforms(t *testing.T) {
	windows := Inventory{
		Platform: PlatformLinux,
		Packages: []Package{
			pkg("CrowdStrike Sensor Platform", "7.20"),
			pkg("Sophos Endpoint Defense", "2.28.10"),
			pkg("WatchGuard EPDR", "8.00.24.0000"),
		},
		Services: []Service{svc("WinDefend", true, true), svc("cyserver", true, true)},
	}

	found := byID(Detect(windows))
	assert.NotContains(t, found, "microsoft-defender", "Defender does not run on Linux")
	assert.NotContains(t, found, "sophos")
	assert.NotContains(t, found, "watchguard-epdr")
	assert.NotContains(t, found, "crowdstrike-falcon", "the Windows package name is not the Linux one")
	// cyserver is the Cortex service on Windows only; Linux uses traps_pmd.
	assert.NotContains(t, found, "cortex-xdr")
}

func TestSophosIsWindowsOnly(t *testing.T) {
	for _, platform := range []string{PlatformLinux, PlatformMacOS} {
		found := byID(Detect(Inventory{
			Platform: platform,
			Packages: []Package{pkg("Sophos Endpoint Defense", "2.28.10")},
			Services: []Service{svc("Sophos Endpoint Defense Service", true, true)},
		}))
		assert.NotContains(t, found, "sophos", "platform %s", platform)
	}
}

func TestUnknownPlatformDetectsNothing(t *testing.T) {
	assert.Empty(t, Detect(Inventory{
		Platform: "freebsd",
		Packages: []Package{pkg("falcon-sensor", "7.20.0")},
		Services: []Service{svc("falcon-sensor", true, true)},
	}))
}

// --- the absent case ---

func TestAssetWithNoAgent(t *testing.T) {
	found := Detect(Inventory{
		Platform: PlatformLinux,
		Packages: []Package{pkg("openssh-server", "9.6p1"), pkg("curl", "8.5.0")},
		Services: []Service{svc("sshd", true, true), svc("cron", true, true)},
	})
	assert.Empty(t, found)
}

func TestEmptyInventory(t *testing.T) {
	for _, platform := range []string{PlatformWindows, PlatformLinux, PlatformMacOS} {
		assert.Empty(t, Detect(Inventory{Platform: platform}), "platform %s", platform)
	}
}

func TestNilPathLookupDoesNotPanic(t *testing.T) {
	// ESET on Linux and Wazuh on macOS are recognized only by a path, so a
	// connection that cannot stat must degrade rather than crash.
	assert.NotPanics(t, func() {
		Detect(Inventory{Platform: PlatformLinux, Services: []Service{svc("eraagent", true, true)}})
	})
}

func TestServiceThatIsNotInstalledIsNotInstallEvidence(t *testing.T) {
	found := Detect(Inventory{
		Platform: PlatformWindows,
		Services: []Service{{Name: "WinDefend", Installed: false}},
	})
	assert.Empty(t, found, "a service entry that reports itself uninstalled proves nothing")
}

// --- several agents on one asset ---

func TestMultipleAgentsOnOneAsset(t *testing.T) {
	// Defender is commonly left installed alongside a third-party sensor.
	found := byID(Detect(Inventory{
		Platform: PlatformWindows,
		Packages: []Package{pkg("CrowdStrike Sensor Platform", "7.20")},
		Services: []Service{
			svc("CSFalconService", true, true),
			svc("WinDefend", true, true),
		},
	}))

	require.Contains(t, found, "crowdstrike-falcon")
	require.Contains(t, found, "microsoft-defender")
	assert.True(t, found["crowdstrike-falcon"].Healthy)
	assert.True(t, found["microsoft-defender"].Healthy)
}

func TestDetectionsComeBackInCatalogOrder(t *testing.T) {
	found := Detect(Inventory{
		Platform: PlatformWindows,
		Packages: []Package{
			pkg("Malwarebytes Endpoint Agent", "1.2.0.1131"),
			pkg("CrowdStrike Sensor Platform", "7.20"),
		},
	})
	require.Len(t, found, 2)
	assert.Equal(t, "crowdstrike-falcon", found[0].Product.ID)
	assert.Equal(t, "malwarebytes", found[1].Product.ID)
}

// --- reported detail ---

func TestVersionComesFromTheMatchedPackage(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformLinux,
		Packages: []Package{pkg("wazuh-agent", "4.9.0-1")},
		Services: []Service{svc("wazuh-agent", true, true)},
	}, "wazuh")

	assert.Equal(t, "4.9.0-1", d.Version)
}

func TestVersionComesFromTheFirstMatchedPackage(t *testing.T) {
	// Sophos ships two packages. Taking the last match instead of the first
	// would report the component version where the product version belongs.
	d := detectOne(t, Inventory{
		Platform: PlatformWindows,
		Packages: []Package{
			pkg("Sophos Endpoint Defense", "2.28.10"),
			pkg("Sophos Endpoint Agent", "1.5.0"),
		},
	}, "sophos")

	assert.Equal(t, "2.28.10", d.Version)
}

func TestVersionIsEmptyWhenNothingReportsOne(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform: PlatformWindows,
		Services: []Service{svc("WinDefend", true, true)},
	}, "microsoft-defender")

	assert.Empty(t, d.Version, "an invented version is worse than none")
}

func TestDetectedBySignalsAreRecorded(t *testing.T) {
	d := detectOne(t, Inventory{
		Platform:         PlatformMacOS,
		Packages:         []Package{pkg("Falcon", "7.20.0")},
		SystemExtensions: []SystemExtension{ext("com.crowdstrike.falcon.Agent", true, true)},
	}, "crowdstrike-falcon")

	assert.Equal(t, []string{SignalPackage, SignalSystemExtension}, d.DetectedBy)
}

func TestIndexSlicesPointAtTheMatchedEntries(t *testing.T) {
	inv := Inventory{
		Platform: PlatformWindows,
		Packages: []Package{
			pkg("7-Zip", "24.08"),
			pkg("CrowdStrike Sensor Platform", "7.20"),
		},
		Services: []Service{
			svc("Spooler", true, true),
			svc("CSFalconService", true, true),
		},
	}
	d := detectOne(t, inv, "crowdstrike-falcon")

	require.Equal(t, []int{1}, d.PackageIdx)
	require.Equal(t, []int{1}, d.ServiceIdx)
	assert.Equal(t, "CrowdStrike Sensor Platform", inv.Packages[d.PackageIdx[0]].Name)
	assert.Equal(t, "CSFalconService", inv.Services[d.ServiceIdx[0]].Name)
}

// --- the catalog itself ---

func TestCatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	categories := map[string]bool{CategoryEDR: true, CategoryEPP: true, CategoryAV: true, CategoryXDR: true}
	platforms := map[string]bool{PlatformWindows: true, PlatformLinux: true, PlatformMacOS: true}

	for _, product := range Catalog {
		t.Run(product.ID, func(t *testing.T) {
			assert.NotEmpty(t, product.ID)
			assert.NotEmpty(t, product.Name)
			assert.NotEmpty(t, product.Vendor)
			assert.True(t, categories[product.Category], "unknown category %q", product.Category)
			assert.False(t, seen[product.ID], "duplicate product id")
			seen[product.ID] = true

			require.NotEmpty(t, product.Platforms)
			for platform, sig := range product.Platforms {
				assert.True(t, platforms[platform], "unknown platform %q", platform)

				installSignals := len(sig.Packages) > 0 || sig.PackagePattern != nil ||
					len(sig.Paths) > 0 || len(sig.SystemExtensions) > 0 ||
					len(sig.Services) > 0 || sig.ServicePattern != nil
				assert.True(t, installSignals, "%s has no way to be detected", platform)

				switch sig.RunVia {
				case RunViaServices:
					assert.True(t, len(sig.Services) > 0 || sig.ServicePattern != nil,
						"%s runs via services but names none", platform)
				case RunViaProcesses:
					assert.NotNil(t, sig.ProcessPattern, "%s runs via processes but has no pattern", platform)
				case RunViaSystemExtensions:
					assert.NotEmpty(t, sig.SystemExtensions, "%s runs via extensions but names none", platform)
				}

				if platform == PlatformMacOS && sig.RunVia == RunViaServices {
					assert.False(t, sig.BootStartReported,
						"launchd reports every loaded label as enabled, so boot start cannot be trusted")
				}
			}
		})
	}
}

func TestCatalogCoversTheProductsThePolicyChecks(t *testing.T) {
	// Written out from mondoo-edr-policy v1.6.4. A product dropped from the
	// catalog silently narrows fleet coverage, so name them here.
	want := []string{
		"crowdstrike-falcon", "sentinelone", "eset", "microsoft-defender",
		"wazuh", "sophos", "cortex-xdr", "watchguard-epdr", "malwarebytes",
	}

	have := map[string]bool{}
	for _, product := range Catalog {
		have[product.ID] = true
	}
	for _, id := range want {
		assert.True(t, have[id], "catalog lost %q", id)
	}
}
