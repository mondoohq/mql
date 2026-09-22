// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package edr recognizes endpoint security agents from an inventory of the
// packages, services, processes, system extensions and paths present on an
// asset. The catalog is the only place a product is described: adding a vendor
// is a new Product entry, and no MQL, schema or policy changes with it.
package edr

import "regexp"

// Platform keys used by the catalog. They name the OS family rather than a
// distribution, because agents ship the same components across a family.
const (
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
	PlatformMacOS   = "macos"
)

// Product categories.
const (
	CategoryEDR = "edr"
	CategoryEPP = "epp"
	CategoryAV  = "av"
	CategoryXDR = "xdr"
)

// Signals recorded in a detection, in the order they are evaluated.
const (
	SignalPackage         = "package"
	SignalPath            = "path"
	SignalSystemExtension = "systemExtension"
	SignalService         = "service"
	SignalProcess         = "process"
)

// RunSignal names what proves an agent is running on a platform.
type RunSignal int

const (
	// RunViaServices requires every named service, and at least one service
	// matched by ServicePattern, to be running.
	RunViaServices RunSignal = iota
	// RunViaProcesses requires a live process matching ProcessPattern.
	RunViaProcesses
	// RunViaSystemExtensions requires the registered system extension to be
	// both enabled and active.
	RunViaSystemExtensions
)

// Signature describes how one product presents itself on one platform.
type Signature struct {
	// Packages are installed package names, compared without regard to case.
	Packages []string
	// PackagePattern matches package names whose exact spelling varies across
	// releases, for example the several names Cortex XDR ships under.
	PackagePattern *regexp.Regexp
	// Paths exist on an asset where the agent is installed. They are the only
	// signal for agents that install outside the package database.
	Paths []string
	// SystemExtensions are the extension identifiers the agent registers on
	// macOS.
	SystemExtensions []string
	// Services are the service names every component of the agent runs under.
	// All of them must be running for the agent to count as running.
	Services []string
	// ServicePattern matches a family of services whose names carry a version
	// or instance suffix. At least one match must be running. It is applied to
	// the name without systemd's optional .service suffix, and is case
	// sensitive unless it asks for (?i).
	ServicePattern *regexp.Regexp
	// ProcessPattern matches the executables the agent runs.
	ProcessPattern *regexp.Regexp
	// RunVia selects which of the above proves the agent is running.
	RunVia RunSignal
	// BootStartReported is false where the platform's service manager reports
	// no distinct boot-start setting. launchd reports every loaded label as
	// enabled, so a macOS agent's enabled field would otherwise always read
	// true whatever the asset does at boot.
	BootStartReported bool
}

// Product is one endpoint security agent across every platform it ships on.
type Product struct {
	ID       string
	Name     string
	Vendor   string
	Category string
	// Platforms is keyed by PlatformWindows, PlatformLinux or PlatformMacOS. A
	// product with no entry for a platform is never reported on it.
	Platforms map[string]Signature
}

var (
	cortexPackages = regexp.MustCompile(`(?i)Cortex XDR`)
	// Unanchored on purpose: it matches the agent's whole service family,
	// SentinelAgent and SentinelAgentWatchdog alike.
	sentinelServices = regexp.MustCompile(`SentinelAgent`)
	esetServices     = regexp.MustCompile(`^com\.eset\.`)
	malwarebytesProc = regexp.MustCompile(`Malwarebytes`)
)

// Catalog is every agent this provider recognizes.
var Catalog = []Product{
	{
		ID:       "crowdstrike-falcon",
		Name:     "CrowdStrike Falcon",
		Vendor:   "CrowdStrike",
		Category: CategoryEDR,
		Platforms: map[string]Signature{
			PlatformMacOS: {
				Packages:          []string{"Falcon"},
				SystemExtensions:  []string{"com.crowdstrike.falcon.Agent"},
				RunVia:            RunViaSystemExtensions,
				BootStartReported: true,
			},
			PlatformLinux: {
				Packages:          []string{"falcon-sensor"},
				Services:          []string{"falcon-sensor"},
				BootStartReported: true,
			},
			PlatformWindows: {
				Packages:          []string{"CrowdStrike Sensor Platform"},
				Services:          []string{"CSFalconService"},
				BootStartReported: true,
			},
		},
	},
	{
		ID:       "sentinelone",
		Name:     "SentinelOne",
		Vendor:   "SentinelOne",
		Category: CategoryEDR,
		Platforms: map[string]Signature{
			PlatformMacOS: {
				Packages: []string{"SentinelOne Extensions"},
				// sentineld-shell is started on demand and is deliberately not
				// required to be running.
				Services: []string{
					"com.sentinelone.sentineld",
					"com.sentinelone.sentineld-helper",
					"com.sentinelone.sentineld-guard",
					"com.sentinelone.sentinel-extensions",
				},
			},
			PlatformLinux: {
				Packages:          []string{"SentinelAgent", "sentinelagent"},
				Services:          []string{"sentinelone"},
				BootStartReported: true,
			},
			PlatformWindows: {
				Packages:          []string{"Sentinel Agent"},
				ServicePattern:    sentinelServices,
				BootStartReported: true,
			},
		},
	},
	{
		ID:       "eset",
		Name:     "ESET Endpoint Security",
		Vendor:   "ESET",
		Category: CategoryEPP,
		Platforms: map[string]Signature{
			PlatformMacOS: {
				Packages:       []string{"ESET Endpoint Security"},
				ServicePattern: esetServices,
			},
			PlatformLinux: {
				Paths:             []string{"/opt/eset/RemoteAdministrator/Agent"},
				Services:          []string{"eraagent"},
				BootStartReported: true,
			},
			PlatformWindows: {
				Packages:          []string{"ESET Endpoint Security", "ESET Server Security"},
				Services:          []string{"ekrn"},
				BootStartReported: true,
			},
		},
	},
	{
		ID:       "microsoft-defender",
		Name:     "Microsoft Defender Antivirus",
		Vendor:   "Microsoft",
		Category: CategoryAV,
		Platforms: map[string]Signature{
			PlatformWindows: {
				Services:          []string{"WinDefend"},
				BootStartReported: true,
			},
		},
	},
	{
		ID:       "wazuh",
		Name:     "Wazuh Agent",
		Vendor:   "Wazuh",
		Category: CategoryEDR,
		Platforms: map[string]Signature{
			PlatformMacOS: {
				Paths:    []string{"/Library/Ossec"},
				Services: []string{"com.wazuh.agent"},
			},
			PlatformLinux: {
				Packages:          []string{"wazuh-agent"},
				Services:          []string{"wazuh-agent"},
				BootStartReported: true,
			},
			PlatformWindows: {
				Packages:          []string{"Wazuh Agent"},
				Services:          []string{"WazuhSvc"},
				BootStartReported: true,
			},
		},
	},
	{
		ID:       "sophos",
		Name:     "Sophos Endpoint",
		Vendor:   "Sophos",
		Category: CategoryEDR,
		Platforms: map[string]Signature{
			PlatformWindows: {
				Packages: []string{"Sophos Endpoint Defense", "Sophos Endpoint Agent"},
				Services: []string{
					"Sophos Endpoint Defense Service",
					"Sophos MCS Agent",
				},
				BootStartReported: true,
			},
		},
	},
	{
		ID:       "cortex-xdr",
		Name:     "Cortex XDR",
		Vendor:   "Palo Alto Networks",
		Category: CategoryXDR,
		Platforms: map[string]Signature{
			PlatformMacOS: {
				Packages: []string{"Cortex XDR", "Cortex XDR Agent"},
				Services: []string{"com.paloaltonetworks.cortex.agent"},
			},
			PlatformLinux: {
				Packages:          []string{"Cortex XDR", "Cortex XDR Agent", "cortex-agent"},
				Services:          []string{"traps_pmd"},
				BootStartReported: true,
			},
			PlatformWindows: {
				PackagePattern:    cortexPackages,
				Services:          []string{"cyserver"},
				BootStartReported: true,
			},
		},
	},
	{
		ID:       "watchguard-epdr",
		Name:     "WatchGuard EPDR",
		Vendor:   "WatchGuard",
		Category: CategoryEPP,
		Platforms: map[string]Signature{
			PlatformWindows: {
				Packages:          []string{"WatchGuard EPDR"},
				Services:          []string{"PandaAetherAgent"},
				BootStartReported: true,
			},
		},
	},
	{
		ID:       "malwarebytes",
		Name:     "Malwarebytes Endpoint Agent",
		Vendor:   "Malwarebytes",
		Category: CategoryEPP,
		Platforms: map[string]Signature{
			PlatformMacOS: {
				Paths:          []string{"/Library/Application Support/Malwarebytes"},
				ProcessPattern: malwarebytesProc,
				RunVia:         RunViaProcesses,
			},
			PlatformWindows: {
				Packages:          []string{"Malwarebytes Endpoint Agent"},
				Services:          []string{"MBEndpointAgent"},
				BootStartReported: true,
			},
		},
	},
}
