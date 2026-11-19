// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package rmm recognizes remote monitoring and management, remote access,
// patch management and client management agents. It is a catalog for the edr
// package's matcher: a product is described here once, and adding a vendor is
// a new Product entry with no MQL, schema or policy change.
//
// A platform is only listed when both what proves the agent is installed and
// what proves it is running are known. A platform with only an install signal
// would report every healthy agent as not running.
//
// Comments marked "Observed" name package names that mql's packages resource
// reported for the agent on real hosts. Every other value comes from the
// vendor's documentation or source code, or, where the vendor publishes
// nothing, from public uninstall scripts, incident reports and detection
// rules.
package rmm

import (
	"regexp"

	"go.mondoo.com/mql/providers/os/resources/edr"
)

// Product categories.
const (
	// CategoryRMM is a remote monitoring and management agent: inventory,
	// scripting, patching and remote control from one console.
	CategoryRMM = "rmm"
	// CategoryRemoteAccess is a remote control or support client.
	CategoryRemoteAccess = "remoteAccess"
	// CategoryPatchManagement is an agent whose main job is patching.
	CategoryPatchManagement = "patchManagement"
	// CategoryClientManagement is a client management or software
	// distribution agent, usually run from an on-premises server.
	CategoryClientManagement = "clientManagement"
)

// Detect returns every Catalog product found on the asset, in catalog order.
func Detect(inv edr.Inventory) []edr.Detection {
	return edr.DetectIn(Catalog, inv)
}

var (
	// Agent v1 and v2 run under different labels.
	ateraLaunchd = regexp.MustCompile(`^com\.atera\.(agent|ateraagent)$`)

	automateLaunchd = regexp.MustCompile(`^com\.labtechsoftware\.(ltechagent|LTSvc)$`)

	// Kaseya names the Add/Remove Programs entry after the machine ID and the
	// server the agent reports to, for example
	// "Kaseya Agent (pc1.group.org - vsa.example.com)". A second agent on the
	// same machine is "Kaseya Agent #2 (...)".
	kaseyaPackages = regexp.MustCompile(`^Kaseya Agent( #\d+)? \(`)
	// The agent service's name is KA followed by the agent GUID: the
	// six-character customer ID and 14 digits. KAEND<GUID>, the endpoint
	// helper, does not match and is not required.
	kaseyaServices = regexp.MustCompile(`(?i)^KA[A-Z0-9]{6}\d{14}$`)
	kaseyaProcess  = regexp.MustCompile(`AgentMon`)

	nsightProcess = regexp.MustCompile(`rmmagentd`)

	ninjaLaunchd = regexp.MustCompile(`^com\.ninjarmm\.agentd?$`)

	// Every ScreenConnect client carries the 16-hex-digit fingerprint of the
	// server instance it belongs to, so a machine runs one client per
	// instance. connectwisecontrol- is the current Linux and macOS prefix,
	// screenconnect- the one older installs kept. The Unix pattern is
	// anchored, so macOS's per-user -onlogin and -prelogin agents do not
	// stand in for the daemon.
	screenConnectWindows = regexp.MustCompile(`(?i)^ScreenConnect Client \([0-9a-f]+\)$`)
	screenConnectUnix    = regexp.MustCompile(`^(connectwisecontrol|screenconnect)-[0-9a-f]+$`)

	// Some UEM Agent releases append their version to the name ("Matrix42
	// UEM Agent Windows 2503.2.2"), and the Empirum Agent it replaced always
	// does ("Empirum Agent 19.0").
	matrix42Packages = regexp.MustCompile(`^(Matrix42 UEM Agent( Windows .+)?|UEM Agent Windows \(64 bit\)|Empirum Agent \d.*)$`)
	// Matrix42UAF runs the UEM Agent, ERIS the Empirum Agent.
	matrix42Services = regexp.MustCompile(`(?i)^(Matrix42UAF|ERIS)$`)
	matrix42Launchd  = regexp.MustCompile(`(?i)^com\.matrix42\.empirumd$`)
)

// Catalog is every agent this provider recognizes, ordered by category and
// then by id.
var Catalog = []edr.Product{
	// --- remote monitoring and management ---
	{
		ID:       "atera",
		Name:     "Atera Agent",
		Vendor:   "Atera",
		Category: CategoryRMM,
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed.
				Packages:          []string{"AteraAgent"},
				Services:          []string{"AteraAgent"},
				BootStartReported: true,
			},
			edr.PlatformLinux: {
				Paths:             []string{"/usr/lib/atera-agent"},
				Services:          []string{"AteraAgent"},
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				Packages:       []string{"AteraAgent"},
				Paths:          []string{"/Library/Application Support/com.atera.ateraagent"},
				ServicePattern: ateraLaunchd,
			},
		},
	},
	{
		ID:       "connectwise-automate",
		Name:     "ConnectWise Automate Agent",
		Vendor:   "ConnectWise",
		Category: CategoryRMM,
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// The LabTech name stays on agents installed before the
				// rename.
				Packages:          []string{"ConnectWise Automate Remote Agent", "LabTech® Software Remote Agent"},
				Services:          []string{"LTService", "LTSvcMon"},
				BootStartReported: true,
			},
			edr.PlatformLinux: {
				Paths:             []string{"/usr/local/ltechagent"},
				Services:          []string{"ltechagent"},
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				Paths:          []string{"/usr/local/ltechagent", "/usr/LTSvc"},
				ServicePattern: automateLaunchd,
			},
		},
	},
	{
		ID:       "datto-rmm",
		Name:     "Datto RMM Agent",
		Vendor:   "Datto",
		Category: CategoryRMM,
		// The agent kept its CentraStage names through both renames.
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed, both names.
				Packages:          []string{"Datto RMM", "CentraStage"},
				Services:          []string{"CagService"},
				BootStartReported: true,
			},
			edr.PlatformLinux: {
				Paths:             []string{"/opt/CentraStage"},
				Services:          []string{"cag"},
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				// Observed.
				Packages: []string{"AEM Agent"},
				Paths:    []string{"/usr/local/share/CentraStage"},
				Services: []string{"com.centrastage.cag"},
			},
		},
	},
	{
		ID:       "kaseya-vsa",
		Name:     "Kaseya VSA Agent",
		Vendor:   "Kaseya",
		Category: CategoryRMM,
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed.
				PackagePattern:    kaseyaPackages,
				ServicePattern:    kaseyaServices,
				BootStartReported: true,
			},
			edr.PlatformLinux: {
				// Installed by a script, under /opt/Kaseya/<agent GUID>.
				Paths:          []string{"/opt/Kaseya"},
				ProcessPattern: kaseyaProcess,
				RunVia:         edr.RunViaProcesses,
			},
		},
	},
	{
		ID:       "kaseya-vsa-x",
		Name:     "Kaseya VSA X Agent",
		Vendor:   "Kaseya",
		Category: CategoryRMM,
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed.
				Packages:          []string{"VSA X"},
				Services:          []string{"VSAX"},
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				Paths:    []string{"/Library/Application Support/VSA"},
				Services: []string{"com.kaseya.VSAHelper"},
			},
		},
	},
	{
		ID:       "n-able-n-central",
		Name:     "N-able N-central Agent",
		Vendor:   "N-able",
		Category: CategoryRMM,
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed. The name is generic, so the two services the
				// agent registers are what the running state rests on.
				Packages:          []string{"Windows Agent"},
				Services:          []string{"Windows Agent Service", "Windows Agent Maintenance Service"},
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				Paths:    []string{"/Library/N-central Agent"},
				Services: []string{"com.n-central.agent"},
			},
		},
	},
	{
		ID:       "n-able-n-sight",
		Name:     "N-able N-sight RMM Agent",
		Vendor:   "N-able",
		Category: CategoryRMM,
		// Formerly SolarWinds RMM, MAXfocus and GFI MAX. The Windows agent is
		// still called the Advanced Monitoring Agent.
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed. The GP name is a Group Policy install.
				Packages:          []string{"Advanced Monitoring Agent", "Advanced Monitoring Agent GP"},
				Services:          []string{"Advanced Monitoring Agent"},
				BootStartReported: true,
			},
			edr.PlatformLinux: {
				Packages:          []string{"rmmagent"},
				Services:          []string{"rmmagent"},
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				Paths:          []string{"/usr/local/rmmagent"},
				ProcessPattern: nsightProcess,
				RunVia:         edr.RunViaProcesses,
			},
		},
	},
	{
		ID:       "ninjaone",
		Name:     "NinjaOne Agent",
		Vendor:   "NinjaOne",
		Category: CategoryRMM,
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed. Current builds keep the NinjaRMM spelling.
				Packages:          []string{"NinjaRMMAgent"},
				Services:          []string{"NinjaRMMAgent"},
				BootStartReported: true,
			},
			edr.PlatformLinux: {
				Paths:             []string{"/opt/NinjaRMMAgent"},
				Services:          []string{"ninjarmm-agent"},
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				// A hidden folder, not an app bundle.
				Paths:          []string{"/Applications/NinjaRMMAgent"},
				ServicePattern: ninjaLaunchd,
			},
		},
	},
	{
		ID:       "syncro",
		Name:     "Syncro Agent",
		Vendor:   "Syncro",
		Category: CategoryRMM,
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed. SyncroLive and SyncroOvermind run beside it but
				// are not required.
				Packages:          []string{"Syncro"},
				Services:          []string{"Syncro"},
				BootStartReported: true,
			},
			edr.PlatformLinux: {
				// Installed by a .run installer, not a distribution package.
				Services:          []string{"syncro"},
				BootStartReported: true,
			},
		},
	},
	{
		ID:       "tactical-rmm",
		Name:     "Tactical RMM Agent",
		Vendor:   "AmidaWare",
		Category: CategoryRMM,
		// Tactical also installs MeshCentral's Mesh Agent. It is not a
		// signal: Mesh Agent runs standalone too, and can be renamed.
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				Packages:          []string{"Tactical RMM Agent"},
				Services:          []string{"tacticalrmm"},
				BootStartReported: true,
			},
			edr.PlatformLinux: {
				// Installed by a script, not a distribution package.
				Paths:             []string{"/usr/local/bin/tacticalagent"},
				Services:          []string{"tacticalagent"},
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				Paths:    []string{"/opt/tacticalagent"},
				Services: []string{"tacticalagent"},
			},
		},
	},

	// --- remote access ---
	{
		ID:       "connectwise-screenconnect",
		Name:     "ConnectWise ScreenConnect Client",
		Vendor:   "ConnectWise",
		Category: CategoryRemoteAccess,
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed: "ScreenConnect Client (<instance>)", where the
				// instance is a hex string naming the server the client
				// reports to. The service carries the same name.
				PackagePattern:    screenConnectWindows,
				ServicePattern:    screenConnectWindows,
				BootStartReported: true,
			},
			edr.PlatformLinux: {
				PackagePattern:    screenConnectUnix,
				ServicePattern:    screenConnectUnix,
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				// Observed: the app is "connectwisecontrol-<instance>".
				PackagePattern: screenConnectUnix,
				ServicePattern: screenConnectUnix,
			},
		},
	},

	// --- patch management ---
	{
		ID:       "automox",
		Name:     "Automox Agent",
		Vendor:   "Automox",
		Category: CategoryPatchManagement,
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				Packages:          []string{"Automox Agent"},
				Services:          []string{"amagent"},
				BootStartReported: true,
			},
			edr.PlatformLinux: {
				Packages:          []string{"amagent"},
				Services:          []string{"amagent"},
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				Paths:    []string{"/Library/Application Support/Automox", "/usr/local/bin/amagent"},
				Services: []string{"com.automox.agent"},
			},
		},
	},

	// --- client management ---
	{
		ID:       "baramundi",
		Name:     "baramundi Management Agent",
		Vendor:   "baramundi software",
		Category: CategoryClientManagement,
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed.
				Packages:          []string{"baramundi Management Agent"},
				Services:          []string{"BARAAGNT"},
				BootStartReported: true,
			},
		},
	},
	{
		ID:       "matrix42",
		Name:     "Matrix42 UEM Agent",
		Vendor:   "Matrix42",
		Category: CategoryClientManagement,
		// The Empirum Agent the UEM Agent replaced is the same product here,
		// so a check for Matrix42 management holds across the migration.
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed, every name the pattern lists.
				PackagePattern:    matrix42Packages,
				ServicePattern:    matrix42Services,
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				Paths:          []string{"/Library/Application Support/matrix42"},
				ServicePattern: matrix42Launchd,
			},
		},
	},
	{
		ID:       "microsoft-configmgr",
		Name:     "Microsoft Configuration Manager Client",
		Vendor:   "Microsoft",
		Category: CategoryClientManagement,
		// Formerly System Center Configuration Manager (SCCM) and Microsoft
		// Endpoint Configuration Manager (MECM). Microsoft removed the macOS
		// and Linux clients.
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed, the current and both earlier names of the client.
				// The admin console registers "... Console" and does not
				// match.
				Packages: []string{
					"Microsoft Configuration Manager",
					"Endpoint Configuration Manager",
					"System Center Configuration Manager",
				},
				// The SMS Agent Host.
				Services:          []string{"CcmExec"},
				BootStartReported: true,
			},
		},
	},
	{
		ID:       "opsi",
		Name:     "opsi Client Agent",
		Vendor:   "uib",
		Category: CategoryClientManagement,
		Platforms: map[string]edr.Signature{
			edr.PlatformWindows: {
				// Observed.
				Packages:          []string{"opsi-client-agent"},
				Services:          []string{"opsiclientd"},
				BootStartReported: true,
			},
			edr.PlatformLinux: {
				// Installed by the opsi server, not a distribution package.
				Paths:             []string{"/usr/lib/opsi-client-agent"},
				Services:          []string{"opsiclientd"},
				BootStartReported: true,
			},
			edr.PlatformMacOS: {
				Paths:    []string{"/usr/local/lib/opsi-client-agent"},
				Services: []string{"org.opsi.opsiclientd"},
			},
		},
	},
}
