// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package rmm

import (
	"fmt"
	"regexp"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/edr"
)

// Every literal in this file is written out by hand. Nothing is read back out
// of Catalog, so a catalog entry edited to the wrong package or service name
// fails these tests instead of moving the expectation with it.
//
// Each case says where its values come from:
//
//   - Observed: the package name and version are what mql's packages
//     resource reported for the agent on a real managed host, as recorded in
//     Mondoo's product catalog. The rest of the inventory is synthetic.
//   - Synthetic: assembled from the names the vendor's documentation or
//     source code gives; no target showed this.

func pkg(name, version string) edr.Package {
	return edr.Package{Name: name, Version: version}
}

func svc(name string, running, enabled bool) edr.Service {
	return edr.Service{Name: name, Installed: true, Running: running, Enabled: enabled}
}

func proc(executable, state string) edr.Process {
	return edr.Process{Executable: executable, State: state}
}

func paths(present ...string) func(string) bool {
	return func(p string) bool {
		return slices.Contains(present, p)
	}
}

func byID(detections []edr.Detection) map[string]edr.Detection {
	out := make(map[string]edr.Detection, len(detections))
	for _, d := range detections {
		out[d.Product.ID] = d
	}
	return out
}

func detectOne(t *testing.T, inv edr.Inventory, id string) edr.Detection {
	t.Helper()
	d, ok := byID(Detect(inv))[id]
	require.True(t, ok, "expected %q to be detected", id)
	return d
}

type healthyCase struct {
	name    string
	id      string
	inv     edr.Inventory
	version string
}

func healthyCases() []healthyCase {
	return []healthyCase{
		// --- Atera ---
		{
			// Observed: AteraAgent 2.5.19.0.
			name:    "Atera on Windows",
			id:      "atera",
			version: "2.5.19.0",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("AteraAgent", "2.5.19.0")},
				Services: []edr.Service{svc("AteraAgent", true, true)},
			},
		},
		{
			// Synthetic: Atera's Linux uninstall article; no target showed this.
			name: "Atera on Linux",
			id:   "atera",
			inv: edr.Inventory{
				Platform:   edr.PlatformLinux,
				Services:   []edr.Service{svc("AteraAgent.service", true, true)},
				PathExists: paths("/usr/lib/atera-agent"),
			},
		},
		{
			// Synthetic: Atera's macOS uninstall article, agent v2 label; no target showed this.
			name:    "Atera on macOS",
			id:      "atera",
			version: "2.0.0",
			inv: edr.Inventory{
				Platform: edr.PlatformMacOS,
				Packages: []edr.Package{pkg("AteraAgent", "2.0.0")},
				Services: []edr.Service{svc("com.atera.agent", true, true)},
			},
		},
		{
			// Synthetic: agent v1 label from the same article; no target showed this.
			name: "Atera v1 on macOS",
			id:   "atera",
			inv: edr.Inventory{
				Platform:   edr.PlatformMacOS,
				Services:   []edr.Service{svc("com.atera.ateraagent", true, true)},
				PathExists: paths("/Library/Application Support/com.atera.ateraagent"),
			},
		},

		// --- ConnectWise Automate ---
		{
			// Synthetic: names from the LabTech PowerShell module; no target showed this.
			name:    "ConnectWise Automate on Windows",
			id:      "connectwise-automate",
			version: "2023.10.0.123",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("ConnectWise Automate Remote Agent", "2023.10.0.123")},
				Services: []edr.Service{
					svc("LTService", true, true),
					svc("LTSvcMon", true, true),
				},
			},
		},
		{
			// Synthetic: a pre-rename agent keeps the LabTech name; no target showed this.
			name: "ConnectWise Automate on Windows, LabTech name",
			id:   "connectwise-automate",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("LabTech® Software Remote Agent", "")},
				Services: []edr.Service{
					svc("LTService", true, true),
					svc("LTSvcMon", true, true),
				},
			},
		},
		{
			// Synthetic: the ltechagent install script and unit; no target showed this.
			name: "ConnectWise Automate on Linux",
			id:   "connectwise-automate",
			inv: edr.Inventory{
				Platform:   edr.PlatformLinux,
				Services:   []edr.Service{svc("ltechagent", true, true)},
				PathExists: paths("/usr/local/ltechagent"),
			},
		},
		{
			// Synthetic: public uninstall script labels; no target showed this.
			name: "ConnectWise Automate on macOS",
			id:   "connectwise-automate",
			inv: edr.Inventory{
				Platform:   edr.PlatformMacOS,
				Services:   []edr.Service{svc("com.labtechsoftware.ltechagent", true, true)},
				PathExists: paths("/usr/local/ltechagent"),
			},
		},

		// --- Datto RMM ---
		{
			// Observed: Datto RMM 4.4.11965.11965.
			name:    "Datto RMM on Windows",
			id:      "datto-rmm",
			version: "4.4.11965.11965",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("Datto RMM", "4.4.11965.11965")},
				Services: []edr.Service{svc("CagService", true, true)},
			},
		},
		{
			// Observed: CentraStage 15.1.1.12357, the name older agents keep.
			name:    "Datto RMM on Windows, CentraStage name",
			id:      "datto-rmm",
			version: "15.1.1.12357",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("CentraStage", "15.1.1.12357")},
				Services: []edr.Service{svc("CagService", true, true)},
			},
		},
		{
			// Synthetic: Datto's Linux install and cloning articles; no target showed this.
			name: "Datto RMM on Linux",
			id:   "datto-rmm",
			inv: edr.Inventory{
				Platform:   edr.PlatformLinux,
				Services:   []edr.Service{svc("cag", true, true)},
				PathExists: paths("/opt/CentraStage"),
			},
		},
		{
			// Observed: AEM Agent 4.4. The label is from Datto's cloning article.
			name:    "Datto RMM on macOS",
			id:      "datto-rmm",
			version: "4.4",
			inv: edr.Inventory{
				Platform: edr.PlatformMacOS,
				Packages: []edr.Package{pkg("AEM Agent", "4.4")},
				Services: []edr.Service{svc("com.centrastage.cag", true, true)},
			},
		},

		// --- Kaseya VSA ---
		{
			// Observed: the package name shape and 9.5.0.52. The service name follows
			// Kaseya's documented KA<GUID> form; no target showed it.
			name:    "Kaseya VSA on Windows",
			id:      "kaseya-vsa",
			version: "9.5.0.52",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("Kaseya Agent (pc1.workstations.example - vsa.example.com)", "9.5.0.52")},
				Services: []edr.Service{
					svc("KAKSAASC01234567890123", true, true),
					// The endpoint helper is not required.
					svc("KAENDKSAASC01234567890123", false, false),
				},
			},
		},
		{
			// Synthetic: Kaseya's Linux agent article; no target showed this.
			name: "Kaseya VSA on Linux",
			id:   "kaseya-vsa",
			inv: edr.Inventory{
				Platform:   edr.PlatformLinux,
				Processes:  []edr.Process{proc("/opt/Kaseya/KSAASC01234567890123/bin/AgentMon", "sleeping")},
				PathExists: paths("/opt/Kaseya"),
			},
		},

		// --- Kaseya VSA X ---
		{
			// Observed: VSA X 10.7.1.
			name:    "Kaseya VSA X on Windows",
			id:      "kaseya-vsa-x",
			version: "10.7.1",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("VSA X", "10.7.1")},
				Services: []edr.Service{svc("VSAX", true, true)},
			},
		},
		{
			// Synthetic: Kaseya's VSA 10 macOS deployment article; no target showed this.
			name: "Kaseya VSA X on macOS",
			id:   "kaseya-vsa-x",
			inv: edr.Inventory{
				Platform:   edr.PlatformMacOS,
				Services:   []edr.Service{svc("com.kaseya.VSAHelper", true, true)},
				PathExists: paths("/Library/Application Support/VSA"),
			},
		},

		// --- N-able N-central ---
		{
			// Observed: Windows Agent 2026.3.10010. The services are the ones
			// N-able's own deployment script queries.
			name:    "N-able N-central on Windows",
			id:      "n-able-n-central",
			version: "2026.3.10010",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("Windows Agent", "2026.3.10010")},
				Services: []edr.Service{
					svc("Windows Agent Service", true, true),
					svc("Windows Agent Maintenance Service", true, true),
				},
			},
		},
		{
			// Synthetic: N-able's macOS uninstall tool; no target showed this.
			name: "N-able N-central on macOS",
			id:   "n-able-n-central",
			inv: edr.Inventory{
				Platform:   edr.PlatformMacOS,
				Services:   []edr.Service{svc("com.n-central.agent", true, true)},
				PathExists: paths("/Library/N-central Agent"),
			},
		},

		// --- N-able N-sight ---
		{
			// Observed: Advanced Monitoring Agent, reported without a version.
			name: "N-able N-sight on Windows",
			id:   "n-able-n-sight",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("Advanced Monitoring Agent", "")},
				Services: []edr.Service{svc("Advanced Monitoring Agent", true, true)},
			},
		},
		{
			// Synthetic: N-able's Linux agent install article; no target showed this.
			name:    "N-able N-sight on Linux",
			id:      "n-able-n-sight",
			version: "2.2.0",
			inv: edr.Inventory{
				Platform: edr.PlatformLinux,
				Packages: []edr.Package{pkg("rmmagent", "2.2.0")},
				Services: []edr.Service{svc("rmmagent.service", true, true)},
			},
		},
		{
			// Synthetic: N-able's macOS uninstall article; no target showed this.
			name: "N-able N-sight on macOS",
			id:   "n-able-n-sight",
			inv: edr.Inventory{
				Platform:   edr.PlatformMacOS,
				Processes:  []edr.Process{proc("/usr/local/rmmagent/rmmagentd", "running")},
				PathExists: paths("/usr/local/rmmagent"),
			},
		},

		// --- NinjaOne ---
		{
			// Observed: NinjaRMMAgent 14.0.8536.
			name:    "NinjaOne on Windows",
			id:      "ninjaone",
			version: "14.0.8536",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("NinjaRMMAgent", "14.0.8536")},
				Services: []edr.Service{svc("NinjaRMMAgent", true, true)},
			},
		},
		{
			// Synthetic: NinjaOne's Linux install article; no target showed this.
			name: "NinjaOne on Linux",
			id:   "ninjaone",
			inv: edr.Inventory{
				Platform:   edr.PlatformLinux,
				Services:   []edr.Service{svc("ninjarmm-agent.service", true, true)},
				PathExists: paths("/opt/NinjaRMMAgent"),
			},
		},
		{
			// Synthetic: NinjaOne's agent removal guide; no target showed this.
			name: "NinjaOne on macOS",
			id:   "ninjaone",
			inv: edr.Inventory{
				Platform: edr.PlatformMacOS,
				Services: []edr.Service{
					svc("com.ninjarmm.agentd", true, true),
					svc("com.ninjarmm.trayicon", true, true),
				},
				PathExists: paths("/Applications/NinjaRMMAgent"),
			},
		},

		// --- Syncro ---
		{
			// Observed: Syncro 1.0.203.18518.
			name:    "Syncro on Windows",
			id:      "syncro",
			version: "1.0.203.18518",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("Syncro", "1.0.203.18518")},
				Services: []edr.Service{
					svc("Syncro", true, true),
					svc("SyncroLive", true, true),
				},
			},
		},
		{
			// Synthetic: Syncro's Linux agent article; no target showed this.
			name: "Syncro on Linux",
			id:   "syncro",
			inv: edr.Inventory{
				Platform: edr.PlatformLinux,
				Services: []edr.Service{svc("syncro", true, true)},
			},
		},

		// --- Tactical RMM ---
		{
			// Measured: Windows Server 2022, tacticalagent-v2.12.0-windows-amd64.exe,
			// 2026-11-06: package "Tactical RMM Agent" 2.12.0. The agent registers
			// its service only when it enrolls with a server, so the service name
			// is from rmmagent's agent.go.
			name:    "Tactical RMM on Windows",
			id:      "tactical-rmm",
			version: "2.12.0",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("Tactical RMM Agent", "2.12.0")},
				Services: []edr.Service{
					svc("tacticalrmm", true, true),
					svc("Mesh Agent", true, true),
				},
			},
		},
		{
			// Synthetic: Tactical's agent_linux.sh; no target showed this.
			name: "Tactical RMM on Linux",
			id:   "tactical-rmm",
			inv: edr.Inventory{
				Platform:   edr.PlatformLinux,
				Services:   []edr.Service{svc("tacticalagent.service", true, true)},
				PathExists: paths("/usr/local/bin/tacticalagent"),
			},
		},
		{
			// Synthetic: rmmagent's install.go; no target showed this.
			name: "Tactical RMM on macOS",
			id:   "tactical-rmm",
			inv: edr.Inventory{
				Platform:   edr.PlatformMacOS,
				Services:   []edr.Service{svc("tacticalagent", true, true)},
				PathExists: paths("/opt/tacticalagent"),
			},
		},

		// --- ConnectWise ScreenConnect ---
		{
			// Observed: ScreenConnect Client (<instance>) 26.1.25.9592. The
			// instance names the server the client reports to, so a
			// placeholder stands in for the one seen.
			name:    "ScreenConnect on Windows",
			id:      "connectwise-screenconnect",
			version: "26.1.25.9592",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("ScreenConnect Client (1a2b3c4d5e6f7a8b)", "26.1.25.9592")},
				Services: []edr.Service{svc("ScreenConnect Client (1a2b3c4d5e6f7a8b)", true, true)},
			},
		},
		{
			// Synthetic: the connectwisecontrol-<id> package and init script; no target showed this.
			name:    "ScreenConnect on Linux",
			id:      "connectwise-screenconnect",
			version: "26.1.25.9592",
			inv: edr.Inventory{
				Platform: edr.PlatformLinux,
				Packages: []edr.Package{pkg("connectwisecontrol-1a2b3c4d5e6f7a8b", "26.1.25.9592")},
				Services: []edr.Service{svc("connectwisecontrol-1a2b3c4d5e6f7a8b.service", true, true)},
			},
		},
		{
			// Observed: connectwisecontrol-<instance> 26.6, with a placeholder
			// instance as on Windows. The labels are from public uninstall
			// scripts.
			name:    "ScreenConnect on macOS",
			id:      "connectwise-screenconnect",
			version: "26.6",
			inv: edr.Inventory{
				Platform: edr.PlatformMacOS,
				Packages: []edr.Package{pkg("connectwisecontrol-8b7a6f5e4d3c2b1a", "26.6")},
				Services: []edr.Service{
					svc("connectwisecontrol-8b7a6f5e4d3c2b1a", true, true),
					svc("connectwisecontrol-8b7a6f5e4d3c2b1a-onlogin", true, true),
				},
			},
		},

		// --- Automox ---
		{
			// Measured: Windows Server 2022, Automox_Installer-latest.msi, 2026-11-06:
			// package "Automox Agent" 2.7.26, services amagent and watchdog.
			name:    "Automox on Windows",
			id:      "automox",
			version: "2.7.26",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("Automox Agent", "2.7.26")},
				Services: []edr.Service{
					svc("amagent", true, true),
					svc("watchdog", true, true),
				},
			},
		},
		{
			// Synthetic: Automox's file location article; no target showed this.
			name:    "Automox on Linux",
			id:      "automox",
			version: "2.3.34",
			inv: edr.Inventory{
				Platform: edr.PlatformLinux,
				Packages: []edr.Package{pkg("amagent", "2.3.34")},
				Services: []edr.Service{svc("amagent", true, true)},
			},
		},
		{
			// Synthetic: Automox's removal article; no target showed this.
			name: "Automox on macOS",
			id:   "automox",
			inv: edr.Inventory{
				Platform:   edr.PlatformMacOS,
				Services:   []edr.Service{svc("com.automox.agent", true, true)},
				PathExists: paths("/usr/local/bin/amagent"),
			},
		},

		// --- baramundi ---
		{
			// Observed: baramundi Management Agent 25.2.130.0.
			name:    "baramundi on Windows",
			id:      "baramundi",
			version: "25.2.130.0",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("baramundi Management Agent", "25.2.130.0")},
				Services: []edr.Service{svc("BARAAGNT", true, true)},
			},
		},

		// --- Matrix42 ---
		{
			// Observed: UEM Agent Windows (64 bit) 2211.1.2.0.
			name:    "Matrix42 UEM Agent on Windows",
			id:      "matrix42",
			version: "2211.1.2.0",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("UEM Agent Windows (64 bit)", "2211.1.2.0")},
				Services: []edr.Service{svc("Matrix42UAF", true, true)},
			},
		},
		{
			// Observed: Matrix42 UEM Agent Windows 2503.2.2, the name carrying the version.
			name: "Matrix42 UEM Agent on Windows, versioned name",
			id:   "matrix42",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("Matrix42 UEM Agent Windows 2503.2.2", "")},
				Services: []edr.Service{svc("Matrix42UAF", true, true)},
			},
		},
		{
			// Observed: Empirum Agent 19.0. The service name is from public
			// Empirum preparation scripts.
			name:    "Matrix42 Empirum Agent on Windows",
			id:      "matrix42",
			version: "19.0",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("Empirum Agent 19.0", "19.0")},
				Services: []edr.Service{svc("ERIS", true, true)},
			},
		},
		{
			// Synthetic: Matrix42's macOS uninstall script; no target showed this.
			name: "Matrix42 on macOS",
			id:   "matrix42",
			inv: edr.Inventory{
				Platform:   edr.PlatformMacOS,
				Services:   []edr.Service{svc("com.Matrix42.EmpirumD", true, true)},
				PathExists: paths("/Library/Application Support/matrix42"),
			},
		},

		// --- Microsoft Configuration Manager ---
		{
			// Observed: Microsoft Configuration Manager 5.0.9135.1001.
			name:    "Configuration Manager on Windows",
			id:      "microsoft-configmgr",
			version: "5.0.9135.1001",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("Microsoft Configuration Manager", "5.0.9135.1001")},
				Services: []edr.Service{svc("CcmExec", true, true)},
			},
		},
		{
			// Observed: System Center Configuration Manager 5.00.8968.1014, an older client.
			name:    "Configuration Manager on Windows, SCCM name",
			id:      "microsoft-configmgr",
			version: "5.00.8968.1014",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("System Center Configuration Manager", "5.00.8968.1014")},
				Services: []edr.Service{svc("CcmExec", true, true)},
			},
		},

		// --- opsi ---
		{
			// Observed: opsi-client-agent 4.3.22.8-1.
			name:    "opsi on Windows",
			id:      "opsi",
			version: "4.3.22.8-1",
			inv: edr.Inventory{
				Platform: edr.PlatformWindows,
				Packages: []edr.Package{pkg("opsi-client-agent", "4.3.22.8-1")},
				Services: []edr.Service{svc("opsiclientd", true, true)},
			},
		},
		{
			// Synthetic: opsiclientd's setup.py and the opsi Linux client docs; no target showed this.
			name: "opsi on Linux",
			id:   "opsi",
			inv: edr.Inventory{
				Platform:   edr.PlatformLinux,
				Services:   []edr.Service{svc("opsiclientd.service", true, true)},
				PathExists: paths("/usr/lib/opsi-client-agent"),
			},
		},
		{
			// Synthetic: opsiclientd's setup.py and the opsi macOS client docs; no target showed this.
			name: "opsi on macOS",
			id:   "opsi",
			inv: edr.Inventory{
				Platform:   edr.PlatformMacOS,
				Services:   []edr.Service{svc("org.opsi.opsiclientd", true, true)},
				PathExists: paths("/usr/local/lib/opsi-client-agent"),
			},
		},
	}
}

// --- every product, on every platform it ships on, fully healthy ---

func TestDetectHealthy(t *testing.T) {
	for _, tc := range healthyCases() {
		t.Run(tc.name, func(t *testing.T) {
			found := Detect(tc.inv)
			require.Len(t, found, 1, "exactly one agent is installed")
			d := found[0]
			assert.Equal(t, tc.id, d.Product.ID)
			assert.True(t, d.Running, "running")
			assert.True(t, d.Healthy, "healthy")
			assert.Equal(t, tc.version, d.Version)
		})
	}
}

// TestEveryCatalogEntryHasAHealthyCase fails when a product or platform is
// added to the catalog without a test showing it can be recognized at all.
func TestEveryCatalogEntryHasAHealthyCase(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range healthyCases() {
		covered[tc.id+"/"+tc.inv.Platform] = true
	}
	for _, p := range Catalog {
		for platform := range p.Platforms {
			assert.True(t, covered[p.ID+"/"+platform], "no healthy case for %s on %s", p.ID, platform)
		}
	}
}

// --- running, enabled and healthy ---

func TestStoppedAgentIsInstalledButNotHealthy(t *testing.T) {
	d := detectOne(t, edr.Inventory{
		Platform: edr.PlatformWindows,
		Packages: []edr.Package{pkg("NinjaRMMAgent", "14.0.8536")},
		Services: []edr.Service{svc("NinjaRMMAgent", false, true)},
	}, "ninjaone")
	assert.False(t, d.Running)
	assert.False(t, d.Healthy)
}

func TestDisabledAgentIsRunningButNotHealthy(t *testing.T) {
	d := detectOne(t, edr.Inventory{
		Platform: edr.PlatformWindows,
		Packages: []edr.Package{pkg("AteraAgent", "2.5.19.0")},
		Services: []edr.Service{svc("AteraAgent", true, false)},
	}, "atera")
	assert.True(t, d.Running)
	assert.True(t, d.EnabledReported)
	assert.False(t, d.Enabled)
	assert.False(t, d.Healthy)
}

func TestMacOSAgentsDoNotReportBootStart(t *testing.T) {
	// launchd reports every loaded label as enabled, so a macOS agent's
	// enabled field must stay null rather than always reading true.
	d := detectOne(t, edr.Inventory{
		Platform:   edr.PlatformMacOS,
		Services:   []edr.Service{svc("com.automox.agent", true, false)},
		PathExists: paths("/usr/local/bin/amagent"),
	}, "automox")
	assert.False(t, d.EnabledReported)
	assert.True(t, d.Healthy, "a running macOS agent is healthy whatever launchd says about boot")
}

func TestEveryRequiredServiceMustRun(t *testing.T) {
	// N-central needs its maintenance service as well as the agent service.
	d := detectOne(t, edr.Inventory{
		Platform: edr.PlatformWindows,
		Packages: []edr.Package{pkg("Windows Agent", "2026.3.10010")},
		Services: []edr.Service{svc("Windows Agent Service", true, true)},
	}, "n-able-n-central")
	assert.False(t, d.Running, "a missing maintenance service cannot be proven to run")
	assert.False(t, d.Healthy)
}

func TestOptionalServicesAreNotRequired(t *testing.T) {
	// SyncroLive is stopped, which says nothing about the agent itself.
	d := detectOne(t, edr.Inventory{
		Platform: edr.PlatformWindows,
		Packages: []edr.Package{pkg("Syncro", "1.0.203.18518")},
		Services: []edr.Service{
			svc("Syncro", true, true),
			svc("SyncroLive", false, false),
		},
	}, "syncro")
	assert.True(t, d.Healthy)
}

func TestTacticalRMMInstalledButNotEnrolled(t *testing.T) {
	// Measured: Windows Server 2022, tacticalagent-v2.12.0-windows-amd64.exe,
	// 2026-11-06. The installer lays down the package; the tacticalrmm service
	// only appears once the agent enrolls with a server, which this host never
	// did. The agent is installed and cannot be running.
	d := detectOne(t, edr.Inventory{
		Platform: edr.PlatformWindows,
		Packages: []edr.Package{pkg("Tactical RMM Agent", "2.12.0")},
	}, "tactical-rmm")
	assert.Equal(t, []string{edr.SignalPackage}, d.DetectedBy)
	assert.Equal(t, "2.12.0", d.Version)
	assert.False(t, d.Running)
	assert.False(t, d.Healthy)
}

func TestAgentRecognizedByPathWithNoServiceIsNotRunning(t *testing.T) {
	d := detectOne(t, edr.Inventory{
		Platform:   edr.PlatformLinux,
		PathExists: paths("/usr/lib/opsi-client-agent"),
	}, "opsi")
	assert.Equal(t, []string{edr.SignalPath}, d.DetectedBy)
	assert.False(t, d.Running)
	assert.False(t, d.Healthy)
}

func TestZombieProcessDoesNotProveRunning(t *testing.T) {
	d := detectOne(t, edr.Inventory{
		Platform:   edr.PlatformLinux,
		Processes:  []edr.Process{proc("/opt/Kaseya/KSAASC01234567890123/bin/AgentMon", "zombie")},
		PathExists: paths("/opt/Kaseya"),
	}, "kaseya-vsa")
	assert.False(t, d.Running)
	assert.False(t, d.EnabledReported, "an agent recognized by its process reports no boot-start setting")
}

// --- names that look like an agent but are not ---

func TestLookalikeWindowsNamesAreNotAgents(t *testing.T) {
	// Every name here is installed on real hosts beside, or instead of, an
	// agent in the catalog. None of them is the agent.
	inv := edr.Inventory{
		Platform: edr.PlatformWindows,
		Packages: []edr.Package{
			// Synthetic: the ConfigMgr admin console, on administrator
			// workstations rather than managed endpoints.
			pkg("Microsoft Configuration Manager Console", "5.2509.1036.1000"),
			// Synthetic: the Empirum suite record and the UEM Agent's
			// maintenance service, neither of which is the agent.
			pkg("Matrix42 Empirum", "25.4.0"),
			pkg("Matrix42 Maintenance Service", "2503.2.2"),
			// Synthetic: Datto's backup agent, not Datto RMM, and not
			// N-central despite the shared suffix.
			pkg("Datto Windows Agent", "3.0.0"),
			// Synthetic: NinjaOne's remote access tool, a separate install.
			pkg("Ninja Remote", "5.0.0"),
			// Synthetic: MeshCentral's agent runs standalone too.
			pkg("Mesh Agent", ""),
			// Synthetic: a name that merely starts like an agent's.
			pkg("Syncro Desktop Helper", "1.0"),
			pkg("Kaseya Agent Endpoint", "9.5"),
		},
		Services: []edr.Service{
			svc("Mesh Agent", true, true),
			svc("SMS Agent Host", true, true),
			// Kaseya's endpoint helper alone is not the agent.
			svc("KAENDKSAASC01234567890123", true, true),
			svc("Windows Agent", true, true),
		},
	}
	assert.Empty(t, Detect(inv))
}

func TestScreenConnectLoginAgentsDoNotStandInForTheDaemon(t *testing.T) {
	// Synthetic: the per-user LaunchAgents run while the system daemon is
	// unloaded; no target showed this.
	d := detectOne(t, edr.Inventory{
		Platform: edr.PlatformMacOS,
		Packages: []edr.Package{pkg("connectwisecontrol-8b7a6f5e4d3c2b1a", "26.6")},
		Services: []edr.Service{
			svc("connectwisecontrol-8b7a6f5e4d3c2b1a-onlogin", true, true),
			svc("connectwisecontrol-8b7a6f5e4d3c2b1a-prelogin", true, true),
		},
	}, "connectwise-screenconnect")
	assert.False(t, d.Running)
}

func TestScreenConnectReportsEveryInstance(t *testing.T) {
	// Synthetic: two clients for two different server instances, the shape an
	// unapproved instance takes beside the approved one.
	inv := edr.Inventory{
		Platform: edr.PlatformWindows,
		Packages: []edr.Package{
			pkg("ScreenConnect Client (1a2b3c4d5e6f7a8b)", "26.1.25.9592"),
			pkg("ScreenConnect Client (0123456789abcdef)", "24.3.7.8999"),
		},
		Services: []edr.Service{
			svc("ScreenConnect Client (1a2b3c4d5e6f7a8b)", true, true),
			svc("ScreenConnect Client (0123456789abcdef)", false, true),
		},
	}
	d := detectOne(t, inv, "connectwise-screenconnect")
	assert.Equal(t, []int{0, 1}, d.PackageIdx)
	assert.Equal(t, []int{0, 1}, d.ServiceIdx)
	assert.True(t, d.Running, "one running client is enough")
}

func TestKaseyaSecondAgentIsRecognized(t *testing.T) {
	// Synthetic: Kaseya documents "Kaseya Agent #2 (...)" for a second
	// agent on the same machine; no target showed this.
	d := detectOne(t, edr.Inventory{
		Platform: edr.PlatformWindows,
		Packages: []edr.Package{pkg("Kaseya Agent #2 (pc1.workstations.example - vsa2.example.com)", "9.5.0.52")},
		Services: []edr.Service{svc("KAKSAASC01234567890123", true, true)},
	}, "kaseya-vsa")
	assert.True(t, d.Healthy)
}

func TestWindowsServiceNamesAreNotCaseSensitive(t *testing.T) {
	d := detectOne(t, edr.Inventory{
		Platform: edr.PlatformWindows,
		Services: []edr.Service{svc("ccmexec", true, true)},
	}, "microsoft-configmgr")
	assert.True(t, d.Running)
}

func TestLinuxServiceNamesAreCaseSensitive(t *testing.T) {
	// The unit is AteraAgent.service; a unit named ateraagent is not it.
	d := detectOne(t, edr.Inventory{
		Platform:   edr.PlatformLinux,
		Services:   []edr.Service{svc("ateraagent", true, true)},
		PathExists: paths("/usr/lib/atera-agent"),
	}, "atera")
	assert.False(t, d.Running)
}

// --- platforms and other catalogs ---

func TestSignalsAreOnlyReadOnTheirOwnPlatform(t *testing.T) {
	// CcmExec and BARAAGNT are Windows services. The same names on Linux
	// prove nothing, because neither agent ships for Linux.
	assert.Empty(t, Detect(edr.Inventory{
		Platform: edr.PlatformLinux,
		Services: []edr.Service{svc("CcmExec", true, true), svc("BARAAGNT", true, true)},
	}))
}

func TestEndpointSecurityAgentsAreNotManagementAgents(t *testing.T) {
	assert.Empty(t, Detect(edr.Inventory{
		Platform: edr.PlatformWindows,
		Packages: []edr.Package{pkg("CrowdStrike Sensor Platform", "7.20")},
		Services: []edr.Service{svc("CSFalconService", true, true), svc("WinDefend", true, true)},
	}))
}

func TestAssetWithNoAgent(t *testing.T) {
	assert.Empty(t, Detect(edr.Inventory{
		Platform:   edr.PlatformLinux,
		Packages:   []edr.Package{pkg("openssh-server", "9.6p1")},
		Services:   []edr.Service{svc("ssh", true, true)},
		PathExists: paths("/opt"),
	}))
}

func TestUnknownPlatformDetectsNothing(t *testing.T) {
	assert.Empty(t, Detect(edr.Inventory{
		Platform:   "freebsd",
		Services:   []edr.Service{svc("tacticalagent", true, true)},
		PathExists: paths("/opt/tacticalagent"),
	}))
}

func TestSeveralAgentsOnOneAsset(t *testing.T) {
	// Synthetic: an MSP's RMM beside a ScreenConnect client and the
	// customer's own ConfigMgr client.
	found := byID(Detect(edr.Inventory{
		Platform: edr.PlatformWindows,
		Packages: []edr.Package{
			pkg("Datto RMM", "4.4.11965.11965"),
			pkg("ScreenConnect Client (1a2b3c4d5e6f7a8b)", "26.1.25.9592"),
			pkg("Microsoft Configuration Manager", "5.0.9135.1001"),
		},
		Services: []edr.Service{
			svc("CagService", true, true),
			svc("ScreenConnect Client (1a2b3c4d5e6f7a8b)", true, true),
			svc("CcmExec", true, true),
		},
	}))
	assert.Len(t, found, 3)
	assert.Contains(t, found, "datto-rmm")
	assert.Contains(t, found, "connectwise-screenconnect")
	assert.Contains(t, found, "microsoft-configmgr")
}

// --- the catalog itself ---

var idShape = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func TestCatalogIsWellFormed(t *testing.T) {
	categories := []string{"rmm", "remoteAccess", "patchManagement", "clientManagement"}
	seen := map[string]bool{}

	for _, p := range Catalog {
		t.Run(p.ID, func(t *testing.T) {
			assert.Regexp(t, idShape, p.ID)
			assert.False(t, seen[p.ID], "duplicate id")
			seen[p.ID] = true
			assert.NotEmpty(t, p.Name)
			assert.NotEmpty(t, p.Vendor)
			assert.Contains(t, categories, p.Category)
			require.NotEmpty(t, p.Platforms)

			for platform, sig := range p.Platforms {
				where := fmt.Sprintf("%s on %s", p.ID, platform)
				assert.Contains(t, []string{edr.PlatformWindows, edr.PlatformLinux, edr.PlatformMacOS}, platform)

				// A platform is only listed when the agent can be shown
				// both installed and running there.
				installSignal := len(sig.Packages) > 0 || sig.PackagePattern != nil || len(sig.Paths) > 0 ||
					len(sig.Services) > 0 || sig.ServicePattern != nil
				assert.True(t, installSignal, "%s has no install signal", where)
				switch sig.RunVia {
				case edr.RunViaProcesses:
					assert.NotNil(t, sig.ProcessPattern, "%s runs via processes but has no pattern", where)
				case edr.RunViaServices:
					assert.True(t, len(sig.Services) > 0 || sig.ServicePattern != nil, "%s has no running signal", where)
				default:
					t.Errorf("%s uses an unsupported run signal", where)
				}

				// launchd has no distinct boot-start setting, and every
				// Windows and Linux service manager in the catalog does.
				if platform == edr.PlatformMacOS || sig.RunVia == edr.RunViaProcesses {
					assert.False(t, sig.BootStartReported, "%s cannot report boot start", where)
				} else {
					assert.True(t, sig.BootStartReported, "%s should report boot start", where)
				}
			}
		})
	}
}
