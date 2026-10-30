// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// windowsReleases are the releases these fixtures were captured from. Every
// test below runs against all of them, so a property that only holds on the
// release someone happened to develop against fails here.
var windowsReleases = []string{"2016", "2019", "2022", "2025"}

func fixtureExists(name string) bool {
	_, err := os.Stat(filepath.Join("testdata", name))
	return err == nil
}

// TestEventLogChannelFixtures pins the four channel shapes that decide whether
// windows.eventlog reports a real size or an invented one.
//
// The sizes below are the manifest defaults, and they are what
// Get-WinEvent -ListLog reports on each host. They are identical across all
// four releases, which is worth having written down: it is the kind of thing
// that is assumed rather than checked, and a release that changed one would
// otherwise be found by a customer.
func TestEventLogChannelFixtures(t *testing.T) {
	for _, rel := range windowsReleases {
		t.Run(rel, func(t *testing.T) {
			t.Run("classic", func(t *testing.T) {
				c, err := ParseEventLogChannel(openFixture(t, "eventlog-classic-"+rel+".json"))
				require.NoError(t, err)
				assert.Equal(t, "Security", c.LogName)
				assert.True(t, c.IsClassicLog)
				assert.True(t, c.IsEnabled)
				assert.EqualValues(t, 20971520, c.MaximumSizeInBytes)
				// The stored path carries %SystemRoot% unexpanded, and the
				// expansion happens in Go so it works in ConstrainedLanguage
				// mode.
				assert.Equal(t, `C:\Windows\System32\Winevt\Logs\Security.evtx`, c.ExpandedLogFilePath())
			})

			t.Run("modern", func(t *testing.T) {
				c, err := ParseEventLogChannel(openFixture(t, "eventlog-modern-"+rel+".json"))
				require.NoError(t, err)
				assert.Equal(t, "Microsoft-Windows-PowerShell/Operational", c.LogName)
				assert.False(t, c.IsClassicLog)
				assert.True(t, c.IsEnabled)
				assert.EqualValues(t, 15728640, c.MaximumSizeInBytes)
			})

			// The case #10362 exists for. This channel has no MaxSize in the
			// WINEVT key and is not under Services\EventLog either, so no
			// registry source knows its size and only the channel itself does.
			// Before that fix it was reported as the invented 20480 KB.
			t.Run("manifest only", func(t *testing.T) {
				c, err := ParseEventLogChannel(openFixture(t, "eventlog-manifest-only-"+rel+".json"))
				require.NoError(t, err)
				assert.Equal(t, "Microsoft-Windows-WinRM/Operational", c.LogName)
				assert.False(t, c.IsClassicLog)
				assert.EqualValues(t, 1052672, c.MaximumSizeInBytes)
				assert.EqualValues(t, 1028, c.MaximumSizeInBytes/1024,
					"1028 KB is the value a host reports; 20480 was the invented default")
			})

			// A disabled channel collects nothing, so a size or retention
			// assertion about it is worthless until enabled is read.
			t.Run("disabled", func(t *testing.T) {
				c, err := ParseEventLogChannel(openFixture(t, "eventlog-disabled-"+rel+".json"))
				require.NoError(t, err)
				assert.Equal(t, "Microsoft-Windows-TaskScheduler/Operational", c.LogName)
				assert.False(t, c.IsEnabled)
				assert.EqualValues(t, 10485760, c.MaximumSizeInBytes)
				assert.Zero(t, c.RecordCount)
			})
		})
	}
}

// TestOptionalFeatureStateEnum pins the DISM FeatureState encoding against real
// output. The schema used to document 1 as Enabled and 2 as "disable pending",
// which is the wrong way round: a policy written as `state == 1` would have
// matched nothing on any release.
func TestOptionalFeatureStateEnum(t *testing.T) {
	for _, rel := range windowsReleases {
		name := "optionalfeatures-" + rel + ".json"
		if !fixtureExists(name) {
			continue
		}
		t.Run(rel, func(t *testing.T) {
			features, err := ParseWindowsOptionalFeatures(openFixture(t, name))
			require.NoError(t, err)
			require.NotEmpty(t, features)

			var enabled, disabled int
			for _, f := range features {
				assert.NotEmpty(t, f.Name)
				switch f.State {
				case 2:
					assert.True(t, f.Enabled, "%s: state 2 is Enabled", f.Name)
					enabled++
				case 0:
					assert.False(t, f.Enabled, "%s: state 0 is Disabled", f.Name)
					disabled++
				default:
					// 1 (disable pending) and 3 (enable pending) are real but
					// rare; neither is a steady state and neither is Enabled.
					assert.False(t, f.Enabled, "%s: state %d is a pending state", f.Name, f.State)
				}
			}
			assert.NotZero(t, enabled, "the fixture must carry an enabled feature")
			assert.NotZero(t, disabled, "the fixture must carry a disabled feature")
		})
	}
}

// TestWindowsFeatureInstallState pins the ServerManager InstallState encoding,
// and specifically that a pending state still reports Installed. A policy that
// compares the number instead of reading Installed gets this wrong: DNS is
// installed on these hosts and reports InstallState 3, not 1.
func TestWindowsFeatureInstallState(t *testing.T) {
	for _, rel := range windowsReleases {
		name := "features-" + rel + ".json"
		if !fixtureExists(name) {
			continue
		}
		t.Run(rel, func(t *testing.T) {
			features, err := ParseWindowsFeatures(openFixture(t, name))
			require.NoError(t, err)
			require.NotEmpty(t, features)

			states := map[int64]bool{}
			for _, f := range features {
				assert.NotEmpty(t, f.Name)
				states[f.InstallState] = true
				switch f.InstallState {
				case 0, 4, 5: // Available, NotPresent, Removed
					assert.False(t, f.Installed, "%s: InstallState %d is not installed", f.Name, f.InstallState)
				case 1, 3: // Installed, InstallPending
					assert.True(t, f.Installed, "%s: InstallState %d is installed", f.Name, f.InstallState)
				}
			}
			assert.True(t, states[0], "the fixture must carry an available feature")
			assert.True(t, states[1], "the fixture must carry an installed feature")
		})
	}
}

// TestPrinterDriverFixtures pins the packed-version unpacking against real
// spooler output. Windows stores the vendor version as four 16-bit fields in
// one 64-bit integer, and the dotted form is what vendors publish advisories
// against, so getting the unpacking wrong makes every version assertion wrong.
func TestPrinterDriverFixtures(t *testing.T) {
	for _, rel := range windowsReleases {
		name := "printerdriver-" + rel + ".json"
		if !fixtureExists(name) {
			continue
		}
		t.Run(rel, func(t *testing.T) {
			drivers, err := ParsePrinterDrivers(openFixture(t, name))
			require.NoError(t, err)
			require.NotEmpty(t, drivers)

			for _, d := range drivers {
				assert.NotEmpty(t, d.Name)
				assert.NotEmpty(t, d.PrinterEnvironment)
				if d.DriverVersion != 0 {
					assert.Regexp(t, `^\d+\.\d+\.\d+\.\d+$`, d.DottedVersion(),
						"%s: the packed version must unpack to four fields", d.Name)
				}
				if d.Manufacturer != "" && d.Name != "" {
					assert.Contains(t, d.Purl(), "pkg:windows-driver/",
						"%s: a driver with a vendor and a name has a purl", d.Name)
				}
			}
		})
	}
}

// TestScheduledTaskFixtures parses a task Windows ships on every release. The
// Defrag task is the one that exposed the never-ran sentinel: it is enabled and
// ready, and on three of the four releases it has never actually run.
func TestScheduledTaskFixtures(t *testing.T) {
	for _, rel := range windowsReleases {
		name := "scheduledtask-defrag-" + rel + ".json"
		if !fixtureExists(name) {
			continue
		}
		t.Run(rel, func(t *testing.T) {
			tasks, err := ParseWindowsScheduledTasks(openFixture(t, name))
			require.NoError(t, err)
			require.NotEmpty(t, tasks)

			task := tasks[0]
			assert.Equal(t, "ScheduledDefrag", task.Name)
			assert.Equal(t, `\Microsoft\Windows\Defrag\`, task.Path)
			assert.Equal(t, `\Microsoft\Windows\Defrag\ScheduledDefrag`, task.URI)

			require.NotNil(t, task.Principal)
			assert.Equal(t, "SYSTEM", task.Principal.UserId)
			assert.Equal(t, "Highest", task.Principal.RunLevel,
				"a task running as SYSTEM at the highest privilege level is what makes its action worth auditing")

			require.NotEmpty(t, task.Actions)
			assert.Contains(t, task.Actions[0].Execute, "defrag.exe")

			require.NotNil(t, task.Settings)
			require.NotNil(t, task.Settings.Enabled)
			assert.True(t, *task.Settings.Enabled)

			// The task is driven by Automatic Maintenance rather than by a
			// trigger of its own, so an empty trigger list here is the real
			// answer and not a parse that lost them.
			assert.Empty(t, task.Triggers)
		})
	}
}

// TestComputerInfoFixtures pins that Get-ComputerInfo parses on every release
// and that the properties an audit reaches for are present on all of them.
// This cmdlet has gained and lost properties across releases, which is exactly
// the drift a single-release fixture hides.
func TestComputerInfoFixtures(t *testing.T) {
	// Present on every release from 2016 to 2025.
	stable := []string{
		"OsProductType", "OsBuildNumber", "OsArchitecture", "OsVersion",
		"CsDomainRole", "CsPartOfDomain", "CsTotalPhysicalMemory",
		"WindowsEditionId", "WindowsInstallationType", "BiosManufacturer",
		"OsHardwareAbstractionLayer", "CsPhyicallyInstalledMemory", "BiosFirmwareType",
	}

	for _, rel := range windowsReleases {
		name := "computer-info-" + rel + ".json"
		if !fixtureExists(name) {
			continue
		}
		t.Run(rel, func(t *testing.T) {
			info, err := ParseComputerInfo(openFixture(t, name))
			require.NoError(t, err)
			require.NotEmpty(t, info)

			for _, k := range stable {
				assert.Contains(t, info, k)
			}

			// A non-nil OsProductType is what makes windows.computerInfo keep
			// the native reading instead of falling back to the hand-built
			// object, so it decides which code path a host takes.
			assert.NotNil(t, info["OsProductType"])

			// Installed memory is reported in KB and total physical memory in
			// bytes. They are close enough in name to be confused and differ
			// by about 1024x, which is how the fallback came to report one as
			// the other.
			installedKB, ok := info["CsPhyicallyInstalledMemory"].(float64)
			require.True(t, ok)
			totalBytes, ok := info["CsTotalPhysicalMemory"].(float64)
			require.True(t, ok)
			assert.Greater(t, totalBytes/installedKB, float64(900))
		})
	}
}

// TestAclAuditFixture pins the system access control list shape: what an object
// audits, as opposed to what it permits. An audit rule is only meaningful when
// it can be read at all, so this shape has to survive a parse rather than
// degrade to an empty list.
func TestAclAuditFixture(t *testing.T) {
	audit, err := ParseWindowsAclAudit(openFixture(t, "acl-audit-directory-sacl.json"))
	require.NoError(t, err)
	require.Len(t, audit.Audit, 1)

	e := audit.Audit[0]
	assert.Equal(t, "Everyone", e.Identity)
	assert.Equal(t, "S-1-1-0", e.Sid)
	assert.Equal(t, "Success, Failure", e.AuditFlags)
	assert.True(t, e.AuditsSuccess())
	assert.True(t, e.AuditsFailure())
	assert.False(t, e.Inherited)
	assert.Equal(t, "ContainerInherit, ObjectInherit", e.InheritanceFlags)
}

// TestAclFixture covers the discretionary list of the same directory, including
// the entry whose rights render as a bare number because the mask carries
// generic bits. That is why the allows* predicates exist rather than matching
// the rights label.
func TestAclFixture(t *testing.T) {
	acl, err := ParseWindowsAcl(openFixture(t, "acl-audit-directory-dacl.json"))
	require.NoError(t, err)
	assert.Equal(t, `BUILTIN\Administrators`, acl.Owner)
	assert.False(t, acl.Protected, "the directory still inherits from its parent")
	require.NotEmpty(t, acl.Access)

	var sawGeneric bool
	for _, e := range acl.Access {
		if e.Rights == "268435456" {
			sawGeneric = true
			assert.True(t, e.AllowsFullControl(),
				"GENERIC_ALL has no label, so only the mask says it grants everything")
			assert.True(t, e.AllowsWrite())
			assert.True(t, e.AllowsPermissionChange())
		}
	}
	assert.True(t, sawGeneric, "the fixture must keep the entry whose rights have no label")

	assert.Contains(t, acl.AllowedWritePrincipals(), `NT AUTHORITY\SYSTEM`)
	assert.Contains(t, acl.AllowedWritePrincipals(), `BUILTIN\Administrators`)
}
