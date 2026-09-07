// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
)

// The .NET runtime installers register a DIFFERENT SET of Add/Remove-Programs
// entries depending on how the runtime was deployed, and the per-entry unit
// tests in windows_dotnet_version_test.go cannot see that. These tests run the
// real ParseWindowsAppPackages over whole host shapes.
//
// The two JSON blobs below were dumped off a clean Windows 11 ARM64 VM with the
// same registry query cnspec itself runs (installedAppsScript), once after
// installing Microsoft's dotnet-runtime-win-arm64.exe and once after installing
// only the standalone dotnet-runtime-8.0.30-win-arm64.msi. They are verbatim,
// including the null InstallLocation the bundle writes and the Wow6432Node
// PSPath its entry lands under.

// msiOnlyHost is what a managed rollout that pushes the MSI leaves behind:
// a single entry, carrying the packed MSI ProductVersion and nothing else.
const msiOnlyHost = `[
    {
        "DisplayName":  "Microsoft .NET Runtime - 8.0.30 (arm64)",
        "DisplayVersion":  "64.120.56788",
        "Publisher":  "Microsoft Corporation",
        "EstimatedSize":  83332,
        "InstallSource":  "C:\\ProgramData\\Package Cache\\{32D82739-067B-48B4-B8DC-33CA48124882}v64.120.56788\\",
        "UninstallString":  "MsiExec.exe /X{32D82739-067B-48B4-B8DC-33CA48124882}",
        "InstallLocation":  "",
        "InstallDate":  "20260907",
        "PSPath":  "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{32D82739-067B-48B4-B8DC-33CA48124882}"
    }
]`

// bundleHost is what the .exe installer leaves behind: the same MSI entry, its
// two companion MSIs, and the burn bundle's own entry carrying the real release.
const bundleHost = `[
    {
        "DisplayName":  "Microsoft .NET Runtime - 8.0.30 (arm64)",
        "DisplayVersion":  "64.120.56788",
        "Publisher":  "Microsoft Corporation",
        "EstimatedSize":  83332,
        "InstallSource":  "C:\\ProgramData\\Package Cache\\{32D82739-067B-48B4-B8DC-33CA48124882}v64.120.56788\\",
        "UninstallString":  "MsiExec.exe /X{32D82739-067B-48B4-B8DC-33CA48124882}",
        "InstallLocation":  "",
        "InstallDate":  "20260907",
        "PSPath":  "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{32D82739-067B-48B4-B8DC-33CA48124882}"
    },
    {
        "DisplayName":  "Microsoft .NET Host - 8.0.30 (arm64)",
        "DisplayVersion":  "64.120.56788",
        "Publisher":  "Microsoft Corporation",
        "EstimatedSize":  468,
        "InstallSource":  "C:\\ProgramData\\Package Cache\\{738E2CFA-16EB-4E14-9D1C-F3C262209237}v64.120.56788\\",
        "UninstallString":  "MsiExec.exe /X{738E2CFA-16EB-4E14-9D1C-F3C262209237}",
        "InstallLocation":  "",
        "InstallDate":  "20260907",
        "PSPath":  "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{738E2CFA-16EB-4E14-9D1C-F3C262209237}"
    },
    {
        "DisplayName":  "Microsoft .NET Host FX Resolver - 8.0.30 (arm64)",
        "DisplayVersion":  "64.120.56788",
        "Publisher":  "Microsoft Corporation",
        "EstimatedSize":  324,
        "InstallSource":  "C:\\ProgramData\\Package Cache\\{86139208-A42A-4F2A-9B61-3FBBA7F45CF9}v64.120.56788\\",
        "UninstallString":  "MsiExec.exe /X{86139208-A42A-4F2A-9B61-3FBBA7F45CF9}",
        "InstallLocation":  "",
        "InstallDate":  "20260907",
        "PSPath":  "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{86139208-A42A-4F2A-9B61-3FBBA7F45CF9}"
    },
    {
        "DisplayName":  "Microsoft .NET Runtime - 8.0.30 (arm64)",
        "DisplayVersion":  "8.0.30.36317",
        "Publisher":  "Microsoft Corporation",
        "EstimatedSize":  111234,
        "InstallSource":  null,
        "UninstallString":  "\"C:\\ProgramData\\Package Cache\\{720d7dc2-2281-462e-929a-b429c05fdb16}\\dotnet-runtime-8.0.30-win-arm64.exe\"  /uninstall",
        "InstallLocation":  null,
        "InstallDate":  null,
        "PSPath":  "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{720d7dc2-2281-462e-929a-b429c05fdb16}"
    }
]`

func winArm64Platform() *inventory.Platform {
	return &inventory.Platform{Name: "windows", Version: "10.0.26100", Arch: "arm64", Family: []string{"windows"}}
}

func pkgsNamed(pkgs []Package, name string) []Package {
	out := []Package{}
	for _, p := range pkgs {
		if p.Name == name {
			out = append(out, p)
		}
	}
	return out
}

// TestDotNetMsiOnlyHost: the deployment shape where the DisplayName is the only
// place the real release exists. One entry in, one usable package out.
func TestDotNetMsiOnlyHost(t *testing.T) {
	pkgs, err := ParseWindowsAppPackages(winArm64Platform(), strings.NewReader(msiOnlyHost))
	require.NoError(t, err)

	runtimes := pkgsNamed(pkgs, "Microsoft .NET Runtime - 8.0.30 (arm64)")
	require.Len(t, runtimes, 1, "the MSI registers exactly one entry")
	assert.Equal(t, "8.0.30", runtimes[0].Version)
	assert.Contains(t, runtimes[0].PUrl, "@8.0.30")
	assert.NotContains(t, runtimes[0].PUrl, "64.120.56788")
}

// TestDotNetBundleHost is the duplicate-findings guard.
//
// The bundle registers the runtime TWICE — once as the MSI, once as itself.
// Both entries describe one install, so both must land on the same version and
// the same PURL; otherwise they become two package rows and two findings
// carrying the same CVEs for a single runtime.
func TestDotNetBundleHost(t *testing.T) {
	pkgs, err := ParseWindowsAppPackages(winArm64Platform(), strings.NewReader(bundleHost))
	require.NoError(t, err)

	runtimes := pkgsNamed(pkgs, "Microsoft .NET Runtime - 8.0.30 (arm64)")
	require.Len(t, runtimes, 2, "the bundle registers the runtime twice: the MSI and the bundle itself")
	for _, p := range runtimes {
		assert.Equal(t, "8.0.30", p.Version, "both entries describe one install and must agree")
	}
	assert.Equal(t, runtimes[0].PUrl, runtimes[1].PUrl,
		"identical PURLs are what lets the two entries collapse into one finding downstream")

	// The companion MSIs are separate products and keep their own identity —
	// they must not be folded onto the runtime, but their packed version is
	// recovered too, since it is just as unreadable.
	host := pkgsNamed(pkgs, "Microsoft .NET Host - 8.0.30 (arm64)")
	require.Len(t, host, 1)
	assert.Equal(t, "8.0.30", host[0].Version)

	fx := pkgsNamed(pkgs, "Microsoft .NET Host FX Resolver - 8.0.30 (arm64)")
	require.Len(t, fx, 1)
	assert.Equal(t, "8.0.30", fx[0].Version)
}

// TestDotNetSideBySideReleases covers the shape a real estate is actually in:
// several majors installed at once, a stale left-behind framework beside its
// current sibling, and the pre-rebrand spelling. The (DisplayName,
// DisplayVersion) pairs are from the installed-software inventory of a customer
// estate; the registry paths are the plain HKLM location those x64 entries are
// registered under.
func TestDotNetSideBySideReleases(t *testing.T) {
	const hklm = `Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`
	type arpEntry struct {
		DisplayName     string `json:"DisplayName"`
		DisplayVersion  string `json:"DisplayVersion"`
		Publisher       string `json:"Publisher"`
		UninstallString string `json:"UninstallString"`
		InstallLocation string `json:"InstallLocation"`
		PSPath          string `json:"PSPath"`
	}
	pairs := []struct{ name, version string }{
		{"Microsoft .NET Runtime - 10.0.11 (x64)", "80.44.56884"},
		{"Microsoft .NET Runtime - 8.0.30 (x64)", "64.120.56788"},
		{"Microsoft .NET Desktop Runtime - 6.0.36 (x64)", "48.144.23141"},
		{"Microsoft .NET Core Runtime - 3.1.32 (x64)", "24.192.31915"},
		{"Microsoft ASP.NET Core 8.0.28 - Shared Framework (x86)", "8.0.28.26269"},
		{"Microsoft ASP.NET Core 8.0.30 - Shared Framework (x64)", "8.0.30.26373"},
		{"Microsoft ASP.NET Core 8.0.30 Hosting Bundle Options", "8.0.30.26373"},
	}
	entries := make([]arpEntry, 0, len(pairs))
	for i, p := range pairs {
		entries = append(entries, arpEntry{
			DisplayName:     p.name,
			DisplayVersion:  p.version,
			Publisher:       "Microsoft Corporation",
			UninstallString: fmt.Sprintf("MsiExec.exe /X{%08d-0000-0000-0000-000000000000}", i),
			PSPath:          fmt.Sprintf("%s{%08d-0000-0000-0000-000000000000}", hklm, i),
		})
	}
	blob, err := json.Marshal(entries)
	require.NoError(t, err)

	pkgs, err := ParseWindowsAppPackages(
		&inventory.Platform{Name: "windows", Version: "10.0.20348", Arch: "amd64", Family: []string{"windows"}},
		strings.NewReader(string(blob)))
	require.NoError(t, err)

	want := map[string]string{
		"Microsoft .NET Runtime - 10.0.11 (x64)":                 "10.0.11",
		"Microsoft .NET Runtime - 8.0.30 (x64)":                  "8.0.30",
		"Microsoft .NET Desktop Runtime - 6.0.36 (x64)":          "6.0.36",
		"Microsoft .NET Core Runtime - 3.1.32 (x64)":             "3.1.32",
		"Microsoft ASP.NET Core 8.0.28 - Shared Framework (x86)": "8.0.28",
		"Microsoft ASP.NET Core 8.0.30 - Shared Framework (x64)": "8.0.30",
		// Not a Shared Framework and carries no " - <release>": left as scanned.
		"Microsoft ASP.NET Core 8.0.30 Hosting Bundle Options": "8.0.30.26373",
	}
	require.Len(t, pkgs, len(want))
	for _, p := range pkgs {
		w, ok := want[p.Name]
		require.True(t, ok, "unexpected package %q", p.Name)
		assert.Equal(t, w, p.Version, "package %q", p.Name)
	}

	// The stale 8.0.28 framework must stay distinguishable from its current
	// 8.0.30 sibling — collapsing releases together would hide the finding.
	stale := pkgsNamed(pkgs, "Microsoft ASP.NET Core 8.0.28 - Shared Framework (x86)")
	current := pkgsNamed(pkgs, "Microsoft ASP.NET Core 8.0.30 - Shared Framework (x64)")
	require.Len(t, stale, 1)
	require.Len(t, current, 1)
	assert.NotEqual(t, stale[0].Version, current[0].Version)
}
