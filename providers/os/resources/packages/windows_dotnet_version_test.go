// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// TestNormalizeDotNetPackedVersion pins the recovery of the real .NET release
// from a packed MSI ProductVersion.
//
// Every (DisplayName, DisplayVersion) pair below was READ OFF A REAL HOST, never
// composed:
//
//   - "VM" — a clean Windows 11 ARM64 VM after installing Microsoft's own
//     dotnet-runtime-win-arm64.exe (8.0.30) and, separately, the standalone
//     dotnet-runtime-8.0.30-win-arm64.msi.
//   - "fixture" — a captured scan of a Windows Server 2025 host, held as a
//     regression fixture downstream.
//   - "fleet" — the installed-software inventory of a customer estate, from the
//     report that prompted this change.
func TestNormalizeDotNetPackedVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		display string
		version string
		want    string
	}{
		// --- packed MSI ProductVersion: recovered from the DisplayName ---
		{"VM, runtime 8.0.30 MSI entry", "Microsoft .NET Runtime - 8.0.30 (arm64)", "64.120.56788", "8.0.30"},
		{"VM, host", "Microsoft .NET Host - 8.0.30 (arm64)", "64.120.56788", "8.0.30"},
		{"VM, host fx resolver", "Microsoft .NET Host FX Resolver - 8.0.30 (arm64)", "64.120.56788", "8.0.30"},
		{"fixture, runtime 8.0.15", "Microsoft .NET Runtime - 8.0.15 (arm64)", "64.60.31149", "8.0.15"},
		{"fixture, aspnet core preview", "Microsoft ASP.NET Core Runtime - 10.0.0 Preview 3 (arm64)", "80.0.31265", "10.0.0"},
		{"fixture, targeting pack suffixed", "Microsoft .NET Targeting Pack - 8.0.15 (arm64)", "64.60.31149", "8.0.15"},
		{"fleet, .NET 10", "Microsoft .NET Runtime - 10.0.10 (x64)", "80.40.55332", "10.0.10"},
		{"fleet, desktop runtime 6", "Microsoft .NET Desktop Runtime - 6.0.36 (x64)", "48.144.23141", "6.0.36"},
		{"fleet, legacy Core spelling", "Microsoft .NET Core Runtime - 3.1.32 (x64)", "24.192.31915", "3.1.32"},

		// The WPF/WinForms runtime, which Microsoft registers under the "Windows
		// Desktop Runtime" name rather than the ".NET" brand. Its MSI entry is
		// packed like the others; verified on the VM alongside its bundle twin.
		{"VM, windows desktop runtime MSI entry", "Microsoft Windows Desktop Runtime - 8.0.30 (arm64)", "64.120.56881", "8.0.30"},
		{"VM, windows desktop runtime bundle entry", "Microsoft Windows Desktop Runtime - 8.0.30 (arm64)", "8.0.30.36323", "8.0.30"},
		{"fixture, windows desktop runtime", "Microsoft Windows Desktop Runtime - 8.0.15 (arm64)", "64.60.31203", "8.0.15"},
		{"fixture, windows desktop runtime preview", "Microsoft Windows Desktop Runtime - 10.0.0 Preview 3 (arm64)", "80.0.31297", "10.0.0"},
		// Microsoft dropped the separator at 10.0; both punctuations are live.
		{"fleet, windows desktop runtime without separator", "Microsoft Windows Desktop Runtime 10.0.10 (x64)", "80.40.55332", "10.0.10"},

		// --- bundle entries: collapsed onto the same release as their MSI twin, so a\n		// bundle-installed host reports the runtime once instead of twice ---
		{"VM, runtime 8.0.30 bundle entry", "Microsoft .NET Runtime - 8.0.30 (arm64)", "8.0.30.36317", "8.0.30"},
		{"fleet, shared framework hyphenated", "Microsoft ASP.NET Core 8.0.28 - Shared Framework (x86)", "8.0.28.26269", "8.0.28"},
		{"fixture, shared framework unhyphenated", "Microsoft ASP.NET Core 8.0.15 Shared Framework (arm64)", "8.0.15.25165", "8.0.15"},
		{"fleet, legacy Core spelling, sane version", "Microsoft .NET Core Runtime - 3.1.32 (x64)", "3.1.32.31915", "3.1.32"},

		// --- must not be touched ---
		// .NET Framework's version is read from clr.dll, not from an MSI, and the
		// DisplayName carries no release at all.
		{"VM, .NET Framework", "Microsoft .NET Framework", "4.8.9337.0", "4.8.9337.0"},
		// No " - <release>": these encode versions on schemes of their own.
		{"fixture, toolset", "Microsoft .NET Toolset 8.0.408 (arm64)", "32.11.26981", "32.11.26981"},
		{"fixture, toolset preview", "Microsoft .NET Toolset 10.0.100-preview.3.25201.16 (arm64)", "40.9.30292", "40.9.30292"},
		{"fixture, workload manifest", "Microsoft.NET.Workload.Mono.Toolchain.net7.Manifest (arm64)", "64.60.31149", "64.60.31149"},
		{"fixture, sdk manifest", "Microsoft.NET.Sdk.tvOS.Manifest-8.0.100 (arm64)", "17.0.8478", "17.0.8478"},
		// Targeting Pack in the mid-name shape is not the Shared Framework.
		{"fixture, aspnet targeting pack", "Microsoft ASP.NET Core 8.0.15 Targeting Pack (arm64)", "8.0.15.25165", "8.0.15.25165"},
		// Nothing to do with .NET.
		{"unrelated product", "7-Zip 26.02 (x64 edition)", "26.02.00.0", "26.02.00.0"},
		{"empty version", "Microsoft .NET Runtime - 8.0.30 (x64)", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeDotNetPackedVersion(tc.display, tc.version))
		})
	}
}

// TestCreatePackageNormalizesDotNetVersion pins that the recovery happens before
// the PURL is built, so Version and PUrl cannot disagree.
func TestCreatePackageNormalizesDotNetVersion(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Version: "10.0.26100", Arch: "arm64"}

	t.Run("windows/app is normalized", func(t *testing.T) {
		pkg := createPackage("Microsoft .NET Runtime - 8.0.30 (arm64)", "64.120.56788", "windows/app", "ARM64", "Microsoft Corporation", "", platform)
		assert.Equal(t, "8.0.30", pkg.Version)
		assert.Contains(t, pkg.PUrl, "@8.0.30")
		assert.NotContains(t, pkg.PUrl, "64.120.56788")
	})

	t.Run("appx is left alone", func(t *testing.T) {
		// An appx package name never carries a release, so this is belt and
		// braces — the normalization is gated on windows/app regardless.
		pkg := createPackage("Microsoft.NET.Native.Runtime.2.2", "2.2.28604.0", "windows/appx", "arm64", "Microsoft Corporation", "", platform)
		assert.Equal(t, "2.2.28604.0", pkg.Version)
	})
}
