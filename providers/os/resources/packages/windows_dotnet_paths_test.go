// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDotNetComponentSubdir pins which DisplayNames are .NET installer entries
// with a known layout, and — more importantly — which are not. A pattern that
// over-matches would point a Targeting Pack or the SDK at a shared-framework
// directory belonging to a different component.
func TestDotNetComponentSubdir(t *testing.T) {
	for _, tc := range []struct {
		name      string
		subdir    []string
		versioned bool
		ok        bool
	}{
		{"Microsoft .NET Runtime - 8.0.11 (x64)", []string{"shared", "Microsoft.NETCore.App"}, true, true},
		{"Microsoft .NET Core Runtime - 3.1.32 (x64)", []string{"shared", "Microsoft.NETCore.App"}, true, true},
		{"Microsoft Windows Desktop Runtime - 8.0.11 (x64)", []string{"shared", "Microsoft.WindowsDesktop.App"}, true, true},
		{"Microsoft .NET Desktop Runtime - 6.0.36 (x64)", []string{"shared", "Microsoft.WindowsDesktop.App"}, true, true},
		{"Microsoft ASP.NET Core Runtime - 10.0.0 (arm64)", []string{"shared", "Microsoft.AspNetCore.App"}, true, true},
		{"Microsoft ASP.NET Core 8.0.28 - Shared Framework (x86)", []string{"shared", "Microsoft.AspNetCore.App"}, true, true},
		{"Microsoft ASP.NET Core 8.0.15 Shared Framework (arm64)", []string{"shared", "Microsoft.AspNetCore.App"}, true, true},
		{"Microsoft .NET Host FX Resolver - 8.0.15 (arm64)", []string{"host", "fxr"}, true, true},
		// The muxer owns the dotnet root, so no release segment is appended.
		{"Microsoft .NET Host - 8.0.30 (arm64)", nil, false, true},

		// Not runtimes: these install elsewhere (packs\, sdk\) or are a
		// different product entirely, and must resolve to nothing.
		{"Microsoft ASP.NET Core 8.0.15 Targeting Pack (arm64)", nil, false, false},
		{"Microsoft .NET Targeting Pack - 8.0.15 (arm64)", nil, false, false},
		{"Microsoft .NET Toolset 8.0.408 (arm64)", nil, false, false},
		{"Microsoft .NET SDK 8.0.404 (x64)", nil, false, false},
		{"Microsoft .NET Framework 4.8", nil, false, false},
		{"Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211", nil, false, false},
		{"7-Zip 26.03 (x64 edition)", nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subdir, versioned, ok := dotNetComponentSubdir(tc.name)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.versioned, versioned)
			assert.Equal(t, tc.subdir, subdir)
		})
	}
}

// TestDotNetInstallDirCandidates checks the paths themselves. The directory
// name is the whole point of the fix, so a wrong segment or separator here is
// the difference between evidence and no evidence.
func TestDotNetInstallDirCandidates(t *testing.T) {
	candidates := dotNetInstallDirCandidates("Microsoft .NET Runtime - 8.0.11 (x64)", "8.0.11")
	assert.Equal(t, []string{
		`C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.11`,
		"Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.11",
		`C:\Program Files (x86)\dotnet\shared\Microsoft.NETCore.App\8.0.11`,
		"Program Files (x86)/dotnet/shared/Microsoft.NETCore.App/8.0.11",
	}, candidates)

	// The host muxer sits at the root: no release segment.
	assert.Equal(t, []string{
		`C:\Program Files\dotnet`,
		"Program Files/dotnet",
		`C:\Program Files (x86)\dotnet`,
		"Program Files (x86)/dotnet",
	}, dotNetInstallDirCandidates("Microsoft .NET Host - 8.0.30 (arm64)", "8.0.30"))

	assert.Nil(t, dotNetInstallDirCandidates("7-Zip 26.03 (x64 edition)", "26.03.00.0"))

	// A versioned component with no release cannot name a directory. Returning
	// the un-suffixed parent would attach the whole shared-framework folder as
	// this package's evidence.
	assert.Nil(t, dotNetInstallDirCandidates("Microsoft .NET Runtime - 8.0.11 (x64)", ""))
}

// TestDotNetInstallDirCandidatesX86First: a 32-bit runtime installs under
// Program Files (x86) alongside a 64-bit sibling of the same release under
// Program Files. Both directories exist on such a host, so the ORDER decides
// which one the x86 package is credited with.
func TestDotNetInstallDirCandidatesX86First(t *testing.T) {
	candidates := dotNetInstallDirCandidates("Microsoft .NET Runtime - 8.0.16 (x86)", "8.0.16")
	require.NotEmpty(t, candidates)
	assert.Equal(t, `C:\Program Files (x86)\dotnet\shared\Microsoft.NETCore.App\8.0.16`, candidates[0])
	// The 64-bit root is still probed: a 32-bit host has no Program Files (x86)
	// and its entries carry no (x86) suffix either.
	assert.Contains(t, candidates, `C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.16`)
}

// TestFillDotNetInstallPathsAttachesExistingDir is the fix in one case: the
// directory is on disk, so the package gets it.
func TestFillDotNetInstallPathsAttachesExistingDir(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.11", 0o755))

	pkgs := []Package{{
		Name:    "Microsoft .NET Runtime - 8.0.11 (x64)",
		Version: "8.0.11",
		Format:  "windows/app",
	}}
	fillDotNetInstallPaths(fs, pkgs)

	require.Len(t, pkgs[0].Files, 1)
	assert.Equal(t, "Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.11", pkgs[0].Files[0].Path)
	assert.Equal(t, PkgFilesIncluded, pkgs[0].FilesAvailable,
		"a package carrying files must say so, or the resource layer never reads them")
}

// TestFillDotNetInstallPathsSkipsMissingDir: the reconstructed path is a
// candidate, not a claim. A runtime installed somewhere else (DOTNET_ROOT) must
// report nothing rather than a directory that isn't there.
func TestFillDotNetInstallPathsSkipsMissingDir(t *testing.T) {
	fs := afero.NewMemMapFs()
	// A different release is installed — the 8.0.11 directory does not exist.
	require.NoError(t, fs.MkdirAll("Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.30", 0o755))

	pkgs := []Package{{
		Name:    "Microsoft .NET Runtime - 8.0.11 (x64)",
		Version: "8.0.11",
		Format:  "windows/app",
	}}
	fillDotNetInstallPaths(fs, pkgs)

	assert.Empty(t, pkgs[0].Files)
	assert.Equal(t, PkgFilesNotAvailable, pkgs[0].FilesAvailable)
}

// TestFillDotNetInstallPathsKeepsRegistryLocation: a real InstallLocation is
// what the installer actually recorded, so it outranks anything reconstructed
// here — including on a host where both directories exist.
func TestFillDotNetInstallPathsKeepsRegistryLocation(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.11", 0o755))

	pkgs := []Package{{
		Name:           "Microsoft .NET Runtime - 8.0.11 (x64)",
		Version:        "8.0.11",
		Format:         "windows/app",
		Files:          []FileRecord{{Path: `D:\dotnet`}},
		FilesAvailable: PkgFilesIncluded,
	}}
	fillDotNetInstallPaths(fs, pkgs)

	require.Len(t, pkgs[0].Files, 1)
	assert.Equal(t, `D:\dotnet`, pkgs[0].Files[0].Path)
}

// TestFillDotNetInstallPathsIgnoresOtherFormats: appx packages already carry
// their install location and are keyed on a different layout entirely.
func TestFillDotNetInstallPathsIgnoresOtherFormats(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.11", 0o755))

	pkgs := []Package{{
		Name:    "Microsoft .NET Runtime - 8.0.11 (x64)",
		Version: "8.0.11",
		Format:  "windows/appx",
	}}
	fillDotNetInstallPaths(fs, pkgs)

	assert.Empty(t, pkgs[0].Files)
}

// TestFillDotNetInstallPathsBundleHost is the regression guard for the reported
// bug: it runs the real registry dump from a bundle install through the real
// parser, then fills. Every .NET entry the bundle registers — all four of which
// carry an empty InstallLocation — must come out with the directory its
// component owns.
//
// Before this fix all four came out with no files, which is what left a CVE
// matched to the runtime with no evidence and no "Located filepath" in the UI.
func TestFillDotNetInstallPathsBundleHost(t *testing.T) {
	pkgs, err := ParseWindowsAppPackages(winArm64Platform(), strings.NewReader(bundleHost))
	require.NoError(t, err)
	for _, p := range pkgs {
		require.Empty(t, p.Files, "the bundle writes no InstallLocation for %q", p.Name)
	}

	fs := afero.NewMemMapFs()
	for _, dir := range []string{
		"Program Files/dotnet",
		"Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.30",
		"Program Files/dotnet/host/fxr/8.0.30",
	} {
		require.NoError(t, fs.MkdirAll(dir, 0o755))
	}

	fillDotNetInstallPaths(fs, pkgs)

	want := map[string]string{
		"Microsoft .NET Runtime - 8.0.30 (arm64)":          "Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.30",
		"Microsoft .NET Host - 8.0.30 (arm64)":             "Program Files/dotnet",
		"Microsoft .NET Host FX Resolver - 8.0.30 (arm64)": "Program Files/dotnet/host/fxr/8.0.30",
	}
	for name, dir := range want {
		matches := pkgsNamed(pkgs, name)
		require.NotEmpty(t, matches, "expected %q in the parsed package list", name)
		for _, p := range matches {
			require.Len(t, p.Files, 1, "%q should have exactly one evidence path", name)
			assert.Equal(t, dir, p.Files[0].Path, "wrong install directory for %q", name)
			assert.Equal(t, PkgFilesIncluded, p.FilesAvailable)
		}
	}
}
