// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/registry"
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
		// ARM64 hosts keep the x64/x86 runtimes in a subfolder of the native root.
		`C:\Program Files\dotnet\x64\shared\Microsoft.NETCore.App\8.0.11`,
		"Program Files/dotnet/x64/shared/Microsoft.NETCore.App/8.0.11",
		`C:\Program Files\dotnet\x86\shared\Microsoft.NETCore.App\8.0.11`,
		"Program Files/dotnet/x86/shared/Microsoft.NETCore.App/8.0.11",
		`C:\Program Files\dotnet\arm64\shared\Microsoft.NETCore.App\8.0.11`,
		"Program Files/dotnet/arm64/shared/Microsoft.NETCore.App/8.0.11",
	}, candidates)

	// The host muxer sits at the root: no release segment.
	assert.Equal(t, []string{
		`C:\Program Files\dotnet`,
		"Program Files/dotnet",
		`C:\Program Files (x86)\dotnet`,
		"Program Files (x86)/dotnet",
		`C:\Program Files\dotnet\x64`,
		"Program Files/dotnet/x64",
		`C:\Program Files\dotnet\x86`,
		"Program Files/dotnet/x86",
		`C:\Program Files\dotnet\arm64`,
		"Program Files/dotnet/arm64",
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
	pkgs = fillDotNetInstallPaths(fs, pkgs, nil)

	require.Len(t, pkgs[0].Files, 1)
	assert.Equal(t, "Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.11", pkgs[0].Files[0].Path)
	assert.Equal(t, PkgFilesIncluded, pkgs[0].FilesAvailable,
		"a package carrying files must say so, or the resource layer never reads them")
}

// TestFillDotNetInstallPathsSkipsMissingDir: the reconstructed path is a
// candidate, not a claim. With no way to look anywhere else (no lookup of
// relocated roots) the entry is kept as it is, without files: fail open.
func TestFillDotNetInstallPathsSkipsMissingDir(t *testing.T) {
	fs := afero.NewMemMapFs()
	// A different release is installed — the 8.0.11 directory does not exist.
	require.NoError(t, fs.MkdirAll("Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.30", 0o755))

	pkgs := []Package{{
		Name:    "Microsoft .NET Runtime - 8.0.11 (x64)",
		Version: "8.0.11",
		Format:  "windows/app",
	}}
	pkgs = fillDotNetInstallPaths(fs, pkgs, nil)

	require.Len(t, pkgs, 1, "without a lookup of relocated roots the entry must be kept")
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
	pkgs = fillDotNetInstallPaths(fs, pkgs, nil)

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
	pkgs = fillDotNetInstallPaths(fs, pkgs, nil)

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

	pkgs = fillDotNetInstallPaths(fs, pkgs, nil)

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

// The tests below cover dropping a runtime whose Add/Remove Programs entry
// outlived its files (a failed uninstall). The names and releases are the
// ones used by the host-shape fixtures in windows_dotnet_hostshapes_test.go.

func dotNetRuntimePkg(name, version string) Package {
	return Package{Name: name, Version: version, Format: "windows/app"}
}

// completeRoots is a lookup of relocated roots that was read in full.
func completeRoots(roots ...string) dotNetRootLookup {
	return func() ([]string, bool) { return roots, true }
}

// visibleSystemVolume makes the filesystem show a Windows directory, which the
// drop requires as proof that "not found" is not "cannot see".
func visibleSystemVolume(t *testing.T, fs afero.Fs, dirs ...string) {
	t.Helper()
	for _, d := range append(dirs, "Windows") {
		require.NoError(t, fs.MkdirAll(d, 0o755))
	}
}

func TestFillDotNetInstallPathsDropsLeftoverRuntime(t *testing.T) {
	fs := afero.NewMemMapFs()
	// 8.0.30 is installed, 10.0.11 only survives as a registry entry.
	visibleSystemVolume(t, fs, "Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.30")

	pkgs := []Package{
		dotNetRuntimePkg("Microsoft .NET Runtime - 10.0.11 (x64)", "10.0.11"),
		dotNetRuntimePkg("Microsoft .NET Runtime - 8.0.30 (x64)", "8.0.30"),
	}
	pkgs = fillDotNetInstallPaths(fs, pkgs, completeRoots())

	require.Len(t, pkgs, 1)
	assert.Equal(t, "Microsoft .NET Runtime - 8.0.30 (x64)", pkgs[0].Name)
	require.Len(t, pkgs[0].Files, 1)
}

func TestFillDotNetInstallPathsDropsEveryRuntimeFlavour(t *testing.T) {
	fs := afero.NewMemMapFs()
	visibleSystemVolume(t, fs)

	pkgs := []Package{
		dotNetRuntimePkg("Microsoft .NET Core Runtime - 3.1.32 (x64)", "3.1.32"),
		dotNetRuntimePkg("Microsoft .NET Desktop Runtime - 6.0.36 (x64)", "6.0.36"),
		dotNetRuntimePkg("Microsoft ASP.NET Core 8.0.28 - Shared Framework (x86)", "8.0.28"),
		dotNetRuntimePkg("Microsoft ASP.NET Core Runtime - 10.0.0 (arm64)", "10.0.0"),
	}
	assert.Empty(t, fillDotNetInstallPaths(fs, pkgs, completeRoots()))
}

// TestFillDotNetInstallPathsKeepsNonRuntimes: only shared-framework runtimes
// are judged by their folder. The muxer and the resolver are not runtimes, and
// everything else is no .NET installer entry at all.
func TestFillDotNetInstallPathsKeepsNonRuntimes(t *testing.T) {
	fs := afero.NewMemMapFs()
	visibleSystemVolume(t, fs)

	pkgs := []Package{
		dotNetRuntimePkg("Microsoft .NET Host - 8.0.30 (arm64)", "8.0.30"),
		dotNetRuntimePkg("Microsoft .NET Host FX Resolver - 8.0.30 (arm64)", "8.0.30"),
		dotNetRuntimePkg("Microsoft .NET SDK 8.0.404 (x64)", "8.0.404"),
		dotNetRuntimePkg("Microsoft .NET Framework 4.8", "4.8"),
		dotNetRuntimePkg("7-Zip 26.03 (x64 edition)", "26.03.00.0"),
	}
	assert.Len(t, fillDotNetInstallPaths(fs, pkgs, completeRoots()), len(pkgs))
}

func TestFillDotNetInstallPathsKeepsRuntimeUnderDefaultRoots(t *testing.T) {
	for _, dir := range []string{
		"Program Files/dotnet/shared/Microsoft.NETCore.App/8.0.30",
		"Program Files (x86)/dotnet/shared/Microsoft.NETCore.App/8.0.30",
		// x64 runtime on an ARM64 host.
		"Program Files/dotnet/x64/shared/Microsoft.NETCore.App/8.0.30",
	} {
		t.Run(dir, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			visibleSystemVolume(t, fs, dir)
			pkgs := fillDotNetInstallPaths(fs,
				[]Package{dotNetRuntimePkg("Microsoft .NET Runtime - 8.0.30 (x64)", "8.0.30")},
				completeRoots())
			require.Len(t, pkgs, 1)
			require.Len(t, pkgs[0].Files, 1)
			assert.Equal(t, dir, pkgs[0].Files[0].Path)
		})
	}
}

// TestFillDotNetInstallPathsKeepsRelocatedRuntime: the runtime is on a root the
// host recorded (InstallLocation or DOTNET_ROOT), not under Program Files.
func TestFillDotNetInstallPathsKeepsRelocatedRuntime(t *testing.T) {
	fs := afero.NewMemMapFs()
	visibleSystemVolume(t, fs, `D:\dotnet\shared\Microsoft.NETCore.App\10.0.11`, `D:\`)

	pkgs := fillDotNetInstallPaths(fs,
		[]Package{dotNetRuntimePkg("Microsoft .NET Runtime - 10.0.11 (x64)", "10.0.11")},
		completeRoots(`D:\dotnet`))

	require.Len(t, pkgs, 1)
	require.Len(t, pkgs[0].Files, 1)
	assert.Equal(t, `D:\dotnet\shared\Microsoft.NETCore.App\10.0.11`, pkgs[0].Files[0].Path)
}

func TestFillDotNetInstallPathsKeepsRelocatedRuntimeOnMountedVolume(t *testing.T) {
	fs := afero.NewMemMapFs()
	visibleSystemVolume(t, fs, "Tools/dotnet/shared/Microsoft.AspNetCore.App/8.0.30")

	pkgs := fillDotNetInstallPaths(fs,
		[]Package{dotNetRuntimePkg("Microsoft ASP.NET Core 8.0.30 - Shared Framework (x64)", "8.0.30")},
		completeRoots("Tools/dotnet"))

	require.Len(t, pkgs, 1)
	assert.Equal(t, "Tools/dotnet/shared/Microsoft.AspNetCore.App/8.0.30", pkgs[0].Files[0].Path)
}

// TestFillDotNetInstallPathsDropsWhenRelocatedRootLacksIt: a recorded root that
// exists but does not hold this release does not save the entry.
func TestFillDotNetInstallPathsDropsWhenRelocatedRootLacksIt(t *testing.T) {
	fs := afero.NewMemMapFs()
	visibleSystemVolume(t, fs, `D:\dotnet\shared\Microsoft.NETCore.App\8.0.30`, `D:\`)

	pkgs := fillDotNetInstallPaths(fs,
		[]Package{dotNetRuntimePkg("Microsoft .NET Runtime - 10.0.11 (x64)", "10.0.11")},
		completeRoots(`D:\dotnet`))
	assert.Empty(t, pkgs)
}

// TestFillDotNetInstallPathsFailsOpen: whenever "not found" could mean "could
// not look", the entry stays, as it did before the drop existed.
func TestFillDotNetInstallPathsFailsOpen(t *testing.T) {
	leftover := func() []Package {
		return []Package{dotNetRuntimePkg("Microsoft .NET Runtime - 10.0.11 (x64)", "10.0.11")}
	}

	t.Run("registry roots incomplete", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		visibleSystemVolume(t, fs)
		got := fillDotNetInstallPaths(fs, leftover(), func() ([]string, bool) { return nil, false })
		assert.Len(t, got, 1)
	})

	t.Run("no registry on this connection", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		visibleSystemVolume(t, fs)
		assert.Len(t, fillDotNetInstallPaths(fs, leftover(), nil), 1)
	})

	t.Run("system volume not visible", func(t *testing.T) {
		assert.Len(t, fillDotNetInstallPaths(afero.NewMemMapFs(), leftover(), completeRoots()), 1)
	})

	t.Run("recorded root on a drive that is not visible", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		visibleSystemVolume(t, fs)
		assert.Len(t, fillDotNetInstallPaths(fs, leftover(), completeRoots(`E:\dotnet`)), 1)
	})

	t.Run("filesystem errors while probing", func(t *testing.T) {
		fs := &failingStatFs{Fs: afero.NewMemMapFs()}
		visibleSystemVolume(t, fs.Fs)
		assert.Len(t, fillDotNetInstallPaths(fs, leftover(), completeRoots()), 1)
	})

	t.Run("prerelease whose folder name is not the DisplayName release", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		visibleSystemVolume(t, fs)
		pkgs := []Package{dotNetRuntimePkg("Microsoft .NET Runtime - 11.0.0-preview.1.26104.118 (x64)", "11.0.0-preview.1.26104.118")}
		assert.Len(t, fillDotNetInstallPaths(fs, pkgs, completeRoots()), 1)
	})

	t.Run("version that is not the release in the DisplayName", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		visibleSystemVolume(t, fs)
		pkgs := []Package{dotNetRuntimePkg("Microsoft .NET Runtime - 8.0.30 (arm64)", "64.120.56788")}
		assert.Len(t, fillDotNetInstallPaths(fs, pkgs, completeRoots()), 1)
	})
}

// failingStatFs answers every Stat except the system-volume canary with a
// permission error.
type failingStatFs struct{ afero.Fs }

func (f *failingStatFs) Stat(name string) (os.FileInfo, error) {
	if strings.Contains(name, "dotnet") {
		return nil, os.ErrPermission
	}
	return f.Fs.Stat(name)
}

// fakeDotNetRegistry serves registry values by "<hive>\<path>".
type fakeDotNetRegistry struct {
	keys map[string][]registry.RegistryKeyItem
	errs map[string]error
}

func (f fakeDotNetRegistry) keyItems(hive, path string) ([]registry.RegistryKeyItem, bool, error) {
	k := hive + `\` + path
	if err := f.errs[k]; err != nil {
		return nil, false, err
	}
	items, ok := f.keys[k]
	return items, ok, nil
}

func regSz(key, value string) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{Key: key, Value: registry.RegistryKeyValue{Kind: registry.SZ, String: value}}
}

func TestRelocatedDotNetRoots(t *testing.T) {
	t.Run("installer location and machine DOTNET_ROOT", func(t *testing.T) {
		roots, complete := relocatedDotNetRoots(fakeDotNetRegistry{keys: map[string][]registry.RegistryKeyItem{
			`SOFTWARE\dotnet\Setup\InstalledVersions\x64`:                  {regSz("InstallLocation", `D:\dotnet\`), regSz("SharedHost", "x")},
			`SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions\x86`:      {regSz("InstallLocation", `C:\Program Files (x86)\dotnet\`)},
			`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`: {regSz("DOTNET_ROOT", `d:\DOTNET`), regSz("Path", `C:\x`), regSz("DOTNET_ROOT(x86)", `E:\x86\dotnet`)},
		}}, false)
		assert.True(t, complete)
		assert.Equal(t, []string{`D:\dotnet`, `C:\Program Files (x86)\dotnet`, `E:\x86\dotnet`}, roots,
			"duplicates ignoring case and trailing separators collapse")
	})

	t.Run("nothing recorded is complete and empty", func(t *testing.T) {
		roots, complete := relocatedDotNetRoots(fakeDotNetRegistry{}, false)
		assert.True(t, complete)
		assert.Empty(t, roots)
	})

	t.Run("an unreadable key makes the result incomplete", func(t *testing.T) {
		_, complete := relocatedDotNetRoots(fakeDotNetRegistry{errs: map[string]error{
			`SOFTWARE\dotnet\Setup\InstalledVersions\x64`: errors.New("access denied"),
		}}, false)
		assert.False(t, complete)
	})

	t.Run("a value that cannot be resolved makes it incomplete", func(t *testing.T) {
		for _, v := range []string{`%ProgramData%\dotnet`, `\\fileserver\share\dotnet`, `dotnet`} {
			_, complete := relocatedDotNetRoots(fakeDotNetRegistry{keys: map[string][]registry.RegistryKeyItem{
				`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`: {regSz("DOTNET_ROOT", v)},
			}}, false)
			assert.False(t, complete, v)
		}
	})

	t.Run("mounted volume: system drive relative, other drives incomplete", func(t *testing.T) {
		reg := fakeDotNetRegistry{keys: map[string][]registry.RegistryKeyItem{
			`SOFTWARE\dotnet\Setup\InstalledVersions\x64`: {regSz("InstallLocation", `C:\Tools\dotnet\`)},
		}}
		roots, complete := relocatedDotNetRoots(reg, true)
		assert.True(t, complete)
		assert.Equal(t, []string{"Tools/dotnet"}, roots)

		reg.keys[`SOFTWARE\dotnet\Setup\InstalledVersions\arm64`] = []registry.RegistryKeyItem{regSz("InstallLocation", `D:\dotnet`)}
		_, complete = relocatedDotNetRoots(reg, true)
		assert.False(t, complete)
	})
}
