// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// The .NET runtime installers register no InstallLocation, so the Add/Remove
// Programs entry says nothing about where the runtime landed. Verified on the
// registry dumps in windows_dotnet_hostshapes_test.go — every .NET entry the
// bundle and the standalone MSI write carries `"InstallLocation": ""` or null,
// where an ordinary application (Office, Edge, .NET Framework) carries a real
// path.
//
// createPackage only attaches a FileRecord when InstallLocation is non-empty,
// so these packages ship with no files at all. That is what the SBOM bundle's
// `packages.where(files.length < 3) { purl files.map(path) }` projection reads,
// so downstream a CVE matched to "Microsoft .NET Runtime - 8.0.11 (x64)" has no
// evidence: no "Located filepath", no Evidence card, nothing telling an
// operator which directory to go look at.
//
// The location is not actually unknown — .NET installs to a fixed, documented
// layout under the dotnet root. This file reconstructs the directory from the
// DisplayName and then CONFIRMS IT ON THE TARGET before attaching it. A guess
// that does not exist is dropped, so a relocated (DOTNET_ROOT) or preview
// install reports what it reports today: nothing. Evidence is only ever a
// directory we saw.
//
// Refs:
//   - https://learn.microsoft.com/dotnet/core/install/windows#install-location
//   - https://learn.microsoft.com/dotnet/core/versions/selection

// dotNetComponentSubdirs maps a .NET installer DisplayName to the directory
// its component owns, relative to the dotnet root.
//
// Patterns are anchored on the product name and matched in order. Each shape
// below was taken from a real Add/Remove Programs entry; the alternations are
// the spellings Microsoft has shipped over the 1.x → 10.x lifetime, all of
// which still occur in a mixed fleet.
var dotNetComponentSubdirs = []struct {
	name   *regexp.Regexp
	subdir []string
}{
	// WPF/WinForms. "Windows Desktop Runtime" is the current name,
	// ".NET Desktop Runtime" the earlier one.
	//
	//	Microsoft Windows Desktop Runtime - 8.0.11 (x64)
	//	Microsoft .NET Desktop Runtime - 6.0.36 (x64)
	{
		regexp.MustCompile(`^Microsoft (?:Windows Desktop Runtime|\.NET Desktop Runtime)\b`),
		[]string{"shared", "Microsoft.WindowsDesktop.App"},
	},
	// ASP.NET Core, which registers under two unrelated DisplayName shapes.
	// The version-in-the-middle shape must keep "Shared Framework" in the
	// pattern: its sibling "Microsoft ASP.NET Core 8.0.15 Targeting Pack" is a
	// different component that installs under packs\, not shared\.
	//
	//	Microsoft ASP.NET Core Runtime - 10.0.0 (x64)
	//	Microsoft ASP.NET Core 8.0.28 - Shared Framework (x86)
	//	Microsoft ASP.NET Core 8.0.15 Shared Framework (arm64)
	{
		regexp.MustCompile(`^Microsoft ASP\.NET Core (?:Runtime\b|\d[\d.]* (?:- )?Shared Framework\b)`),
		[]string{"shared", "Microsoft.AspNetCore.App"},
	},
	// The base runtime. ".NET Core Runtime" is the 1.x–3.x spelling.
	// "Microsoft .NET Framework" is a different product with its own
	// InstallPath in the registry (getDotNetFramework4x) and does not match.
	//
	//	Microsoft .NET Runtime - 8.0.11 (x64)
	//	Microsoft .NET Core Runtime - 3.1.32 (x64)
	{
		regexp.MustCompile(`^Microsoft \.NET (?:Core )?Runtime\b`),
		[]string{"shared", "Microsoft.NETCore.App"},
	},
	// The host resolver, versioned under host\fxr rather than shared\.
	//
	//	Microsoft .NET Host FX Resolver - 8.0.15 (arm64)
	{
		regexp.MustCompile(`^Microsoft \.NET Host FX Resolver\b`),
		[]string{"host", "fxr"},
	},
}

// dotNetHostEntry matches the muxer (dotnet.exe), which owns the dotnet root
// itself rather than a versioned directory beneath it. The " - " is required so
// this cannot swallow "Microsoft .NET Host FX Resolver", which is a different
// component handled above.
//
//	Microsoft .NET Host - 8.0.30 (arm64)
var dotNetHostEntry = regexp.MustCompile(`^Microsoft \.NET Host - `)

// dotNetComponentSubdir returns the dotnet-root-relative directory a .NET
// installer entry owns. versioned reports whether the release is appended as a
// final path segment; it is false only for the host muxer, which lives at the
// root.
func dotNetComponentSubdir(name string) (subdir []string, versioned bool, ok bool) {
	for _, c := range dotNetComponentSubdirs {
		if c.name.MatchString(name) {
			return c.subdir, true, true
		}
	}
	if dotNetHostEntry.MatchString(name) {
		return nil, false, true
	}
	return nil, false, false
}

// dotNetInstallDirCandidates returns the directories a .NET component of this
// DisplayName and release can occupy, most likely first. Nothing is claimed by
// returning a candidate — fillDotNetInstallPaths keeps only the one that exists
// on the target.
//
// Two spellings of every root are emitted because the same package list is
// built over connections with different filesystem roots: a local or remote
// Windows host reads the native `C:\Program Files\dotnet`, while a mounted
// image or device connection reads `Program Files/dotnet` relative to the mount
// (the same pair getFsAppxPackages searches for appx manifests).
//
// The 32-bit root is tried first when the DisplayName declares an x86 build,
// since a 32-bit runtime on a 64-bit host installs under Program Files (x86)
// while its 64-bit sibling of the SAME release sits under Program Files. Both
// are always probed, because the DisplayName's arch token is advisory: a 32-bit
// host has no (x86) suffix on its entries and no Program Files (x86) at all.
func dotNetInstallDirCandidates(name, version string) []string {
	subdir, versioned, ok := dotNetComponentSubdir(name)
	if !ok {
		return nil
	}

	segments := append([]string{}, subdir...)
	if versioned {
		if version == "" {
			return nil
		}
		segments = append(segments, version)
	}

	roots := []string{"Program Files", "Program Files (x86)"}
	if dotNetBuildIsX86(name) {
		roots = []string{"Program Files (x86)", "Program Files"}
	}

	candidates := make([]string, 0, len(roots)*2)
	for _, root := range roots {
		parts := append([]string{root, "dotnet"}, segments...)
		candidates = append(candidates,
			`C:\`+strings.Join(parts, `\`),
			strings.Join(parts, "/"),
		)
	}
	return candidates
}

// dotNetBuildIsX86 reports whether the DisplayName declares a 32-bit build, via
// the same "(x86)" / "(x64)" / "(arm64)" token normalizeDotNetInstallerArch
// reads. The Package's own Arch cannot answer this: it is normalized to the
// HOST architecture for 64-bit builds, so a 32-bit runtime and a 64-bit one on
// the same host are not distinguishable there.
func dotNetBuildIsX86(name string) bool {
	m := dotNetDisplayNameArch.FindStringSubmatch(name)
	return m != nil && strings.EqualFold(m[1], "x86")
}

// fillDotNetInstallPaths attaches the on-disk install directory to .NET
// installer entries the registry left without an InstallLocation.
//
// Only entries with no files are touched, so a real InstallLocation always
// wins over the reconstructed path, and only directories that exist on the
// target are attached — this never invents evidence. Probes are memoized
// because the .NET components on one host share their roots: a bundle install
// registers four entries that between them probe the same two or three
// directories.
func fillDotNetInstallPaths(fs afero.Fs, pkgs []Package) {
	if fs == nil {
		return
	}
	afs := &afero.Afero{Fs: fs}
	probed := map[string]bool{}

	for i := range pkgs {
		pkg := &pkgs[i]
		if pkg.Format != "windows/app" || len(pkg.Files) > 0 {
			continue
		}
		for _, dir := range dotNetInstallDirCandidates(pkg.Name, pkg.Version) {
			exists, seen := probed[dir]
			if !seen {
				var err error
				exists, err = afs.DirExists(dir)
				if err != nil {
					// A connection whose filesystem cannot answer (no file
					// capability, a permission error, an SFTP hiccup) leaves the
					// package exactly as it is today: no files, no evidence.
					log.Debug().Err(err).Str("path", dir).Msg("could not probe .NET install directory")
					exists = false
				}
				probed[dir] = exists
			}
			if !exists {
				continue
			}
			pkg.Files = []FileRecord{{Path: dir}}
			pkg.FilesAvailable = PkgFilesIncluded
			log.Debug().Str("package", pkg.Name).Str("path", dir).Msg("resolved .NET install directory")
			break
		}
	}
}
