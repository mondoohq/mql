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
// A runtime entry whose directory is verifiably gone is dropped altogether (see
// fillDotNetInstallPaths): a failed uninstall leaves the Add/Remove Programs
// entry behind without the files, and reporting that runtime would raise
// findings nobody can close.
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

// dotNetSegments returns the path segments below a dotnet root that a .NET
// installer entry of this DisplayName and release owns, and whether the entry
// is a shared-framework runtime (as opposed to the host muxer or the host FX
// resolver). ok is false for anything that is not a known .NET component, and
// for a versioned component without a release.
func dotNetSegments(name, version string) (segments []string, runtime, ok bool) {
	subdir, versioned, ok := dotNetComponentSubdir(name)
	if !ok {
		return nil, false, false
	}
	segments = append([]string{}, subdir...)
	if versioned {
		if version == "" {
			return nil, false, false
		}
		segments = append(segments, version)
	}
	return segments, len(subdir) > 0 && subdir[0] == "shared", true
}

// dotNetInstallDirCandidates returns the directories a .NET component of this
// DisplayName and release can occupy under the default roots, most likely
// first. Nothing is claimed by returning a candidate — fillDotNetInstallPaths
// keeps only the one that exists on the target.
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
//
// The last roots are the per-architecture subfolders: on an ARM64 host the
// default location of the x64 (and x86) runtimes is `dotnet\x64` (`dotnet\x86`)
// beneath the native dotnet folder.
// https://learn.microsoft.com/dotnet/core/tools/dotnet-environment-variables#dotnet_root-dotnet_rootx86-dotnet_root_x86-dotnet_root_x64
func dotNetInstallDirCandidates(name, version string) []string {
	segments, _, ok := dotNetSegments(name, version)
	if !ok {
		return nil
	}

	roots := [][]string{{"Program Files", "dotnet"}, {"Program Files (x86)", "dotnet"}}
	if dotNetBuildIsX86(name) {
		roots[0], roots[1] = roots[1], roots[0]
	}
	roots = append(roots,
		[]string{"Program Files", "dotnet", "x64"},
		[]string{"Program Files", "dotnet", "x86"},
		[]string{"Program Files", "dotnet", "arm64"},
	)

	candidates := make([]string, 0, len(roots)*2)
	for _, root := range roots {
		parts := append(append([]string{}, root...), segments...)
		candidates = append(candidates,
			`C:\`+strings.Join(parts, `\`),
			strings.Join(parts, "/"),
		)
	}
	return candidates
}

// dotNetRootCandidates is dotNetInstallDirCandidates for a root recorded on the
// host (an InstallLocation or DOTNET_ROOT value) instead of a default one. root
// is a drive-absolute Windows path (`D:\dotnet`), or the same path relative to
// a mounted system volume (`tools/dotnet`).
func dotNetRootCandidates(root, name, version string) []string {
	segments, _, ok := dotNetSegments(name, version)
	if !ok {
		return nil
	}
	sep := "/"
	if strings.Contains(root, `\`) {
		sep = `\`
	}
	return []string{root + sep + strings.Join(segments, sep)}
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

// dotNetRootLookup reports the dotnet roots the host records outside the
// default Program Files locations, as drive-absolute Windows paths (or, on a
// mounted system volume, paths relative to the mount). complete is false when
// any source could not be read (no registry on this connection, a failed read,
// a value that cannot be resolved), in which case roots may be missing and
// nothing may be concluded from a directory's absence.
type dotNetRootLookup func() (roots []string, complete bool)

// dotNetPlainRelease is the shape of a release whose version folder is named
// exactly like the DisplayName's release. Previews and release candidates are
// left out: their folder name is the full product version, which the
// DisplayName does not always spell the same way.
var dotNetPlainRelease = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// fillDotNetInstallPaths attaches the on-disk install directory to .NET
// installer entries the registry left without an InstallLocation, and drops
// .NET runtime entries whose directory is gone.
//
// Only entries with no files are touched, so a real InstallLocation always
// wins over the reconstructed path, and only directories that exist on the
// target are attached — this never invents evidence. Probes are memoized
// because the .NET components on one host share their roots: a bundle install
// registers four entries that between them probe the same two or three
// directories.
//
// A failed uninstall can leave the Add/Remove Programs entry of a runtime
// behind with its files removed. The package would then report a runtime that
// is not on the host, and every advisory for that release becomes a finding
// that nothing can fix. A shared-framework runtime (Microsoft.NETCore.App,
// Microsoft.AspNetCore.App, Microsoft.WindowsDesktop.App) of a plain release is
// therefore dropped when its version folder is absent from EVERY place the host
// can have it: the default Program Files roots and the roots recorded by the
// host (relocated). It is kept, as before, whenever that cannot be established:
// relocated is nil or incomplete, a probe fails, the system volume cannot be
// seen through the filesystem, or a recorded root lies on a volume this
// connection cannot read. SDKs, the host muxer, the host FX resolver and .NET
// Framework are never dropped.
func fillDotNetInstallPaths(fs afero.Fs, pkgs []Package, relocated dotNetRootLookup) []Package {
	if fs == nil {
		return pkgs
	}
	afs := &afero.Afero{Fs: fs}

	type probeResult struct {
		exists bool
		err    error
	}
	probed := map[string]probeResult{}
	probe := func(dir string) probeResult {
		if r, seen := probed[dir]; seen {
			return r
		}
		exists, err := afs.DirExists(dir)
		if err != nil {
			// A connection whose filesystem cannot answer (no file
			// capability, a permission error, an SFTP hiccup) leaves the
			// package exactly as it is today: no files, no evidence, kept.
			log.Debug().Err(err).Str("path", dir).Msg("could not probe .NET install directory")
			exists = false
		}
		r := probeResult{exists, err}
		probed[dir] = r
		return r
	}

	// The filesystem must demonstrably show the system volume, or "not found"
	// may only mean "cannot see".
	systemVolume := func() bool {
		return probe(`C:\Windows`).exists || probe("Windows").exists
	}

	var (
		rootsLoaded    bool
		extraRoots     []string
		extraRootsDone bool
	)
	loadRoots := func() {
		if rootsLoaded {
			return
		}
		rootsLoaded = true
		if relocated != nil {
			extraRoots, extraRootsDone = relocated()
		}
	}

	kept := pkgs[:0]
	for i := range pkgs {
		pkg := pkgs[i]
		if pkg.Format != "windows/app" || len(pkg.Files) > 0 {
			kept = append(kept, pkg)
			continue
		}

		_, isRuntime, known := dotNetSegments(pkg.Name, pkg.Version)
		if !known {
			kept = append(kept, pkg)
			continue
		}

		// conclusive: every place checked answered, and none had the folder.
		conclusive := true
		match := ""
		for _, dir := range dotNetInstallDirCandidates(pkg.Name, pkg.Version) {
			r := probe(dir)
			if r.err != nil {
				conclusive = false
			}
			if r.exists {
				match = dir
				break
			}
		}

		if match == "" {
			loadRoots()
			if !extraRootsDone {
				conclusive = false
			}
			for _, root := range extraRoots {
				// A recorded root on another drive proves nothing unless the
				// drive itself is visible: a detached volume looks the same as
				// a deleted folder.
				if len(root) >= 3 && root[1] == ':' && root[2] == '\\' && !strings.EqualFold(root[:1], "c") {
					if v := probe(root[:3]); v.err != nil || !v.exists {
						conclusive = false
					}
				}
				for _, dir := range dotNetRootCandidates(root, pkg.Name, pkg.Version) {
					r := probe(dir)
					if r.err != nil {
						conclusive = false
					}
					if r.exists {
						match = dir
						break
					}
				}
				if match != "" {
					break
				}
			}
		}

		if match != "" {
			pkg.Files = []FileRecord{{Path: match}}
			pkg.FilesAvailable = PkgFilesIncluded
			log.Debug().Str("package", pkg.Name).Str("path", match).Msg("resolved .NET install directory")
			kept = append(kept, pkg)
			continue
		}

		if isRuntime && conclusive && dotNetPlainRelease.MatchString(pkg.Version) &&
			strings.Contains(pkg.Name, pkg.Version) && systemVolume() {
			log.Debug().Str("package", pkg.Name).Msg("dropping .NET runtime entry: its install directory is not on the host")
			continue
		}
		kept = append(kept, pkg)
	}
	return kept
}
