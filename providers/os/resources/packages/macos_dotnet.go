// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"path"
	"regexp"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

// dotnetRoot is a .NET installation root on macOS. The shared frameworks of
// the runtime live in <root>/shared/<framework>/<version>/.
type dotnetRoot struct {
	dir string
	// arch overrides the platform architecture. Empty means the host's.
	arch string
}

// macOSDotnetRoots are the roots the Microsoft installers and the Homebrew
// cask use. The x64 subdirectory holds x64 runtimes installed on Apple Silicon.
var macOSDotnetRoots = []dotnetRoot{
	{dir: "/usr/local/share/dotnet"},
	{dir: "/usr/local/share/dotnet/x64", arch: "x86_64"},
}

// macOSDotnetFrameworks are the shared frameworks reported as packages. Both
// receive security advisories of their own. Other frameworks are not listed:
// Microsoft.WindowsDesktop.App does not exist on macOS, and we only report
// what advisories can be matched against.
var macOSDotnetFrameworks = []string{
	"Microsoft.NETCore.App",
	"Microsoft.AspNetCore.App",
}

// dotnetVersionRe matches a release (8.0.10) or a prerelease
// (9.0.0-preview.7.24405.7) directory name.
var dotnetVersionRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$`)

// macOSDotnetPackages lists the installed .NET shared framework versions. The
// runtimes are plain directories, not application bundles, so neither
// system_profiler nor the application folders see them. Side-by-side versions
// are normal and each is its own package. Missing directories mean nothing is
// installed.
func macOSDotnetPackages(fs afero.Fs, platform *inventory.Platform) []Package {
	var pkgs []Package
	for _, root := range macOSDotnetRoots {
		arch := root.arch
		if arch == "" && platform != nil {
			arch = platform.Arch
		}
		for _, framework := range macOSDotnetFrameworks {
			dir := path.Join(root.dir, "shared", framework)
			versions, err := readDirNames(fs, dir)
			if err != nil {
				continue
			}
			for _, version := range versions {
				if !dotnetVersionRe.MatchString(version) {
					continue
				}
				if fi, err := fs.Stat(path.Join(dir, version)); err != nil || !fi.IsDir() {
					continue
				}
				pkgs = append(pkgs, Package{
					Name:    framework,
					Version: version,
					Format:  MacosPkgFormat,
					Arch:    arch,
					PUrl: purl.NewPackageURL(
						platform, purl.TypeMacos, framework, version,
						purl.WithArch(arch),
					).String(),
					Files: []FileRecord{{Path: path.Join(dir, version)}},
				})
			}
		}
	}
	return pkgs
}
