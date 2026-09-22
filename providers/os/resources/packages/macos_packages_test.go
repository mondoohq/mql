// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

func TestMacOsXPackageParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_macos.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("system_profiler SPApplicationsDataType -xml")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	pf := &inventory.Platform{
		Name:    "macos",
		Version: "15.2",
		Arch:    "x86_64",
		Family:  []string{"darwin", "bsd", "unix", "os"},
	}
	m, err := packages.ParseMacOSPackages(mock, pf, c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 10, len(m), "detected the right amount of packages")

	assert.Equal(t, "Preview", m[0].Name, "pkg name detected")
	assert.Equal(t, "10.0", m[0].Version, "pkg version detected")
	assert.Equal(t, packages.MacosPkgFormat, m[0].Format, "pkg format detected")
	assert.Equal(t, packages.PkgFilesIncluded, m[0].FilesAvailable)
	assert.Equal(t, "pkg:macos/macos/Preview@10.0?arch=x86_64", m[0].PUrl)
	assert.Equal(t, []packages.FileRecord{{Path: "/Applications/Preview.app"}}, m[0].Files)
	assert.Equal(t, m[0].Arch, "x86_64")

	assert.Equal(t, "Contacts", m[1].Name, "pkg name detected")
	assert.Equal(t, "11.0", m[1].Version, "pkg version detected")
	assert.Equal(t, packages.MacosPkgFormat, m[1].Format, "pkg format detected")
	assert.Equal(t, packages.PkgFilesIncluded, m[1].FilesAvailable)
	assert.Equal(t, "pkg:macos/macos/Contacts@11.0?arch=x86_64", m[1].PUrl)
	assert.Equal(t, []packages.FileRecord{{Path: "/Applications/Contacts.app"}}, m[1].Files)

	assert.Equal(t, "Firefox", m[2].Name, "pkg name detected")
	assert.Equal(t, "128.12.0", m[2].Version, "pkg version detected")
	assert.Equal(t, packages.MacosPkgFormat, m[2].Format, "pkg format detected")
	assert.Equal(t, "pkg:macos/macos/Firefox@128.12.0?arch=x86_64&remoting-name=firefox-esr", m[2].PUrl)
	assert.Equal(t, []packages.FileRecord{{Path: "/Applications/Firefox.app"}}, m[2].Files)

	// system_profiler only surfaces CFBundleShortVersionString; when that is
	// absent (e.g. a PWA that ships only a CFBundleVersion) we recover the
	// version from the bundle's Info.plist.
	assert.Equal(t, "Microsoft Teams (PWA)", m[3].Name, "pkg name detected")
	assert.Equal(t, "7778.181", m[3].Version, "pkg version recovered from Info.plist")
	assert.Equal(t, "pkg:macos/macos/Microsoft%20Teams%20%28PWA%29@7778.181?arch=x86_64", m[3].PUrl)

	// An application bundle whose Info.plist carries no version keys at all is
	// still a real installed application, so it is reported with an empty
	// version rather than dropped.
	assert.Equal(t, "qFlipper", m[4].Name, "versionless app bundle kept")
	assert.Equal(t, "", m[4].Version, "no version available in the Info.plist")
	assert.Equal(t, "pkg:macos/macos/qFlipper?arch=x86_64", m[4].PUrl)

	// Wrapped iOS apps keep their Info.plist inside Wrapper/, so there is no
	// Contents/Info.plist to find. They report a version, so they must never
	// be dropped by the bundle check. An iPhone/iPad app running on Apple
	// Silicon is reported alongside native Mac apps and is only
	// distinguishable by its origin.
	assert.Equal(t, "Victory", m[5].Name, "wrapped iOS app kept")
	assert.Equal(t, "3.2.1", m[5].Version, "version reported by system_profiler")
	assert.Equal(t, "pkg:macos/macos/Victory@3.2.1?arch=x86_64", m[5].PUrl)
	assert.Equal(t, "ios_app_store", m[5].Origin, "iOS App Store provenance detected")

	// system_profiler's obtained_from is surfaced as the package origin, which
	// is what lets a consumer tell an App Store install from a direct download.
	// Both matter for remediation: `brew upgrade` cannot update either one.
	assert.Equal(t, "WireGuard", m[6].Name, "pkg name detected")
	assert.Equal(t, "1.0.16", m[6].Version, "pkg version detected")
	assert.Equal(t, "mac_app_store", m[6].Origin, "App Store provenance detected")

	// The pre-existing entries keep their own provenance — this is additive,
	// and macOS reported an empty origin for every package before now.
	assert.Equal(t, "apple", m[0].Origin, "OS-shipped app")
	assert.Equal(t, "identified_developer", m[2].Origin, "Developer ID-signed app")

	// A backup copy of an application is enumerated by system_profiler at the
	// version it held when it was set aside, and it is the only Docker entry
	// that survives if the newer real install is filtered by mistake. Assert
	// the installed version, not just the name: reporting 4.88.1 here is the
	// customer-visible bug (findings pinned to a version that is not on the
	// machine and that no upgrade can clear).
	assert.Equal(t, "Docker", m[7].Name, "real application kept")
	assert.Equal(t, "4.89.0", m[7].Version, "version of the installed bundle, not of the backup")
	assert.Equal(t, []packages.FileRecord{{Path: "/Applications/Docker.app"}}, m[7].Files)

	// system_profiler enumerates every path carrying a bundle-like extension,
	// not just application bundles. Entries with no version and no
	// Contents/Info.plist are not installed applications and are dropped
	// instead of being reported with an unusable, versionless purl.
	for _, dropped := range []string{
		"liquiddetectiond",     // bare .app directory holding a daemon
		"https+++bsky",         // Firefox origin storage directory
		"group.is.workflow.my", // app-group script container
	} {
		assert.NotContains(t, names(m), dropped, "non-application entry dropped")
	}

	// A dependency or build cache holds build inputs and build products, not
	// installed software. The Go module cache is the case seen in the field:
	// github.com/ollama/ollama vendors a prebuilt app skeleton under
	// app/darwin/ whose Info.plist carries the placeholder version 0.0.0, so
	// every host that has fetched the module reports a phantom Ollama install
	// next to the real one, once per cached module version. A 0.0.0 row sorts
	// below every advisory bound, so it matches every advisory for the product
	// no matter which version is actually installed.
	//
	// Only the real install survives, and it keeps its own version: asserting
	// the version rather than just the count is what catches a filter that
	// drops the wrong Ollama.
	ollama := findByName(m, "Ollama")
	assert.Len(t, ollama, 1, "only the installed Ollama bundle is reported")
	assert.Equal(t, "0.33.3", ollama[0].Version, "version of the installed bundle, not the 0.0.0 skeleton")
	assert.Equal(t, []packages.FileRecord{{Path: "/Applications/Ollama.app"}}, ollama[0].Files)

	// The module cache is matched by its /pkg/mod/ path segment, not by the
	// default $GOPATH: the second skeleton sits under a relocated GOPATH, and a
	// filter hardcoded to ~/go would let it through.
	for _, dropped := range []string{
		"Electron",   // vendored in node_modules, a dependency of a project
		"Scratchpad", // an Xcode build product under DerivedData
	} {
		assert.NotContains(t, names(m), dropped, "dependency or build cache entry dropped")
	}

	// Paths that are not an installed application bundle are dropped whatever
	// version they report, so a stale copy on disk cannot keep a fixed CVE open.
	for _, dropped := range []string{
		"Docker.app",     // /Applications/Docker.app.back, named by stripping .back
		"Docker Desktop", // helper bundle inside the backup's Contents/
		"DockerHelper",   // login item inside the backup's Contents/
		"AirDrop",        // ships inside Finder.app, patched with Finder
		"Spotlight",      // a .service bundle, not an application
	} {
		assert.NotContains(t, names(m), dropped, "non-application entry dropped")
	}

	// system_profiler enumerates what Launch Services has registered, which
	// includes a hypervisor's per-guest-application launcher stubs. Such a stub
	// carries the guest application's display name, so it arrives as a second
	// "Google Chrome" alongside the browser installed on this Mac -- and the
	// one seen in the field reports the guest OS name where a version belongs.
	//
	// Assert the surviving entry's version, not just the count: reporting
	// "Windows 11" is the customer-visible bug, and it reaches the purl too,
	// where the stub takes an identity that looks like the browser and matches
	// no advisory bound. The browser the stub launches lives in the virtual
	// machine, which is scanned as its own asset.
	chrome := findByName(m, "Google Chrome")
	assert.Len(t, chrome, 1, "only the browser installed on this Mac is reported")
	assert.Equal(t, "154.0.8037.45", chrome[0].Version, "version of the installed browser")
	assert.Equal(t, "pkg:macos/macos/Google%20Chrome@154.0.8037.45?arch=x86_64", chrome[0].PUrl)
	assert.Equal(t, []packages.FileRecord{{Path: "/Applications/Google Chrome.app"}}, chrome[0].Files)
}

func names(pkgs []packages.Package) []string {
	list := make([]string, len(pkgs))
	for i := range pkgs {
		list[i] = pkgs[i].Name
	}
	return list
}

func findByName(pkgs []packages.Package, name string) []packages.Package {
	var found []packages.Package
	for i := range pkgs {
		if pkgs[i].Name == name {
			found = append(found, pkgs[i])
		}
	}
	return found
}
