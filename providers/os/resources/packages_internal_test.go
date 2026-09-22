// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/resources/packages"
	"go.mondoo.com/mql/v13/utils/syncx"
)

// list() reuses one args map for every package, so fillPackageArgs has to
// leave no trace of the previous one. license is the field that exposes this:
// it is only set when the backend reported one, so without the clear a package
// that has no license inherits whichever license came before it.
func TestFillPackageArgsDoesNotLeakBetweenPackages(t *testing.T) {
	args := make(map[string]*llx.RawData, 15)
	installed := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	withLicense := packages.Package{
		Name: "openssl", Version: "3.0.11", Arch: "x86_64", Format: "rpm",
		License: "Apache-2.0", InstallDate: installed,
	}
	withoutLicense := packages.Package{
		Name: "libfoo", Version: "1.2.3", Arch: "amd64", Format: "deb",
	}

	fillPackageArgs(args, &withLicense, "", nil)
	require.Contains(t, args, "license")
	assert.Equal(t, "Apache-2.0", args["license"].Value)
	require.IsType(t, &time.Time{}, args["installDate"].Value)
	assert.Equal(t, installed, *args["installDate"].Value.(*time.Time))

	fillPackageArgs(args, &withoutLicense, "", nil)
	assert.NotContains(t, args, "license",
		"license leaked from the previous package")
	assert.Equal(t, llx.NilData.Value, args["installDate"].Value,
		"installDate leaked from the previous package")
	assert.Equal(t, "libfoo", args["name"].Value)
	assert.Equal(t, "deb", args["format"].Value)
}

func TestFillPackageArgs(t *testing.T) {
	args := make(map[string]*llx.RawData, 15)

	pkg := packages.Package{
		Name:        "openssl",
		Version:     "3.0.11-1",
		Arch:        "x86_64",
		Status:      "install ok installed",
		Description: "TLS toolkit",
		Format:      "rpm",
		Origin:      "openssl-src",
		Epoch:       "1",
		PUrl:        "pkg:rpm/redhat/openssl@3.0.11-1?arch=x86_64",
		Vendor:      "Red Hat",
	}
	fillPackageArgs(args, &pkg, "3.0.12-1", nil)

	assert.Equal(t, "openssl", args["name"].Value)
	assert.Equal(t, "3.0.11-1", args["version"].Value)
	assert.Equal(t, "3.0.12-1", args["available"].Value)
	assert.Equal(t, "x86_64", args["arch"].Value)
	assert.Equal(t, "install ok installed", args["status"].Value)
	assert.Equal(t, "TLS toolkit", args["description"].Value)
	assert.Equal(t, "rpm", args["format"].Value)
	assert.Equal(t, true, args["installed"].Value)
	assert.Equal(t, "openssl-src", args["origin"].Value)
	assert.Equal(t, "1", args["epoch"].Value)
	assert.Equal(t, "pkg:rpm/redhat/openssl@3.0.11-1?arch=x86_64", args["purl"].Value)
	assert.Equal(t, "Red Hat", args["vendor"].Value)

	// An absent install date must stay a real null rather than becoming the Go
	// zero time, which would report 0001-01-01 as a genuine install date.
	assert.Equal(t, llx.NilData.Value, args["installDate"].Value)

	// dpkg reports no license inline; the key must stay absent so the lazy
	// license() accessor still runs.
	assert.NotContains(t, args, "license")
}

// The reuse is only sound because CreateResource copies every value out and
// keeps no reference to the map. If it ever retained one, every package would
// collapse onto the last package's values.
func TestCreateResourceDoesNotRetainArgs(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	args := make(map[string]*llx.RawData, 15)

	pkgs := []packages.Package{
		{Name: "alpha", Version: "1.0", Arch: "amd64", Format: "deb", License: "MIT"},
		{Name: "beta", Version: "2.0", Arch: "amd64", Format: "deb"},
		{Name: "gamma", Version: "3.0", Arch: "amd64", Format: "deb", License: "GPL-2.0"},
	}

	created := make([]*mqlPackage, 0, len(pkgs))
	for i := range pkgs {
		fillPackageArgs(args, &pkgs[i], "", nil)
		res, err := CreateResource(runtime, "package", args)
		require.NoError(t, err)
		created = append(created, res.(*mqlPackage))
	}

	for i, got := range created {
		assert.Equal(t, pkgs[i].Name, got.Name.Data, "package %d name", i)
		assert.Equal(t, pkgs[i].Version, got.Version.Data, "package %d version", i)
	}

	// beta has no license of its own and must not have picked up alpha's.
	assert.Equal(t, "MIT", created[0].License.Data)
	assert.Empty(t, created[1].License.Data, "beta inherited a license")
	assert.Equal(t, "GPL-2.0", created[2].License.Data)
}

// Two macOS bundles can share a name and version (Siri.app and Siri AI.app
// both report "Siri" 1.0). Their ids have to differ by bundle path, or the
// resource cache hands the second bundle the first one's resource.
func TestMacOSBundlesWithSameNameAndVersionStayDistinct(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	args := make(map[string]*llx.RawData, 15)

	pkgs := []packages.Package{
		{Name: "Siri", Version: "1.0", Arch: "arm64", Format: packages.MacosPkgFormat, Files: []packages.FileRecord{{Path: "/System/Applications/Siri.app"}}},
		{Name: "Siri", Version: "1.0", Arch: "arm64", Format: packages.MacosPkgFormat, Files: []packages.FileRecord{{Path: "/System/Applications/Siri AI.app"}}},
	}

	created := make([]*mqlPackage, 0, len(pkgs))
	for i := range pkgs {
		fillPackageArgs(args, &pkgs[i], "", nil)
		res, err := CreateResource(runtime, "package", args)
		require.NoError(t, err)
		created = append(created, res.(*mqlPackage))
	}

	assert.NotSame(t, created[0], created[1])
	assert.Equal(t, "macos://Siri/1.0/arm64/path/System/Applications/Siri.app", created[0].__id)
	assert.Equal(t, "macos://Siri/1.0/arm64/path/System/Applications/Siri AI.app", created[1].__id)
}

// Only macOS packages are keyed by path. A deb or rpm lists the files it
// installs, and a package that happens to install exactly one file keeps the
// id it always had.
func TestPackageIDIgnoresFilesOutsideMacOS(t *testing.T) {
	files := []packages.FileRecord{{Path: "/usr/bin/tool"}}
	assert.Equal(t, "deb://tool/1.0/amd64", packageID("deb", "tool", "1.0", "amd64", files))

	// A macOS package without its file record has no path to add.
	assert.Equal(t, "macos://Safari/27.0/arm64", packageID(packages.MacosPkgFormat, "Safari", "27.0", "arm64", nil))
}
