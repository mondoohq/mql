// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/sbom"
)

// Imported Windows SBOMs need windows/app, windows/appx and windows/hotfix
// packages in the recording, otherwise packages.list comes back empty and
// vulnerability matching has nothing to chew on. Hotfix entries also carry
// no purl, so the recording ID must fall back to the package name.
func TestNewRecording_WindowsPackages(t *testing.T) {
	asset := &inventory.Asset{
		Name: "WIN-TEST01",
		Platform: &inventory.Platform{
			Name:    "windows",
			Title:   "Microsoft Windows Server 2012 R2 Standard",
			Version: "9600",
			Arch:    "AMD64",
			Family:  []string{"windows", "os"},
		},
	}

	doc := &sbom.Sbom{
		Asset: &sbom.Asset{
			Name: asset.Name,
			Platform: &sbom.Platform{
				Name:    asset.Platform.Name,
				Title:   asset.Platform.Title,
				Version: asset.Platform.Version,
				Arch:    asset.Platform.Arch,
				Family:  asset.Platform.Family,
			},
		},
		Packages: []*sbom.Package{
			{Name: "alpine-baselayout", Version: "3.4.3-r2", Purl: "pkg:apk/alpine/alpine-baselayout@3.4.3-r2", Type: "apk"},
			{Name: "VMware Tools", Version: "12.1.5.20735119", Purl: "pkg:windows/windows/VMware%20Tools@12.1.5.20735119", Type: "windows/app"},
			{Name: "Microsoft.UI.Xaml.2.4", Version: "2.42007.9001.0", Purl: "pkg:windows/windows/Microsoft.UI.Xaml.2.4@2.42007.9001.0", Type: "windows/appx"},
			{Name: "KB2919355", Type: "windows/hotfix"},
			{Name: "KB2999226", Type: "windows/hotfix"},
		},
	}

	rec, err := newRecording(asset, doc)
	require.NoError(t, err)

	packages, ok := rec.GetResource("packages", "")
	require.True(t, ok, "packages resource must exist")

	list, ok := packages.Fields["list"]
	require.True(t, ok, "packages.list field must exist")

	refs, ok := list.Value.([]any)
	require.True(t, ok, "packages.list must be an array")
	assert.Len(t, refs, 5, "every supported os package type must show up in packages.list")

	seenIDs := map[string]bool{}
	for i, pkg := range doc.Packages {
		// Mirror the production fallback (newOsPackage): use purl when set,
		// else name. Hotfixes have no purl so the recording must key them by
		// name to keep IDs unique.
		lookupKey := pkg.Purl
		if lookupKey == "" {
			lookupKey = pkg.Name
		}
		pkgRes, ok := rec.GetResource("package", lookupKey)
		require.Truef(t, ok, "package %d (%s) missing from recording", i, pkg.Name)
		assert.NotEmptyf(t, pkgRes.ID, "package %s recording ID must not be empty", pkg.Name)
		assert.Falsef(t, seenIDs[pkgRes.ID], "package ID %q collides between two recording resources", pkgRes.ID)
		seenIDs[pkgRes.ID] = true
	}
}
