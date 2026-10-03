// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/utils/syncx"
)

// The composer.lock and installed.json extractors read a license, but until
// php.package carried the field there was nowhere for it to land: the value was
// set on languages.Package and the resource never mapped it, so `php.packages`
// answered `cannot find field or resource 'license'`. This pins the mapping, so
// the extractor work stays reachable from MQL rather than only from the Go API.
func TestPhpPackageCarriesLicenseAndDescription(t *testing.T) {
	runtime := &plugin.Runtime{
		Resources: &syncx.Map[plugin.Resource]{},
		Callback:  &providerCallbacks{},
	}

	pkg, err := newPhpPackage(runtime, &languages.Package{
		Name:    "dual/licensed",
		Version: "1.0.0",
		Purl:    "pkg:composer/dual/licensed@1.0.0",
		// What LicenseExpression renders for a composer.lock list: the package
		// is offered under either, and the consumer chooses.
		License:     "(LGPL-2.1-only OR GPL-3.0-or-later)",
		Description: "Two licenses",
	})
	require.NoError(t, err)

	require.Equal(t, "(LGPL-2.1-only OR GPL-3.0-or-later)", pkg.License.Data)
	require.Equal(t, "Two licenses", pkg.Description.Data)
}

// A package whose manifest declares neither reports empty rather than carrying
// a value from somewhere else, and the fields are still set so a query reads ""
// instead of failing.
func TestPhpPackageWithoutLicenseIsEmpty(t *testing.T) {
	runtime := &plugin.Runtime{
		Resources: &syncx.Map[plugin.Resource]{},
		Callback:  &providerCallbacks{},
	}

	pkg, err := newPhpPackage(runtime, &languages.Package{
		Name:    "bare/package",
		Version: "2.0.0",
		Purl:    "pkg:composer/bare/package@2.0.0",
	})
	require.NoError(t, err)

	require.Empty(t, pkg.License.Data)
	require.Empty(t, pkg.Description.Data)
	require.True(t, pkg.License.IsSet(), "the field must be set, so a query reads \"\" rather than erroring")
}

// Fails if /srv/www/htdocs is dropped from defaultPhpPaths: a composer.lock in
// SUSE's document root was never read by the default scan.
func TestPhpDefaultsSUSEDocroot(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// trimmed from the composer.lock in /srv/www/htdocs on a SLES 15 SP7 host
	require.NoError(t, afero.WriteFile(mockFS, "/srv/www/htdocs/composer.lock", []byte(`{
    "content-hash": "af8e842d49ff6d4bd3a16a4c5114ab90",
    "packages": [
        {
            "name": "composer/ca-bundle",
            "version": "1.5.14"
        }
    ],
    "packages-dev": []
}`), 0o644))

	r := &mqlPhpPackages{MqlRuntime: memFSRuntime(t, mockFS)}
	require.NoError(t, r.gatherData())
	require.Len(t, r.List.Data, 1)
	pkg := r.List.Data[0].(*mqlPhpPackage)
	assert.Equal(t, "composer/ca-bundle", pkg.Name.Data)
	assert.Equal(t, "1.5.14", pkg.Version.Data)
	require.Len(t, r.Files.Data, 1)
	assert.Equal(t, "/srv/www/htdocs/composer.lock", r.Files.Data[0].(*mqlPkgFileInfo).Path.Data)
}
