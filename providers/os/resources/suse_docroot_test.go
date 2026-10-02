// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/utils/syncx"
)

func docrootTestRuntime(t *testing.T, mockFS afero.Fs) *plugin.Runtime {
	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{}, "", nil, mockFS)
	require.NoError(t, err)
	return &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}
}

// akismetReadme is the start of the readme.txt of the akismet plugin bundled
// with WordPress 6.6.2, as installed on a SLES 15 SP7 host.
const akismetReadme = `=== Akismet Anti-spam: Spam Protection ===
Contributors: matt, ryan, andy, mdawaffe, tellyworth, josephscott, lessbloat, eoigal, cfinke, automattic, jgs, procifer, stephdau, kbrownkd, bluefuton, akismetantispam
Stable tag: 5.3.3
`

// SUSE's Apache serves /srv/www/htdocs. Fails if the SUSE document root paths
// are dropped from defaultWordPressPluginPaths: WordPress installed there was
// invisible to the default scan, and a plugin version check passed.
func TestWordPressDefaultsSUSEDocroot(t *testing.T) {
	for _, dir := range []string{"/srv/www/htdocs/wordpress", "/srv/www/htdocs"} {
		t.Run(dir, func(t *testing.T) {
			mockFS := afero.NewMemMapFs()
			require.NoError(t, afero.WriteFile(mockFS, dir+"/wp-content/plugins/akismet/readme.txt", []byte(akismetReadme), 0o644))

			r := &mqlWordpressPackages{MqlRuntime: docrootTestRuntime(t, mockFS)}
			require.NoError(t, r.gatherData())
			require.Len(t, r.List.Data, 1)
			pkg := r.List.Data[0].(*mqlWordpressPackage)
			assert.Equal(t, "akismet", pkg.Name.Data)
			assert.Equal(t, "5.3.3", pkg.Version.Data)
		})
	}
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

	r := &mqlPhpPackages{MqlRuntime: docrootTestRuntime(t, mockFS)}
	require.NoError(t, r.gatherData())
	require.Len(t, r.List.Data, 1)
	pkg := r.List.Data[0].(*mqlPhpPackage)
	assert.Equal(t, "composer/ca-bundle", pkg.Name.Data)
	assert.Equal(t, "1.5.14", pkg.Version.Data)
	require.Len(t, r.Files.Data, 1)
	assert.Equal(t, "/srv/www/htdocs/composer.lock", r.Files.Data[0].(*mqlPkgFileInfo).Path.Data)
}
