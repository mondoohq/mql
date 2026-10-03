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

// The default npm search missed the global packages of every Node version nvm
// installs (npm -g under nvm puts them in ~/.nvm/versions/node/<v>/lib), and
// projects in /home/<user>/app other than /home/node/app, so a check that no
// vulnerable lodash is installed passed on a host that had it. Fails if either
// default is dropped, or if /home/node/app is listed twice and its packages
// reported twice.
func TestNpmDefaultsFindNvmGlobalsAndHomeApps(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	write := func(p, content string) {
		require.NoError(t, afero.WriteFile(mockFS, p, []byte(content), 0o644))
	}
	write("/home/ubuntu/.nvm/versions/node/v20.18.0/lib/node_modules/lodash/package.json", `{"name":"lodash","version":"4.17.20"}`)
	write("/root/.nvm/versions/node/v22.11.0/lib/node_modules/left-pad/package.json", `{"name":"left-pad","version":"1.3.0"}`)
	write("/home/alice/app/package.json", `{"name":"alice-app","version":"1.0.0"}`)
	write("/home/node/app/package.json", `{"name":"node-app","version":"2.0.0"}`)

	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{}, "", nil, mockFS)
	require.NoError(t, err)
	r := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}

	direct, _, _, err := collectNpmPackagesInPaths(r, conn.FileSystem(), defaultNpmPaths)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"lodash@4.17.20",
		"left-pad@1.3.0",
		"alice-app@1.0.0",
		"node-app@2.0.0",
	}, packageNames(direct))
}
