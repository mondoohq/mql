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
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/utils/syncx"
)

// npm11PackageJSON is the start of the package.json nodejs24-npm installs on Fedora 44.
const npm11PackageJSON = `{
  "version": "11.16.0",
  "name": "npm",
  "description": "a package manager for JavaScript"
}`

func npmTestRuntime(t *testing.T, mockFS afero.Fs) *plugin.Runtime {
	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{}, "", nil, mockFS)
	require.NoError(t, err)
	return &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}
}

func npmNameVersions(pkgs []*languages.Package) []string {
	res := []string{}
	for _, p := range pkgs {
		res = append(res, p.Name+"@"+p.Version)
	}
	return res
}

func TestCollectNpmPackagesInPaths_fedoraVersionedNodeModules(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// Fedora 44: /usr/lib/node_modules is empty, nodejs24-npm lives in
	// /usr/lib/node_modules_24
	require.NoError(t, mockFS.MkdirAll("/usr/lib/node_modules", 0o755))
	require.NoError(t, afero.WriteFile(mockFS, "/usr/lib/node_modules_24/npm/package.json", []byte(npm11PackageJSON), 0o644))
	require.NoError(t, afero.WriteFile(mockFS, "/usr/lib/node_modules_24/@scope/tool/package.json", []byte(`{"name":"@scope/tool","version":"1.2.3"}`), 0o644))
	// a file directly in the directory is not a package
	require.NoError(t, afero.WriteFile(mockFS, "/usr/lib/node_modules_24/.package-lock.json", []byte(`{}`), 0o644))

	r := npmTestRuntime(t, mockFS)
	direct, _, _, err := collectNpmPackagesInPaths(r, mockFS, defaultNpmPaths)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"npm@11.16.0", "@scope/tool@1.2.3"}, npmNameVersions(direct))
}

func TestCollectNpmPackagesInPaths_rhel10LinkedNodeModulesOnce(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// RHEL 10: /usr/lib/node_modules -> node_modules_22, so the same npm is
	// visible under both names and must be reported once
	npm10 := []byte(`{"name":"npm","version":"10.9.8"}`)
	require.NoError(t, afero.WriteFile(mockFS, "/usr/lib/node_modules/npm/package.json", npm10, 0o644))
	require.NoError(t, afero.WriteFile(mockFS, "/usr/lib/node_modules_22/npm/package.json", npm10, 0o644))

	r := npmTestRuntime(t, mockFS)
	direct, _, _, err := collectNpmPackagesInPaths(r, mockFS, defaultNpmPaths)
	require.NoError(t, err)
	assert.Equal(t, []string{"npm@10.9.8"}, npmNameVersions(direct))
}

func TestCollectNpmPackagesInPaths_differentVersionsInBothDirs(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// two nodejs streams side by side: each npm is a separate install
	require.NoError(t, afero.WriteFile(mockFS, "/usr/lib/node_modules/npm/package.json", []byte(`{"name":"npm","version":"10.9.8"}`), 0o644))
	require.NoError(t, afero.WriteFile(mockFS, "/usr/lib/node_modules_24/npm/package.json", []byte(npm11PackageJSON), 0o644))

	r := npmTestRuntime(t, mockFS)
	direct, _, _, err := collectNpmPackagesInPaths(r, mockFS, defaultNpmPaths)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"npm@10.9.8", "npm@11.16.0"}, npmNameVersions(direct))
}
