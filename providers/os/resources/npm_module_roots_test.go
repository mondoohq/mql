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

func writeNpmManifest(t *testing.T, fs afero.Fs, dir, name, version string) []byte {
	t.Helper()
	data := []byte(`{"name":"` + name + `","version":"` + version + `"}`)
	require.NoError(t, afero.WriteFile(fs, dir+"/package.json", data, 0o644))
	return data
}

func TestCollectNpmPackagesInPaths_debianModuleRoots(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// Debian 11: arch-independent modules and npm in /usr/share/nodejs, the
	// rest in /usr/lib/nodejs (names and versions from a Debian 11 host)
	writeNpmManifest(t, mockFS, "/usr/share/nodejs/npm", "npm", "7.5.2")
	writeNpmManifest(t, mockFS, "/usr/share/nodejs/node-gyp", "node-gyp", "7.1.2")
	writeNpmManifest(t, mockFS, "/usr/share/nodejs/@types/node", "@types/node", "14.14.20")
	writeNpmManifest(t, mockFS, "/usr/lib/nodejs/extend", "extend", "3.0.2")
	// @npmcli/node_modules links to npm/node_modules, it is not a package
	require.NoError(t, mockFS.MkdirAll("/usr/share/nodejs/@npmcli/node_modules", 0o755))
	// a global npm install beside them
	writeNpmManifest(t, mockFS, "/usr/local/lib/node_modules/semver", "semver", "7.5.0")

	r := npmTestRuntime(t, mockFS)
	direct, _, _, err := collectNpmPackagesInPaths(r, mockFS, defaultNpmPaths)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"npm@7.5.2", "node-gyp@7.1.2", "@types/node@14.14.20", "extend@3.0.2", "semver@7.5.0",
	}, npmNameVersions(direct))
}

func TestCollectNpmPackagesInPaths_debian9LibNodejs(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// Debian 9: node-lodash and node-semver install into /usr/lib/nodejs
	writeNpmManifest(t, mockFS, "/usr/lib/nodejs/lodash", "lodash", "4.16.6")
	writeNpmManifest(t, mockFS, "/usr/lib/nodejs/semver", "semver", "5.3.0")

	r := npmTestRuntime(t, mockFS)
	direct, _, _, err := collectNpmPackagesInPaths(r, mockFS, []string{"/usr/lib/nodejs"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"lodash@4.16.6", "semver@5.3.0"}, npmNameVersions(direct))
}

func TestCollectNpmPackagesInPaths_debianAliasesReportedOnce(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// Debian links gyp -> node-gyp and lodash-es/package.json ->
	// ../lodash/package.json, so both aliases carry the sibling's manifest
	gyp := writeNpmManifest(t, mockFS, "/usr/share/nodejs/node-gyp", "node-gyp", "7.1.2")
	require.NoError(t, afero.WriteFile(mockFS, "/usr/share/nodejs/gyp/package.json", gyp, 0o644))
	lodash := writeNpmManifest(t, mockFS, "/usr/share/nodejs/lodash", "lodash", "4.17.21")
	require.NoError(t, afero.WriteFile(mockFS, "/usr/share/nodejs/lodash-es/package.json", lodash, 0o644))
	// a directory whose manifest names another package that is not installed
	// under its own name is still reported
	writeNpmManifest(t, mockFS, "/usr/share/nodejs/duplexer2", "duplexer3", "0.1.4")

	r := npmTestRuntime(t, mockFS)
	direct, _, _, err := collectNpmPackagesInPaths(r, mockFS, []string{"/usr/share/nodejs"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"node-gyp@7.1.2", "lodash@4.17.21", "duplexer3@0.1.4"}, npmNameVersions(direct))
}

func TestIsNodeModuleRootPath(t *testing.T) {
	for _, p := range []string{
		"/usr/share/nodejs",
		"/usr/share/nodejs/",
		"/usr/lib/nodejs",
		"/usr/lib/x86_64-linux-gnu/nodejs",
		"/usr/lib/*/nodejs",
		"/usr/lib/node_modules",
		"/usr/lib/node_modules_24",
		"/srv/app/node_modules",
	} {
		assert.True(t, isNodeModuleRootPath(p), p)
	}
	for _, p := range []string{
		"/usr/lib",
		"/usr/local/lib",
		"/srv/nodejs",
		"/usr/share/nodejs/npm",
		"/srv/app",
		"/srv/app/package.json",
	} {
		assert.False(t, isNodeModuleRootPath(p), p)
	}
}

func TestCollectNpmPackagesInPaths_debianPackageWithUpstreamLockfile(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// Debian 12's node-browserslist ships upstream's pnpm-lock.yaml next to
	// package.json; the installed package is what package.json describes
	writeNpmManifest(t, mockFS, "/usr/share/nodejs/browserslist", "browserslist", "4.21.4")
	require.NoError(t, afero.WriteFile(mockFS, "/usr/share/nodejs/browserslist/pnpm-lock.yaml", []byte(`lockfileVersion: 5.4

specifiers:
  '@logux/eslint-config': ^47.2.0
  c8: ^7.12.0
  caniuse-lite: ^1.0.30001400
`), 0o644))

	r := npmTestRuntime(t, mockFS)
	direct, _, _, err := collectNpmPackagesInPaths(r, mockFS, defaultNpmPaths)
	require.NoError(t, err)
	assert.Equal(t, []string{"browserslist@4.21.4"}, npmNameVersions(direct))
}

// Fails if /usr/lib64 is dropped from defaultNpmPaths: on SLES and openSUSE
// Leap the npm bundled with each nodejs package is the only npm on the host,
// and npm.packages.list.none(name == "npm") passes.
func TestCollectNpmPackagesInPaths_suseLib64BundledNpm(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// SLES 16.0 with nodejs22 and nodejs24: no /usr/lib/node_modules, each
	// npm in /usr/lib64/node_modules/npm<major> (versions from those hosts)
	writeNpmManifest(t, mockFS, "/usr/lib64/node_modules/npm22", "npm", "10.9.8")
	writeNpmManifest(t, mockFS, "/usr/lib64/node_modules/npm24", "npm", "11.16.0")

	r := npmTestRuntime(t, mockFS)
	direct, _, _, err := collectNpmPackagesInPaths(r, mockFS, defaultNpmPaths)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"npm@10.9.8", "npm@11.16.0"}, npmNameVersions(direct))
}
