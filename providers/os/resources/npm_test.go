// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/syncx"
)

func TestNpmPackage_unique(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// create test files and directories
	err := mockFS.MkdirAll("/usr/local/lib/node_modules/generator-code", 0o755)
	require.NoError(t, err)
	err = mockFS.MkdirAll("/usr/local/lib/node_modules/yo", 0o755)
	require.NoError(t, err)

	// Read package.json files from testdata
	yoPkg, err := os.ReadFile(filepath.Join("packages", "testdata", "yo_package.json"))
	require.NoError(t, err)
	require.NotNil(t, yoPkg)

	gcPkg, err := os.ReadFile(filepath.Join("packages", "testdata", "gc_package.json"))
	require.NoError(t, err)
	require.NotNil(t, gcPkg)

	// Both declare yosay. A range ("^2.0.2") is not an installed version and is
	// not listed, so pin each one: the same name then comes from two files.
	yoPkg = bytes.Replace(yoPkg, []byte(`"yosay": "^2.0.2"`), []byte(`"yosay": "2.0.2"`), 1)
	gcPkg = bytes.Replace(gcPkg, []byte(`"yosay": "^3.0.0"`), []byte(`"yosay": "3.0.0"`), 1)

	err = afero.WriteFile(mockFS, "/usr/local/lib/node_modules/generator-code/package.json", gcPkg, 0o644)
	require.NoError(t, err)
	err = afero.WriteFile(mockFS, "/usr/local/lib/node_modules/yo/package.json", yoPkg, 0o644)
	require.NoError(t, err)

	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{}, "", nil, mockFS)
	require.NoError(t, err)

	r := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}
	mqlNpm := &mqlNpmPackages{
		MqlRuntime: r,
	}

	// Create resources from filesystem
	err = mqlNpm.gatherData()
	require.NoError(t, err)

	// Check that we have 4 packages
	require.Equal(t, 4, len(mqlNpm.List.Data))

	// Check that the first package is yosay
	pkg2 := mqlNpm.List.Data[2].(*mqlNpmPackage)
	require.Equal(t, "yosay", pkg2.Name.Data)
	require.Equal(t, "2.0.2", pkg2.Version.Data)

	// Check that the third package is also yosay, but with a different version
	pkg3 := mqlNpm.List.Data[3].(*mqlNpmPackage)
	require.Equal(t, "yosay", pkg3.Name.Data)
	require.Equal(t, "3.0.0", pkg3.Version.Data)

	// To get the correct data, we need distinct IDs
	require.NotEqual(t, pkg2.MqlID(), pkg3.MqlID())
	require.Equal(t, "yosay/usr/local/lib/node_modules/yo/package.json", pkg2.MqlID())
	require.Equal(t, "yosay/usr/local/lib/node_modules/generator-code/package.json", pkg3.MqlID())
}

// Mock callbacks for testing
// These are needed during calls to CreateSharedResource
type providerCallbacks struct{}

func (p *providerCallbacks) GetData(req *plugin.DataReq) (*plugin.DataRes, error) {
	return &plugin.DataRes{
		Data: &llx.Primitive{
			Type:  string(types.Resource(req.Resource)),
			Value: []byte("not of interest"),
		},
	}, nil
}

func (p *providerCallbacks) GetRecording(req *plugin.DataReq) (*plugin.ResourceData, error) {
	res := plugin.ResourceData{}
	return &res, nil
}

func (p *providerCallbacks) Collect(req *plugin.DataRes) error {
	return nil
}

func TestCollectNpmPackagesInPaths(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T, afero.Fs) string
		validate func(*testing.T, []*languages.Package, []*languages.Package, []string)
	}{
		{
			name: "root package.json, no lock file, no node_modules",
			setup: func(t *testing.T, mockFS afero.Fs) string {
				// Create a test project directory with package.json at root (no lock file, no node_modules)
				testProjectPath := "/app"
				err := mockFS.MkdirAll(testProjectPath, 0o755)
				require.NoError(t, err)

				// Create a simple package.json at root
				rootPackageJSON := `{
					"name": "test-app",
					"version": "1.0.0",
					"dependencies": {
						"lodash": "^4.17.21"
					}
				}`
				err = afero.WriteFile(mockFS, filepath.Join(testProjectPath, "package.json"), []byte(rootPackageJSON), 0o644)
				require.NoError(t, err)
				return testProjectPath
			},
			validate: func(t *testing.T, direct, transitive []*languages.Package, evidenceFiles []string) {
				require.Empty(t, evidenceFiles)
				require.Greater(t, len(direct), 0, "should find at least the root package")

				foundRoot := false
				for _, pkg := range direct {
					if pkg.Name == "test-app" {
						foundRoot = true
						require.Equal(t, "1.0.0", pkg.Version)
						break
					}
				}
				require.True(t, foundRoot, "should find root package 'test-app'")

				// "lodash": "^4.17.21" is declared, not installed: nothing is in node_modules
				for _, pkg := range transitive {
					require.NotEqual(t, "lodash", pkg.Name, "a declared range is not an installed package")
				}
			},
		},
		{
			name: "with lock file",
			setup: func(t *testing.T, mockFS afero.Fs) string {
				// Create a test project with package-lock.json at root
				testProjectPath := "/app"
				err := mockFS.MkdirAll(testProjectPath, 0o755)
				require.NoError(t, err)

				// Create package.json at root
				rootPackageJSON := `{
					"name": "test-app",
					"version": "1.0.0"
				}`
				err = afero.WriteFile(mockFS, filepath.Join(testProjectPath, "package.json"), []byte(rootPackageJSON), 0o644)
				require.NoError(t, err)

				// Create package-lock.json at root (this should cause node_modules to be skipped)
				packageLockJSON := `{
					"name": "test-app",
					"version": "1.0.0",
					"lockfileVersion": 2
				}`
				err = afero.WriteFile(mockFS, filepath.Join(testProjectPath, "package-lock.json"), []byte(packageLockJSON), 0o644)
				require.NoError(t, err)

				// Create node_modules directory with a package (should be skipped due to lock file)
				err = mockFS.MkdirAll(filepath.Join(testProjectPath, "node_modules", "some-package"), 0o755)
				require.NoError(t, err)
				nodeModulesPackageJSON := `{
					"name": "some-package",
					"version": "2.0.0"
				}`
				err = afero.WriteFile(mockFS, filepath.Join(testProjectPath, "node_modules", "some-package", "package.json"), []byte(nodeModulesPackageJSON), 0o644)
				require.NoError(t, err)
				return testProjectPath
			},
			validate: func(t *testing.T, direct, transitive []*languages.Package, evidenceFiles []string) {
				require.Empty(t, evidenceFiles)
				require.Greater(t, len(direct), 0, "should find at least the root package")

				// Should NOT find the node_modules package (because lock file exists)
				foundNodeModulesPackage := false
				for _, pkg := range direct {
					if pkg.Name == "some-package" {
						foundNodeModulesPackage = true
						break
					}
				}
				require.False(t, foundNodeModulesPackage, "should not find node_modules package when lock file exists")
			},
		},
		{
			name: "root and node_modules, no lock file",
			setup: func(t *testing.T, mockFS afero.Fs) string {
				// Create a test project with both root package.json and node_modules
				testProjectPath := "/app"
				err := mockFS.MkdirAll(testProjectPath, 0o755)
				require.NoError(t, err)

				// Create package.json at root (no lock file)
				rootPackageJSON := `{
					"name": "test-app",
					"version": "1.0.0"
				}`
				err = afero.WriteFile(mockFS, filepath.Join(testProjectPath, "package.json"), []byte(rootPackageJSON), 0o644)
				require.NoError(t, err)

				// Create node_modules directory with a package (should be checked since no lock file)
				err = mockFS.MkdirAll(filepath.Join(testProjectPath, "node_modules", "lodash"), 0o755)
				require.NoError(t, err)

				// Read test data for a real package
				yoPkg, err := os.ReadFile(filepath.Join("packages", "testdata", "yo_package.json"))
				require.NoError(t, err)
				err = afero.WriteFile(mockFS, filepath.Join(testProjectPath, "node_modules", "lodash", "package.json"), yoPkg, 0o644)
				require.NoError(t, err)
				return testProjectPath
			},
			validate: func(t *testing.T, direct, transitive []*languages.Package, evidenceFiles []string) {
				require.Empty(t, evidenceFiles)
				// Should find packages from both root and node_modules
				require.Greater(t, len(direct)+len(transitive), 0, "should find packages from root and/or node_modules")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFS := afero.NewMemMapFs()
			testProjectPath := tt.setup(t, mockFS)

			conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{}, "", nil, mockFS)
			require.NoError(t, err)

			r := &plugin.Runtime{
				Resources:  &syncx.Map[plugin.Resource]{},
				Connection: conn,
				Callback:   &providerCallbacks{},
			}

			direct, transitive, evidenceFiles, err := collectNpmPackagesInPaths(r, conn.FileSystem(), []string{testProjectPath})
			require.NoError(t, err)

			tt.validate(t, direct, transitive, evidenceFiles)
		})
	}
}

// TestCollectNpmPackagesInPaths_filtering tests the filtering logic for non-existent paths
func TestCollectNpmPackagesInPaths_skipsNoneExistentPaths(t *testing.T) {
	mockFS := afero.NewMemMapFs()

	// Create a valid path with package.json
	validPath := "/app1"
	err := mockFS.MkdirAll(validPath, 0o755)
	require.NoError(t, err)

	rootPackageJSON := `{
		"name": "test-app-1",
		"version": "1.0.0"
	}`
	err = afero.WriteFile(mockFS, filepath.Join(validPath, "package.json"), []byte(rootPackageJSON), 0o644)
	require.NoError(t, err)

	// Create another valid path with package.json
	validPath2 := "/app2"
	err = mockFS.MkdirAll(validPath2, 0o755)
	require.NoError(t, err)

	rootPackageJSON2 := `{
		"name": "test-app-2",
		"version": "2.0.0"
	}`
	err = afero.WriteFile(mockFS, filepath.Join(validPath2, "package.json"), []byte(rootPackageJSON2), 0o644)
	require.NoError(t, err)

	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{}, "", nil, mockFS)
	require.NoError(t, err)

	r := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}

	// Test with multiple paths: some exist, some don't
	// This tests the filtering logic in collectNpmPackages and hasLockfile
	paths := []string{
		validPath,            // exists
		"/nonexistent/path1", // doesn't exist
		validPath2,           // exists
		"/nonexistent/path2", // doesn't exist
		"/another/missing",   // doesn't exist
	}

	direct, _, evidenceFiles, err := collectNpmPackagesInPaths(r, conn.FileSystem(), paths)
	require.NoError(t, err)
	require.Empty(t, evidenceFiles)

	// Should find packages from existing paths only
	require.Greater(t, len(direct), 0, "should find packages from existing paths")

	// Verify we found both valid packages
	foundApp1 := false
	foundApp2 := false
	for _, pkg := range direct {
		if pkg.Name == "test-app-1" {
			foundApp1 = true
			require.Equal(t, "1.0.0", pkg.Version)
		}
		if pkg.Name == "test-app-2" {
			foundApp2 = true
			require.Equal(t, "2.0.0", pkg.Version)
		}
	}
	require.True(t, foundApp1, "should find test-app-1 from valid path")
	require.True(t, foundApp2, "should find test-app-2 from valid path")
}

func TestNpmScriptsManifest(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mockFS, "/app/package.json", []byte(`{"scripts":{"test":"jest"}}`), 0o644))
	require.NoError(t, afero.WriteFile(mockFS, "/app/package-lock.json", []byte(`{}`), 0o644))
	require.NoError(t, mockFS.MkdirAll("/empty", 0o755))

	require.Equal(t, "/app/package.json", npmScriptsManifest(mockFS, "/app"))
	require.Equal(t, "/app/package.json", npmScriptsManifest(mockFS, "/app/package.json"))
	require.Equal(t, "/app/package.json", npmScriptsManifest(mockFS, "/app/package-lock.json"))
	require.Equal(t, "", npmScriptsManifest(mockFS, "/empty"))
	require.Equal(t, "", npmScriptsManifest(mockFS, "/missing/package.json"))
	require.Equal(t, "", npmScriptsManifest(mockFS, ""))
}

// A bare npm.packages searches the default locations and has no single
// package.json. scripts used to read the empty path and fail with
// "unexpected end of JSON input" on every host.
func TestNpmPackagesScripts(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mockFS, "/app/package.json",
		[]byte(`{"name":"app","scripts":{"postinstall":"node setup.js"}}`), 0o644))
	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{}, "", nil, mockFS)
	require.NoError(t, err)
	newRuntime := func() *plugin.Runtime {
		return &plugin.Runtime{
			Resources:  &syncx.Map[plugin.Resource]{},
			Connection: conn,
			Callback:   &providerCallbacks{},
		}
	}

	t.Run("default search", func(t *testing.T) {
		raw, err := CreateResource(newRuntime(), "npm.packages", nil)
		require.NoError(t, err)
		scripts := raw.(*mqlNpmPackages).GetScripts()
		require.NoError(t, scripts.Error)
		require.Nil(t, scripts.Data)
	})

	t.Run("a project directory", func(t *testing.T) {
		raw, err := CreateResource(newRuntime(), "npm.packages", map[string]*llx.RawData{
			"path": llx.StringData("/app"),
		})
		require.NoError(t, err)
		scripts := raw.(*mqlNpmPackages).GetScripts()
		require.NoError(t, scripts.Error)
		require.Equal(t, map[string]any{"postinstall": "node setup.js"}, scripts.Data)
	})
}

// The default search skips directories without a lockfile quietly, but must not
// treat a lockfile it cannot parse the same way.
func TestCollectNpmPackagesErrorKinds(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	require.NoError(t, mockFS.MkdirAll("/srv/empty", 0o755))
	require.NoError(t, afero.WriteFile(mockFS, "/srv/broken/yarn.lock", []byte("__metadata:\n  version: 8\n\"x@npm:1.0.0\":\n  version: [\n"), 0o644))
	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{}, "", nil, mockFS)
	require.NoError(t, err)
	r := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}

	_, err = collectNpmPackages(r, mockFS, "/srv/empty")
	require.ErrorIs(t, err, errNoNpmManifest)

	_, err = collectNpmPackages(r, mockFS, "/srv/broken")
	require.Error(t, err)
	require.NotErrorIs(t, err, errNoNpmManifest)
}

// A yarn.lock from yarn 1 with mixed quoted/unquoted entry headers, and one
// from yarn 4, both read through npm.packages.
func TestNpmPackagesYarnLock(t *testing.T) {
	for _, lock := range []string{"classic-multispec-yarn.lock", "berry-yarn.lock"} {
		t.Run(lock, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("languages", "javascript", "yarnlock", "testdata", lock))
			require.NoError(t, err)
			mockFS := afero.NewMemMapFs()
			require.NoError(t, afero.WriteFile(mockFS, "/srv/app/yarn.lock", data, 0o644))
			conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{}, "", nil, mockFS)
			require.NoError(t, err)
			r := &plugin.Runtime{
				Resources:  &syncx.Map[plugin.Resource]{},
				Connection: conn,
				Callback:   &providerCallbacks{},
			}
			raw, err := CreateResource(r, "npm.packages", map[string]*llx.RawData{
				"path": llx.StringData("/srv/app"),
			})
			require.NoError(t, err)
			pkgs := raw.(*mqlNpmPackages)
			require.NoError(t, pkgs.gatherData())

			found := false
			for _, p := range pkgs.List.Data {
				pkg := p.(*mqlNpmPackage)
				if pkg.Name.Data == "lodash" && pkg.Version.Data == "4.17.20" {
					found = true
				}
			}
			require.True(t, found, "lodash 4.17.20 is in the lockfile")
		})
	}
}

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
	assert.ElementsMatch(t, []string{"npm@11.16.0", "@scope/tool@1.2.3"}, packageNames(direct))
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
	assert.Equal(t, []string{"npm@10.9.8"}, packageNames(direct))
}

func TestCollectNpmPackagesInPaths_differentVersionsInBothDirs(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// two nodejs streams side by side: each npm is a separate install
	require.NoError(t, afero.WriteFile(mockFS, "/usr/lib/node_modules/npm/package.json", []byte(`{"name":"npm","version":"10.9.8"}`), 0o644))
	require.NoError(t, afero.WriteFile(mockFS, "/usr/lib/node_modules_24/npm/package.json", []byte(npm11PackageJSON), 0o644))

	r := npmTestRuntime(t, mockFS)
	direct, _, _, err := collectNpmPackagesInPaths(r, mockFS, defaultNpmPaths)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"npm@10.9.8", "npm@11.16.0"}, packageNames(direct))
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
	}, packageNames(direct))
}

func TestCollectNpmPackagesInPaths_debian9LibNodejs(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	// Debian 9: node-lodash and node-semver install into /usr/lib/nodejs
	writeNpmManifest(t, mockFS, "/usr/lib/nodejs/lodash", "lodash", "4.16.6")
	writeNpmManifest(t, mockFS, "/usr/lib/nodejs/semver", "semver", "5.3.0")

	r := npmTestRuntime(t, mockFS)
	direct, _, _, err := collectNpmPackagesInPaths(r, mockFS, []string{"/usr/lib/nodejs"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"lodash@4.16.6", "semver@5.3.0"}, packageNames(direct))
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
	assert.ElementsMatch(t, []string{"node-gyp@7.1.2", "lodash@4.17.21", "duplexer3@0.1.4"}, packageNames(direct))
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
	assert.Equal(t, []string{"browserslist@4.21.4"}, packageNames(direct))
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
	assert.ElementsMatch(t, []string{"npm@10.9.8", "npm@11.16.0"}, packageNames(direct))
}

// The npm that ships with Node.js has no lockfile: its dependencies are
// installed in npm/node_modules, each with a package.json that declares its
// own dependencies as ranges ("debug": "4"). Only installed versions are listed.
func TestCollectNpmPackagesInPaths_bundledNpmDeclaredRanges(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	npmDir := "/opt/nodejs/lib/node_modules/npm"
	writeManifest := func(dir, manifest string) {
		require.NoError(t, afero.WriteFile(mockFS, dir+"/package.json", []byte(manifest), 0o644))
	}
	writeManifest(npmDir, `{"name":"npm","version":"11.6.2","dependencies":{"tar":"^7.5.1","semver":"^7.7.2"}}`)
	writeManifest(npmDir+"/node_modules/agent-base", `{"name":"agent-base","version":"7.1.4","dependencies":{"debug":"4"}}`)
	writeManifest(npmDir+"/node_modules/https-proxy-agent", `{"name":"https-proxy-agent","version":"7.0.6","dependencies":{"agent-base":"^7.1.2","debug":"^4.3.4"}}`)
	writeNpmManifest(t, mockFS, npmDir+"/node_modules/debug", "debug", "4.4.3")
	writeNpmManifest(t, mockFS, npmDir+"/node_modules/tar", "tar", "7.5.22")

	r := npmTestRuntime(t, mockFS)
	direct, transitive, _, err := collectNpmPackagesInPaths(r, mockFS, []string{npmDir})
	require.NoError(t, err)

	installed := []string{"npm@11.6.2", "agent-base@7.1.4", "https-proxy-agent@7.0.6", "debug@4.4.3", "tar@7.5.22"}
	assert.ElementsMatch(t, installed, packageNames(direct))
	assert.ElementsMatch(t, installed, packageNames(transitive))
	for _, pkg := range append(direct, transitive...) {
		assert.NotContains(t, pkg.Version, "^", pkg.Name)
		assert.NotContains(t, pkg.Version, "~", pkg.Name)
		assert.Regexp(t, `^\d+\.\d+\.\d+`, pkg.Version, pkg.Name)
	}
}
