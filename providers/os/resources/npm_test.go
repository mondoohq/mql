// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
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
	require.Equal(t, "^2.0.2", pkg2.Version.Data)

	// Check that the third package is also yosay, but with a different version
	pkg3 := mqlNpm.List.Data[3].(*mqlNpmPackage)
	require.Equal(t, "yosay", pkg3.Name.Data)
	require.Equal(t, "^3.0.0", pkg3.Version.Data)

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
