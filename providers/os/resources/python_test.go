// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/fsutil"
	"go.mondoo.com/mql/providers/os/resources/languages/python"
)

// The default paths overlap by design -- a specific pattern such as
// "/opt/homebrew/lib/python*" sits alongside the general "/opt/*/lib/python*"
// that also matches it. Every directory must still be scanned exactly once.
//
// Regression test for an inventory that was roughly half duplicates: on a macOS
// host python.packages returned 1085 entries for 546 distinct packages, because
// each site-packages directory was collected once per matching pattern. Every
// extra copy became another SBOM entry and another vulnerability finding for a
// package that is installed only once.
//
// These dist-info directories deliberately carry no METADATA, so the packages
// resolve through the directory-name fallback and the test needs no plugin
// runtime.
func TestCollectPythonPackagesInPaths_DeduplicatesOverlappingGlobMatches(t *testing.T) {
	fs := afero.NewMemMapFs()
	const siteDir = "/opt/homebrew/lib/python3.11/site-packages"
	require.NoError(t, fs.MkdirAll(siteDir+"/requests-2.32.3.dist-info", 0o755))

	// precondition: more than one pattern resolves to this directory, which is
	// what made the duplication possible
	matches := 0
	for _, walkPath := range walkedPaths(t, fs) {
		if walkPath == "/opt/homebrew/lib/python3.11" {
			matches++
		}
	}
	require.Greater(t, matches, 1, "precondition: the directory must be matched by several patterns")

	results, err := collectPythonPackagesInPaths(nil, fs, defaultPythonPaths)
	require.NoError(t, err)

	require.Len(t, results, 1, "a directory matched by several patterns must be collected once")
	assert.Equal(t, "requests", results[0].Name)
	assert.Equal(t, "2.32.3", results[0].Version)
}

// An install whose metadata cannot be read still has its identity in the
// directory name. Dropping it loses a package that is genuinely present -- a
// silent gap in the inventory rather than a visible error.
func TestCollectPythonPackages_FallsBackToDistInfoDirName(t *testing.T) {
	const siteDir = "/usr/lib/python3.13/site-packages"

	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll(siteDir+"/litellm-1.80.15.dist-info", 0o755))

	results, err := collectPythonPackages(nil, fs, siteDir)
	require.NoError(t, err)

	require.Len(t, results, 1, "a dist-info without METADATA must still be reported")
	assert.Equal(t, "litellm", results[0].Name)
	assert.Equal(t, "1.80.15", results[0].Version)
	assert.Equal(t, "pkg:pypi/litellm@1.80.15", results[0].Purl)
	assert.Equal(t, siteDir+"/litellm-1.80.15.dist-info", results[0].File,
		"the file must point at the directory the identity came from")
}

// A dist-info directory whose name carries no version must not be turned into a
// package with a garbage version.
func TestCollectPythonPackages_DirNameFallbackWithoutVersion(t *testing.T) {
	const siteDir = "/usr/lib/python3.13/site-packages"

	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll(siteDir+"/mypackage.egg-info", 0o755))

	results, err := collectPythonPackages(nil, fs, siteDir)
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Equal(t, "mypackage", results[0].Name)
	assert.Empty(t, results[0].Version)
}

// Dependencies resolve among the siblings in the environment that declares them,
// so every package has to know which directory it was installed into.
func TestPythonPackageSiteDir(t *testing.T) {
	tests := []struct {
		name string
		file string
		want string
	}{
		{
			"dist-info metadata",
			"/usr/lib/python3.13/site-packages/requests-2.32.3.dist-info/METADATA",
			"/usr/lib/python3.13/site-packages",
		},
		{
			"egg-info pkg-info",
			"/usr/lib/python3.6/site-packages/python_dateutil-2.6.1-py3.6.egg-info/PKG-INFO",
			"/usr/lib/python3.6/site-packages",
		},
		{
			// the directory-name fallback records the dist-info directory itself
			"dist-info directory",
			"/usr/lib/python3.13/site-packages/litellm-1.80.15.dist-info",
			"/usr/lib/python3.13/site-packages",
		},
		{
			// a bare .egg-info file sits directly in the site directory
			"egg-info file",
			"/usr/lib/python3.11/site-packages/setuptools.egg-info",
			"/usr/lib/python3.11/site-packages",
		},
		{
			// packages read out of a manifest belong to the manifest's directory
			"requirements manifest",
			"/srv/app/requirements.txt",
			"/srv/app",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, pythonPackageSiteDir(tc.file))
		})
	}
}

func TestCollectPythonManifestPackages_PipfileLock(t *testing.T) {
	fs := afero.NewMemMapFs()
	_ = afero.WriteFile(fs, "/project/Pipfile.lock", []byte(`{
		"_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
		"default": {
			"openai": {"version": "==1.30.0"},
			"requests": {"version": "==2.32.0"}
		},
		"develop": {}
	}`), 0644)

	results := collectPythonManifestPackages(fs, "/project")

	require.Len(t, results, 2)
	names := map[string]string{}
	for _, r := range results {
		names[r.Name] = r.Version
	}
	assert.Equal(t, "1.30.0", names["openai"])
	assert.Equal(t, "2.32.0", names["requests"])

	for _, r := range results {
		assert.NotEmpty(t, r.Purl, "should have PURL for %s", r.Name)
		assert.Equal(t, "/project/Pipfile.lock", r.File)
	}
}

func TestCollectPythonManifestPackages_PoetryLock(t *testing.T) {
	fs := afero.NewMemMapFs()
	_ = afero.WriteFile(fs, "/project/poetry.lock", []byte(`
[[package]]
name = "anthropic"
version = "0.25.0"

[[package]]
name = "httpx"
version = "0.27.0"
`), 0644)

	results := collectPythonManifestPackages(fs, "/project")

	require.Len(t, results, 2)
	names := map[string]string{}
	for _, r := range results {
		names[r.Name] = r.Version
	}
	assert.Equal(t, "0.25.0", names["anthropic"])
	assert.Equal(t, "0.27.0", names["httpx"])
}

func TestCollectPythonManifestPackages_RequirementsTxt(t *testing.T) {
	fs := afero.NewMemMapFs()
	_ = afero.WriteFile(fs, "/project/requirements.txt", []byte(`
transformers>=4.40.0
torch==2.3.0
numpy
# comment line
`), 0644)

	results := collectPythonManifestPackages(fs, "/project")

	require.Len(t, results, 3)
	byName := map[string]string{}
	for _, r := range results {
		byName[r.Name] = r.Version
	}
	assert.Contains(t, byName, "transformers")
	assert.Contains(t, byName, "torch")
	assert.Contains(t, byName, "numpy")

	// Pinned versions (==) should be extracted
	assert.Equal(t, "2.3.0", byName["torch"])
	// Unpinned constraints (>=) have empty version
	assert.Equal(t, "", byName["transformers"])
	// Bare names have empty version
	assert.Equal(t, "", byName["numpy"])
}

func TestCollectPythonManifestPackages_LockFilePriority(t *testing.T) {
	fs := afero.NewMemMapFs()
	// Both Pipfile.lock and requirements.txt exist — lock file should win
	_ = afero.WriteFile(fs, "/project/Pipfile.lock", []byte(`{
		"_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
		"default": {"openai": {"version": "==1.30.0"}},
		"develop": {}
	}`), 0644)
	_ = afero.WriteFile(fs, "/project/requirements.txt", []byte("openai\ntorch\n"), 0644)

	results := collectPythonManifestPackages(fs, "/project")

	// Should use Pipfile.lock (1 package with version), not requirements.txt (2 packages without)
	require.Len(t, results, 1)
	assert.Equal(t, "openai", results[0].Name)
	assert.Equal(t, "1.30.0", results[0].Version)
}

func TestCollectPythonManifestPackages_NoManifest(t *testing.T) {
	fs := afero.NewMemMapFs()
	_ = fs.Mkdir("/project", 0755)

	results := collectPythonManifestPackages(fs, "/project")
	assert.Nil(t, results)
}

func TestCollectPythonManifestPackages_SetupPy(t *testing.T) {
	fs := afero.NewMemMapFs()
	_ = afero.WriteFile(fs, "/project/setup.py", []byte(`
from setuptools import setup

setup(
    name="myproject",
    version="1.0.0",
    install_requires=[
        'openai==1.30.0',
        "transformers==4.40.0",
        'numpy>=1.21',
    ],
)
`), 0644)

	results := collectPythonManifestPackages(fs, "/project")

	require.Len(t, results, 2)
	byName := map[string]string{}
	for _, r := range results {
		byName[r.Name] = r.Version
	}
	assert.Equal(t, "1.30.0", byName["openai"])
	assert.Equal(t, "4.40.0", byName["transformers"])

	for _, r := range results {
		assert.Equal(t, "/project/setup.py", r.File)
		assert.NotEmpty(t, r.Purl, "should have PURL for %s", r.Name)
	}
}

func TestCollectPythonManifestPackages_SetupCfg(t *testing.T) {
	fs := afero.NewMemMapFs()
	_ = afero.WriteFile(fs, "/project/setup.cfg", []byte(`
[options]
install_requires =
    requests==2.31.0
    anthropic==0.25.0
`), 0644)

	results := collectPythonManifestPackages(fs, "/project")

	require.Len(t, results, 2)
	byName := map[string]string{}
	for _, r := range results {
		byName[r.Name] = r.Version
	}
	assert.Equal(t, "2.31.0", byName["requests"])
	assert.Equal(t, "0.25.0", byName["anthropic"])
}

func TestCollectPythonManifestPackages_LockFileBeatsSetupPy(t *testing.T) {
	fs := afero.NewMemMapFs()
	// Both Pipfile.lock and setup.py exist — lock file should win
	_ = afero.WriteFile(fs, "/project/Pipfile.lock", []byte(`{
		"_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
		"default": {"openai": {"version": "==1.30.0"}},
		"develop": {}
	}`), 0644)
	_ = afero.WriteFile(fs, "/project/setup.py", []byte(`
setup(install_requires=['openai==1.28.0', 'torch==2.3.0'])
`), 0644)

	results := collectPythonManifestPackages(fs, "/project")

	require.Len(t, results, 1)
	assert.Equal(t, "openai", results[0].Name)
	assert.Equal(t, "1.30.0", results[0].Version)
}

func TestMergePythonPackages(t *testing.T) {
	primary := []python.PackageDetails{
		{Name: "openai", Version: "1.30.0"},
		{Name: "requests", Version: "2.32.0"},
	}
	secondary := []python.PackageDetails{
		{Name: "openai", Version: "1.28.0"}, // duplicate, should be skipped
		{Name: "torch", Version: "2.3.0"},   // new, should be added
	}

	merged := mergePythonPackages(primary, secondary)

	require.Len(t, merged, 3)
	names := map[string]string{}
	for _, p := range merged {
		names[p.Name] = p.Version
	}
	assert.Equal(t, "1.30.0", names["openai"], "primary should take precedence")
	assert.Equal(t, "2.32.0", names["requests"])
	assert.Equal(t, "2.3.0", names["torch"])
}

func TestMergePythonPackages_CaseInsensitive(t *testing.T) {
	primary := []python.PackageDetails{
		{Name: "PyYAML", Version: "6.0.1"},
	}
	secondary := []python.PackageDetails{
		{Name: "pyyaml", Version: "6.0.0"},
	}

	merged := mergePythonPackages(primary, secondary)
	require.Len(t, merged, 1)
	assert.Equal(t, "PyYAML", merged[0].Name)
}

func TestMergePythonPackages_EmptySecondary(t *testing.T) {
	primary := []python.PackageDetails{
		{Name: "openai", Version: "1.30.0"},
	}

	merged := mergePythonPackages(primary, nil)
	assert.Equal(t, primary, merged)
}

// walkedPaths returns every directory defaultPythonPaths resolves to on the
// given filesystem. This is the discovery half of collectPythonPackagesInPaths,
// isolated so it can be exercised without a plugin runtime.
func walkedPaths(t *testing.T, fs afero.Fs) []string {
	t.Helper()
	found := []string{}
	err := fsutil.WalkGlob(fs, defaultPythonPaths, func(fs afero.Fs, walkPath string) error {
		found = append(found, walkPath)
		return nil
	})
	require.NoError(t, err)
	return found
}

// afero.Glob is based on filepath.Match, where "*" matches any run of
// non-separator characters -- including a leading dot. That is what makes
// "/app/*/lib/python*" match "/app/.venv/...", unlike shell globbing. The venv
// patterns all depend on this, so pin the behavior.
func TestDefaultPythonPaths_GlobMatchesDotDirectories(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/app/.venv/lib/python3.13/site-packages", 0o755))

	assert.Contains(t, walkedPaths(t, fs), "/app/.venv/lib/python3.13")
}

func TestDefaultPythonPaths_VirtualenvLayouts(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want string
	}{
		// the layout that prompted this: a container app with its deps in a venv
		{"app dot-venv", "/app/.venv/lib/python3.13/site-packages", "/app/.venv/lib/python3.13"},
		{"app plain venv", "/app/venv/lib/python3.12/site-packages", "/app/venv/lib/python3.12"},
		{"app env", "/app/env/lib/python3.11/site-packages", "/app/env/lib/python3.11"},
		{"opt venv", "/opt/venv/lib/python3.12/site-packages", "/opt/venv/lib/python3.12"},
		{"opt app venv", "/opt/myapp/lib/python3.12/site-packages", "/opt/myapp/lib/python3.12"},
		{"rootfs venv", "/venv/lib/python3.12/site-packages", "/venv/lib/python3.12"},
		{"rootfs dot-venv", "/.venv/lib/python3.12/site-packages", "/.venv/lib/python3.12"},
		{"code", "/code/.venv/lib/python3.12/site-packages", "/code/.venv/lib/python3.12"},
		{"workspace", "/workspace/.venv/lib/python3.12/site-packages", "/workspace/.venv/lib/python3.12"},
		{"srv", "/srv/app/lib/python3.12/site-packages", "/srv/app/lib/python3.12"},
		{"usr src app", "/usr/src/app/.venv/lib/python3.12/site-packages", "/usr/src/app/.venv/lib/python3.12"},
		{"root home", "/root/.venv/lib/python3.12/site-packages", "/root/.venv/lib/python3.12"},
		{"virtualenvwrapper", "/home/dev/.virtualenvs/proj/lib/python3.12/site-packages", "/home/dev/.virtualenvs/proj/lib/python3.12"},
		{"user venv", "/home/dev/.venv/lib/python3.12/site-packages", "/home/dev/.venv/lib/python3.12"},
		// non-dotted venv names must work wherever dotted ones do
		{"user plain venv", "/home/dev/venv/lib/python3.12/site-packages", "/home/dev/venv/lib/python3.12"},
		{"user env", "/home/dev/env/lib/python3.12/site-packages", "/home/dev/env/lib/python3.12"},
		{"macos user venv", "/Users/dev/venv/lib/python3.12/site-packages", "/Users/dev/venv/lib/python3.12"},
		// a project checkout carrying its own venv, one level below a known root
		{"project under app", "/app/myservice/.venv/lib/python3.12/site-packages", "/app/myservice/.venv/lib/python3.12"},
		{"project under workspace", "/workspace/proj/.venv/lib/python3.12/site-packages", "/workspace/proj/.venv/lib/python3.12"},
		{"project under opt", "/opt/myservice/.venv/lib/python3.12/site-packages", "/opt/myservice/.venv/lib/python3.12"},
		// dist-packages is resolved by the caller, so the walk only needs the parent
		{"debian dist-packages", "/usr/lib/python3/dist-packages", "/usr/lib/python3"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			require.NoError(t, fs.MkdirAll(tc.dir, 0o755))
			assert.Contains(t, walkedPaths(t, fs), tc.want)
		})
	}
}

// Documents where the glob list deliberately stops. Without "**" the depth has
// to be bounded, and under user homes -- where a shared machine can have many
// users each with many project directories -- an extra level costs a ReadDir per
// directory. Container roots like /app are shallow and purpose-built, so they do
// get the extra level (see "project under app" above).
//
// If this test starts failing because a deeper pattern was added, that is a
// deliberate trade-off, not a bug: update it and note the scan-cost impact.
func TestDefaultPythonPaths_DeepUserProjectVenvNotCovered(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/home/dev/proj/.venv/lib/python3.12/site-packages", 0o755))

	assert.NotContains(t, walkedPaths(t, fs), "/home/dev/proj/.venv/lib/python3.12",
		"a venv nested under a project directory in a user home is a known gap; use the python resource's path argument")
}

// The system paths must keep working exactly as before.
func TestDefaultPythonPaths_SystemLayoutsStillMatch(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/usr/lib/python3.11/site-packages", 0o755))
	require.NoError(t, fs.MkdirAll("/usr/local/lib/python3.9/site-packages", 0o755))

	found := walkedPaths(t, fs)
	assert.Contains(t, found, "/usr/lib/python3.11")
	assert.Contains(t, found, "/usr/local/lib/python3.9")
}

// A glob that lands on a file instead of a directory must not abort the whole
// search -- with patterns this broad, one odd match would otherwise cost us
// every other venv on the system.
//
// This one runs on a real filesystem on purpose: reading "<file>/site-packages"
// has to fail with ENOTDIR rather than "not exist" for the skip to be exercised,
// and MemMapFs does not reproduce that distinction.
func TestCollectPythonPackagesInPaths_SkipsUnreadableMatches(t *testing.T) {
	fs := afero.NewBasePathFs(afero.NewOsFs(), t.TempDir())

	// /opt/*/lib/python* matches this, but it is a file, so reading
	// "<match>/site-packages" fails with ENOTDIR
	require.NoError(t, fs.MkdirAll("/opt/weird/lib", 0o755))
	f, err := fs.Create("/opt/weird/lib/python3.12")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// a real venv alongside it, which must still be found
	require.NoError(t, fs.MkdirAll("/app/.venv/lib/python3.13/site-packages", 0o755))

	found := []string{}
	err = fsutil.WalkGlob(fs, defaultPythonPaths, func(fs afero.Fs, walkPath string) error {
		found = append(found, walkPath)
		return nil
	})
	require.NoError(t, err)
	require.Contains(t, found, "/opt/weird/lib/python3.12", "precondition: the file must be matched by a glob")

	_, err = collectPythonPackagesInPaths(nil, fs, defaultPythonPaths)
	assert.NoError(t, err, "an unreadable match must be skipped, not fatal")
}

// ghostDirFs lists ghost as a directory but fails to open it, reproducing what a
// container image's layered filesystem does with a dist-info deleted in a later
// layer: the entry survives in the merged listing, opening it does not.
type ghostDirFs struct {
	afero.Fs
	ghost string
}

func (f *ghostDirFs) Open(name string) (afero.File, error) {
	if name == f.ghost {
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	}
	return f.Fs.Open(name)
}

// A single unreadable entry must not abort the whole site-packages directory.
//
// Regression test for a real container scan: site-packages listed a stale
// autocommand-2.2.2.dist-info, reading it failed, collection returned that error
// for the entire directory, and the image reported zero Python packages --
// litellm among them, even though litellm-1.80.15.dist-info sat right there and
// was perfectly readable.
//
// The readable sibling here deliberately carries no METADATA, so nothing has to
// be turned into a resource and the test needs no plugin runtime. Reaching it at
// all is the point: before the fix the ghost aborted the loop and this returned
// an error.
func TestCollectPythonPackages_UnreadableEntryDoesNotAbortDirectory(t *testing.T) {
	const siteDir = "/usr/lib/python3.13/site-packages"

	base := afero.NewMemMapFs()
	// "autocommand" sorts before "litellm", matching the real failure where the
	// bad entry is reached first and kills everything after it
	require.NoError(t, base.MkdirAll(siteDir+"/autocommand-2.2.2.dist-info", 0o755))
	require.NoError(t, base.MkdirAll(siteDir+"/litellm-1.80.15.dist-info", 0o755))

	fs := &ghostDirFs{Fs: base, ghost: siteDir + "/autocommand-2.2.2.dist-info"}

	// precondition: both are listed, and the ghost genuinely fails to open
	entries, err := afero.ReadDir(fs, siteDir)
	require.NoError(t, err)
	require.Len(t, entries, 2, "both entries must appear in the listing")
	_, err = afero.ReadDir(fs, siteDir+"/autocommand-2.2.2.dist-info")
	require.Error(t, err, "the ghost entry must fail to open")

	_, err = collectPythonPackages(nil, fs, siteDir)
	assert.NoError(t, err,
		"one unreadable entry must be skipped, not fail the entire site-packages directory")
}
