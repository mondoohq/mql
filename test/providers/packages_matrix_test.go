// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest

// Package-resource regression matrix.
//
// Run it deliberately while working on `packages`, not on every build:
//
//	make test/packages/matrix
//
// It pulls one image per package manager, so it costs minutes and bandwidth,
// which is why it carries the debugtest tag and does not compile into
// `go test ./...`.
//
// It asserts *invariants*, not recorded values. A golden file over public
// images breaks every time upstream rebuilds, and a test that fails for that
// reason gets muted, which is worse than not having it.
package providers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/test"
)

type matrixPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Format  string `json:"format"`
	Purl    string `json:"purl"`
	Pinned  bool   `json:"pinned"`
}

type matrixCase struct {
	image  string
	format string // the package format this platform must resolve to
	// pkg is locked, then re-scanned. Empty means the manager has no lock
	// mechanism, and the assertion becomes "nothing is ever pinned".
	pkg  string
	lock string
}

// One image per manager and era. The lock commands are the real ones; what
// they write to disk is what the resource reads.
var packageMatrix = []matrixCase{
	{
		image: "debian:12", format: "deb", pkg: "nginx",
		lock: "apt-get update -qq && apt-get install -y -qq nginx && apt-mark hold nginx",
	},
	{
		image: "almalinux:9", format: "rpm", pkg: "vim-minimal",
		lock: "dnf install -y python3-dnf-plugin-versionlock && dnf versionlock add vim-minimal",
	},
	{
		image: "amazonlinux:2", format: "rpm", pkg: "vim-minimal",
		lock: "yum install -y yum-plugin-versionlock && yum versionlock add vim-minimal",
	},
	{
		image: "fedora:latest", format: "rpm", pkg: "vim-minimal",
		lock: "dnf install -y 'dnf5-command(versionlock)' && dnf versionlock add vim-minimal",
	},
	{
		image: "opensuse/leap:15", format: "rpm", pkg: "vim",
		lock: "zypper --non-interactive install vim && zypper --non-interactive al vim",
	},
	// tdnf ships no versionlock plugin, and none is available in the Photon
	// repositories, so a Photon host can never report a pinned package.
	{image: "photon:5.0", format: "rpm"},
	// apk has no lock mechanism at all.
	{image: "alpine:3.21", format: "apk"},
}

func TestPackagesMatrix(t *testing.T) {
	once.Do(setup)
	requireDocker(t)

	// setup() installs the provider into the user's config directory, but a
	// system-wide provider under /Library/Mondoo (or /opt/mondoo) shadows it
	// when one is present, and a stale system provider silently answers with
	// the previous schema. Point the search path at the build under test
	// instead, so this matrix always exercises the working tree.
	providerDir := stageProviderUnderTest(t)
	t.Setenv("PROVIDERS_PATH", providerDir)

	for _, tc := range packageMatrix {
		t.Run(tc.image, func(t *testing.T) {
			id := dockerRunDetached(t, tc.image)

			before := matrixPackages(t, "docker", "container", id)
			assertPackageInvariants(t, tc, before)

			for _, p := range before {
				assert.Falsef(t, p.Pinned, "%s is pinned before anything was locked", p.Name)
			}

			if tc.pkg == "" {
				// Nothing to lock: this manager has no mechanism, and the
				// assertion above is the whole test.
				return
			}

			target := findPackage(before, tc.pkg)
			if target == nil {
				// Install happens as part of the lock command below, so an
				// absent package here is expected for images that do not ship
				// it. The post-lock scan is what matters.
				t.Logf("%s is not preinstalled; the lock command installs it", tc.pkg)
			}

			runInContainer(t, id, tc.lock)

			// Re-scan the same running container.
			after := matrixPackages(t, "docker", "container", id)
			assertPackageInvariants(t, tc, after)
			assertOnlyPinned(t, after, tc.pkg)

			// The same state read as an image, where no command can run. This
			// is the assertion the file-based design rests on: a reader that
			// shelled out would report nothing pinned here.
			img := commitContainer(t, id)
			viaImage := matrixPackages(t, "docker", "image", img)
			assertPackageInvariants(t, tc, viaImage)
			assertOnlyPinned(t, viaImage, tc.pkg)

			assert.ElementsMatch(t, names(after), names(viaImage),
				"the container and image connections disagree about which packages exist")
		})
	}
}

// assertPackageInvariants holds for every image, before and after locking.
func assertPackageInvariants(t *testing.T, tc matrixCase, pkgs []matrixPkg) {
	t.Helper()
	require.NotEmpty(t, pkgs, "no packages were read at all")

	seen := map[string]string{}
	for _, p := range pkgs {
		assert.NotEmptyf(t, p.Name, "a package has no name: %+v", p)
		assert.NotEmptyf(t, p.Version, "%s has no version", p.Name)
		assert.Equalf(t, tc.format, p.Format, "%s has the wrong format for this platform", p.Name)
		assert.Truef(t, strings.HasPrefix(p.Purl, "pkg:"), "%s has an unparseable purl %q", p.Name, p.Purl)

		// The identity a package is cached under. A collision means one entry
		// silently reports another's data.
		key := p.Name + "\x00" + p.Arch + "\x00" + p.Version
		if prev, dup := seen[key]; dup {
			t.Errorf("two packages share name+arch+version: %s and %s", prev, p.Name)
		}
		seen[key] = p.Name
	}
}

// assertOnlyPinned checks that the locked package is pinned and nothing else is.
func assertOnlyPinned(t *testing.T, pkgs []matrixPkg, locked string) {
	t.Helper()

	var pinned []string
	for _, p := range pkgs {
		if p.Pinned {
			pinned = append(pinned, p.Name)
		}
	}
	assert.Equalf(t, []string{locked}, pinned,
		"expected exactly %q to be pinned", locked)
}

func findPackage(pkgs []matrixPkg, name string) *matrixPkg {
	for i := range pkgs {
		if pkgs[i].Name == name {
			return &pkgs[i]
		}
	}
	return nil
}

func names(pkgs []matrixPkg) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Name)
	}
	return out
}

// matrixPackages runs the query the same way the rpm smoke test does, and
// parses the result key-agnostically so it does not depend on how mql labels
// the queried block.
func matrixPackages(t *testing.T, target ...string) []matrixPkg {
	t.Helper()

	args := make([]string, 0, 4+len(target))
	args = append(args, "run")
	args = append(args, target...)
	args = append(args, "-c", "packages.list { name version arch format purl pinned }", "-j")

	r := test.NewCliTestRunner("./mql", args...)
	require.NoError(t, r.Run())
	require.Equalf(t, 0, r.ExitCode(), "mql exited non-zero; stderr: %s", string(r.Stderr()))

	var assets []map[string][]matrixPkg
	if err := r.Json(&assets); err != nil {
		t.Fatalf("parsing mql json failed: %v\n--- stdout ---\n%s\n--- stderr ---\n%s",
			err, string(r.Stdout()), string(r.Stderr()))
	}
	require.Lenf(t, assets, 1, "expected exactly one asset result; stdout: %s", string(r.Stdout()))
	for _, list := range assets[0] {
		return list
	}
	t.Fatalf("no package list in mql output; stdout: %s", string(r.Stdout()))
	return nil
}

// stageProviderUnderTest copies the freshly built os provider into a directory
// of its own and returns it for PROVIDERS_PATH, which replaces the provider
// search path entirely.
func stageProviderUnderTest(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	osDir := filepath.Join(dir, "os")
	require.NoError(t, os.MkdirAll(osDir, 0o755))

	matches, err := filepath.Glob(filepath.Join("..", "..", "providers", "os", "dist", "os*"))
	require.NoError(t, err)
	require.NotEmptyf(t, matches, "no built os provider in providers/os/dist; setup() should have built one")

	for _, src := range matches {
		raw, err := os.ReadFile(src)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(osDir, filepath.Base(src)), raw, 0o755))
	}
	return dir
}

func runInContainer(t *testing.T, id, script string) {
	t.Helper()
	cmd := exec.Command("docker", "exec", id, "sh", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("could not apply the lock in %s: %v\n%s", id, err, string(out))
	}
}

func commitContainer(t *testing.T, id string) string {
	t.Helper()
	tag := fmt.Sprintf("mql-pkgmatrix-%s:latest", id[:12])
	out, err := exec.Command("docker", "commit", id, tag).CombinedOutput()
	require.NoErrorf(t, err, "could not commit %s: %s", id, string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	return tag
}
