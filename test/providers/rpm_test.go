// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/test"
)

// rpmTestImages are rpm-based images this smoke test scans. We deliberately
// use the *minimal* variants (~15-20 MB compressed) to keep the pull cheap;
// they carry a real rpm database, which is what the static rpmdb path reads.
var rpmTestImages = []string{
	"redhat/ubi9-minimal",
	"almalinux:9-minimal",
}

type pkgInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Format  string `json:"format"`
	Vendor  string `json:"vendor"`
}

// requireDocker fails the test (it does NOT skip) when docker is unavailable.
// A silently skipped integration test gives the same false-green as the
// hand-edited mock fixtures that caused the rpm delimiter incident: the test
// looks healthy while never exercising the real code path. If docker is
// missing where these tests run, that is a setup error worth a red build.
func requireDocker(t *testing.T) {
	t.Helper()
	out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput()
	require.NoErrorf(t, err, "docker is required for the rpm integration tests: %s", string(out))
}

// dockerRunDetached starts a long-lived container from image and returns its
// id, so the scan goes through ContainerConnection rather than the image
// snapshot connection. (Both still resolve to the static rpmdb path — see the
// TestRpmPackages doc comment.)
func dockerRunDetached(t *testing.T, image string) string {
	t.Helper()
	// Pull explicitly first: `docker run` prints image-pull progress, and if
	// that progress ends up mixed with the container id we read back, the id
	// becomes garbage and mql falls back to printing usage.
	if out, err := exec.Command("docker", "pull", image).CombinedOutput(); err != nil {
		t.Fatalf("pulling %s: %v\n%s", image, err, string(out))
	}
	// --rm so the daemon reaps the container if the test process dies before
	// the cleanup callback runs (SIGKILL, OOM, CI timeout). Read only stdout so
	// the container id is never contaminated by warnings on stderr.
	out, err := exec.Command("docker", "run", "-d", "--rm", image, "sleep", "3600").Output()
	require.NoErrorf(t, err, "starting container for %s", image)
	id := strings.TrimSpace(string(out))
	require.NotEmpty(t, id, "empty container id for %s", image)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", id).Run()
	})
	return id
}

// queryPackages runs mql against the target and returns the parsed package
// list. It projects the fields explicitly with a block: a bare `packages`
// query only serializes the resource's @defaults (name, version) under -j, so
// arch and format would come back empty.
func queryPackages(t *testing.T, target ...string) []pkgInfo {
	t.Helper()
	args := make([]string, 0, 1+len(target)+3)
	args = append(args, "run")
	args = append(args, target...)
	args = append(args, "-c", "packages.list { name version arch format }", "-j")
	r := test.NewCliTestRunner("./mql", args...)
	require.NoError(t, r.Run())
	require.Equalf(t, 0, r.ExitCode(), "mql exited non-zero; stderr: %s", string(r.Stderr()))

	// The -j output is an array with one object per scanned asset; that object
	// has a single key (the queried block) whose value is the package list.
	// Parse key-agnostically so we don't depend on how mql labels the block.
	var assets []map[string][]pkgInfo
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

func hasPackage(list []pkgInfo, name string) (pkgInfo, bool) {
	for _, p := range list {
		if p.Name == name {
			return p, true
		}
	}
	return pkgInfo{}, false
}

func packageNames(list []pkgInfo) []string {
	names := make([]string, 0, len(list))
	for _, p := range list {
		names = append(names, p.Name)
	}
	return names
}

// assertRpmPackages smoke-checks that a real rpm database parsed into sane
// packages via the static rpmdb path. It is NOT a guard for the queryformat
// field separator — that lives on the runtime path and is covered by
// TestRpmQueryFormatRoundTrip (see the TestRpmPackages doc comment).
func assertRpmPackages(t *testing.T, conn string, list []pkgInfo) {
	t.Helper()
	// Even a minimal image has dozens of packages; 20 is a safe floor that
	// catches a wholly broken read.
	assert.Greaterf(t, len(list), 20, "%s: too few packages (broken rpmdb read?)", conn)

	for _, p := range list {
		assert.NotEmptyf(t, p.Name, "%s: package with empty name", conn)
		assert.NotEmptyf(t, p.Version, "%s: %q has empty version", conn, p.Name)
	}

	// glibc is present on every rpm image (including minimal variants) and
	// carries a normal arch and format, so it proves field mapping worked end
	// to end. We assert these on glibc rather than every package because
	// gpg-pubkey (a GPG-key pseudo-package, not real software) has neither.
	glibc, ok := hasPackage(list, "glibc")
	require.Truef(t, ok, "%s: base package glibc missing", conn)
	assert.NotEmptyf(t, glibc.Arch, "%s: glibc has empty arch", conn)
	assert.Equalf(t, "rpm", glibc.Format, "%s: glibc has unexpected format %q", conn, glibc.Format)
}

// TestRpmPackages is a smoke test that mql parses a real rpm database into
// sane packages across distros, via both the running-container connection and
// the image-snapshot connection.
//
// Both connections resolve to the *static* rpmdb path: rpm scans over the
// docker transport do not reliably use the runtime `rpm -qa --queryformat`
// path, because the exit code of the `rpm --version` probe is unreliable over docker,
// so isStaticAnalysis() prefers the static read. This test therefore does NOT
// guard the queryformat field separator — that bug (#7818, reverted in #7963)
// lives on the runtime path and is covered deterministically by
// TestRpmQueryFormatRoundTrip in providers/os/resources/packages.
//
// It requires docker rather than skipping, so a CI box without docker fails
// loudly instead of silently covering nothing.
func TestRpmPackages(t *testing.T) {
	once.Do(setup)
	requireDocker(t)

	for _, image := range rpmTestImages {
		t.Run(image, func(t *testing.T) {
			// Scan via ContainerConnection (running container).
			id := dockerRunDetached(t, image)
			viaContainer := queryPackages(t, "docker", id)
			assertRpmPackages(t, "container", viaContainer)

			// Scan the same image as an image reference (snapshot connection).
			viaImage := queryPackages(t, "docker", image)
			assertRpmPackages(t, "image", viaImage)

			// Both connections read the same installed rpm database, so the
			// package name sets must match — a cross-check that the static read
			// is consistent across connection types.
			assert.ElementsMatchf(t, packageNames(viaImage), packageNames(viaContainer),
				"container and image package sets diverge for %s", image)
		})
	}
}
