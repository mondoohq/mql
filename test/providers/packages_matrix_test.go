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

// Where packages came from (ADR 049), across package managers. Each case
// installs software from the distribution, from a third-party repository and
// from a local file, then checks what those packages report, first in the
// running container and then committed as an image, where no command can run.
// Assertions name only the packages the setup installs, so upstream image
// rebuilds do not break them.

type sourcePkg struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Format     string `json:"format"`
	OSProvided *bool  `json:"osProvided"`
	Source     struct {
		Channel string `json:"channel"`
		Name    string `json:"name"`
	} `json:"source"`
}

// sourceWant is what one package must report. osProvided nil means null.
type sourceWant struct {
	osProvided *bool
	channel    string
	name       string // checked when not empty
}

type sourceCase struct {
	image string
	setup string
	want  map[string]sourceWant
	// noSources means no package can be attributed on this platform.
	noSources bool
}

func boolPtr(b bool) *bool { return &b }

const (
	debianVendorRepos = `export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq curl gnupg ca-certificates tree >/dev/null
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list
curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian bookworm nginx" > /etc/apt/sources.list.d/nginx.list
printf "Package: *\nPin: origin nginx.org\nPin-Priority: 900\n" > /etc/apt/preferences.d/99nginx
apt-get update -qq && apt-get install -y -qq nginx docker-ce-cli >/dev/null
mkdir -p /tmp/p/DEBIAN && printf "Package: acme-agent\nVersion: 1.2.3\nArchitecture: all\nMaintainer: Acme <ops@acme.example>\nDescription: test\n" > /tmp/p/DEBIAN/control
dpkg-deb --build /tmp/p /tmp/acme.deb >/dev/null && dpkg -i /tmp/acme.deb >/dev/null`

	elVendorRepos = `dnf -q -y install dnf-plugins-core rpm-build tree >/dev/null
dnf -q -y install epel-release >/dev/null && dnf -q -y install htop >/dev/null
dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo >/dev/null && dnf -q -y install docker-ce-cli >/dev/null
dnf -q -y download --destdir /tmp nano >/dev/null && rpm -i /tmp/nano-*.rpm
mkdir -p ~/rpmbuild/SPECS && printf 'Name: acme-agent\nVersion: 1.2.3\nRelease: 1\nSummary: t\nLicense: MIT\nBuildArch: noarch\n%%description\nt\n%%files\n' > ~/rpmbuild/SPECS/a.spec
rpmbuild -bb ~/rpmbuild/SPECS/a.spec >/dev/null 2>&1 && rpm -i ~/rpmbuild/RPMS/noarch/acme-agent-1.2.3-1.noarch.rpm`
)

var sourceMatrix = []sourceCase{
	{
		image: "debian:12",
		setup: debianVendorRepos,
		want: map[string]sourceWant{
			"tree":          {boolPtr(true), "os", "Debian"},
			"nginx":         {boolPtr(false), "vendor-repository", "nginx"},
			"docker-ce-cli": {boolPtr(false), "vendor-repository", "Docker"},
			"acme-agent":    {boolPtr(false), "direct", ""},
		},
	},
	{
		image: "ubuntu:24.04",
		setup: `export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq curl ca-certificates tree >/dev/null
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" > /etc/apt/sources.list.d/docker.list
apt-get update -qq && apt-get install -y -qq docker-ce-cli >/dev/null`,
		want: map[string]sourceWant{
			"tree":          {boolPtr(true), "os", "Ubuntu"},
			"docker-ce-cli": {boolPtr(false), "vendor-repository", "Docker"},
		},
	},
	{
		image: "almalinux:9",
		setup: elVendorRepos,
		want: map[string]sourceWant{
			"tree":          {boolPtr(true), "os", ""},
			"epel-release":  {boolPtr(true), "os", "extras"},
			"htop":          {boolPtr(false), "vendor-repository", "epel"},
			"docker-ce-cli": {boolPtr(false), "vendor-repository", "docker-ce-stable"},
			"nano":          {boolPtr(true), "os", ""},
			"acme-agent":    {boolPtr(false), "direct", ""},
		},
	},
	{
		image: "fedora:latest",
		setup: `dnf -q -y install tree >/dev/null`,
		want: map[string]sourceWant{
			"tree": {boolPtr(true), "os", "fedora"},
			// installed by the image build, whose throwaway repository id is
			// not reported
			"bash": {boolPtr(true), "os", ""},
		},
	},
	{
		image: "opensuse/leap:15.6",
		setup: `zypper -q -n --gpg-auto-import-keys addrepo https://download.opensuse.org/repositories/shells:/fish:/release:/4/15.6/shells:fish:release:4.repo >/dev/null
zypper -q -n --gpg-auto-import-keys refresh >/dev/null && zypper -q -n install tree fish >/dev/null`,
		want: map[string]sourceWant{
			"tree": {boolPtr(true), "os", ""},
			"fish": {boolPtr(false), "vendor-repository", ""},
		},
	},
	{
		image: "amazonlinux:2",
		setup: `yum -q -y install tree >/dev/null && amazon-linux-extras install -y epel >/dev/null && yum -q -y install ncdu >/dev/null`,
		want: map[string]sourceWant{
			"tree": {boolPtr(true), "os", "amzn2-core"},
			// only EPEL has ncdu; amzn2-core has an htop of its own
			"ncdu": {boolPtr(false), "vendor-repository", "epel"},
		},
	},
	{
		image: "photon:5.0",
		want: map[string]sourceWant{
			"bash": {boolPtr(true), "os", ""},
		},
	},
	{image: "alpine:3.21", noSources: true},
}

func TestPackageSourceMatrix(t *testing.T) {
	once.Do(setup)
	requireDocker(t)
	t.Setenv("PROVIDERS_PATH", stageProviderUnderTest(t))

	for _, tc := range sourceMatrix {
		t.Run(tc.image, func(t *testing.T) {
			id := dockerRunDetached(t, tc.image)
			if tc.setup != "" {
				runInContainer(t, id, tc.setup)
			}

			live := sourcePackages(t, "docker", "container", id)
			assertSources(t, tc, live)

			img := commitContainer(t, id)
			viaImage := sourcePackages(t, "docker", "image", img)
			assertSources(t, tc, viaImage)

			// Reading the image cannot run a single command, and must still
			// reach the same answer.
			assert.Equal(t, sourceSummary(live), sourceSummary(viaImage),
				"the container and image connections disagree about where packages came from")
		})
	}

	// Most Debian container images ship without apt indexes. Without them no
	// package can be attributed, and none is guessed.
	t.Run("debian:12 without apt indexes", func(t *testing.T) {
		id := dockerRunDetached(t, "debian:12")
		runInContainer(t, id, debianVendorRepos+"\nrm -rf /var/lib/apt/lists/*")
		for _, p := range sourcePackages(t, "docker", "container", id) {
			assert.Nilf(t, p.OSProvided, "%s is attributed without an index to attribute it by", p.Name)
			assert.Equalf(t, "unknown", p.Source.Channel, "%s", p.Name)
		}
	})
}

func assertSources(t *testing.T, tc sourceCase, pkgs []sourcePkg) {
	t.Helper()
	require.NotEmpty(t, pkgs)
	osCount := 0
	for _, p := range pkgs {
		assert.NotEmptyf(t, p.Source.Channel, "%s has no channel", p.Name)
		if tc.noSources {
			assert.Nilf(t, p.OSProvided, "%s", p.Name)
		}
		if p.OSProvided != nil && *p.OSProvided {
			osCount++
			assert.Equalf(t, "os", p.Source.Channel, "%s is the operating system's but not on its channel", p.Name)
		}
	}
	if !tc.noSources {
		assert.Greaterf(t, osCount, len(pkgs)/2, "most of a fresh image's packages are the operating system's")
	}
	for name, want := range tc.want {
		var p *sourcePkg
		for i := range pkgs {
			if pkgs[i].Name == name {
				p = &pkgs[i]
				break
			}
		}
		if !assert.NotNilf(t, p, "%s is not installed", name) {
			continue
		}
		assert.Equalf(t, want.osProvided, p.OSProvided, "%s osProvided", name)
		assert.Equalf(t, want.channel, p.Source.Channel, "%s channel", name)
		if want.name != "" {
			assert.Equalf(t, want.name, p.Source.Name, "%s source name", name)
		}
	}
}

// sourceSummary keys each package to what it reported, for comparing two scans.
func sourceSummary(pkgs []sourcePkg) map[string]string {
	out := map[string]string{}
	for _, p := range pkgs {
		v := "null"
		if p.OSProvided != nil {
			v = fmt.Sprint(*p.OSProvided)
		}
		out[p.Name+" "+p.Version] = v + " " + p.Source.Channel + " " + p.Source.Name
	}
	return out
}

func sourcePackages(t *testing.T, target ...string) []sourcePkg {
	t.Helper()
	args := append([]string{"run"}, target...)
	args = append(args, "-c", "packages.list { name version format osProvided source { channel name } }", "-j")
	r := test.NewCliTestRunner("./mql", args...)
	require.NoError(t, r.Run())
	require.Equalf(t, 0, r.ExitCode(), "mql exited non-zero; stderr: %s", string(r.Stderr()))
	var assets []map[string][]sourcePkg
	require.NoErrorf(t, r.Json(&assets), "stdout: %s", string(r.Stdout()))
	require.Len(t, assets, 1)
	for _, list := range assets[0] {
		return list
	}
	t.Fatal("no package list in mql output")
	return nil
}
