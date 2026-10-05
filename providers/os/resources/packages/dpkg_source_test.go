// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// The fixtures under testdata/source/dpkg were copied from a debian:12
// container (arm64) that had nginx.org's and Docker's apt repositories added
// and nginx, docker-ce-cli and libc6 installed from them and from Debian:
//
//   - lists/*_InRelease are the release files apt downloaded, unchanged.
//   - lists/*_Packages are whole stanzas cut from the indexes apt downloaded:
//     the installed version and older ones.
//   - keyrings/ are the key files the sources trusted. The Debian one is
//     owned by debian-archive-keyring; nginx's and Docker's by no package.
//   - info/debian-archive-keyring.list is dpkg's file list of that package.
//   - sources/ are the sources files as the setup wrote them.
const dpkgFixtures = "testdata/source/dpkg"

// debianSourcesFS lays the fixtures out where apt and dpkg keep them.
func debianSourcesFS(t *testing.T) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	copyDir := func(src, dst string) {
		entries, err := os.ReadDir(path.Join(dpkgFixtures, src))
		require.NoError(t, err)
		for _, e := range entries {
			data, err := os.ReadFile(path.Join(dpkgFixtures, src, e.Name()))
			require.NoError(t, err)
			target := path.Join(dst, e.Name())
			require.NoError(t, afero.WriteFile(fs, target, data, 0o644))
		}
	}
	copyDir("lists", aptListsDir)
	// The host had an index for every component its sources enable. Only the
	// indexes that list the packages under test are kept as fixtures; the
	// others are present and list none of them.
	for _, n := range []string{
		"deb.debian.org_debian_dists_bookworm_main_binary-arm64_Packages",
		"deb.debian.org_debian_dists_bookworm-updates_main_binary-arm64_Packages",
	} {
		require.NoError(t, afero.WriteFile(fs, path.Join(aptListsDir, n), nil, 0o644))
	}
	copyDir("info", dpkgInfoDir)
	copyDir("sources", "/etc/apt/sources.list.d")
	for _, k := range []struct{ name, dir string }{
		{"debian-archive-bookworm-security-automatic.gpg", "/usr/share/keyrings"},
		{"nginx-archive-keyring.gpg", "/usr/share/keyrings"},
		{"docker.asc", "/etc/apt/keyrings"},
	} {
		data, err := os.ReadFile(path.Join(dpkgFixtures, "keyrings", k.name))
		require.NoError(t, err)
		require.NoError(t, afero.WriteFile(fs, path.Join(k.dir, k.name), data, 0o644))
	}
	return fs
}

// newTestAptLists builds the lists reader the way Sources does, over a file
// system alone.
func newTestAptLists(fs afero.Fs, keys openPGPKeys, known bool, sources aptSources) *aptLists {
	l := newAptLists(newLocalSourceFiles(fs), aptSources{})
	l.setTrust(keys, known, sources)
	return l
}

func debPkg(name, version, arch string) Package {
	return Package{Name: name, Version: version, Arch: arch, Format: DpkgPkgFormat}
}

func TestDpkgSourcesFromFixtures(t *testing.T) {
	fs := debianSourcesFS(t)
	keys, known := readDpkgOSKeys(newLocalSourceFiles(fs), "debian", map[string]string{"debian-archive-keyring": "all"})
	require.True(t, known, "the Debian keyring package's key files must be read")

	pkgs := []Package{
		debPkg("libc6", "2.36-9+deb12u7", "arm64"),
		debPkg("nginx", "1.30.5-1~bookworm", "arm64"),
		debPkg("docker-ce-cli", "5:29.8.2-1~debian.12~bookworm", "arm64"),
		debPkg("acme-agent", "1.2.3", "all"),
		// a Debian package the security index does not list at this version:
		// the snapshot the fixture comes from has deb12u7, the host had
		// deb12u14 from a point release
		debPkg("libc6", "2.36-9+deb12u14", "arm64"),
		// an nginx.org build no longer in its index, while Debian's index
		// does not list nginx at all in these fixtures: the vendor index
		// still names it
		debPkg("nginx", "1.22.0-1~bookworm", "arm64"),
	}
	installed := map[string]struct{}{}
	for _, p := range pkgs {
		installed[p.Name] = struct{}{}
	}
	idx := newTestAptLists(fs, keys, known, readAptSources(newLocalSourceFiles(fs))).read(installed)
	require.True(t, idx.complete, "every component the fixture sources enable has an index")
	got := dpkgSources(pkgs, idx)

	assert.Equal(t, Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "Debian", URL: "http://deb.debian.org/debian-security"}, got[0], "libc6 from the Debian security archive")
	assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelVendorRepository, Name: "nginx", URL: "http://nginx.org/packages/debian"}, got[1], "nginx from nginx.org")
	assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelVendorRepository, Name: "Docker", URL: "https://download.docker.com/linux/debian"}, got[2], "docker-ce-cli from Docker")
	assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelDirect}, got[3], "a package no index lists was installed from a file")
	assert.Equal(t, Source{OSProvided: osProvided(true), Channel: ChannelOS}, got[4], "an outdated Debian package is still Debian's")
	assert.Equal(t, unknownSource(), got[5], "a version no index lists, named by a third-party index, is not decided by its name")
}

func TestDpkgSourcesWithoutOSKeys(t *testing.T) {
	fs := debianSourcesFS(t)
	// a distribution with no entry in dpkgOSKeyringPackages
	keys, known := readDpkgOSKeys(newLocalSourceFiles(fs), "someotherdistro", map[string]string{"debian-archive-keyring": "all"})
	assert.False(t, known)

	pkgs := []Package{debPkg("nginx", "1.30.5-1~bookworm", "arm64")}
	idx := newTestAptLists(fs, keys, known, readAptSources(newLocalSourceFiles(fs))).read(map[string]struct{}{"nginx": {}})
	got := dpkgSources(pkgs, idx)
	// the repository is still named, but nothing says whose it is
	assert.Nil(t, got[0].OSProvided)
	assert.Equal(t, ChannelUnknown, got[0].Channel)
	assert.Equal(t, "nginx", got[0].Name)
}

func TestDpkgSourcesWithoutIndexes(t *testing.T) {
	// most container images: dpkg's status, no apt indexes
	got := dpkgSources([]Package{debPkg("libc6", "2.36-9+deb12u14", "arm64")}, aptIndexes{})
	assert.Equal(t, unknownSource(), got[0])
	assert.Nil(t, got[0].OSProvided)
}

func TestDpkgSourceDecisions(t *testing.T) {
	osRel := &aptRelease{origin: "Debian", trustKnown: true, osSigned: true}
	vendorRel := &aptRelease{origin: "nginx", trustKnown: true}
	unknownRel := &aptRelease{origin: "Example", trustKnown: false}

	tests := []struct {
		name    string
		pkg     Package
		entries []aptIndexEntry
		want    Source
	}{
		{
			name:    "exact match in an OS index wins over a vendor index",
			pkg:     debPkg("nginx", "1.22.1-9+deb12u10", "amd64"),
			entries: []aptIndexEntry{{"1.22.1-9+deb12u10", "amd64", vendorRel}, {"1.22.1-9+deb12u10", "amd64", osRel}},
			want:    Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "Debian"},
		},
		{
			name:    "architecture must match",
			pkg:     debPkg("nginx", "1.30.5-1~bookworm", "amd64"),
			entries: []aptIndexEntry{{"1.30.5-1~bookworm", "arm64", vendorRel}},
			want:    unknownSource(),
		},
		{
			name:    "the version with its epoch is compared",
			pkg:     debPkg("docker-ce-cli", "5:29.8.2-1~debian.12~bookworm", "amd64"),
			entries: []aptIndexEntry{{"29.8.2-1~debian.12~bookworm", "amd64", vendorRel}},
			want:    unknownSource(),
		},
		{
			name:    "a vendor version older than the index still matches when the vendor keeps it",
			pkg:     debPkg("nginx", "1.30.4-1~bookworm", "amd64"),
			entries: []aptIndexEntry{{"1.30.4-1~bookworm", "amd64", vendorRel}, {"1.30.5-1~bookworm", "amd64", vendorRel}},
			want:    Source{OSProvided: osProvided(false), Channel: ChannelVendorRepository, Name: "nginx"},
		},
		{
			name:    "an exact match in an index of unknown trust is reported without a verdict",
			pkg:     debPkg("tool", "1.0", "amd64"),
			entries: []aptIndexEntry{{"1.0", "amd64", unknownRel}},
			want:    Source{Channel: ChannelUnknown, Name: "Example"},
		},
		{
			name:    "a name only an index of unknown trust lists is not attributed",
			pkg:     debPkg("tool", "0.9", "amd64"),
			entries: []aptIndexEntry{{"1.0", "amd64", unknownRel}},
			want:    unknownSource(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkg := tc.pkg
			assert.Equal(t, tc.want, dpkgSource(&pkg, tc.entries, true))
		})
	}
}

func TestParseAptReleaseFile(t *testing.T) {
	data, err := os.ReadFile(path.Join(dpkgFixtures, "lists", "nginx.org_packages_debian_dists_bookworm_InRelease"))
	require.NoError(t, err)
	origin, label, signed, sig := parseAptReleaseFile(data)
	assert.Equal(t, "nginx", origin)
	assert.Equal(t, "nginx", label)
	require.NotEmpty(t, sig, "the clearsigned release must yield its signature")

	keys := openPGPKeys{}
	nginxKey, err := os.ReadFile(path.Join(dpkgFixtures, "keyrings", "nginx-archive-keyring.gpg"))
	require.NoError(t, err)
	keys.addKeyring(nginxKey)
	assert.True(t, keys.verifies(signed, sig), "nginx.org's release is signed by nginx's key")

	debianKeys := openPGPKeys{}
	debianKey, err := os.ReadFile(path.Join(dpkgFixtures, "keyrings", "debian-archive-bookworm-security-automatic.gpg"))
	require.NoError(t, err)
	debianKeys.addKeyring(debianKey)
	assert.False(t, debianKeys.verifies(signed, sig), "and not by Debian's")

	// the signature is checked, not only the key ID it names: a release
	// whose signed text was changed after signing is not the key owner's
	tampered := bytes.Replace(signed, []byte("Origin: nginx"), []byte("Origin: Debian"), 1)
	require.NotEqual(t, signed, tampered)
	assert.False(t, keys.verifies(tampered, sig), "a changed release does not verify")
}

func TestOpenPGPKeysArmored(t *testing.T) {
	// Docker publishes its key armored, as docker.asc
	data, err := os.ReadFile(path.Join(dpkgFixtures, "keyrings", "docker.asc"))
	require.NoError(t, err)
	keys := openPGPKeys{}
	keys.addKeyring(data)
	release, err := os.ReadFile(path.Join(dpkgFixtures, "lists", "download.docker.com_linux_debian_dists_bookworm_InRelease"))
	require.NoError(t, err)
	_, _, signed, sig := parseAptReleaseFile(release)
	assert.True(t, keys.verifies(signed, sig), "Docker signs with a subkey and names only its key ID")
}

func TestReadDpkgOSKeysSkipsRemovedKeys(t *testing.T) {
	fs := afero.NewMemMapFs()
	list := "/usr/share/keyrings/debian-archive-removed-keys.gpg\n"
	require.NoError(t, afero.WriteFile(fs, path.Join(dpkgInfoDir, "debian-archive-keyring.list"), []byte(list), 0o644))
	// a real key at the removed-keys path must still not be trusted
	data, err := os.ReadFile(path.Join(dpkgFixtures, "keyrings", "debian-archive-bookworm-security-automatic.gpg"))
	require.NoError(t, err)
	require.NoError(t, afero.WriteFile(fs, "/usr/share/keyrings/debian-archive-removed-keys.gpg", data, 0o644))
	_, known := readDpkgOSKeys(newLocalSourceFiles(fs), "debian", map[string]string{"debian-archive-keyring": "all"})
	assert.False(t, known)
}

func TestAptPackagesFile(t *testing.T) {
	tests := []struct{ file, base, compression string }{
		{"deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages", "deb.debian.org_debian_dists_bookworm_main_binary-amd64_", ""},
		{"deb.debian.org_debian_dists_bookworm_main_binary-arm64_Packages.lz4", "deb.debian.org_debian_dists_bookworm_main_binary-arm64_", ".lz4"},
		{"archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_Packages.gz", "archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_", ".gz"},
	}
	for _, tc := range tests {
		base, compression, ok := aptPackagesFile(tc.file)
		assert.True(t, ok, tc.file)
		assert.Equal(t, tc.base, base, tc.file)
		assert.Equal(t, tc.compression, compression, tc.file)
	}
	for _, notIndex := range []string{
		"deb.debian.org_debian_dists_bookworm_InRelease",
		"deb.debian.org_debian_dists_bookworm_main_i18n_Translation-en",
		"deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages.diff_Index",
		"lock",
	} {
		_, _, ok := aptPackagesFile(notIndex)
		assert.False(t, ok, notIndex)
	}
}

func TestAptListHost(t *testing.T) {
	assert.Equal(t, "nginx.org/packages/debian", aptListHost("nginx.org_packages_debian_dists_bookworm_"))
	assert.Equal(t, "download.docker.com/linux/debian", aptListHost("download.docker.com_linux_debian_dists_bookworm_"))
	// a flat repository has no dists part
	assert.Equal(t, "repo.example/debian", aptListHost("repo.example_debian_._"))
	// apt escapes "_" in the URL before it turns "/" into "_"
	assert.Equal(t, "repo.example/my_repo", aptListHost("repo.example_my%5frepo_dists_stable_"))
	// a token in the query string is not a name to report
	assert.Equal(t, "pkgs.example.com/deb", aptListHost("pkgs.example.com_deb%3ftoken%3dabc_dists_stable_"))
	assert.Equal(t, "pkgs.example.com/deb", aptListHost("pkgs.example.com_deb?token=abc_dists_stable_"))
	assert.NotContains(t, aptListHost("user:secret%40repo.example_deb_dists_stable_"), "secret")
}

func TestReadAptSources(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/apt/sources.list", []byte(
		"# comment\n"+
			"deb http://deb.debian.org/debian bookworm main contrib # trailing comment\n"+
			"deb-src http://deb.debian.org/debian bookworm main\n"+
			"deb [arch=amd64 signed-by=/etc/apt/keyrings/x.gpg] https://user:s3cret@repo.example/apt/ stable main\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/apt/sources.list.d/vendor.sources", []byte(
		"Types: deb\nURIs: https://pkgs.example.com/deb?token=abc\nSuites: stable\nComponents: main\n\n"+
			"Types: deb\nURIs: https://disabled.example.com/deb\nSuites: stable\nComponents: main\nEnabled: no\n"), 0o644))
	// the Debian EC2 image points apt at a mirror list
	require.NoError(t, afero.WriteFile(fs, "/etc/apt/sources.list.d/mirror.list", []byte(
		"deb mirror+file:///etc/apt/mirrors/debian.list bookworm main\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/apt/mirrors/debian.list", []byte(
		"https://cdn-aws.deb.debian.org/debian\n"), 0o644))

	// a mirror list outside apt's configuration is not read
	require.NoError(t, afero.WriteFile(fs, "/etc/apt/sources.list.d/elsewhere.list", []byte(
		"deb mirror+file:///etc/shadow bookworm main\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/shadow", []byte("https://secret.example/x\n"), 0o600))

	got := readAptSources(newLocalSourceFiles(fs))
	assert.NotContains(t, got.urls, "_etc_shadow")
	assert.Equal(t, "http://deb.debian.org/debian", got.urls["deb.debian.org_debian"])
	assert.Equal(t, "https://repo.example/apt", got.urls["repo.example_apt"])
	assert.Equal(t, "https://pkgs.example.com/deb", got.urls["pkgs.example.com_deb"])
	assert.Equal(t, "https://cdn-aws.deb.debian.org/debian", got.urls["_etc_apt_mirrors_debian.list"])
	assert.NotContains(t, got.urls, "disabled.example.com_deb", "a disabled stanza enables nothing")
	for _, v := range got.urls {
		assert.NotContains(t, v, "s3cret")
		assert.NotContains(t, v, "token")
	}
	// deb-src lines name source packages, not installable ones
	assert.Len(t, got.entries, 5)
	assert.Equal(t, []string{"main", "contrib"}, got.entries[0].components)
}

func TestAptURIListPrefix(t *testing.T) {
	// each expectation is the file name prefix apt 2.6 printed with --print-uris
	tests := map[string]string{
		"http://deb.debian.org/debian":                       "deb.debian.org_debian",
		"http://ports.ubuntu.com/ubuntu-ports/":              "ports.ubuntu.com_ubuntu-ports",
		"http://user:pw@example.invalid:8080/a_b~c/d=e/":     "example.invalid:8080_a%5fb%7ec_d%3de",
		"mirror+file:///etc/apt/mirrors/x.list":              "_etc_apt_mirrors_x.list",
		"https://download.opensuse.org/repositories/shells:": "download.opensuse.org_repositories_shells:",
	}
	for uri, want := range tests {
		assert.Equal(t, want, aptURIListPrefix(uri), uri)
	}
}

func TestAptListsComplete(t *testing.T) {
	fs := afero.NewMemMapFs()
	write := func(name string) {
		require.NoError(t, afero.WriteFile(fs, path.Join(aptListsDir, name), []byte(""), 0o644))
	}
	write("archive.ubuntu.com_ubuntu_dists_noble_InRelease")
	write("archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_Packages")
	sources := aptSources{entries: []aptSourceEntry{{
		uri: "http://archive.ubuntu.com/ubuntu/", suites: []string{"noble"}, components: []string{"main", "universe"},
	}}}

	// an Ubuntu cloud image: main is indexed, universe is not until apt-get update
	l := newTestAptLists(fs, openPGPKeys{}, true, sources)
	assert.False(t, l.complete())
	assert.Equal(t, unknownSource(), dpkgSource(&Package{Name: "x", Version: "1", Format: DpkgPkgFormat}, nil, false),
		"a name missing from a partial set of indexes is not proof of a local install")

	write("archive.ubuntu.com_ubuntu_dists_noble_universe_binary-amd64_Packages.lz4")
	l = newTestAptLists(fs, openPGPKeys{}, true, sources)
	assert.True(t, l.complete())

	// a flat repository has no components
	write("repo.example_debian_._Packages")
	l = newTestAptLists(fs, openPGPKeys{}, true, aptSources{entries: []aptSourceEntry{{uri: "https://repo.example/debian", suites: []string{"./"}}}})
	assert.True(t, l.complete())

	// no sources to compare against: not known to be complete
	assert.False(t, newTestAptLists(fs, openPGPKeys{}, true, aptSources{}).complete())
}

func TestAptListsParseRemote(t *testing.T) {
	fs := debianSourcesFS(t)
	keys, known := readDpkgOSKeys(newLocalSourceFiles(fs), "debian", map[string]string{"debian-archive-keyring": "all"})
	l := newTestAptLists(fs, keys, known, readAptSources(newLocalSourceFiles(fs)))
	// what aptRemoteIndexCmd prints: each index behind a "#", then only the
	// identifying lines of installed names
	out := "#/var/lib/apt/lists/nginx.org_packages_debian_dists_bookworm_nginx_binary-arm64_Packages\n" +
		"Package: nginx\nVersion: 1.30.5-1~bookworm\nArchitecture: arm64\n" +
		"Package: nginx\nVersion: 1.30.4-1~bookworm\nArchitecture: arm64\n" +
		"#/var/lib/apt/lists/deb.debian.org_debian-security_dists_bookworm-security_main_binary-arm64_Packages\n" +
		"Package: libc6\nVersion: 2.36-9+deb12u7\nArchitecture: arm64\n"
	idx, err := l.parseRemote(strings.NewReader(out), map[string]struct{}{"nginx": {}, "libc6": {}})
	require.NoError(t, err)
	got := dpkgSources([]Package{
		debPkg("nginx", "1.30.5-1~bookworm", "arm64"),
		debPkg("libc6", "2.36-9+deb12u7", "arm64"),
	}, idx)
	assert.Equal(t, ChannelVendorRepository, got[0].Channel)
	assert.Equal(t, "nginx", got[0].Name)
	assert.Equal(t, ChannelOS, got[1].Channel)
	require.NotNil(t, got[1].OSProvided)
	assert.True(t, *got[1].OSProvided)
}

// sshConnection runs aptRemoteIndexCmd like an SSH connection to a Debian host
// would, and records whether it was asked to.
type sshConnection struct {
	fsConnection
	typ    shared.ConnectionType
	out    string
	status int
	ran    bool
}

func (c *sshConnection) Type() shared.ConnectionType { return c.typ }
func (c *sshConnection) Capabilities() shared.Capabilities {
	return shared.Capability_RunCommand | shared.Capability_File
}

func (c *sshConnection) RunCommand(command string) (*shared.Command, error) {
	c.ran = command == aptRemoteIndexCmd
	return &shared.Command{Command: command, Stdout: bytes.NewBufferString(c.out), Stderr: &bytes.Buffer{}, ExitStatus: c.status}, nil
}

func TestAptListsReadRemote(t *testing.T) {
	fs := debianSourcesFS(t)
	keys, known := readDpkgOSKeys(newLocalSourceFiles(fs), "debian", map[string]string{"debian-archive-keyring": "all"})
	out := "#/var/lib/apt/lists/nginx.org_packages_debian_dists_bookworm_nginx_binary-arm64_Packages\n" +
		"Package: nginx\nVersion: 1.30.5-1~bookworm\nArchitecture: arm64\n"

	ssh := &sshConnection{fsConnection: fsConnection{fs: fs}, typ: shared.Type_SSH, out: out}
	idx, ok := newTestAptLists(fs, keys, known, readAptSources(newLocalSourceFiles(fs))).readRemote(ssh, map[string]struct{}{"nginx": {}})
	require.True(t, ok)
	assert.True(t, ssh.ran, "an SSH connection filters the indexes on the host")
	assert.Len(t, idx.byName["nginx"], 1)

	// a local, container or image connection reads the files
	local := &sshConnection{fsConnection: fsConnection{fs: fs}, typ: shared.Type_Local, out: out}
	_, ok = newTestAptLists(fs, keys, known, readAptSources(newLocalSourceFiles(fs))).readRemote(local, map[string]struct{}{"nginx": {}})
	assert.False(t, ok)
	assert.False(t, local.ran)

	// a command that fails falls back to reading the files
	failed := &sshConnection{fsConnection: fsConnection{fs: fs}, typ: shared.Type_SSH, status: 127}
	_, ok = newTestAptLists(fs, keys, known, readAptSources(newLocalSourceFiles(fs))).readRemote(failed, map[string]struct{}{"nginx": {}})
	assert.False(t, ok)
}

func TestReadDpkgOSKeysOnlyReadsInstalledKeyringPackages(t *testing.T) {
	fs := debianSourcesFS(t)
	// the keyring package's file list is on disk, but dpkg does not list the
	// package as installed: its keys are not the system's
	_, known := readDpkgOSKeys(newLocalSourceFiles(fs), "debian", map[string]string{"bash": "arm64"})
	assert.False(t, known)

	// a multiarch package records its files under <name>:<arch>.list
	data, err := afero.ReadFile(fs, path.Join(dpkgInfoDir, "debian-archive-keyring.list"))
	require.NoError(t, err)
	require.NoError(t, fs.Remove(path.Join(dpkgInfoDir, "debian-archive-keyring.list")))
	require.NoError(t, afero.WriteFile(fs, path.Join(dpkgInfoDir, "debian-archive-keyring:arm64.list"), data, 0o644))
	_, known = readDpkgOSKeys(newLocalSourceFiles(fs), "debian", map[string]string{"debian-archive-keyring": "arm64"})
	assert.True(t, known)
}
