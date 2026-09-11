// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every fixture in this file was captured from a real host: a RHEL 10.2
// container (registry.access.redhat.com/ubi10/ubi) running flatpak 1.18.0 with
// both the Flathub and the entitled Red Hat remotes configured, and Firefox
// installed from Flathub.
//
// That matters more than usual here. The fixtures this replaced were written by
// hand, and the deployment `metadata` file they invented carried `origin=` and
// `version=` keys that a real deployment does not have, so the filesystem
// fallback passed its tests while producing, on a real host, a package with no
// version and no origin that could never match an advisory.

func TestParseFlatpakList(t *testing.T) {
	f, err := os.Open("testdata/flatpak_list.txt")
	require.NoError(t, err)
	defer f.Close()

	deployments, err := parseFlatpakList(f)
	require.NoError(t, err)
	pkgs := flatpakPackages(deployments, nil)
	require.Len(t, pkgs, 1)

	firefox := pkgs[0]
	assert.Equal(t, "org.mozilla.firefox", firefox.Name)
	assert.Equal(t, "154.0.1", firefox.Version)
	assert.Equal(t, "flathub", firefox.Origin)
	assert.Equal(t, "aarch64", firefox.Arch)
	assert.Equal(t, "flatpak", firefox.Format)
	// The remote is the namespace: one application ID names different software
	// depending on where it came from. branch and commit are qualifiers, never
	// the version.
	assert.Equal(t,
		"pkg:flatpak/flathub/org.mozilla.firefox@154.0.1?branch=stable&commit=c84b98e041e5",
		firefox.PUrl)
}

// TestParseFlatpakListCellShapes covers the cell shapes the parser has to
// survive, using a listing captured WITHOUT --app so the runtimes are included.
// The collector itself only lists applications (see flatpakListCmd), but these
// are the real shapes flatpak emits and the parser must not mangle them.
func TestParseFlatpakListCellShapes(t *testing.T) {
	f, err := os.Open("testdata/flatpak_list_with_runtimes.txt")
	require.NoError(t, err)
	defer f.Close()

	deployments, err := parseFlatpakList(f)
	require.NoError(t, err)
	pkgs := flatpakPackages(deployments, nil)
	require.Len(t, pkgs, 5)

	byPurl := map[string]Package{}
	for _, p := range pkgs {
		byPurl[p.PUrl] = p
	}

	t.Run("an empty version stays empty", func(t *testing.T) {
		// org.freedesktop.Platform.codecs-extra genuinely publishes no version.
		// It must not be filled in with the branch or the commit: a PURL that
		// looks versioned but can never match is worse than one that is visibly
		// unversioned.
		p, ok := byPurl["pkg:flatpak/flathub/org.freedesktop.Platform.codecs-extra?branch=25.08-extra&commit=9c99837c6427"]
		require.True(t, ok, "got: %v", byPurl)
		assert.Empty(t, p.Version)
	})

	t.Run("a build-string version is preserved verbatim", func(t *testing.T) {
		p, ok := byPurl["pkg:flatpak/flathub/org.freedesktop.Platform@freedesktop-sdk-25.08.16?branch=25.08&commit=2c80d3df465c"]
		require.True(t, ok)
		assert.Equal(t, "freedesktop-sdk-25.08.16", p.Version)
	})

	t.Run("one application on two branches stays two packages", func(t *testing.T) {
		// org.freedesktop.Platform.GL.default is deployed on both 25.08 and
		// 25.08-extra at the same version but different commits. Without the
		// branch and commit qualifiers these two collapse into one identity.
		var glDefault []Package
		for _, p := range pkgs {
			if p.Name == "org.freedesktop.Platform.GL.default" {
				glDefault = append(glDefault, p)
			}
		}
		require.Len(t, glDefault, 2)
		assert.NotEqual(t, glDefault[0].PUrl, glDefault[1].PUrl)
	})
}

func TestParseFlatpakRemotes(t *testing.T) {
	f, err := os.Open("testdata/flatpak_remotes.txt")
	require.NoError(t, err)
	defer f.Close()

	remotes := ParseFlatpakRemotes(f)
	require.Len(t, remotes, 2)
	assert.Equal(t, "https://dl.flathub.org/repo/",
		remotes[flatpakRemoteKey(flatpakScopeSystem, "flathub")])
	// The entitled Red Hat remote. Its URL is an oci+https one, which is why
	// the value is taken verbatim rather than validated as an http(s) URL.
	assert.Equal(t, "oci+https://flatpaks.redhat.io/rhel/",
		remotes[flatpakRemoteKey(flatpakScopeSystem, "rhel")])
}

// TestParseFlatpakRemotesScopesByInstallation pins that a per-user remote cannot
// redefine a system remote of the same name.
//
// `flatpak remotes` lists system and user remotes together with no installation
// column, so the name alone is ambiguous. Captured from the lab host after
// `flatpak remote-add --user testuser https://example.com/repo/`, then edited to
// reuse the name "rhel" -- which is legal, and is the case that matters.
func TestParseFlatpakRemotesScopesByInstallation(t *testing.T) {
	const listing = "flathub\thttps://dl.flathub.org/repo/\tsystem\n" +
		"rhel\toci+https://flatpaks.redhat.io/rhel/\tsystem,oci,no-gpg-verify\n" +
		"rhel\thttps://example.com/repo/\tuser\n"

	remotes := ParseFlatpakRemotes(strings.NewReader(listing))
	require.Len(t, remotes, 3, "the two 'rhel' remotes are distinct entries")
	assert.Equal(t, "oci+https://flatpaks.redhat.io/rhel/",
		remotes[flatpakRemoteKey(flatpakScopeSystem, "rhel")])
	assert.Equal(t, "https://example.com/repo/",
		remotes[flatpakRemoteKey(flatpakScopeUser, "rhel")])
}

func TestParseFlatpakDir(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewOsFs()}
	deployments, err := parseFlatpakDir(afs, "testdata/flatpak/app", "testdata/flatpak")
	require.NoError(t, err)

	// One deployment, though the fixture tree holds three branch directories.
	// The other two (com.spotify.Client/x86_64 and org.mozilla.firefox/x86_64)
	// carry a metadata file and no deploy record, which is precisely the shape
	// the previous implementation read: it parsed metadata, found neither an
	// origin= nor a version= key in it, and reported a package with neither.
	// They must be skipped, and skipped silently -- a directory holding no
	// deployment record is not a deployment.
	require.Len(t, deployments, 1)
	for _, d := range deployments {
		assert.NotEqual(t, "com.spotify.Client", d.appID,
			"a metadata-only directory is not a deployment")
		assert.NotEqual(t, "x86_64", d.arch,
			"a metadata-only directory is not a deployment")
	}

	firefox := deployments[0]
	assert.Equal(t, "org.mozilla.firefox", firefox.appID)
	assert.Equal(t, "aarch64", firefox.arch)
	assert.Equal(t, "stable", firefox.branch)
	// The three fields the previous implementation could not produce, because
	// it read them from a file that does not contain them.
	assert.Equal(t, "flathub", firefox.origin)
	assert.Equal(t, "154.0.1", firefox.version)
	// The filesystem path gets the FULL commit; the CLI truncates it to 12.
	assert.Equal(t, "c84b98e041e58749e824ae83bb2de6da268f0a0ca19f299329a6943de768cb67", firefox.commit)

	// The PURL publishes the SHORT commit even though the filesystem knows the
	// full one, so that a running container and its own image do not become two
	// packages in an inventory. Compare with TestParseFlatpakList, which reaches
	// the same PURL through the CLI.
	assert.Equal(t,
		"pkg:flatpak/flathub/org.mozilla.firefox@154.0.1?branch=stable&commit=c84b98e041e5",
		firefox.toPackage().PUrl)
}

// TestParseFlatpakDirIgnoresSymlinkedViews is the regression test for the
// duplicate explosion: scanning one installed application through a filesystem
// connection produced 207 identical packages, because "current" (beside the
// arch directories) and "active" (beside the commit directories) are symlinks
// back into the same tree, and a backend that reports them as directories, or
// that flattens a listing, walks the deployment again under every one of them.
//
// Requiring the deploy file at the exact expected depth is what stops it.
func TestParseFlatpakDirIgnoresSymlinkedViews(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	const (
		appDir = "/var/lib/flatpak/app"
		appID  = "org.mozilla.firefox"
		commit = "c84b98e041e58749e824ae83bb2de6da268f0a0ca19f299329a6943de768cb67"
	)
	deploy := buildFlatpakDeploy("flathub", commit, [2]string{"appdata-version", "154.0.1"})

	// The real deployment.
	require.NoError(t, afs.WriteFile(appDir+"/"+appID+"/aarch64/stable/active/deploy", deploy, 0o644))
	// The same deployment reachable through the "current" symlink, as a
	// directory-flattening backend reports it.
	require.NoError(t, afs.WriteFile(appDir+"/"+appID+"/current/stable/active/deploy", deploy, 0o644))
	// And through the "active" alias at the branch level.
	require.NoError(t, afs.WriteFile(appDir+"/"+appID+"/aarch64/active/active/deploy", deploy, 0o644))
	// A path inside the deployment rather than a branch of it: no deploy file
	// at the expected depth, so it must not become a package.
	require.NoError(t, afs.WriteFile(appDir+"/"+appID+"/aarch64/stable/"+commit+"/files/bin/firefox", []byte("elf"), 0o755))

	deployments, err := parseFlatpakDir(afs, appDir, "/var/lib/flatpak")
	require.NoError(t, err)
	require.Len(t, deployments, 1)
	assert.Equal(t, "aarch64", deployments[0].arch)
	assert.Equal(t, "stable", deployments[0].branch)
}

// TestParseFlatpakDeploy works on the bytes of a real deploy file.
func TestParseFlatpakDeploy(t *testing.T) {
	data, err := os.ReadFile("testdata/flatpak/app/org.mozilla.firefox/aarch64/stable/active/deploy")
	require.NoError(t, err)

	deployment, ok := parseFlatpakDeploy(data)
	require.True(t, ok)
	assert.Equal(t, "flathub", deployment.origin)
	assert.Equal(t, "c84b98e041e58749e824ae83bb2de6da268f0a0ca19f299329a6943de768cb67", deployment.commit)
	assert.Equal(t, "154.0.1", deployment.version)
}

func TestParseFlatpakDeployRejectsGarbage(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"no NUL terminator", []byte("flathub")},
		{"second field is not a commit", []byte("flathub\x00not-a-commit\x00")},
		{
			// A truncated commit is the shape a short read produces. Accepting
			// it would invent an identity for a deployment we could not read.
			name: "truncated commit",
			data: []byte("flathub\x00c84b98e041e5\x00"),
		},
		{
			name: "binary noise",
			data: []byte{0x01, 0x02, 0x00, 0x03, 0x04, 0x00},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := parseFlatpakDeploy(tc.data)
			assert.False(t, ok)
		})
	}
}

// TestParseFlatpakDeployVersionIsOptional pins that a deployment without an
// appdata-version is still reported, with an empty version. Dropping it would
// lose the application from the inventory entirely.
func TestParseFlatpakDeployVersionIsOptional(t *testing.T) {
	const commit = "9c99837c6427a4bd0e6be5be5e4f0f2bd6c6a2f4b0d7a1c8e3f5b9d2a7c4e6f8"
	deployment, ok := parseFlatpakDeploy(buildFlatpakDeploy("flathub", commit,
		[2]string{"runtime", "org.freedesktop.Platform/aarch64/25.08"}))
	require.True(t, ok)
	assert.Equal(t, "flathub", deployment.origin)
	assert.Equal(t, commit, deployment.commit)
	assert.Empty(t, deployment.version)
}

func TestParseFlatpakRepoConfig(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewOsFs()}
	remotes := parseFlatpakRepoConfig(afs, "testdata/flatpak/repo/config")
	require.Len(t, remotes, 2)
	assert.Equal(t, "https://dl.flathub.org/repo/", remotes["flathub"])
	assert.Equal(t, "oci+https://flatpaks.redhat.io/rhel/", remotes["rhel"])

	t.Run("missing file is not an error", func(t *testing.T) {
		assert.Nil(t, parseFlatpakRepoConfig(afs, "testdata/flatpak/repo/does-not-exist"))
	})
}

func TestNewFlatpakPurl(t *testing.T) {
	assert.Equal(t,
		"pkg:flatpak/flathub/org.mozilla.firefox@154.0.1?branch=stable&commit=c84b98e041e5",
		newFlatpakPurl("org.mozilla.firefox", "154.0.1", "flathub", "stable", "c84b98e041e5"))

	t.Run("no origin", func(t *testing.T) {
		assert.Equal(t,
			"pkg:flatpak/com.spotify.Client@1.2.31.564",
			newFlatpakPurl("com.spotify.Client", "1.2.31.564", "", "", ""))
	})

	t.Run("no application ID yields no PURL", func(t *testing.T) {
		assert.Equal(t, "", newFlatpakPurl("", "1.0", "flathub", "stable", ""))
	})

	t.Run("application ID casing is preserved", func(t *testing.T) {
		// Flatpak application IDs are case-sensitive reverse-DNS names, and
		// Red Hat's Thunderbird really is spelled with a capital T. A PURL type
		// that case-folded the name would stop it matching.
		assert.Equal(t,
			"pkg:flatpak/rhel/org.mozilla.Thunderbird@140.13.0?branch=stable",
			newFlatpakPurl("org.mozilla.Thunderbird", "140.13.0", "rhel", "stable", ""))
	})
}

func TestAddFlatpakRepositoryURL(t *testing.T) {
	purl := newFlatpakPurl("org.mozilla.firefox", "140.14.0", "rhel", "stable", "")
	assert.Equal(t,
		"pkg:flatpak/rhel/org.mozilla.firefox@140.14.0?branch=stable&repository_url=oci%2Bhttps:%2F%2Fflatpaks.redhat.io%2Frhel%2F",
		addFlatpakRepositoryURL(purl, "oci+https://flatpaks.redhat.io/rhel/"))

	t.Run("no URL leaves the PURL alone", func(t *testing.T) {
		assert.Equal(t, purl, addFlatpakRepositoryURL(purl, ""))
	})

	t.Run("unparseable PURL is returned unchanged", func(t *testing.T) {
		assert.Equal(t, "not-a-purl", addFlatpakRepositoryURL("not-a-purl", "https://example.com"))
	})
}

// TestFlatpakPurlIsStableAcrossPaths pins that the CLI and the filesystem paths
// describe one deployment identically. They do not know the same things -- the
// filesystem reads the full commit and the CLI a 12-character prefix -- so
// without normalizing, scanning a running container and scanning its own image
// would put two packages in the inventory for one installed application.
func TestFlatpakPurlIsStableAcrossPaths(t *testing.T) {
	const (
		fullCommit  = "c84b98e041e58749e824ae83bb2de6da268f0a0ca19f299329a6943de768cb67"
		shortCommit = "c84b98e041e5"
	)

	fromFS := flatpakDeployment{
		appID: "org.mozilla.firefox", version: "154.0.1", branch: "stable",
		arch: "aarch64", origin: "flathub", commit: fullCommit,
	}
	fromCLI := fromFS
	fromCLI.commit = shortCommit

	assert.Equal(t, fromCLI.toPackage().PUrl, fromFS.toPackage().PUrl)
	assert.Equal(t,
		"pkg:flatpak/flathub/org.mozilla.firefox@154.0.1?branch=stable&commit="+shortCommit,
		fromFS.toPackage().PUrl)
}

// TestFlatpakDeployDictStringHandlesAlignmentPadding is the regression test for
// a reader that only worked by coincidence.
//
// GVariant aligns the variant inside an {sv} entry to 8 bytes, so up to 7 NUL
// padding bytes follow a key whose length+1 is not a multiple of 8. Both shapes
// are present in the real fixture: "appdata-version" (15+1=16) has none, while
// "appdata-name" (12+1=13) has three. The original reader took the byte right
// after the key and therefore read "" for the padded half.
func TestFlatpakDeployDictStringHandlesAlignmentPadding(t *testing.T) {
	data, err := os.ReadFile("testdata/flatpak/app/org.mozilla.firefox/aarch64/stable/active/deploy")
	require.NoError(t, err)

	t.Run("aligned key", func(t *testing.T) {
		v, ok := flatpakDeployDictString(data, "appdata-version")
		require.True(t, ok)
		assert.Equal(t, "154.0.1", v)
	})

	t.Run("padded key", func(t *testing.T) {
		v, ok := flatpakDeployDictString(data, "appdata-name")
		require.True(t, ok, "a key needing alignment padding must still resolve")
		assert.Equal(t, "Firefox", v)
	})

	t.Run("another aligned key", func(t *testing.T) {
		v, ok := flatpakDeployDictString(data, "runtime")
		require.True(t, ok)
		assert.Equal(t, "org.freedesktop.Platform/aarch64/25.08", v)
	})

	t.Run("absent key", func(t *testing.T) {
		_, ok := flatpakDeployDictString(data, "no-such-key")
		assert.False(t, ok)
	})

	t.Run("a long NUL run is not padding", func(t *testing.T) {
		// More than 7 NULs cannot be alignment; refusing to walk it keeps the
		// reader from wandering into binary and returning noise.
		_, ok := flatpakDeployDictString([]byte("eol\x00\x00\x00\x00\x00\x00\x00\x00\x00value\x00"), "eol")
		assert.False(t, ok)
	})
}

// TestParseFlatpakListDedupesInstallations pins that the CLI path collapses the
// same software the filesystem path does. `flatpak list` prints one row per
// INSTALLATION, so an application installed both system-wide and per-user
// appears twice with identical fields.
func TestParseFlatpakListDedupesInstallations(t *testing.T) {
	const row = "org.mozilla.firefox\t154.0.1\tstable\taarch64\tflathub\tc84b98e041e5\tsystem\n"
	deployments, err := parseFlatpakList(strings.NewReader(row + row))
	require.NoError(t, err)
	pkgs := flatpakPackages(deployments, nil)
	require.Len(t, pkgs, 1, "one application, not two identical PURLs")
	assert.Equal(t,
		"pkg:flatpak/flathub/org.mozilla.firefox@154.0.1?branch=stable&commit=c84b98e041e5",
		pkgs[0].PUrl)

	t.Run("a different branch is different software", func(t *testing.T) {
		other := "org.mozilla.firefox\t154.0.1\tbeta\taarch64\tflathub\tdeadbeefcafe\tsystem\n"
		deployments, err := parseFlatpakList(strings.NewReader(row + other))
		require.NoError(t, err)
		pkgs := flatpakPackages(deployments, nil)
		assert.Len(t, pkgs, 2)
	})
}

// TestListFromFSScopesRemotesPerInstallation pins that a per-user remote cannot
// redefine a system remote's URL.
//
// A remote name is scoped to its installation, so `flatpak remote-add --user
// rhel <other-url>` is legal. Merging every root's repo config into one map
// would let it overwrite the system `rhel` entry, hand every system-installed
// Red Hat Flatpak a foreign repository_url, and — because the server reads that
// URL to decide the publisher — drop all Red Hat advisory coverage. That is the
// exact boundary the URL exists to enforce.
func TestListFromFSScopesRemotesPerInstallation(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	const (
		commit     = "c84b98e041e58749e824ae83bb2de6da268f0a0ca19f299329a6943de768cb67"
		userCommit = "9c99837c6427a4bd0e6be5be5e4f0f2bd6c6a2f4b0d7a1c8e3f5b9d2a7c4e6f8"
	)
	deploy := buildFlatpakDeploy("rhel", commit, [2]string{"appdata-version", "140.14.0"})

	// System installation: the entitled Red Hat remote.
	require.NoError(t, afs.WriteFile(
		"/var/lib/flatpak/app/org.mozilla.firefox/aarch64/stable/active/deploy", deploy, 0o644))
	require.NoError(t, afs.WriteFile("/var/lib/flatpak/repo/config",
		[]byte("[remote \"rhel\"]\nurl=oci+https://flatpaks.redhat.io/rhel/\n"), 0o644))

	// A per-user installation that reuses the name "rhel" for something else.
	// It must carry a deployment of its OWN: parseFlatpakDir errors on a missing
	// app directory and the loop moves on, so a root with only a repo config is
	// never read -- an earlier version of this test did exactly that and would
	// have passed against the merged map it was written to rule out.
	const userRoot = "/home/alice/.local/share/flatpak"
	userDeploy := buildFlatpakDeploy("rhel", userCommit, [2]string{"appdata-version", "1.2.3"})
	require.NoError(t, afs.WriteFile(
		userRoot+"/app/org.example.App/aarch64/stable/active/deploy", userDeploy, 0o644))
	require.NoError(t, afs.WriteFile(userRoot+"/repo/config",
		[]byte("[remote \"rhel\"]\nurl=https://flatpaks.example.com/repo/\n"), 0o644))

	fpm := &FlatpakPkgManager{}
	pkgs, err := fpm.listFromFSWith(afs)
	require.NoError(t, err)
	require.Len(t, pkgs, 2)

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	// Both deployments name the remote "rhel"; each must get ITS OWN URL.
	assert.Contains(t, byName["org.mozilla.firefox"].PUrl, "flatpaks.redhat.io",
		"the system deployment must keep the SYSTEM remote's URL")
	assert.NotContains(t, byName["org.mozilla.firefox"].PUrl, "flatpaks.example.com")
	assert.Contains(t, byName["org.example.App"].PUrl, "flatpaks.example.com",
		"the per-user deployment must keep the USER remote's URL")
}

// TestFlatpakDeployDictStringEmptyValue pins that an empty string value reads as
// empty rather than as the byte that follows it.
//
// The alignment gap has to be COMPUTED from the key's offset, not found by
// scanning for NULs: a scan cannot tell padding from a value that is itself the
// empty string, so it consumes the empty value's own terminator and returns the
// GVariant type-signature byte ("s") as the version. That would publish
// <app>@s — a PURL that looks versioned and can never match, which is exactly
// what newFlatpakPurl's contract says is worse than a visibly unversioned one.
func TestFlatpakDeployDictStringEmptyValue(t *testing.T) {
	const commit = "c84b98e041e58749e824ae83bb2de6da268f0a0ca19f299329a6943de768cb67"
	data := buildFlatpakDeploy("flathub", commit, [2]string{"appdata-version", ""})

	v, ok := flatpakDeployDictString(data, "appdata-version")
	assert.Empty(t, v, "an empty value must not read as the following type byte")
	assert.False(t, ok)

	d, parsed := parseFlatpakDeploy(data)
	require.True(t, parsed)
	assert.Empty(t, d.version)
	assert.NotContains(t, d.toPackage().PUrl, "@s")
}

// TestListFromFSFindsRootUserInstallation pins that /root is treated as a home
// directory rather than as a container of them.
//
// Iterating the entries INSIDE /root builds /root/<subdir>/.local/share/flatpak
// and never /root/.local/share/flatpak, so anything installed with
// `sudo flatpak install --user` is invisible — and the filesystem walk is the
// only path available when a container image is scanned.
func TestListFromFSFindsRootUserInstallation(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	const commit = "c84b98e041e58749e824ae83bb2de6da268f0a0ca19f299329a6943de768cb67"
	deploy := buildFlatpakDeploy("flathub", commit, [2]string{"appdata-version", "154.0.1"})
	require.NoError(t, afs.WriteFile(
		"/root/.local/share/flatpak/app/org.mozilla.firefox/aarch64/stable/active/deploy",
		deploy, 0o644))

	fpm := &FlatpakPkgManager{}
	pkgs, err := fpm.listFromFSWith(afs)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "org.mozilla.firefox", pkgs[0].Name)
	assert.Equal(t, "154.0.1", pkgs[0].Version)
}

// TestParseFlatpakDeployAcceptsEmptyOrigin pins that a bundle-installed
// application still reaches the inventory.
//
// flatpak stores the origin as `origin ? origin : ""`, so
// `flatpak install --bundle app.flatpak` produces a record whose first string is
// empty. Treating that as a parse failure drops the application entirely — and
// on a container image the filesystem walk is the only path — to lose a field
// that only the provenance qualifier needs.
func TestParseFlatpakDeployAcceptsEmptyOrigin(t *testing.T) {
	const commit = "c84b98e041e58749e824ae83bb2de6da268f0a0ca19f299329a6943de768cb67"
	deployment, ok := parseFlatpakDeploy(buildFlatpakDeploy("", commit,
		[2]string{"appdata-version", "1.4.2"}))
	require.True(t, ok, "an empty origin is a value, not a parse failure")
	assert.Empty(t, deployment.origin)
	assert.Equal(t, commit, deployment.commit)
	assert.Equal(t, "1.4.2", deployment.version)

	deployment.appID = "org.example.Bundled"
	// No remote namespace, but the commit still identifies the deployment.
	assert.Equal(t, "pkg:flatpak/org.example.Bundled@1.4.2?commit=c84b98e041e5",
		deployment.toPackage().PUrl)
}

// TestFlatpakScopeFromOptions pins that a CUSTOM system installation is its own
// scope.
//
// flatpak names a custom installation in the options cell, so collapsing
// anything-not-"user" onto "system" lets a custom installation's remote
// overwrite the default installation's remote of the same name — the collision
// the (scope, name) key exists to prevent.
func TestFlatpakScopeFromOptions(t *testing.T) {
	tests := map[string]string{
		"system":                   flatpakScopeSystem,
		"user":                     flatpakScopeUser,
		"system,oci,no-gpg-verify": flatpakScopeSystem,
		"user,no-enumerate":        flatpakScopeUser,
		"extra,oci":                "extra",
		// A flag we do not know about must not shadow a standard scope, wherever
		// it appears in the cell. Reading the first non-flag token would have
		// returned "no-filter" here and given the remote a scope no deployment
		// uses.
		"no-filter,system":  flatpakScopeSystem,
		"no-filter,user":    flatpakScopeUser,
		"oci,no-gpg-verify": flatpakScopeSystem,
		"":                  flatpakScopeSystem,
	}
	for options, want := range tests {
		assert.Equal(t, want, flatpakScopeFromOptions(options), options)
	}

	t.Run("a custom installation does not collide with the default one", func(t *testing.T) {
		const listing = "flathub\thttps://dl.flathub.org/repo/\tsystem\n" +
			"flathub\thttps://mirror.corp/repo/\textra,oci\n"
		remotes := ParseFlatpakRemotes(strings.NewReader(listing))
		require.Len(t, remotes, 2)
		assert.Equal(t, "https://dl.flathub.org/repo/",
			remotes[flatpakRemoteKey(flatpakScopeSystem, "flathub")])
		assert.Equal(t, "https://mirror.corp/repo/",
			remotes[flatpakRemoteKey("extra", "flathub")])
	})
}

// TestResolveFlatpakDeploymentOutcomes pins the difference between a directory
// that is not a branch and a branch whose record cannot be read. A container
// image is read as a layered tar whose ReadDir reports every descendant, so
// every file under a deployment arrives here as a branch candidate; warning on
// those produced 154 WARN lines for a single installed application. Only the
// unreadable case may warn.
func TestResolveFlatpakDeploymentOutcomes(t *testing.T) {
	const (
		appID  = "org.mozilla.firefox"
		arch   = "aarch64"
		commit = "c84b98e041e58749e824ae83bb2de6da268f0a0ca19f299329a6943de768cb67"
		root   = "/var/lib/flatpak"
	)

	t.Run("a readable deployment resolves", func(t *testing.T) {
		afs := &afero.Afero{Fs: afero.NewMemMapFs()}
		branchDir := root + "/app/" + appID + "/" + arch + "/stable"
		deploy := buildFlatpakDeploy("flathub", commit, [2]string{"appdata-version", "154.0.1"})
		require.NoError(t, afs.WriteFile(branchDir+"/active/deploy", deploy, 0o644))

		got, outcome := resolveFlatpakDeployment(afs, branchDir, root, appID, arch, "stable")
		assert.Equal(t, flatpakResolveOK, outcome)
		assert.Equal(t, "154.0.1", got.version)
	})

	t.Run("a path inside the deployment is not a branch", func(t *testing.T) {
		afs := &afero.Afero{Fs: afero.NewMemMapFs()}
		// "browser" is a directory inside the deployed app, not a branch. It
		// holds no commit-named subdirectory, so it must resolve silently.
		branchDir := root + "/app/" + appID + "/" + arch + "/browser"
		require.NoError(t, afs.WriteFile(branchDir+"/omni.ja", []byte("zip"), 0o644))

		_, outcome := resolveFlatpakDeployment(afs, branchDir, root, appID, arch, "browser")
		assert.Equal(t, flatpakResolveNotADeployment, outcome)
	})

	t.Run("a missing directory is not a branch", func(t *testing.T) {
		afs := &afero.Afero{Fs: afero.NewMemMapFs()}
		_, outcome := resolveFlatpakDeployment(afs, root+"/app/"+appID+"/"+arch+"/th", root, appID, arch, "th")
		assert.Equal(t, flatpakResolveNotADeployment, outcome)
	})

	t.Run("a commit directory that will not parse is unreadable", func(t *testing.T) {
		afs := &afero.Afero{Fs: afero.NewMemMapFs()}
		branchDir := root + "/app/" + appID + "/" + arch + "/stable"
		// Shaped like a deployment -- a commit-named directory -- but the
		// record is not a deploy tuple. This is the case worth a WARN: a
		// GVariant layout change would look exactly like this.
		require.NoError(t, afs.WriteFile(branchDir+"/"+commit+"/deploy", []byte("not gvariant"), 0o644))

		_, outcome := resolveFlatpakDeployment(afs, branchDir, root, appID, arch, "stable")
		assert.Equal(t, flatpakResolveUnreadable, outcome)
	})
}

// TestParseFlatpakDirReadsSiblingApplications covers the app-directory loop:
// several applications installed side by side in one installation root, each
// resolved to its own identity.
//
// The on-disk fixture holds a single application, because it is a byte-for-byte
// capture of one lab host. This is the case that capture cannot express, and it
// was previously covered by a hand-written fixture whose `metadata` file
// declared `version=` and `origin=` keys that flatpak does not write -- the
// reason that fixture is gone. The deploy records here are built by
// buildFlatpakDeploy, whose encoding is pinned against the real captured file
// by TestParseFlatpakDeploy.
func TestParseFlatpakDirReadsSiblingApplications(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	const (
		appDir         = "/var/lib/flatpak/app"
		firefoxCommit  = "c84b98e041e58749e824ae83bb2de6da268f0a0ca19f299329a6943de768cb67"
		spotifyCommit  = "1f3c7a9b2d4e6f8a0b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a"
		thunderbirdSha = "5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b"
		gimpCommit     = "3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f"
	)

	// Three applications, two remotes, one installation root.
	require.NoError(t, afs.WriteFile(appDir+"/org.mozilla.firefox/aarch64/stable/active/deploy",
		buildFlatpakDeploy("flathub", firefoxCommit, [2]string{"appdata-version", "154.0.1"}), 0o644))
	require.NoError(t, afs.WriteFile(appDir+"/com.spotify.Client/aarch64/stable/active/deploy",
		buildFlatpakDeploy("flathub", spotifyCommit, [2]string{"appdata-version", "1.2.31.564"}), 0o644))
	require.NoError(t, afs.WriteFile(appDir+"/org.mozilla.Thunderbird/aarch64/stable/active/deploy",
		buildFlatpakDeploy("rhel", thunderbirdSha, [2]string{"appdata-version", "140.14.0"}), 0o644))

	// An x86_64 deployment alongside the aarch64 ones. The arch is a pass-through
	// directory level -- nothing in the walk matches on its value -- and the
	// on-disk fixture can only capture the arch of the host it was taken from,
	// so the arch that most real hosts actually run is pinned here instead.
	require.NoError(t, afs.WriteFile(appDir+"/org.gimp.GIMP/x86_64/stable/active/deploy",
		buildFlatpakDeploy("flathub", gimpCommit, [2]string{"appdata-version", "3.0.4"}), 0o644))

	deployments, err := parseFlatpakDir(afs, appDir, "/var/lib/flatpak")
	require.NoError(t, err)
	require.Len(t, deployments, 4, "one deployment per installed application")

	byID := map[string]flatpakDeployment{}
	for _, d := range deployments {
		byID[d.appID] = d
	}

	require.Contains(t, byID, "org.mozilla.firefox")
	assert.Equal(t, "154.0.1", byID["org.mozilla.firefox"].version)
	assert.Equal(t, "flathub", byID["org.mozilla.firefox"].origin)

	require.Contains(t, byID, "com.spotify.Client")
	assert.Equal(t, "1.2.31.564", byID["com.spotify.Client"].version)
	assert.Equal(t, spotifyCommit, byID["com.spotify.Client"].commit)

	// A sibling from a different remote keeps its own origin: the origin is a
	// property of the deployment, never of the installation it sits in.
	require.Contains(t, byID, "org.mozilla.Thunderbird")
	assert.Equal(t, "rhel", byID["org.mozilla.Thunderbird"].origin)
	assert.Equal(t, "140.14.0", byID["org.mozilla.Thunderbird"].version)

	// The arch travels through untouched, whatever it is.
	require.Contains(t, byID, "org.gimp.GIMP")
	assert.Equal(t, "x86_64", byID["org.gimp.GIMP"].arch)
	assert.Equal(t, "3.0.4", byID["org.gimp.GIMP"].version)
	assert.Equal(t, "aarch64", byID["org.mozilla.firefox"].arch)
}

// TestFlatpakDeployDictStringMatchesKeyStart pins that a key lookup matches a
// key, not any occurrence of the key's bytes.
//
// The blob is searched with bytes.Index, which has no notion of where a string
// begins. A longer key ending in the same suffix ("xa-appdata-version" for
// "appdata-version") matches at an offset inside that longer key, and the value
// read back belongs to the wrong field entirely. Strings here are
// NUL-terminated, so a genuine key starts the buffer or follows a NUL.
func TestFlatpakDeployDictStringMatchesKeyStart(t *testing.T) {
	const commit = "c84b98e041e58749e824ae83bb2de6da268f0a0ca19f299329a6943de768cb67"

	t.Run("a longer key ending in the same suffix is not the key", func(t *testing.T) {
		deploy := buildFlatpakDeploy("flathub", commit,
			[2]string{"xa-appdata-version", "999.999.999"},
			[2]string{"appdata-version", "154.0.1"})

		got, ok := flatpakDeployDictString(deploy, "appdata-version")
		require.True(t, ok)
		assert.Equal(t, "154.0.1", got,
			"matched inside xa-appdata-version and read the wrong field's value")
	})

	t.Run("the key is still found when it is the only entry", func(t *testing.T) {
		deploy := buildFlatpakDeploy("flathub", commit,
			[2]string{"appdata-version", "154.0.1"})

		got, ok := flatpakDeployDictString(deploy, "appdata-version")
		require.True(t, ok)
		assert.Equal(t, "154.0.1", got)
	})

	t.Run("an absent key is absent", func(t *testing.T) {
		deploy := buildFlatpakDeploy("flathub", commit,
			[2]string{"xa-appdata-version", "999.999.999"})

		_, ok := flatpakDeployDictString(deploy, "appdata-version")
		assert.False(t, ok, "only a suffix match exists, which is not the key")
	})
}
