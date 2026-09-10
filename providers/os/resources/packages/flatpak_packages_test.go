// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
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

	pkgs, err := ParseFlatpakList(f)
	require.NoError(t, err)
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

	pkgs, err := ParseFlatpakList(f)
	require.NoError(t, err)
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
	assert.Equal(t, "https://dl.flathub.org/repo/", remotes["flathub"])
	// The entitled Red Hat remote. Its URL is an oci+https one, which is why
	// the value is taken verbatim rather than validated as an http(s) URL.
	assert.Equal(t, "oci+https://flatpaks.redhat.io/rhel/", remotes["rhel"])
}

func TestParseFlatpakDir(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewOsFs()}
	deployments, err := parseFlatpakDir(afs, "testdata/flatpak/app", "testdata/flatpak")
	require.NoError(t, err)
	require.Len(t, deployments, 1)

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
	deploy := []byte("flathub\x00" + commit + "\x00\x00\x00appdata-version\x00154.0.1\x00")

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
	deployment, ok := parseFlatpakDeploy([]byte("flathub\x00" + commit + "\x00\x00\x00runtime\x00org.freedesktop.Platform/aarch64/25.08\x00"))
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
