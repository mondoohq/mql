// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// brewHostConn is a Linuxbrew host: brew under /home/linuxbrew/.linuxbrew,
// owned by uid 1000, and a scan running as uid.
type brewHostConn struct {
	shared.Connection
	uid       string
	fs        afero.Fs
	cellarUID int64
	commands  []string
	brewInfo  string // stdout of brew info; the real command runs brew
}

func (c *brewHostConn) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	out := ""
	if command == "id -u" {
		out = c.uid + "\n"
	} else if c.brewInfo != "" {
		out = c.brewInfo
	}
	return &shared.Command{Command: command, Stdout: bytes.NewBufferString(out), Stderr: &bytes.Buffer{}}, nil
}

func (c *brewHostConn) FileInfo(path string) (shared.FileInfoDetails, error) {
	if path == "/home/linuxbrew/.linuxbrew/Cellar" {
		return shared.FileInfoDetails{Uid: c.cellarUID}, nil
	}
	return shared.FileInfoDetails{}, os.ErrNotExist
}

func (c *brewHostConn) Capabilities() shared.Capabilities { return shared.Capability_RunCommand }

func (c *brewHostConn) FileSystem() afero.Fs { return c.fs }

const linuxbrew = "/home/linuxbrew/.linuxbrew"

// As root, brew exits with "Running Homebrew as root is extremely dangerous
// and no longer supported", so the scan fell back to the Cellar and lost
// outdated and pinned. It now runs brew as the owner of the Cellar.
func TestBrewInfoCommandAsRoot(t *testing.T) {
	c := &brewHostConn{uid: "0", cellarUID: 1000}
	h := &HomebrewPkgManager{Conn: c}
	assert.Equal(t,
		"sudo -n -H -u '#1000' /bin/sh -c 'cd / && exec /home/linuxbrew/.linuxbrew/bin/brew info --json=v2 --installed'",
		h.brewInfoCommand(linuxbrew+"/bin/brew", linuxbrew))

	// not root: brew runs as is
	c = &brewHostConn{uid: "1000", cellarUID: 1000}
	h = &HomebrewPkgManager{Conn: c}
	assert.Equal(t, linuxbrew+"/bin/brew info --json=v2 --installed", h.brewInfoCommand(linuxbrew+"/bin/brew", linuxbrew))

	// a root-owned installation has no one else to run as
	c = &brewHostConn{uid: "0", cellarUID: 0}
	h = &HomebrewPkgManager{Conn: c}
	assert.Equal(t, linuxbrew+"/bin/brew info --json=v2 --installed", h.brewInfoCommand(linuxbrew+"/bin/brew", linuxbrew))
}

// The filesystem fallback reads `brew pin` from var/homebrew/pinned and,
// with no access to brew's index, cannot know whether a formula is outdated.
func TestListFromFSPinnedAndOutdatedUnknown(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll(linuxbrew+"/Cellar/hello/2.12.3", 0o755))
	require.NoError(t, fs.MkdirAll(linuxbrew+"/Cellar/jq/1.8.2", 0o755))
	require.NoError(t, afero.WriteFile(fs, linuxbrew+"/Cellar/jq/1.8.2/INSTALL_RECEIPT.json",
		[]byte(`{"installed_on_request": true, "source": {"tap": "homebrew/core"}}`), 0o644))
	require.NoError(t, fs.MkdirAll(linuxbrew+"/Cellar/oniguruma/6.9.10", 0o755))
	require.NoError(t, afero.WriteFile(fs, linuxbrew+"/Cellar/oniguruma/6.9.10/INSTALL_RECEIPT.json",
		[]byte(`{"installed_on_request": false, "source": {"tap": "homebrew/core"}}`), 0o644))
	// brew pin hello: a symlink named after the formula; its target does not matter here
	require.NoError(t, afero.WriteFile(fs, linuxbrew+"/var/homebrew/pinned/hello", nil, 0o644))

	h := &HomebrewPkgManager{Conn: &brewHostConn{fs: fs}}
	pkgs, err := h.listFromFS()
	require.NoError(t, err)
	require.Len(t, pkgs, 3)

	hello := findHomebrewPkg(pkgs, "hello")
	require.NotNil(t, hello)
	assert.True(t, hello.Pinned)
	assert.True(t, hello.OutdatedUnknown)

	jq := findHomebrewPkg(pkgs, "jq")
	require.NotNil(t, jq)
	assert.False(t, jq.Pinned)
	assert.True(t, jq.OutdatedUnknown)
	assert.False(t, jq.InstalledAsDependency)

	// Homebrew 4 receipts carry no installed_as_dependency
	onig := findHomebrewPkg(pkgs, "oniguruma")
	require.NotNil(t, onig)
	assert.True(t, onig.InstalledAsDependency)
}

// `brew info --json=v2 --installed` from Homebrew 4 on Ubuntu 24.04. It has
// no installed_as_dependency key, so every formula used to report false,
// including oniguruma, which brew installed for jq.
func TestParseHomebrewInfoWithoutInstalledAsDependency(t *testing.T) {
	data, err := os.ReadFile("./testdata/homebrew_info_linuxbrew.json")
	require.NoError(t, err)
	pkgs, err := ParseHomebrewInfo(data, linuxbrew)
	require.NoError(t, err)
	require.Len(t, pkgs, 4)

	onig := findHomebrewPkg(pkgs, "oniguruma")
	require.NotNil(t, onig)
	assert.False(t, onig.InstalledOnRequest)
	assert.True(t, onig.InstalledAsDependency)

	jq := findHomebrewPkg(pkgs, "jq")
	require.NotNil(t, jq)
	assert.True(t, jq.InstalledOnRequest)
	assert.False(t, jq.InstalledAsDependency)

	g03 := findHomebrewPkg(pkgs, "g03hello")
	require.NotNil(t, g03)
	assert.True(t, g03.Outdated)
	assert.False(t, g03.OutdatedUnknown)
	assert.True(t, findHomebrewPkg(pkgs, "hello").Pinned)
}

// linkFs is a MemMapFs that can read symlinks. MemMapFs has none, so a link is
// an empty file plus an entry in the table: link path to target, as readlink
// prints it.
type linkFs struct {
	afero.Fs
	links map[string]string
}

func (f linkFs) ReadlinkIfPossible(name string) (string, error) {
	if t, ok := f.links[name]; ok {
		return t, nil
	}
	return "", os.ErrInvalid
}

// A cask names its Caskroom folder after the version at install time and never
// renames it, while an auto-updating app moves on. The *.app links in that
// folder are the only record of where the app lives. Layout measured on
// macOS 26.4 with Homebrew 6.0.2 (google-chrome); the others are variations.
func caskroomFixture(t *testing.T) *brewHostConn {
	t.Helper()
	mem := afero.NewMemMapFs()
	fs := linkFs{Fs: mem, links: map[string]string{}}
	cr := "/opt/homebrew/Caskroom"
	link := func(path, target string) {
		require.NoError(t, afero.WriteFile(mem, path, nil, 0o755))
		fs.links[path] = target
	}
	// google-chrome: absolute link to the app Chrome updates in place
	require.NoError(t, afero.WriteFile(mem, cr+"/google-chrome/146.0.7680.178/.keystone_install", nil, 0o755))
	link(cr+"/google-chrome/146.0.7680.178/Google Chrome.app", "/Applications/Google Chrome.app")
	require.NoError(t, afero.WriteFile(mem, cr+"/google-chrome/.metadata/INSTALL_RECEIPT.json", nil, 0o644))
	require.NoError(t, mem.MkdirAll(cr+"/google-chrome/.metadata/146.0.7680.178/20260301/Casks", 0o755))
	// relative link, as a custom appdir under the version folder would give
	link(cr+"/rel/1.0/Rel.app", "../../../../../Users/me/Applications/Rel.app")
	// a real bundle directory
	require.NoError(t, mem.MkdirAll(cr+"/real/2.0/Real.app/Contents", 0o755))
	// a pkg-installed cask has no app bundle
	require.NoError(t, afero.WriteFile(mem, cr+"/zoom-pkg/6.0/zoom.pkg", nil, 0o644))
	return &brewHostConn{fs: fs}
}

func TestCaskAppPathsFromCaskroom(t *testing.T) {
	h := &HomebrewPkgManager{Conn: caskroomFixture(t)}
	pkgs, err := h.listFromFS()
	require.NoError(t, err)
	require.Len(t, pkgs, 4) // .metadata is not a version

	chrome := findHomebrewPkg(pkgs, "google-chrome")
	require.NotNil(t, chrome)
	assert.Equal(t, "146.0.7680.178", chrome.Version)
	assert.Equal(t, []string{"/Applications/Google Chrome.app"}, chrome.AppPaths)
	assert.Equal(t, []string{"/Users/me/Applications/Rel.app"}, findHomebrewPkg(pkgs, "rel").AppPaths)
	assert.Equal(t, []string{"/opt/homebrew/Caskroom/real/2.0/Real.app"}, findHomebrewPkg(pkgs, "real").AppPaths)
	assert.Empty(t, findHomebrewPkg(pkgs, "zoom-pkg").AppPaths)
}

// Without symlink support the links are skipped, not guessed; a real bundle
// still counts.
func TestCaskAppPathsFsWithoutLinkSupport(t *testing.T) {
	conn := caskroomFixture(t)
	conn.fs = conn.fs.(linkFs).Fs
	h := &HomebrewPkgManager{Conn: conn}
	pkgs, err := h.listFromFS()
	require.NoError(t, err)
	assert.Empty(t, findHomebrewPkg(pkgs, "google-chrome").AppPaths)
	assert.Equal(t, []string{"/opt/homebrew/Caskroom/real/2.0/Real.app"}, findHomebrewPkg(pkgs, "real").AppPaths)
}

// The brew info route sets the same Path as the filesystem route and gets its
// app paths from the Caskroom; formulae get none.
func TestCaskAppPathsFromCLI(t *testing.T) {
	conn := caskroomFixture(t)
	require.NoError(t, afero.WriteFile(conn.fs, "/opt/homebrew/bin/brew", nil, 0o755))
	conn.brewInfo = `{"formulae":[{"name":"jq","tap":"homebrew/core","installed":[{"version":"1.7","installed_on_request":true}]}],
	"casks":[{"token":"google-chrome","tap":"homebrew/cask","version":"156.0.1","installed":"146.0.7680.178","auto_updates":true},
	{"token":"zoom-pkg","tap":"homebrew/cask","version":"6.0","installed":"6.0"}]}`

	pkgs, err := (&HomebrewPkgManager{Conn: conn}).ListExtended()
	require.NoError(t, err)
	require.Len(t, pkgs, 3)

	chrome := findHomebrewPkg(pkgs, "google-chrome")
	assert.Equal(t, "/opt/homebrew/Caskroom/google-chrome/146.0.7680.178", chrome.Path)
	assert.Equal(t, []string{"/Applications/Google Chrome.app"}, chrome.AppPaths)
	assert.Empty(t, findHomebrewPkg(pkgs, "zoom-pkg").AppPaths)
	assert.Empty(t, findHomebrewPkg(pkgs, "jq").AppPaths)
}
