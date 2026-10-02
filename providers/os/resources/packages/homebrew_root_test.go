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
}

func (c *brewHostConn) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	out := ""
	if command == "id -u" {
		out = c.uid + "\n"
	}
	return &shared.Command{Command: command, Stdout: bytes.NewBufferString(out), Stderr: &bytes.Buffer{}}, nil
}

func (c *brewHostConn) FileInfo(path string) (shared.FileInfoDetails, error) {
	if path == "/home/linuxbrew/.linuxbrew/Cellar" {
		return shared.FileInfoDetails{Uid: c.cellarUID}, nil
	}
	return shared.FileInfoDetails{}, os.ErrNotExist
}

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
