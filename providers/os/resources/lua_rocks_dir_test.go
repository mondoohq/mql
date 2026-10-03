// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Amazon Linux 2023 has no /usr/lib/luarocks: LuaRocks is built into
// /usr/local. A search of /usr then fell through to reading /usr as a rocks
// directory under another name, which read every directory two levels down
// and took 9 to 12 minutes over SSH with --sudo. Fails if collectLuaPackages
// reads past the first directory of /usr that is not a rock.
func TestCollectLuaPackagesRockTreeWithoutLuaRocksIsNotARocksDir(t *testing.T) {
	mem := afero.NewMemMapFs()
	for _, p := range []string{
		"/usr/bin/lua",
		"/usr/bin/luarocks",
		"/usr/include/openssl/ssl.h",
		"/usr/lib/python3.9/site-packages/dnf/__init__.py",
		"/usr/lib64/lua/5.4/lpeg.so",
		"/usr/share/doc/lua/README",
		"/usr/local/lib/luarocks/rocks-5.4/manifest",
		"/usr/local/lib/luarocks/rocks-5.4/argparse/0.7.1-1/argparse-0.7.1-1.rockspec",
		"/usr/local/lib/luarocks/rocks-5.4/argparse/0.7.1-1/rock_manifest",
	} {
		require.NoError(t, afero.WriteFile(mem, p, nil, 0o644))
	}
	require.NoError(t, mem.MkdirAll("/usr/games", 0o755))
	counter := &readdirCounter{Fs: mem, entries: map[string]int{}, opened: map[string]int{}}

	pkgs, _ := collectLuaPackages(&afero.Afero{Fs: counter}, "/usr")
	assert.Empty(t, pkgs)
	for _, dir := range []string{"/usr/games", "/usr/include", "/usr/include/openssl", "/usr/lib", "/usr/lib64", "/usr/share", "/usr/local"} {
		assert.Zero(t, counter.opened[dir], dir)
	}
	// over SSH with --sudo, reading the entries of /usr/bin stats every program
	assert.Zero(t, counter.entries["/usr/bin"], "/usr/bin entries read")

	// the rock tree and its rocks directory are still read
	pkgs, _ = collectLuaPackages(&afero.Afero{Fs: mem}, "/usr/local")
	assert.Equal(t, []string{"argparse@0.7.1-1"}, names(pkgs))
	// a copy of a rocks directory under a name of its own, with its manifest
	for _, p := range []string{
		"/srv/rocks-copy/manifest",
		"/srv/rocks-copy/argparse/0.7.1-1/rock_manifest",
	} {
		require.NoError(t, afero.WriteFile(mem, p, nil, 0o644))
	}
	pkgs, _ = collectLuaPackages(&afero.Afero{Fs: mem}, "/srv/rocks-copy")
	assert.Equal(t, []string{"argparse@0.7.1-1"}, names(pkgs))
}

// readdirCounter records every directory opened through it, and every
// directory whose entries (not just names) were read.
type readdirCounter struct {
	afero.Fs
	opened  map[string]int
	entries map[string]int
}

func (c *readdirCounter) Open(name string) (afero.File, error) {
	c.opened[name]++
	f, err := c.Fs.Open(name)
	if err != nil {
		return nil, err
	}
	return &readdirCountingFile{File: f, counter: c}, nil
}

type readdirCountingFile struct {
	afero.File
	counter *readdirCounter
}

func (f *readdirCountingFile) Readdir(n int) ([]os.FileInfo, error) {
	f.counter.entries[f.Name()]++
	return f.File.Readdir(n)
}
