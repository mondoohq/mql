// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/lua/luarocks"
	"go.mondoo.com/mql/sbom"
)

// The layout of an Ubuntu host with luarocks installed from the archive: the
// luarocks modules under /usr/share/lua, a LuaRocks 2.x system tree (one
// unversioned rocks directory, Ubuntu 16.04 to 20.04), and a per-user tree.
func luaHostFS(t *testing.T, systemRocksDir string) *afero.Afero {
	t.Helper()
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for _, p := range []string{
		"/usr/share/lua/5.1/luarocks/cmd/install.lua",
		"/usr/share/lua/5.1/luarocks/fs/unix/tools.lua",
		"/usr/share/lua/5.3/luarocks/core/cfg.lua",
		"/usr/local/lib/luarocks/" + systemRocksDir + "/manifest",
		"/usr/local/lib/luarocks/" + systemRocksDir + "/argparse/0.7.1-1/argparse-0.7.1-1.rockspec",
		"/usr/local/lib/luarocks/" + systemRocksDir + "/argparse/0.7.1-1/rock_manifest",
		"/usr/local/lib/luarocks/" + systemRocksDir + "/inspect/3.1.1-0/inspect-3.1.1-0.rockspec",
		"/home/ubuntu/.luarocks/lib/luarocks/rocks-5.1/serpent/0.30-2/serpent-0.30-2.rockspec",
	} {
		require.NoError(t, afs.WriteFile(p, nil, 0o644))
	}
	return afs
}

func names(pkgs []*languages.Package) []string {
	out := []string{}
	for _, p := range pkgs {
		out = append(out, p.Name+"@"+p.Version)
	}
	sort.Strings(out)
	return out
}

func TestCollectLuaPackagesPathForms(t *testing.T) {
	for _, rocksDir := range []string{"rocks", "rocks-5.1"} {
		afs := luaHostFS(t, rocksDir)
		want := []string{"argparse@0.7.1-1", "inspect@3.1.1-0"}

		for _, p := range []string{
			"/usr/local/lib/luarocks/" + rocksDir, // the rocks directory
			"/usr/local/lib/luarocks",             // its parent
			"/usr/local",                          // the rock tree
		} {
			pkgs, fps := collectLuaPackages(afs, p)
			assert.Equal(t, want, names(pkgs), "%s with %s", p, rocksDir)
			assert.Len(t, fps, 2)
		}
	}

	afs := luaHostFS(t, "rocks")
	pkgs, _ := collectLuaPackages(afs, "/usr/share/lua/5.1")
	assert.Empty(t, pkgs, "Lua module directories hold no rocks")
	pkgs, _ = collectLuaPackages(afs, "/home/ubuntu/.luarocks")
	assert.Equal(t, []string{"serpent@0.30-2"}, names(pkgs))
}

// Without the CLI the system trees and per-user trees are read from disk.
func TestAddLuaRockTreesWithoutCLI(t *testing.T) {
	afs := luaHostFS(t, "rocks")
	trees := append(append([]string{}, defaultLuaRocksSystemTrees...), "/home/ubuntu/.luarocks")
	pkgs, fps := addLuaRockTrees(afs, nil, nil, trees)
	assert.Equal(t, []string{"argparse@0.7.1-1", "inspect@3.1.1-0", "serpent@0.30-2"}, names(pkgs))
	assert.Len(t, fps, 3)
}

// `luarocks list` run by one user reports that user's own tree. The per-user
// trees read from disk add the other users' rocks without repeating those.
func TestAddLuaRockTreesSkipsWhatTheCLIReported(t *testing.T) {
	afs := luaHostFS(t, "rocks-5.1")
	cli := "serpent\t0.30-2\tinstalled\t/home/ubuntu/.luarocks/lib/luarocks/rocks-5.1\n" +
		"argparse\t0.7.1-1\tinstalled\t/usr/local/lib/luarocks/rocks-5.1\n"
	cliPkgs, cliFps := luarocks.ParseLuaRocksList(stringsReader(cli), "")

	pkgs, fps := addLuaRockTrees(afs, cliPkgs, cliFps, []string{"/home/ubuntu/.luarocks"})
	assert.Equal(t, []string{"argparse@0.7.1-1", "serpent@0.30-2"}, names(pkgs))
	assert.Len(t, fps, 2)

	// run as root, the CLI does not see the user's tree
	rootPkgs, rootFps := luarocks.ParseLuaRocksList(stringsReader(cli[len("serpent\t0.30-2\tinstalled\t/home/ubuntu/.luarocks/lib/luarocks/rocks-5.1\n"):]), "")
	pkgs, _ = addLuaRockTrees(afs, rootPkgs, rootFps, []string{"/root/.luarocks", "/home/ubuntu/.luarocks"})
	assert.Equal(t, []string{"argparse@0.7.1-1", "serpent@0.30-2"}, names(pkgs))
	for _, p := range pkgs {
		if p.Name == "serpent" {
			assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "/home/ubuntu/.luarocks/lib/luarocks/rocks-5.1/serpent/0.30-2"}}, p.EvidenceList)
		}
	}
}

func stringsReader(s string) io.Reader { return strings.NewReader(s) }

// The layout of a RHEL 9/10 or Fedora host with luarocks from the distro: the
// system rock tree is /usr, rocks for the default Lua 5.4 sit in
// /usr/lib/luarocks/rocks-5.4, a rock installed for compat-lua
// (`luarocks --lua-version 5.1`) in rocks-5.1, and the luarocks modules plus
// rpm-installed Lua modules under /usr/share/lua/5.4.
func rhelLuaHostFS(t *testing.T) *afero.Afero {
	t.Helper()
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for _, p := range []string{
		"/usr/share/lua/5.4/luarocks/cmd/install.lua",
		"/usr/share/lua/5.4/json/decode/util.lua",
		"/usr/share/lua/5.1/say/init.lua",
		"/usr/lib/luarocks/rocks-5.4/manifest",
		"/usr/lib/luarocks/rocks-5.4/argparse/0.7.1-1/argparse-0.7.1-1.rockspec",
		"/usr/lib/luarocks/rocks-5.4/argparse/0.7.1-1/rock_manifest",
		"/usr/lib/luarocks/rocks-5.4/inspect/3.1.1-0/inspect-3.1.1-0.rockspec",
		"/usr/lib/luarocks/rocks-5.4/inspect/3.1.1-0/rock_manifest",
		"/usr/lib/luarocks/rocks-5.1/manifest",
		"/usr/lib/luarocks/rocks-5.1/say/1.4.1-3/say-1.4.1-3.rockspec",
		"/usr/lib/luarocks/rocks-5.1/say/1.4.1-3/rock_manifest",
		"/home/ec2-user/.luarocks/lib/luarocks/rocks-5.4/serpent/0.30-2/serpent-0.30-2.rockspec",
	} {
		require.NoError(t, afs.WriteFile(p, nil, 0o644))
	}
	return afs
}

// `luarocks list --porcelain` as root on RHEL 9 lists the rocks of the default
// Lua version only. The rock installed for Lua 5.1 must still be reported.
func TestAddDefaultLuaRockTreesAddsOtherLuaVersions(t *testing.T) {
	afs := rhelLuaHostFS(t)
	cli := "argparse\t0.7.1-1\tinstalled\t/usr/lib/luarocks/rocks-5.4\n" +
		"inspect\t3.1.1-0\tinstalled\t/usr/lib/luarocks/rocks-5.4\n"
	cliPkgs, cliFps := luarocks.ParseLuaRocksList(stringsReader(cli), "")

	pkgs, fps := addDefaultLuaRockTrees(afs, cliPkgs, cliFps)
	assert.Equal(t, []string{"argparse@0.7.1-1", "inspect@3.1.1-0", "say@1.4.1-3", "serpent@0.30-2"}, names(pkgs))
	assert.Len(t, fps, 4)
}

// Without the CLI, the RHEL system tree /usr is read; the Lua modules in
// /usr/share/lua (json, luarocks) are not rocks.
func TestAddDefaultLuaRockTreesRHELWithoutCLI(t *testing.T) {
	afs := rhelLuaHostFS(t)
	pkgs, _ := addDefaultLuaRockTrees(afs, nil, nil)
	assert.Equal(t, []string{"argparse@0.7.1-1", "inspect@3.1.1-0", "say@1.4.1-3", "serpent@0.30-2"}, names(pkgs))
}

// The path forms on a RHEL host: the directory holding the rocks-5.x
// directories unions every Lua version, and the /usr tree yields only rocks.
func TestCollectLuaPackagesRHELPathForms(t *testing.T) {
	afs := rhelLuaHostFS(t)
	all := []string{"argparse@0.7.1-1", "inspect@3.1.1-0", "say@1.4.1-3"}
	for _, p := range []string{"/usr/lib/luarocks", "/usr"} {
		pkgs, fps := collectLuaPackages(afs, p)
		assert.Equal(t, all, names(pkgs), p)
		assert.Len(t, fps, 3, p)
	}
	pkgs, _ := collectLuaPackages(afs, "/usr/lib/luarocks/rocks-5.1")
	assert.Equal(t, []string{"say@1.4.1-3"}, names(pkgs))
	pkgs, _ = collectLuaPackages(afs, "/usr/share/lua/5.4")
	assert.Empty(t, pkgs)
}

// readDirCounter records every directory opened through it, and every
// directory whose entries (not just names) were read.
type readDirCounter struct {
	afero.Fs
	opened  map[string]int
	entries map[string]int
}

func (c *readDirCounter) Open(name string) (afero.File, error) {
	c.opened[name]++
	f, err := c.Fs.Open(name)
	if err != nil {
		return nil, err
	}
	return &readDirCountingFile{File: f, counter: c}, nil
}

type readDirCountingFile struct {
	afero.File
	counter *readDirCounter
}

func (f *readDirCountingFile) Readdir(n int) ([]os.FileInfo, error) {
	f.counter.entries[f.Name()]++
	return f.File.Readdir(n)
}

// A rock tree such as /usr must be read through its lib/luarocks directory,
// not walked two levels deep as if it were a rocks directory: on SLES that
// walk read all of /usr/lib64 and /usr/share and took 11 minutes over SSH
// with --sudo. Fails if collectLuaPackages tries ParseRocksDir on the tree
// before the rock tree layout.
func TestCollectLuaPackagesRockTreeSkipsUnrelatedDirectories(t *testing.T) {
	mem := afero.NewMemMapFs()
	// SLES 15 SP7: system rocks for Lua 5.3 and 5.1 under /usr/lib/luarocks
	for _, p := range []string{
		"/usr/lib/luarocks/rocks-5.3/argparse/0.7.1-1/rock_manifest",
		"/usr/lib/luarocks/rocks-5.3/inspect/3.1.1-0/rock_manifest",
		"/usr/lib/luarocks/rocks-5.1/say/1.4.1-3/rock_manifest",
		"/usr/lib64/python3.6/site-packages/yaml/__init__.py",
		"/usr/share/doc/packages/lua53/README",
	} {
		require.NoError(t, afero.WriteFile(mem, p, nil, 0o644))
	}
	counter := &readDirCounter{Fs: mem, opened: map[string]int{}, entries: map[string]int{}}
	afs := &afero.Afero{Fs: counter}

	pkgs, _ := collectLuaPackages(afs, "/usr")
	assert.Equal(t, []string{"argparse@0.7.1-1", "inspect@3.1.1-0", "say@1.4.1-3"}, names(pkgs))
	for _, dir := range []string{"/usr/lib64", "/usr/share", "/usr/lib64/python3.6"} {
		assert.Zero(t, counter.opened[dir], dir)
	}

	// rocks directories, under LuaRocks' names and under a name of their own,
	// are still read
	pkgs, _ = collectLuaPackages(&afero.Afero{Fs: mem}, "/usr/lib/luarocks/rocks-5.3")
	assert.Equal(t, []string{"argparse@0.7.1-1", "inspect@3.1.1-0"}, names(pkgs))
	require.NoError(t, afero.WriteFile(mem, "/opt/myrocks/serpent/0.30-2/rock_manifest", nil, 0o644))
	pkgs, _ = collectLuaPackages(&afero.Afero{Fs: mem}, "/opt/myrocks")
	assert.Equal(t, []string{"serpent@0.30-2"}, names(pkgs))
}

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
	counter := &readDirCounter{Fs: mem, opened: map[string]int{}, entries: map[string]int{}}

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

// `luarocks list` names a rock by its version directory, a rock read from
// disk by its rockspec, so lua.packages.files differed between a scan that
// found the CLI and one that did not (root on RHEL 7, whose secure_path has
// no /usr/local/bin). Fails if the CLI's version directories are reported as
// they are again.
func TestLuaRocksCLIFilesMatchDisk(t *testing.T) {
	afs := luaHostFS(t, "rocks-5.1")
	cli := "argparse\t0.7.1-1\tinstalled\t/usr/local/lib/luarocks/rocks-5.1\n" +
		"inspect\t3.1.1-0\tinstalled\t/usr/local/lib/luarocks/rocks-5.1\n" +
		"gone\t1.0-1\tinstalled\t/usr/local/lib/luarocks/rocks-5.1\n"
	_, cliFps := luarocks.ParseLuaRocksList(stringsReader(cli), "")
	_, diskFps := addLuaRockTrees(afs, nil, nil, []string{"/usr/local"})

	assert.Equal(t, append(diskFps, "/usr/local/lib/luarocks/rocks-5.1/gone/1.0-1"), luaRocksListFiles(afs, cliFps))
}
