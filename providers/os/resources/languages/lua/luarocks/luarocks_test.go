// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package luarocks

import (
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLuaRocksList(t *testing.T) {
	f, err := os.Open("testdata/luarocks_list.txt")
	require.NoError(t, err)
	defer f.Close()

	pkgs, fps := ParseLuaRocksList(f, "luarocks list")
	require.Len(t, pkgs, 4)

	assert.Equal(t, "luasocket", pkgs[0].Name)
	assert.Equal(t, "3.1.0-1", pkgs[0].Version)
	assert.Equal(t, "pkg:lua/luasocket@3.1.0-1", pkgs[0].Purl)

	// File paths extracted from ROCKS_DIR column
	assert.Len(t, fps, 4)

	assert.Equal(t, "lua-cjson", pkgs[1].Name)
	assert.Equal(t, "2.1.0.14-1", pkgs[1].Version)

	assert.Equal(t, "lpeg", pkgs[2].Name)
	assert.Equal(t, "luafilesystem", pkgs[3].Name)
}

func TestParseRocksDir(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewOsFs()}
	pkgs, fps := ParseRocksDir(afs, "testdata/rocks")
	require.Len(t, pkgs, 2)
	require.NotEmpty(t, fps)

	byName := map[string]string{}
	for _, p := range pkgs {
		byName[p.Name] = p.Version
	}

	assert.Equal(t, "3.1.0-1", byName["luasocket"])
	assert.Equal(t, "2.1.0.14-1", byName["lua-cjson"])

	// Verify PURL
	for _, p := range pkgs {
		if p.Name == "luasocket" {
			assert.Equal(t, "pkg:lua/luasocket@3.1.0-1", p.Purl)
		}
	}
}

func memFS(t *testing.T, files map[string]string) *afero.Afero {
	t.Helper()
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for p, content := range files {
		require.NoError(t, afs.WriteFile(p, []byte(content), 0o644))
	}
	return afs
}

// /usr/share/lua/5.1 as the Ubuntu luarocks package installs it: the modules
// of luarocks itself, two levels deep. None of it is a rock.
func TestParseRocksDirIgnoresLuaModuleDirectories(t *testing.T) {
	afs := memFS(t, map[string]string{
		"/usr/share/lua/5.1/luarocks/build/builtin.lua": "",
		"/usr/share/lua/5.1/luarocks/build/make.lua":    "",
		"/usr/share/lua/5.1/luarocks/fs/lua.lua":        "",
		"/usr/share/lua/5.1/luarocks/fs/unix/tools.lua": "",
		"/usr/share/lua/5.1/luarocks/cmd/install.lua":   "",
	})
	pkgs, fps := ParseRocksDir(afs, "/usr/share/lua/5.1")
	assert.Empty(t, pkgs)
	assert.Empty(t, fps)
}

// A rock installed by LuaRocks has a rock_manifest beside its rockspec. Either
// one marks the directory as a rock; the rockspec is the preferred evidence.
func TestParseRocksDirEvidence(t *testing.T) {
	afs := memFS(t, map[string]string{
		"/r/inspect/3.1.1-0/inspect-3.1.1-0.rockspec": "",
		"/r/inspect/3.1.1-0/rock_manifest":            "",
		"/r/inspect/3.1.1-0/doc/README.md":            "",
		"/r/argparse/0.7.1-1/rock_manifest":           "",
		"/r/stray/notaversion/README":                 "",
	})
	pkgs, fps := ParseRocksDir(afs, "/r")
	require.Len(t, pkgs, 2)
	require.Len(t, fps, 2)

	got := map[string]string{}
	for i, p := range pkgs {
		got[p.Name+"@"+p.Version] = fps[i]
		assert.Equal(t, "/r/"+p.Name+"/"+p.Version, p.EvidenceList[0].Value)
	}
	assert.Equal(t, map[string]string{
		"inspect@3.1.1-0":  "/r/inspect/3.1.1-0/inspect-3.1.1-0.rockspec",
		"argparse@0.7.1-1": "/r/argparse/0.7.1-1/rock_manifest",
	}, got)
}
