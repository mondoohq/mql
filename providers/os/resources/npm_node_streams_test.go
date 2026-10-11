// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/utils/syncx"
)

// Amazon Linux 2023 with nodejs (18, selected through alternatives) and
// nodejs22 installed: `npm-22 root -g` is /usr/lib/nodejs22/lib/node_modules,
// and /usr/lib/node_modules links to the selected stream's node_modules.
func al2023NodeStreamsFs(t *testing.T) afero.Fs {
	mockFS := afero.NewMemMapFs()
	write := func(p, content string) {
		require.NoError(t, mockFS.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, afero.WriteFile(mockFS, p, []byte(content), 0o644))
	}
	leftPad := `{"name": "left-pad", "version": "1.3.0", "description": "String left pad", "main": "index.js"}`
	isNumber := `{"name": "is-number", "version": "7.0.0", "license": "MIT", "main": "index.js"}`
	write("/usr/lib/nodejs18/lib/node_modules/left-pad/package.json", leftPad)
	// MemMapFs has no symlinks: this copy is what the link shows
	write("/usr/lib/node_modules/left-pad/package.json", leftPad)
	write("/usr/lib/nodejs22/lib/node_modules/is-number/package.json", isNumber)
	return mockFS
}

func TestNpmDefaultPathsFindSecondNodeStream(t *testing.T) {
	mockFS := al2023NodeStreamsFs(t)
	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{}, "", nil, mockFS)
	require.NoError(t, err)
	r := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}

	resolve := func(p string) (string, bool) {
		if p == "/usr/lib/node_modules" {
			return "/usr/lib/nodejs18/lib/node_modules", true
		}
		return "", false
	}
	paths := expandNodeStreamPrefixes(mockFS, defaultNpmPaths, resolve)
	assert.Contains(t, paths, "/usr/lib/nodejs22/lib")
	assert.NotContains(t, paths, "/usr/lib/nodejs18/lib", "the selected stream is read through /usr/lib/node_modules")

	direct, _, _, err := collectNpmPackagesInPaths(r, mockFS, paths)
	require.NoError(t, err)
	got := map[string]int{}
	for _, p := range direct {
		got[p.Name+"@"+p.Version]++
	}
	assert.Equal(t, map[string]int{"left-pad@1.3.0": 1, "is-number@7.0.0": 1}, got)
}

func TestExpandNodeStreamPrefixes(t *testing.T) {
	mockFS := al2023NodeStreamsFs(t)

	t.Run("link not resolvable keeps every stream", func(t *testing.T) {
		paths := expandNodeStreamPrefixes(mockFS, []string{"/usr/lib", nodeStreamPrefixGlob}, func(string) (string, bool) { return "", false })
		assert.Equal(t, []string{"/usr/lib", "/usr/lib/nodejs18/lib", "/usr/lib/nodejs22/lib"}, paths)
	})

	t.Run("selected stream through a relative link target", func(t *testing.T) {
		paths := expandNodeStreamPrefixes(mockFS, []string{"/usr/lib", nodeStreamPrefixGlob}, func(string) (string, bool) {
			return "/usr/lib/nodejs22/lib/node_modules/", true
		})
		assert.Equal(t, []string{"/usr/lib", "/usr/lib/nodejs18/lib"}, paths)
	})

	t.Run("no streams installed", func(t *testing.T) {
		paths := expandNodeStreamPrefixes(afero.NewMemMapFs(), []string{"/usr/lib", nodeStreamPrefixGlob, "/app"}, func(string) (string, bool) { return "", false })
		assert.Equal(t, []string{"/usr/lib", "/app"}, paths)
	})

	t.Run("other paths stay as they are", func(t *testing.T) {
		in := []string{"/usr/local/lib", "/home/*/.npm-global/lib"}
		assert.Equal(t, in, expandNodeStreamPrefixes(mockFS, in, func(string) (string, bool) { t.Fatal("resolved without a stream path"); return "", false }))
	})
}
