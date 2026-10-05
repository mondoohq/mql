// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package jenkins

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestPlugin creates a minimal .jpi file with the given MANIFEST.MF content.
func createTestPlugin(t *testing.T, manifest string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	f, err := w.Create("META-INF/MANIFEST.MF")
	require.NoError(t, err)
	_, err = f.Write([]byte(manifest))
	require.NoError(t, err)

	require.NoError(t, w.Close())
	return buf.Bytes()
}

func TestScanPlugin(t *testing.T) {
	manifest := `Manifest-Version: 1.0
Short-Name: git
Plugin-Version: 5.2.2
Long-Name: Git plugin
Url: https://github.com/jenkinsci/git-plugin
Plugin-Dependencies: credentials:1289.vb_5b_3a_f,git-client:4.7.0,ssh-credentials:308.ve4a_b_307d
 1d3;resolution:=optional
`

	pluginData := createTestPlugin(t, manifest)

	tmpDir := t.TempDir()
	pluginPath := filepath.Join(tmpDir, "git.jpi")
	require.NoError(t, os.WriteFile(pluginPath, pluginData, 0644))

	afs := &afero.Afero{Fs: afero.NewOsFs()}
	plugin, err := scanPlugin(afs, pluginPath)
	require.NoError(t, err)
	require.NotNil(t, plugin)

	assert.Equal(t, "git", plugin.Name)
	assert.Equal(t, "5.2.2", plugin.Version)
	assert.Equal(t, "Git plugin", plugin.LongName)
	assert.Equal(t, "https://github.com/jenkinsci/git-plugin", plugin.Url)
	assert.Equal(t, []string{"credentials", "git-client", "ssh-credentials"}, plugin.Dependencies)
}

func TestScanPluginDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two test plugins
	gitManifest := `Manifest-Version: 1.0
Short-Name: git
Plugin-Version: 5.2.2
Long-Name: Git plugin
`
	credentialsManifest := `Manifest-Version: 1.0
Short-Name: credentials
Plugin-Version: 1289.vb_5b_3a_f
Long-Name: Credentials plugin
`

	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, "git.jpi"),
		createTestPlugin(t, gitManifest), 0644))
	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, "credentials.hpi"),
		createTestPlugin(t, credentialsManifest), 0644))
	// Non-plugin file should be ignored
	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, "readme.txt"),
		[]byte("not a plugin"), 0644))

	afs := &afero.Afero{Fs: afero.NewOsFs()}
	plugins, err := ScanPluginDirExtended(afs, tmpDir)
	require.NoError(t, err)
	assert.Equal(t, 2, len(plugins))

	var gitPlugin, credsPlugin *JenkinsPlugin
	for i := range plugins {
		switch plugins[i].Name {
		case "git":
			gitPlugin = &plugins[i]
		case "credentials":
			credsPlugin = &plugins[i]
		}
	}

	require.NotNil(t, gitPlugin)
	assert.Equal(t, "5.2.2", gitPlugin.Version)

	require.NotNil(t, credsPlugin)
	assert.Equal(t, "1289.vb_5b_3a_f", credsPlugin.Version)
}

func TestNewPackageUrl(t *testing.T) {
	assert.Equal(t, "pkg:jenkins-plugin/git@5.2.2", NewPackageUrl("git", "5.2.2"))
}

func TestIsPluginFile(t *testing.T) {
	assert.True(t, isPluginFile("git.jpi"))
	assert.True(t, isPluginFile("credentials.hpi"))
	assert.True(t, isPluginFile("test.JPI"))
	assert.False(t, isPluginFile("readme.txt"))
	assert.False(t, isPluginFile("plugin.jar"))
}

type refusingFs struct {
	afero.Fs
	refused string
}

func (f *refusingFs) Open(name string) (afero.File, error) {
	if name == f.refused {
		return nil, &os.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return f.Fs.Open(name)
}

// A plugin file the scan may not read is a refusal, returned beside the
// plugins that could be read; a file that is not an archive is skipped.
// Fails if the refusal is logged and dropped again.
func TestScanPluginDirReportsUnreadablePlugin(t *testing.T) {
	mem := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mem, "/plugins/git.jpi", createTestPlugin(t, "Manifest-Version: 1.0\nShort-Name: git\nPlugin-Version: 5.2.2\n"), 0o644))
	require.NoError(t, afero.WriteFile(mem, "/plugins/structs.jpi", createTestPlugin(t, "Manifest-Version: 1.0\nShort-Name: structs\nPlugin-Version: 1.24\n"), 0o600))
	require.NoError(t, afero.WriteFile(mem, "/plugins/broken.jpi", []byte("not a zip"), 0o644))
	afs := &afero.Afero{Fs: &refusingFs{Fs: mem, refused: "/plugins/structs.jpi"}}

	plugins, err := ScanPluginDirExtended(afs, "/plugins")
	assert.ErrorIs(t, err, fs.ErrPermission)
	require.Len(t, plugins, 1)
	assert.Equal(t, "git", plugins[0].Name)
}
