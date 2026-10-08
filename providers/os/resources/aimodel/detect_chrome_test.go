// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The manifest as Chrome 139 writes it on macOS.
const chromeManifest = `{
  "manifest_version": 2,
  "name": "Optimization Guide On Device Model",
  "version": "2025.8.8.1141",
  "BaseModelSpec": {
    "name": "v3Nano",
    "version": "2025.06.30.1229",
    "supported_performance_hints": [2, 1]
  }
}`

func writeChromeComponent(t *testing.T, fs afero.Fs, dir, manifest string, weights int) {
	t.Helper()
	require.NoError(t, afero.WriteFile(fs, filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644))
	if weights >= 0 {
		require.NoError(t, afero.WriteFile(fs, filepath.Join(dir, "weights.bin"), make([]byte, weights), 0o644))
	}
}

func detectChrome(afs *afero.Afero, home, osFamily string) []ModelInfo {
	return (&ChromeDetector{}).Detect(DetectContext{Fs: afs, Home: home, OSFamily: osFamily})
}

func TestDetectChrome(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/Users/testuser"
	dir := filepath.Join(home, "Library/Application Support/Google/Chrome/OptGuideOnDeviceModel/2025.8.8.1141")
	writeChromeComponent(t, fs, dir, chromeManifest, 1000)

	results := detectChrome(afs, home, "darwin")
	require.Len(t, results, 1)

	m := results[0]
	assert.Equal(t, "v3Nano", m.Name)
	assert.Equal(t, "chrome", m.Source)
	assert.Equal(t, "google", m.Vendor)
	assert.Equal(t, "gemini-nano", m.Family)
	assert.Equal(t, "2025.06.30.1229", m.Version)
	assert.Equal(t, dir, m.Path)
	assert.Equal(t, int64(1000+len(chromeManifest)), m.Size)
	assert.Empty(t, m.Format)
	assert.Empty(t, m.ParameterSize)
}

func TestDetectChrome_NoBaseModelSpec(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"
	dir := filepath.Join(home, ".config/google-chrome/OptGuideOnDeviceModel/2024.9.25.2033")
	writeChromeComponent(t, fs, dir, `{"manifest_version": 2, "name": "Optimization Guide On Device Model", "version": "2024.9.25.2033"}`, 10)

	results := detectChrome(afs, home, "linux")
	require.Len(t, results, 1)
	assert.Equal(t, "gemini-nano", results[0].Name)
	assert.Equal(t, "2024.9.25.2033", results[0].Version)
}

func TestDetectChrome_SkipsIncompleteDownload(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"
	dir := filepath.Join(home, ".config/google-chrome/OptGuideOnDeviceModel/2025.8.8.1141")
	writeChromeComponent(t, fs, dir, chromeManifest, -1)

	assert.Empty(t, detectChrome(afs, home, "linux"))
}

func TestDetectChrome_SkipsMalformedManifest(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"
	dir := filepath.Join(home, ".config/google-chrome/OptGuideOnDeviceModel/2025.8.8.1141")
	writeChromeComponent(t, fs, dir, `{not json`, 10)

	assert.Empty(t, detectChrome(afs, home, "linux"))
}

func TestDetectChrome_EachChannelIsItsOwnModel(t *testing.T) {
	afs, fs := newTestAfs()
	home := `C:\Users\testuser`
	stable := filepath.Join(home, "AppData/Local/Google/Chrome/User Data/OptGuideOnDeviceModel/2025.8.8.1141")
	canary := filepath.Join(home, "AppData/Local/Google/Chrome SxS/User Data/OptGuideOnDeviceModel/2025.8.8.1141")
	writeChromeComponent(t, fs, stable, chromeManifest, 10)
	writeChromeComponent(t, fs, canary, chromeManifest, 10)

	results := detectChrome(afs, home, "windows")
	require.Len(t, results, 2)
	assert.ElementsMatch(t, []string{stable, canary}, []string{results[0].Path, results[1].Path})
}

func TestDetectChrome_UnknownOSFamily(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"
	writeChromeComponent(t, fs, filepath.Join(home, ".config/google-chrome/OptGuideOnDeviceModel/1"), chromeManifest, 10)

	assert.Empty(t, detectChrome(afs, home, ""))
}
