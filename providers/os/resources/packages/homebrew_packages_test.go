// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHomebrewInfo(t *testing.T) {
	data, err := os.ReadFile("./testdata/homebrew_info.json")
	require.NoError(t, err)

	pkgs, err := ParseHomebrewInfo(data, "/opt/homebrew")
	require.NoError(t, err)

	// 3 formulae + 2 casks = 5 packages
	assert.Equal(t, 5, len(pkgs))

	// Check formula: curl
	curl := findHomebrewPkg(pkgs, "curl")
	require.NotNil(t, curl)
	assert.Equal(t, "8.7.1", curl.Version)
	assert.Equal(t, "8.7.1", curl.LatestVersion)
	assert.Equal(t, "formula", curl.Type)
	assert.Equal(t, "homebrew/core", curl.Tap)
	assert.Equal(t, "Get a file from an HTTP, HTTPS or FTP server", curl.Description)
	assert.Equal(t, "https://curl.se", curl.Homepage)
	assert.True(t, curl.InstalledOnRequest)
	assert.False(t, curl.InstalledAsDependency)
	assert.False(t, curl.Outdated)
	assert.False(t, curl.Pinned)
	assert.Equal(t, "/opt/homebrew/Cellar/curl/8.7.1", curl.Path)
	assert.Equal(t, "/opt/homebrew", curl.Prefix)
	assert.Equal(t, "pkg:brew/homebrew/core/curl@8.7.1", curl.Purl)

	// Check formula: openssl (dependency, pinned) — name with @ is percent-encoded in PURL
	openssl := findHomebrewPkg(pkgs, "openssl@3")
	require.NotNil(t, openssl)
	assert.Equal(t, "3.3.0", openssl.Version)
	assert.Equal(t, "pkg:brew/homebrew/core/openssl%403@3.3.0", openssl.Purl)
	assert.False(t, openssl.InstalledOnRequest)
	assert.True(t, openssl.InstalledAsDependency)
	assert.True(t, openssl.Pinned)

	// Check formula: jq (outdated)
	jq := findHomebrewPkg(pkgs, "jq")
	require.NotNil(t, jq)
	assert.Equal(t, "1.7", jq.Version)
	assert.Equal(t, "1.7.1", jq.LatestVersion) // newer version available
	assert.True(t, jq.Outdated)

	// Check cask: google-chrome
	chrome := findHomebrewPkg(pkgs, "google-chrome")
	require.NotNil(t, chrome)
	assert.Equal(t, "126.0.6478.127", chrome.Version)
	assert.Equal(t, "cask", chrome.Type)
	assert.Equal(t, "Google Chrome", chrome.AppName)
	assert.True(t, chrome.AutoUpdates)
	assert.True(t, chrome.InstalledOnRequest)
	assert.False(t, chrome.Outdated)
	assert.Equal(t, "homebrew/cask", chrome.Tap)
	assert.Equal(t, "pkg:brew/homebrew/cask/google-chrome@126.0.6478.127", chrome.Purl)

	// Check cask: visual-studio-code (outdated)
	vscode := findHomebrewPkg(pkgs, "visual-studio-code")
	require.NotNil(t, vscode)
	assert.Equal(t, "1.89.1", vscode.Version)       // installed
	assert.Equal(t, "1.90.0", vscode.LatestVersion) // available
	assert.True(t, vscode.Outdated)
	assert.Equal(t, "Microsoft Visual Studio Code", vscode.AppName)
}

func TestParseHomebrewInfoFormulaRevision(t *testing.T) {
	data := []byte(`{
		"formulae": [
			{
				"name": "revised",
				"versions": {"stable": "13.55"},
				"revision": 1,
				"installed": [{"version": "13.55_1"}]
			},
			{
				"name": "unrevised",
				"versions": {"stable": "3.3.0"},
				"revision": 0,
				"installed": [{"version": "3.3.0"}]
			}
		]
	}`)

	pkgs, err := ParseHomebrewInfo(data, "/opt/homebrew")
	require.NoError(t, err)
	require.Len(t, pkgs, 2)
	assert.Equal(t, "13.55_1", pkgs[0].LatestVersion)
	assert.Equal(t, "3.3.0", pkgs[1].LatestVersion)
}

func TestDeriveBrewPrefix(t *testing.T) {
	assert.Equal(t, "/opt/homebrew", deriveBrewPrefix("/opt/homebrew/bin/brew"))
	assert.Equal(t, "/usr/local", deriveBrewPrefix("/usr/local/bin/brew"))
	assert.Equal(t, "/home/linuxbrew/.linuxbrew", deriveBrewPrefix("/home/linuxbrew/.linuxbrew/bin/brew"))
}

func findHomebrewPkg(pkgs []HomebrewPackage, name string) *HomebrewPackage {
	for i := range pkgs {
		if pkgs[i].Name == name {
			return &pkgs[i]
		}
	}
	return nil
}
