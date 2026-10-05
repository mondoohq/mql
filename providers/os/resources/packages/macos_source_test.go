// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// fsConnection is a connection that only offers a file system.
type fsConnection struct {
	shared.Connection
	fs afero.Fs
}

func (c *fsConnection) FileSystem() afero.Fs { return c.fs }

func macApp(name, bundle, signer, origin string, appStore bool) Package {
	return Package{
		Name:   name,
		Format: MacosPkgFormat,
		Origin: origin,
		Files:  []FileRecord{{Path: bundle}},
		MacOS:  &MacOSApp{Signer: signer, AppStore: appStore},
	}
}

// The cases are the applications of a macOS 27.0 host, with the signer,
// Gatekeeper class and records system_profiler and the file system reported
// for each.
func TestMacOSAppSource(t *testing.T) {
	casks := map[string]string{
		"/Applications/Alfred 5.app": "alfred",
		// the App Store replaced the cask's copy and left the link behind
		"/Applications/Bitwarden.app": "bitwarden",
	}
	receipts := map[string]macOSReceipt{
		"/Applications/PowerShell.app":  {PackageIdentifier: "com.microsoft.powershell", InstallProcessName: "installer"},
		"/Applications/Bitwarden.app":   {PackageIdentifier: "com.bitwarden.desktop", InstallProcessName: "appstored"},
		"/Applications/Restored.app":    {PackageIdentifier: "com.example.restored", InstallProcessName: "appstoreagent"},
		"/Applications/Calculator2.app": {PackageIdentifier: "com.example.calc", InstallProcessName: "installer"},
	}
	third := osProvided(false)
	tests := []struct {
		name string
		pkg  Package
		want Source
	}{
		{"Calculator ships with macOS", macApp("Calculator", "/System/Applications/Calculator.app", "macOS Software Signing", "apple", false),
			Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "macOS"}},
		// Safari lives on the App cryptex; mql lists it without a signer
		{"Safari on the cryptex", macApp("Safari", "/System/Cryptexes/App/System/Applications/Safari.app", "", "apple", false),
			Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "macOS"}},
		{"an OS component outside /System", macApp("XProtect", "/Library/Apple/System/Library/CoreServices/XProtect.app", "macOS Software Signing", "apple", false),
			Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "macOS"}},
		{"Apple software the user installs is not the OS", macApp("Python", "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app", "Software Signing", "apple", false),
			Source{OSProvided: third, Channel: ChannelDirect}},
		{"the App Store's signature wins over a stale cask link", macApp("Bitwarden", "/Applications/Bitwarden.app", "Apple Mac OS Application Signing", "mac_app_store", true),
			Source{OSProvided: third, Channel: ChannelAppStore, Name: "mac-app-store"}},
		{"an iPhone app", macApp("Some iOS App", "/Applications/Some iOS App.app", "Apple iPhone OS Application Signing", "ios_app_store", false),
			Source{OSProvided: third, Channel: ChannelAppStore, Name: "ios-app-store"}},
		{"a cask", macApp("Alfred 5", "/Applications/Alfred 5.app", "Developer ID Application: Running with Crayons Ltd (XZZXE9SED4)", "identified_developer", false),
			Source{OSProvided: third, Channel: ChannelHomebrew, Name: "alfred"}},
		{"an installer package", macApp("PowerShell", "/Applications/PowerShell.app", "", "unknown", false),
			Source{OSProvided: third, Channel: ChannelInstaller, Name: "com.microsoft.powershell"}},
		{"an App Store receipt without the App Store's signature", macApp("Restored", "/Applications/Restored.app", "Developer ID Application: Example (ABCDE12345)", "identified_developer", false),
			Source{OSProvided: third, Channel: ChannelAppStore, Name: "mac-app-store"}},
		{"dragged from a disk image", macApp("Beyond Compare", "/Applications/Beyond Compare.app", "Developer ID Application: Scooter Software Inc (BS29TEJF86)", "identified_developer", false),
			Source{OSProvided: third, Channel: ChannelDirect}},
		{"an application found without its bundle path", Package{Name: "x", Format: MacosPkgFormat},
			Source{OSProvided: third, Channel: ChannelDirect}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, macOSAppSource(tc.pkg, casks, receipts))
		})
	}
}

func TestParseCaskReceiptApps(t *testing.T) {
	// the uninstall_artifacts of Firefox's cask, as Homebrew 4 wrote them
	data, err := os.ReadFile("testdata/source/macos/firefox-INSTALL_RECEIPT.json")
	require.NoError(t, err)
	assert.Equal(t, []string{"Firefox.app"}, parseCaskReceiptApps(data))

	// a cask that renames the bundle it installs, in both spellings Homebrew
	// writes: a target option and a plain pair
	renamed := `{"uninstall_artifacts":[{"app":[["Source.app",{"target":"Target.app"}]]},{"app":[["Other.app","Renamed.app"]]}]}`
	assert.Equal(t, []string{"Target.app", "Renamed.app"}, parseCaskReceiptApps([]byte(renamed)))

	assert.Nil(t, parseCaskReceiptApps([]byte("not json")))
}

func TestReadMacOSCaskApps(t *testing.T) {
	root := t.TempDir()
	write := func(p, content string) {
		full := filepath.Join(root, p)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
	// a cask whose version directory links to the bundle it moved
	require.NoError(t, os.MkdirAll(filepath.Join(root, "opt/homebrew/Caskroom/alfred/5.8,2348"), 0o755))
	require.NoError(t, os.Symlink("/Applications/Alfred 5.app", filepath.Join(root, "opt/homebrew/Caskroom/alfred/5.8,2348/Alfred 5.app")))
	// a cask with no link: its install receipt names the bundle
	firefox, err := os.ReadFile("testdata/source/macos/firefox-INSTALL_RECEIPT.json")
	require.NoError(t, err)
	write("opt/homebrew/Caskroom/firefox/.metadata/INSTALL_RECEIPT.json", string(firefox))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "opt/homebrew/Caskroom/firefox/150.0"), 0o755))
	// a font cask installs no application
	require.NoError(t, os.MkdirAll(filepath.Join(root, "opt/homebrew/Caskroom/font-hack-nerd-font/3.4.0"), 0o755))

	conn := &fsConnection{fs: afero.NewBasePathFs(afero.NewOsFs(), root)}
	got := readMacOSCaskApps(conn)
	assert.Equal(t, map[string]string{
		"/Applications/Alfred 5.app": "alfred",
		"/Applications/Firefox.app":  "firefox",
	}, got)
}
