// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures under testdata/jetbrains were captured from the plugins bundled
// with a real Rider 2026.2 install, trimmed to the metadata element and its
// direct children; the values are verbatim.
func TestJetBrainsParsePluginXML(t *testing.T) {
	tests := []struct {
		fixture    string
		identifier string
		name       string
		version    string
		vendor     string
		category   string
		since      string
		until      string
	}{
		{
			// id and name differ, which is the whole reason identifier exists:
			// the Title Case name is a label, the id is what the IDE keys on.
			fixture:    "plugin-markdown.xml",
			identifier: "org.intellij.plugins.markdown",
			name:       "Markdown",
			version:    "262.9437.287",
			vendor:     "JetBrains",
			category:   "Languages",
			since:      "262.9437.287",
			until:      "262.9437.287",
		},
		{
			// vendor carries a url attribute alongside its text, and this
			// plugin declares no category.
			fixture:    "plugin-unity.xml",
			identifier: "com.intellij.resharper.unity",
			name:       "Unity Support",
			version:    "262.9437.287",
			vendor:     "JetBrains",
			category:   "",
			since:      "262.9437.287",
			until:      "262.9437.287",
		},
		{
			// name appears before id in this file; element order must not matter.
			fixture:    "plugin-github.xml",
			identifier: "org.jetbrains.plugins.github",
			name:       "GitHub",
			version:    "262.9437.287",
			vendor:     "JetBrains",
			category:   "Version Controls",
			since:      "262.9437.287",
			until:      "262.9437.287",
		},
		{
			fixture:    "plugin-database.xml",
			identifier: "com.intellij.database",
			name:       "Database Tools and SQL",
			version:    "262.9437.287",
			vendor:     "JetBrains",
			category:   "Database",
			since:      "262.9437.287",
			until:      "262.9437.287",
		},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "jetbrains", tt.fixture))
			require.NoError(t, err)

			plugin, err := parseJetBrainsPluginXML(data)
			require.NoError(t, err)

			assert.Equal(t, tt.identifier, plugin.Identifier)
			assert.Equal(t, tt.name, plugin.Name)
			assert.Equal(t, tt.version, plugin.Version)
			assert.Equal(t, tt.vendor, plugin.Vendor)
			assert.Equal(t, tt.category, plugin.Category)
			assert.Equal(t, tt.since, plugin.SinceBuild)
			assert.Equal(t, tt.until, plugin.UntilBuild)
			assert.NotEmpty(t, plugin.Description)
		})
	}
}

func TestJetBrainsPluginXMLIdentity(t *testing.T) {
	tests := []struct {
		name           string
		xml            string
		wantIdentifier string
		wantName       string
		wantErr        bool
	}{
		{
			name:           "id only",
			xml:            `<idea-plugin><id>com.example.thing</id><version>1.0</version></idea-plugin>`,
			wantIdentifier: "com.example.thing",
			// With no name declared the identifier is the only label there is.
			wantName: "com.example.thing",
		},
		{
			name: "name only",
			// Older plugins omit id, in which case the IDE treats the name as
			// the identifier, so we have to as well or they collide on "".
			xml:            `<idea-plugin><name>Legacy Thing</name><version>1.0</version></idea-plugin>`,
			wantIdentifier: "Legacy Thing",
			wantName:       "Legacy Thing",
		},
		{
			name:    "neither id nor name",
			xml:     `<idea-plugin><version>1.0</version></idea-plugin>`,
			wantErr: true,
		},
		{
			name:    "not a plugin descriptor",
			xml:     `<project><id>com.example</id></project>`,
			wantErr: true,
		},
		{
			name:    "not xml at all",
			xml:     `this is not xml`,
			wantErr: true,
		},
		{
			name:           "whitespace around values",
			xml:            "<idea-plugin>\n  <id>  com.example.pad  </id>\n  <name>\tPadded\n</name>\n</idea-plugin>",
			wantIdentifier: "com.example.pad",
			wantName:       "Padded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin, err := parseJetBrainsPluginXML([]byte(tt.xml))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantIdentifier, plugin.Identifier)
			assert.Equal(t, tt.wantName, plugin.Name)
		})
	}
}

// A plugin.xml from a marketplace plugin is third-party input, so the parser
// must not expand entities. Go's encoding/xml does not, and this pins it.
func TestJetBrainsPluginXMLDoesNotExpandEntities(t *testing.T) {
	bomb := `<?xml version="1.0"?>
<!DOCTYPE idea-plugin [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<idea-plugin><id>com.example.bomb</id><name>&c;</name></idea-plugin>`

	plugin, err := parseJetBrainsPluginXML([]byte(bomb))
	// Either outcome is acceptable; what must not happen is a name inflated by
	// entity expansion.
	if err == nil {
		assert.Less(t, len(plugin.Name), 100)
	}
}

// zipWithFiles builds an in-memory jar, since a plugin descriptor lives inside
// one rather than on disk.
func zipWithFiles(t *testing.T, files map[string]string) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	for name, content := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

const jetbrainsMinimalPluginXML = `<idea-plugin>
  <id>com.example.tool</id>
  <name>Example Tool</name>
  <version>2.4.0</version>
  <vendor>Example Inc</vendor>
  <idea-version since-build="241.1" until-build="243.*" />
</idea-plugin>`

func TestJetBrainsReadPluginFromDir(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	jar := zipWithFiles(t, map[string]string{
		"META-INF/plugin.xml": jetbrainsMinimalPluginXML,
	})
	require.NoError(t, afs.MkdirAll("/plugins/example-plugin/lib", 0o755))
	require.NoError(t, afs.WriteFile("/plugins/example-plugin/lib/example-plugin.jar", jar, 0o644))

	plugin, err := readJetBrainsPlugin(afs, "/plugins/example-plugin")
	require.NoError(t, err)
	assert.Equal(t, "com.example.tool", plugin.Identifier)
	assert.Equal(t, "Example Tool", plugin.Name)
	assert.Equal(t, "2.4.0", plugin.Version)
	assert.Equal(t, "Example Inc", plugin.Vendor)
	assert.Equal(t, "241.1", plugin.SinceBuild)
	assert.Equal(t, "243.*", plugin.UntilBuild)
}

// 18 of the 139 plugins bundled with Rider keep plugin.xml in a jar whose name
// does not match the plugin directory (markdown/intellij.markdown.jar,
// DatabaseTools/database-plugin.jar, and so on). Reading only the name-matched
// jar would silently miss 13% of them, so the scan has to fall through.
func TestJetBrainsFindsDescriptorInNonMatchingJar(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/plugins/markdown/lib", 0o755))

	// A jar named after the directory that does NOT hold the descriptor.
	decoy := zipWithFiles(t, map[string]string{"README.txt": "no descriptor here"})
	require.NoError(t, afs.WriteFile("/plugins/markdown/lib/markdown.jar", decoy, 0o644))

	holder := zipWithFiles(t, map[string]string{
		"META-INF/plugin.xml": `<idea-plugin><id>org.intellij.plugins.markdown</id><name>Markdown</name><version>262.9437.287</version></idea-plugin>`,
	})
	require.NoError(t, afs.WriteFile("/plugins/markdown/lib/intellij.markdown.jar", holder, 0o644))

	plugin, err := readJetBrainsPlugin(afs, "/plugins/markdown")
	require.NoError(t, err)
	assert.Equal(t, "org.intellij.plugins.markdown", plugin.Identifier)
}

func TestJetBrainsReadPluginUnpacked(t *testing.T) {
	// Some plugins ship the descriptor on disk rather than inside a jar.
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/plugins/unpacked/META-INF", 0o755))
	require.NoError(t, afs.WriteFile("/plugins/unpacked/META-INF/plugin.xml", []byte(jetbrainsMinimalPluginXML), 0o644))

	plugin, err := readJetBrainsPlugin(afs, "/plugins/unpacked")
	require.NoError(t, err)
	assert.Equal(t, "com.example.tool", plugin.Identifier)
}

func TestJetBrainsReadPluginBareJar(t *testing.T) {
	// A single-jar plugin sits directly in the plugins directory.
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	jar := zipWithFiles(t, map[string]string{"META-INF/plugin.xml": jetbrainsMinimalPluginXML})
	require.NoError(t, afs.MkdirAll("/plugins", 0o755))
	require.NoError(t, afs.WriteFile("/plugins/example.jar", jar, 0o644))

	plugin, err := readJetBrainsPlugin(afs, "/plugins/example.jar")
	require.NoError(t, err)
	assert.Equal(t, "com.example.tool", plugin.Identifier)
}

func TestJetBrainsReadPluginNoDescriptor(t *testing.T) {
	// A directory with jars but no descriptor is not a plugin, and must not be
	// reported as one with empty fields.
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/plugins/notaplugin/lib", 0o755))
	jar := zipWithFiles(t, map[string]string{"code/Thing.class": "x"})
	require.NoError(t, afs.WriteFile("/plugins/notaplugin/lib/thing.jar", jar, 0o644))

	_, err := readJetBrainsPlugin(afs, "/plugins/notaplugin")
	assert.Error(t, err)
}

func TestJetBrainsDisabledPlugins(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/config", 0o755))
	// The IDE writes one plugin id per line; blank lines and stray whitespace
	// appear in the wild after manual edits.
	require.NoError(t, afs.WriteFile("/config/disabled_plugins.txt",
		[]byte("com.example.tool\n\n  org.jetbrains.plugins.github  \n"), 0o644))

	disabled := readJetBrainsDisabledPlugins(afs, "/config")
	assert.True(t, disabled["com.example.tool"])
	assert.True(t, disabled["org.jetbrains.plugins.github"])
	assert.False(t, disabled["com.intellij.database"])
	assert.Len(t, disabled, 2)
}

func TestJetBrainsDisabledPluginsAbsent(t *testing.T) {
	// No file means nothing is disabled, which must read as an empty set rather
	// than an error: that is the normal state of a fresh install.
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/config", 0o755))

	disabled := readJetBrainsDisabledPlugins(afs, "/config")
	assert.Empty(t, disabled)
}

func TestJetBrainsProductFromConfigDir(t *testing.T) {
	// The config directory name carries the product and its version, which is
	// the only place the product is stated for a user-installed plugin.
	tests := []struct {
		dir     string
		product string
		wantOK  bool
	}{
		{dir: "IntelliJIdea2026.2", product: "IntelliJIdea 2026.2", wantOK: true},
		{dir: "GoLand2026.2", product: "GoLand 2026.2", wantOK: true},
		{dir: "PyCharmCE2025.1", product: "PyCharmCE 2025.1", wantOK: true},
		{dir: "DataSpell2026.1", product: "DataSpell 2026.1", wantOK: true},
		{dir: "Toolbox", wantOK: false},
		{dir: "consentOptions", wantOK: false},
		{dir: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			product, ok := jetbrainsProductFromDir(tt.dir)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.product, product)
			}
		})
	}
}

func TestJetBrainsPluginOutsideSupportedBuild(t *testing.T) {
	// until-build below the running IDE build is the check nothing else can
	// express, so the comparison has to handle the wildcard form JetBrains uses.
	tests := []struct {
		name       string
		untilBuild string
		ideBuild   string
		outside    bool
	}{
		{name: "within range", untilBuild: "262.9437.287", ideBuild: "262.9437.287", outside: false},
		{name: "older until", untilBuild: "241.1", ideBuild: "262.9437.287", outside: true},
		{name: "wildcard covers", untilBuild: "262.*", ideBuild: "262.9437.287", outside: false},
		{name: "wildcard older", untilBuild: "241.*", ideBuild: "262.9437.287", outside: true},
		{name: "no until declared", untilBuild: "", ideBuild: "262.9437.287", outside: false},
		{name: "no ide build known", untilBuild: "241.1", ideBuild: "", outside: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.outside, jetbrainsBuildOutsideRange(tt.untilBuild, tt.ideBuild))
		})
	}
}

func TestJetBrainsPluginDirCandidates(t *testing.T) {
	// Only directories and jars are plugin candidates; the IDE also drops
	// bookkeeping files into the plugins directory.
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/plugins/realplugin/lib", 0o755))
	require.NoError(t, afs.WriteFile("/plugins/single.jar", []byte("x"), 0o644))
	require.NoError(t, afs.WriteFile("/plugins/plugin_classpath.txt", []byte("x"), 0o644))

	got := jetbrainsPluginCandidates(afs, "/plugins")
	names := make([]string, 0, len(got))
	for _, g := range got {
		names = append(names, strings.TrimPrefix(g, "/plugins/"))
	}
	assert.ElementsMatch(t, []string{"realplugin", "single.jar"}, names)
}

func TestJetBrainsReadProductInfo(t *testing.T) {
	// Captured from the installed Rider, trimmed to the identity keys.
	data, err := os.ReadFile(filepath.Join("testdata", "jetbrains", "product-info-rider.json"))
	require.NoError(t, err)

	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/app/Contents/Resources", 0o755))
	require.NoError(t, afs.WriteFile("/app/Contents/Resources/product-info.json", data, 0o644))

	info, ok := readJetBrainsProductInfo(afs, "/app")
	require.True(t, ok)
	assert.Equal(t, "JetBrains Rider", info.Name)
	assert.Equal(t, "2026.2.1", info.Version)
	// buildNumber is what a plugin's until-build has to be compared against,
	// and product-info.json is the only place it is stated.
	assert.Equal(t, "262.9437.287", info.BuildNumber)
	assert.Equal(t, "Rider2026.2", info.DataDirectoryName)
}

// Contents/plugins is a standard macOS bundle directory, not a JetBrains
// marker. On a real Mac it matched 1Password, Bitwarden, Zoom, Tailscale,
// WireGuard and eighteen others, against three actual JetBrains IDEs, so an
// app is only a product when it also ships product-info.json.
func TestJetBrainsBundledRequiresProductInfo(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	// A JetBrains IDE: plugins directory plus the product marker.
	require.NoError(t, afs.MkdirAll("/Applications/Rider.app/Contents/plugins", 0o755))
	require.NoError(t, afs.MkdirAll("/Applications/Rider.app/Contents/Resources", 0o755))
	require.NoError(t, afs.WriteFile("/Applications/Rider.app/Contents/Resources/product-info.json",
		[]byte(`{"name":"JetBrains Rider","version":"2026.2.1","buildNumber":"262.9437.287","dataDirectoryName":"Rider2026.2"}`), 0o644))

	// Not a JetBrains IDE, but it has the same bundle subdirectory.
	require.NoError(t, afs.MkdirAll("/Applications/1Password 7.app/Contents/plugins", 0o755))

	dirs := jetbrainsBundledDirs(afs, "/Applications", 501)

	require.Len(t, dirs, 1, "only the app carrying product-info.json is a JetBrains product")
	assert.Equal(t, "/Applications/Rider.app/Contents/plugins", dirs[0].path)
	assert.Equal(t, "JetBrains Rider 2026.2.1", dirs[0].product)
	assert.Equal(t, "262.9437.287", dirs[0].ideBuild)
	assert.True(t, dirs[0].bundled)
}

func TestJetBrainsProductInfoAbsent(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/app/Contents/plugins", 0o755))

	_, ok := readJetBrainsProductInfo(afs, "/app")
	assert.False(t, ok)
}

func TestJetBrainsProductInfoMalformed(t *testing.T) {
	// A file that is not JSON must read as "not a product", not as a product
	// with empty fields that would then be reported as an IDE.
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/app/Contents/Resources", 0o755))
	require.NoError(t, afs.WriteFile("/app/Contents/Resources/product-info.json", []byte("{not json"), 0o644))

	_, ok := readJetBrainsProductInfo(afs, "/app")
	assert.False(t, ok)
}

// An IDE installed system-wide is installed once, so its bundled plugins must
// be reported once. /Applications and /opt are absolute, and scanning them per
// user reported every bundled plugin once per account: on a Linux tree with
// root and one login, the Go plugin came back twice.
func TestJetBrainsSystemPluginsNotDuplicatedPerUser(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/opt/goland/plugins/go-core/lib", 0o755))
	require.NoError(t, afs.WriteFile("/opt/goland/product-info.json",
		[]byte(`{"name":"GoLand","version":"2026.2","buildNumber":"262.9437.287","dataDirectoryName":"GoLand2026.2"}`), 0o644))

	users := []targetUser{
		{name: "root", home: "/root", uid: 0},
		{name: "tester", home: "/home/tester", uid: 1000},
		{name: "second", home: "/home/second", uid: 1001},
	}

	dirs := jetbrainsPluginDirs(afs, "linux", users)

	system := 0
	for _, dir := range dirs {
		if dir.path == "/opt/goland/plugins" {
			system++
		}
	}
	assert.Equal(t, 1, system, "a system-wide IDE is scanned once, not once per user")
}

func TestJetBrainsProductInfoNoName(t *testing.T) {
	// JSON that parses but names no product is equally not a product.
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/app/Contents/Resources", 0o755))
	require.NoError(t, afs.WriteFile("/app/Contents/Resources/product-info.json", []byte(`{"buildNumber":"262.1"}`), 0o644))

	_, ok := readJetBrainsProductInfo(afs, "/app")
	assert.False(t, ok)
}
