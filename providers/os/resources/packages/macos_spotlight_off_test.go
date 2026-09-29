// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/hex"
	"errors"
	"maps"
	"path/filepath"
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	plist "howett.net/plist"
)

const sysProfilerAppsCmd = "system_profiler SPApplicationsDataType -xml"

// What system_profiler prints when Spotlight has not indexed any application,
// for example after `mdutil -i off /`: the envelope of a real
// SPApplicationsDataType report (macOS 26) with an empty item list. The
// _properties column table is left out, the parser does not read it.
const sysProfilerNoApplications = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>_SPCommandLineArguments</key>
		<array>
			<string>/usr/sbin/system_profiler</string>
			<string>-nospawn</string>
			<string>-xml</string>
			<string>SPApplicationsDataType</string>
			<string>-detailLevel</string>
			<string>full</string>
		</array>
		<key>_SPCompletionInterval</key>
		<real>0.41307997703552246</real>
		<key>_SPResponseTime</key>
		<real>0.6247889995574951</real>
		<key>_dataType</key>
		<string>SPApplicationsDataType</string>
		<key>_detailLevel</key>
		<integer>1</integer>
		<key>_items</key>
		<array/>
		<key>_parentDataType</key>
		<string>SPSoftwareDataType</string>
		<key>_timeStamp</key>
		<date>2026-09-29T09:12:44Z</date>
		<key>_versionInfo</key>
		<dict>
			<key>com.apple.SystemProfiler.SPApplicationsReporter</key>
			<string>915</string>
		</dict>
	</dict>
</array>
</plist>
`

func macOSIdentityPlatform() *inventory.Platform {
	return &inventory.Platform{Name: "macos", Version: "26.5", Arch: "arm64", Family: []string{"darwin", "bsd", "unix", "os"}}
}

// failingCommands is a connection on which no command can be started.
type failingCommands struct {
	*mock.Connection
}

func (failingCommands) RunCommand(command string) (*shared.Command, error) {
	return nil, errors.New("fork/exec /bin/sh: resource temporarily unavailable")
}

// listMacOSApps lists the identity fixture's applications. A non-nil cmd
// replaces what system_profiler answers with.
func listMacOSApps(t *testing.T, cmd *mock.Command) ([]Package, error) {
	t.Helper()
	return listMacOSAppsOn(t, identityConn(t, cmd))
}

func identityConn(t *testing.T, cmd *mock.Command) *mock.Connection {
	t.Helper()
	opts := []mock.Option{mock.WithPath("./testdata/packages_macos_identity.toml")}
	if cmd != nil {
		opts = append(opts, mock.WithData(&mock.TomlData{Commands: map[string]*mock.Command{sysProfilerAppsCmd: cmd}}))
	}
	conn, err := mock.New(0, &inventory.Asset{}, opts...)
	require.NoError(t, err)
	return conn
}

func listMacOSAppsOn(t *testing.T, conn shared.Connection) ([]Package, error) {
	t.Helper()
	mpm := &MacOSPkgManager{conn: conn, platform: macOSIdentityPlatform()}
	return mpm.List()
}

// withoutTeamID drops the team-id qualifier from a purl.
func withoutTeamID(t *testing.T, s string) string {
	t.Helper()
	p, err := packageurl.FromString(s)
	require.NoError(t, err)
	q := p.Qualifiers.Map()
	delete(q, PurlQualifierTeamID)
	p.Qualifiers = packageurl.QualifiersFromMap(q)
	return p.ToString()
}

func byFilePath(t *testing.T, pkgs []Package) map[string]Package {
	t.Helper()
	res := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		require.Len(t, p.Files, 1)
		_, dup := res[p.Files[0].Path]
		require.False(t, dup, "bundle reported twice: %s", p.Files[0].Path)
		res[p.Files[0].Path] = p
	}
	return res
}

// With Spotlight off system_profiler has nothing to report. Depending on the
// macOS release and on how indexing was turned off it says so with an empty
// item list, prints nothing, or fails. In every case the applications are
// still listed from their folders, under the same identity: a Mac that
// toggles Spotlight must not see its applications change.
func TestMacOSPackagesWithoutSpotlight(t *testing.T) {
	withSpotlight, err := listMacOSApps(t, nil)
	require.NoError(t, err)
	want := byFilePath(t, withSpotlight)
	require.Len(t, want, 12)

	cases := map[string]func(t *testing.T) shared.Connection{
		"empty item list": func(t *testing.T) shared.Connection {
			return identityConn(t, &mock.Command{Stdout: sysProfilerNoApplications})
		},
		"no output": func(t *testing.T) shared.Connection {
			return identityConn(t, &mock.Command{})
		},
		"exits with an error": func(t *testing.T) shared.Connection {
			return identityConn(t, &mock.Command{Stderr: "system_profiler[812:4431] SPApplicationsReporter: timed out", ExitStatus: 1})
		},
		"truncated output": func(t *testing.T) shared.Connection {
			return identityConn(t, &mock.Command{Stdout: sysProfilerNoApplications[:200]})
		},
		"cannot be started": func(t *testing.T) shared.Connection {
			return failingCommands{identityConn(t, nil)}
		},
	}
	for name, conn := range cases {
		t.Run(name, func(t *testing.T) {
			pkgs, err := listMacOSAppsOn(t, conn(t))
			require.NoError(t, err)
			got := byFilePath(t, pkgs)
			require.Len(t, got, len(want))

			for path, w := range want {
				g, ok := got[path]
				require.True(t, ok, "missing without Spotlight: %s", path)
				// What identifies the application is the same on both paths.
				assert.Equal(t, w.Name, g.Name, path)
				assert.Equal(t, w.Version, g.Version, path)
				assert.Equal(t, w.Arch, g.Arch, path)
				assert.Equal(t, w.Format, g.Format, path)
				assert.Equal(t, w.InstallScope, g.InstallScope, path)
				assert.Equal(t, w.InstallUser, g.InstallUser, path)
				assert.Equal(t, w.MacOS.BundleID, g.MacOS.BundleID, path)
				assert.Equal(t, w.MacOS.AppStore, g.MacOS.AppStore, path)
				assert.Equal(t, withoutTeamID(t, w.PUrl), g.PUrl, path)

				// The team comes from the signing certificate system_profiler
				// reports, and so does the Gatekeeper origin. The bundle's own
				// files carry neither.
				assert.Empty(t, g.MacOS.Signer, path)
				assert.Empty(t, g.MacOS.TeamID, path)
				assert.Empty(t, g.Origin, path)
			}
		})
	}
}

// A target that has neither a working system_profiler nor any application
// folder, such as a non-macOS filesystem, still reports the failure.
func TestMacOSPackagesWithoutSpotlightOrApplications(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, err)
	_, err = listMacOSAppsOn(t, conn)
	require.Error(t, err)
}

// macOSBundle is an application bundle on a mock Mac. The values are copied
// from the real bundle on a macOS 26 Mac (Apple Silicon), keeping only what
// the parser reads.
type macOSBundle struct {
	path string
	// Contents/Info.plist
	info map[string]any
	// The English entries of Contents/Resources/InfoPlist.loctable.
	loc map[string]string
	// The start of the main executable, enough of its Mach-O header to name
	// its architectures.
	exe []byte
	// system_profiler's entry for the bundle when Spotlight is on; nil when
	// it never reports the bundle.
	sp map[string]any
}

// The Mach-O headers the bundles below start with: a universal binary with
// x86_64 and arm64e slices (FindMy's first 48 bytes; every universal bundle
// here has the same slice table apart from offsets and sizes), and a thin
// arm64 binary (Image Playground's first 8 bytes).
var (
	machoUniversal = mustHex("cafebabe000000020100000700000003000040000063d6f00000000e0100000c8000000200644000006b8b600000000e")
	machoArm64     = mustHex("cffaedfe0c000001")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func spEntry(name, version, archKind, obtainedFrom, signer string) map[string]any {
	return map[string]any{"_name": name, "version": version, "arch_kind": archKind, "obtained_from": obtainedFrom, "signed_by": []string{signer}}
}

// spotlightOffBundles is one bundle for each place the folder listing looks,
// plus the bundles whose names test appDisplayName.
var spotlightOffBundles = []macOSBundle{{
	path: "/Applications/Utilities/LogiPluginService.app",
	info: map[string]any{"CFBundleExecutable": "LogiPluginService", "CFBundleIdentifier": "com.logi.pluginservice", "CFBundleName": "LogiPluginService", "CFBundleShortVersionString": "6.2.6.1611"},
	exe:  machoUniversal,
	sp:   spEntry("LogiPluginService", "6.2.6.1611", "arch_arm_i64", "identified_developer", "Developer ID Application: Logitech Inc. (QED4VVPZWA)"),
}, {
	path: "/Users/alice/Applications/Claude Code URL Handler.app",
	info: map[string]any{"CFBundleExecutable": "claude", "CFBundleIdentifier": "com.anthropic.claude-code-url-handler", "CFBundleName": "Claude Code URL Handler", "CFBundleVersion": "1.0"},
	exe:  machoArm64,
	sp:   spEntry("Claude Code URL Handler", "1.0", "arch_ios", "identified_developer", "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)"),
}, {
	path: "/System/Applications/FindMy.app",
	info: map[string]any{"CFBundleDevelopmentRegion": "en", "CFBundleDisplayName": "FindMy", "CFBundleExecutable": "FindMy", "CFBundleIdentifier": "com.apple.findmy", "CFBundleName": "FindMy", "CFBundleShortVersionString": "4.0"},
	loc:  map[string]string{"CFBundleDisplayName": "Find My", "CFBundleName": "Find My"},
	exe:  machoUniversal,
	sp:   spEntry("Find My", "4.0", "arch_arm_i64", "apple", "Software Signing"),
}, {
	path: "/System/Applications/VoiceMemos.app",
	info: map[string]any{"CFBundleDevelopmentRegion": "en", "CFBundleDisplayName": "VoiceMemos", "CFBundleExecutable": "VoiceMemos", "CFBundleIdentifier": "com.apple.VoiceMemos", "CFBundleName": "VoiceMemos", "CFBundleShortVersionString": "3.2"},
	loc:  map[string]string{"CFBundleDisplayName": "Voice Memos", "CFBundleName": "Voice Memos"},
	exe:  machoUniversal,
	sp:   spEntry("Voice Memos", "3.2", "arch_arm_i64", "apple", "Software Signing"),
}, {
	path: "/System/Applications/Image Playground.app",
	info: map[string]any{"CFBundleDevelopmentRegion": "en", "CFBundleDisplayName": "Image Playground", "CFBundleExecutable": "Image Playground", "CFBundleIdentifier": "com.apple.GenerativePlaygroundApp", "CFBundleName": "Image Playground", "CFBundleShortVersionString": "1.0"},
	loc:  map[string]string{"CFBundleDisplayName": "Playground", "CFBundleDisplayName-macos": "Image Playground", "CFBundleName": "Image Playground"},
	exe:  machoArm64,
	sp:   spEntry("Image Playground", "1.0", "arch_arm", "apple", "Software Signing"),
}, {
	path: "/System/Library/CoreServices/PIPAgent.app",
	info: map[string]any{"CFBundleDevelopmentRegion": "en", "CFBundleDisplayName": "Picture in Picture", "CFBundleExecutable": "PIPAgent", "CFBundleIdentifier": "com.apple.PIPAgent", "CFBundleName": "PIPAgent", "CFBundleShortVersionString": "2.0"},
	loc:  map[string]string{"CFBundleDisplayName": "Picture in Picture"},
	exe:  machoUniversal,
	sp:   spEntry("PIPAgent", "2.0", "arch_arm_i64", "apple", "Software Signing"),
}, {
	path: "/System/Library/CoreServices/Applications/Directory Utility.app",
	info: map[string]any{"CFBundleDevelopmentRegion": "English", "CFBundleExecutable": "Directory Utility", "CFBundleIdentifier": "com.apple.DirectoryUtility", "CFBundleName": "Directory Utility", "CFBundleShortVersionString": "7.0", "LSHasLocalizedDisplayName": true},
	loc:  map[string]string{"CFBundleName": "Directory Utility"},
	exe:  machoUniversal,
	sp:   spEntry("Directory Utility", "7.0", "arch_arm_i64", "apple", "Software Signing"),
}, {
	path: "/System/Library/Input Methods/DictationIM.app",
	info: map[string]any{"CFBundleDevelopmentRegion": "English", "CFBundleDisplayName": "DictationIM", "CFBundleExecutable": "DictationIM", "CFBundleIdentifier": "com.apple.inputmethod.ironwood", "CFBundleName": "DictationIM", "CFBundleShortVersionString": "6.2.47"},
	loc:  map[string]string{"CFBundleDisplayName": "Dictation", "CFBundleName": "Dictation"},
	exe:  machoUniversal,
	sp:   spEntry("Dictation", "6.2.47", "arch_arm_i64", "apple", "Software Signing"),
}, {
	path: "/System/Cryptexes/App/System/Applications/Safari.app",
	info: map[string]any{"CFBundleDisplayName": "Safari", "CFBundleExecutable": "Safari", "CFBundleIdentifier": "com.apple.Safari", "CFBundleName": "Safari", "CFBundleShortVersionString": "26.5"},
	exe:  machoUniversal,
}}

// macOSMock builds a mock Mac holding the bundles. system_profiler reports
// the entries report accepts.
func macOSMock(t *testing.T, bundles []macOSBundle, report func(path string) bool) *mock.Connection {
	t.Helper()
	files := map[string]*mock.MockFileData{}
	add := func(path string, data []byte) {
		files[path] = &mock.MockFileData{Path: path, Data: data}
	}
	var items []map[string]any
	for _, b := range bundles {
		for dir := filepath.Dir(b.path); dir != "/"; dir = filepath.Dir(dir) {
			add(dir, nil)
		}
		add(b.path, nil)
		info, err := plist.Marshal(b.info, plist.XMLFormat)
		require.NoError(t, err)
		add(filepath.Join(b.path, "Contents", "Info.plist"), info)
		if b.loc != nil {
			loc, err := plist.Marshal(map[string]map[string]string{"en": b.loc}, plist.BinaryFormat)
			require.NoError(t, err)
			add(filepath.Join(b.path, "Contents", "Resources", "InfoPlist.loctable"), loc)
		}
		add(filepath.Join(b.path, "Contents", "MacOS", b.info["CFBundleExecutable"].(string)), b.exe)
		if b.sp != nil && report(b.path) {
			item := maps.Clone(b.sp)
			item["path"] = b.path
			items = append(items, item)
		}
	}
	out, err := plist.MarshalIndent([]map[string]any{{"_dataType": "SPApplicationsDataType", "_items": items}}, plist.XMLFormat, "\t")
	require.NoError(t, err)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Files:    files,
		Commands: map[string]*mock.Command{sysProfilerAppsCmd: {Stdout: string(out)}},
	}))
	require.NoError(t, err)
	return conn
}

func fullReport(string) bool { return true }

// partialReport is what system_profiler prints with Spotlight indexing off: a
// well-formed report that exits cleanly, but lists only the applications
// outside /System.
func partialReport(path string) bool { return !strings.HasPrefix(path, "/System/") }

// With Spotlight indexing off, system_profiler reports the applications
// outside /System and nothing else, and says nothing about it. The
// applications macOS ships come from the folder listing instead, under the
// names, versions and identities system_profiler gives them when Spotlight
// is on.
func TestMacOSPackagesFromPartialReport(t *testing.T) {
	withSpotlight, err := listMacOSAppsOn(t, macOSMock(t, spotlightOffBundles, fullReport))
	require.NoError(t, err)
	want := byFilePath(t, withSpotlight)
	require.Len(t, want, len(spotlightOffBundles))

	partial, err := listMacOSAppsOn(t, macOSMock(t, spotlightOffBundles, partialReport))
	require.NoError(t, err)
	got := byFilePath(t, partial)
	require.Len(t, got, len(want))

	for path, w := range want {
		g, ok := got[path]
		require.True(t, ok, "missing from a partial report: %s", path)
		assert.Equal(t, w.Name, g.Name, path)
		assert.Equal(t, w.Version, g.Version, path)
		assert.Equal(t, w.Arch, g.Arch, path)
		assert.Equal(t, w.InstallScope, g.InstallScope, path)
		assert.Equal(t, w.MacOS.BundleID, g.MacOS.BundleID, path)
		assert.Equal(t, w.MacOS.AppStore, g.MacOS.AppStore, path)
		if partialReport(path) || strings.HasPrefix(path, cryptexRoot+"/") {
			assert.Equal(t, w, g, path)
		} else {
			// Only system_profiler knows the signer and the Gatekeeper origin.
			assert.Equal(t, withoutTeamID(t, w.PUrl), g.PUrl, path)
			assert.Empty(t, g.Origin, path)
		}
	}
}

// Finder shows the localized name of a bundle whose directory still carries
// its CFBundleDisplayName, and the directory name of every other bundle
// without LSHasLocalizedDisplayName. The expected names are what
// system_profiler reports for these bundles.
func TestAppDisplayNameOfAppleBundles(t *testing.T) {
	conn := macOSMock(t, spotlightOffBundles, fullReport)
	for _, b := range spotlightOffBundles {
		if b.sp == nil {
			continue
		}
		t.Run(b.path, func(t *testing.T) {
			info, isBundle := readInfoPlist(conn, b.path)
			require.True(t, isBundle)
			assert.Equal(t, b.sp["_name"], appDisplayName(conn, b.path, info))
		})
	}
}

func TestCryptexSystemPath(t *testing.T) {
	p, ok := cryptexSystemPath("/System/Cryptexes/App/System/Library/CoreServices/Web App.app")
	assert.True(t, ok)
	assert.Equal(t, "/System/Library/CoreServices/Web App.app", p)
	_, ok = cryptexSystemPath("/System/Library/CoreServices/Finder.app")
	assert.False(t, ok)
}

// A partial report is visible in the debug log. A complete one does not
// claim Spotlight is off, and cryptex bundles, which system_profiler never
// reports, don't count.
func TestUnreportedApplications(t *testing.T) {
	added := func(t *testing.T, report func(string) bool) (int, bool) {
		conn := macOSMock(t, spotlightOffBundles, report)
		items, err := (&MacOSPkgManager{conn: conn}).sysProfilerApplications()
		require.NoError(t, err)
		extra := cryptexApplications(conn, items)
		extra = append(extra, folderApplications(conn, append(items, extra...))...)
		return unreportedApplications(items, extra)
	}

	count, systemMissing := added(t, fullReport)
	assert.Equal(t, 0, count, "Safari comes from its cryptex on every scan")
	assert.False(t, systemMissing)

	count, systemMissing = added(t, partialReport)
	assert.Equal(t, 6, count)
	assert.True(t, systemMissing)

	// A report that has /System applications is not partial, however many
	// bundles it missed.
	count, systemMissing = added(t, func(path string) bool { return !strings.Contains(path, "/CoreServices/") })
	assert.Equal(t, 2, count)
	assert.False(t, systemMissing)
}
