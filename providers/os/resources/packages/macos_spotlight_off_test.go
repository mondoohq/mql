// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

const spotlightOffFixture = "./testdata/packages_macos_spotlight_off.toml"

// partialReport is what system_profiler prints with Spotlight indexing off:
// a well-formed report that exits cleanly, but lists only the applications
// outside /System. It is derived from the fixture's Spotlight-on report by
// dropping the entries under /System.
func partialReport(t *testing.T) string {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath(spotlightOffFixture))
	require.NoError(t, err)
	cmd, err := conn.RunCommand(sysProfilerAppsCmd)
	require.NoError(t, err)
	var data []map[string]any
	_, err = plist.Unmarshal(mustReadAll(t, cmd.Stdout), &data)
	require.NoError(t, err)
	require.Len(t, data, 1)

	var kept []any
	for _, item := range data[0]["_items"].([]any) {
		if path, _ := item.(map[string]any)["path"].(string); !strings.HasPrefix(path, "/System/") {
			kept = append(kept, item)
		}
	}
	require.NotEmpty(t, kept)
	require.Less(t, len(kept), len(data[0]["_items"].([]any)))
	data[0]["_items"] = kept
	out, err := plist.MarshalIndent(data, plist.XMLFormat, "\t")
	require.NoError(t, err)
	return string(out)
}

func mustReadAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return b
}

// With Spotlight indexing off, system_profiler reports the applications
// outside /System and nothing else, and says nothing about it. The
// applications macOS ships come from the folder listing instead, under the
// names, versions and identities system_profiler gives them when Spotlight
// is on.
func TestMacOSPackagesFromPartialReport(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath(spotlightOffFixture))
	require.NoError(t, err)
	withSpotlight, err := listMacOSAppsOn(t, conn)
	require.NoError(t, err)
	want := byFilePath(t, withSpotlight)
	require.Len(t, want, 14)

	conn, err = mock.New(0, &inventory.Asset{}, mock.WithPath(spotlightOffFixture),
		mock.WithData(&mock.TomlData{Commands: map[string]*mock.Command{sysProfilerAppsCmd: {Stdout: partialReport(t)}}}))
	require.NoError(t, err)
	partial, err := listMacOSAppsOn(t, conn)
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
		if strings.HasPrefix(path, "/System/") {
			// Only system_profiler knows the signer and the Gatekeeper origin.
			assert.Equal(t, withoutTeamID(t, w.PUrl), g.PUrl, path)
			assert.Empty(t, g.Origin, path)
		} else {
			assert.Equal(t, w, g, path)
		}
	}

	// What went missing from the partial report on a real Mac.
	for path, name := range map[string]string{
		"/System/Applications/FindMy.app":                                 "Find My",
		"/System/Applications/VoiceMemos.app":                             "Voice Memos",
		"/System/Library/CoreServices/Siri.app":                           "Siri",
		"/System/Library/CoreServices/PeopleViewService.app":              "Contacts",
		"/System/Library/CoreServices/Finder.app":                         "Finder",
		"/System/Library/CoreServices/Applications/Directory Utility.app": "Directory Utility",
		"/System/Library/Input Methods/DictationIM.app":                   "Dictation",
	} {
		assert.Equal(t, name, got[path].Name, path)
	}
}

// Finder shows the localized name of a bundle whose directory still carries
// its CFBundleDisplayName, and the directory name of every other bundle
// without LSHasLocalizedDisplayName. The expected names are what
// system_profiler reported for these bundles.
func TestAppDisplayNameOfAppleBundles(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath(spotlightOffFixture))
	require.NoError(t, err)

	cases := []struct {
		path string
		want string
		why  string
	}{
		{"/System/Applications/FindMy.app", "Find My", "CFBundleDisplayName FindMy, localized in InfoPlist.loctable"},
		{"/System/Applications/VoiceMemos.app", "Voice Memos", "CFBundleDisplayName VoiceMemos, localized"},
		{"/System/Library/CoreServices/TipsSpotlightHandler.app", "Tips", "only the localized display name differs"},
		{"/System/Library/Input Methods/DictationIM.app", "Dictation", "input method"},
		{"/System/Library/CoreServices/PIPAgent.app", "PIPAgent", "CFBundleDisplayName Picture in Picture is not the directory name"},
		{"/System/Library/Input Methods/AinuIM.app", "AinuIM", "CFBundleDisplayName Ainu Input Method is not the directory name"},
		{"/System/Library/CoreServices/screencaptureui.app", "screencaptureui", "no CFBundleDisplayName in Info.plist"},
		{"/System/Library/CoreServices/PeopleViewService.app", "Contacts", "LSHasLocalizedDisplayName"},
		{"/Applications/zoom.us.app", "Zoom", "CFBundleDisplayName zoom.us, localized in en.lproj/InfoPlist.strings"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			info, isBundle := readInfoPlist(conn, tc.path)
			require.True(t, isBundle)
			assert.Equal(t, tc.want, appDisplayName(conn, tc.path, info))
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

// A partial report is visible in the debug log.
func TestLogUnreportedApplications(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf).Level(zerolog.DebugLevel)
	defer func() { log.Logger = prev }()

	outside := []sysProfilerItem{{Path: "/Applications/VLC.app"}}
	system := []sysProfilerItem{{Path: "/System/Library/CoreServices/Siri.app"}, {Path: "/System/Applications/FindMy.app"}}

	logUnreportedApplications(outside, system)
	assert.Contains(t, buf.String(), "Spotlight indexing may be off")
	assert.Contains(t, buf.String(), `"added":2`)

	buf.Reset()
	logUnreportedApplications(append(outside, system[0]), system[1:])
	assert.NotContains(t, buf.String(), "Spotlight")
	assert.Contains(t, buf.String(), `"added":1`)

	buf.Reset()
	logUnreportedApplications(outside, nil)
	assert.Empty(t, buf.String())
}
