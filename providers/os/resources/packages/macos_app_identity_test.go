// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// The arch_kind values and the architectures they stand for were checked
// against `lipo -archs` on the bundles' executables on an Apple Silicon Mac.
// arch_kind is only the fallback for an executable that cannot be read, and
// it never falls back to the host's architecture.
func TestArchFromArchKind(t *testing.T) {
	cases := []struct {
		archKind string
		want     string
	}{
		{"arch_arm_i64", "universal"}, // TextEdit: x86_64 arm64e
		{"arch_arm", "arm64"},         // Microsoft Edge: arm64
		{"arch_ios", "arm64"},         // VLC: arm64, printed as "Kind: iOS"
		{"arch_i64", "x86_64"},        // Oracle Secure Global Desktop Client: x86_64
		{"arch_other", ""},            // ZAP: a shell script launcher
		{"", ""},                      // no arch_kind at all
	}
	for _, tc := range cases {
		t.Run(tc.archKind, func(t *testing.T) {
			assert.Equal(t, tc.want, archFromArchKind(tc.archKind))
		})
	}
}

// Each fixture is the first 512 bytes of a real application executable,
// checked with `lipo -archs`.
func TestMachoArch(t *testing.T) {
	cases := []struct {
		file string
		want string
	}{
		{"universal.bin", "universal"}, // TextEdit: x86_64 arm64e
		{"arm64.bin", "arm64"},         // Microsoft Edge: arm64
		{"arm64e.bin", "arm64"},        // Image Playground: arm64e
		{"x86_64.bin", "x86_64"},       // Oracle Secure Global Desktop Client: x86_64
		{"script.bin", ""},             // ZAP: a bash launcher script
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			header, err := os.ReadFile(filepath.Join("testdata", "macho", tc.file))
			require.NoError(t, err)
			assert.Equal(t, tc.want, machoArch(header))
		})
	}

	t.Run("truncated universal header", func(t *testing.T) {
		header, err := os.ReadFile(filepath.Join("testdata", "macho", "universal.bin"))
		require.NoError(t, err)
		// Two slices need 8+2*20 bytes; one byte short is not a header.
		assert.Equal(t, "", machoArch(header[:47]))
		assert.Equal(t, "universal", machoArch(header[:48]))
	})
	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "", machoArch(nil))
	})
}

// Bundle paths from an Apple Silicon Mac. The directory name is the fallback
// name of an application no other source names.
func TestBundleName(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/Applications/zoom.us.app", "zoom.us"},
		{"/System/Applications/Utilities/Digital Color Meter.app", "Digital Color Meter"},
		{"/Applications/iTerm 2.app", "iTerm 2"},
		{"/Applications/pgAdmin 4.app", "pgAdmin 4"},
		{"/Applications/WhatsApp.localized/WhatsApp.app", "WhatsApp"},
		{"/Applications/Slack.app/", "Slack"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, bundleName(tc.path))
		})
	}
}

func TestAppInstallScope(t *testing.T) {
	cases := []struct {
		path      string
		wantScope string
		wantUser  string
	}{
		{"/Applications/Slack.app", "machine", ""},
		{"/System/Applications/TextEdit.app", "machine", ""},
		{"/Library/Application Support/Adobe/ARMDC/Application/Adobe Acrobat Updater.app", "machine", ""},
		{"/Users/alice/Applications/Claude Code URL Handler.app", "user", "alice"},
		{"/Users/alice/Downloads/Tool.app", "user", "alice"},
		// /Users/Shared is reachable by every user, it is not a home directory.
		{"/Users/Shared/Tool.app", "machine", ""},
		// A path that merely starts like a home directory is not in one.
		{"/Users", "machine", ""},
		{"/Usersfoo/Tool.app", "machine", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			scope, user := appInstallScope(tc.path)
			assert.Equal(t, tc.wantScope, scope)
			assert.Equal(t, tc.wantUser, user)
		})
	}
}

// Signers are the leaf certificates system_profiler reported on a real Mac.
func TestTeamIDFromSigner(t *testing.T) {
	cases := []struct {
		signer string
		want   string
	}{
		{"Developer ID Application: Microsoft Corporation (UBF8T346G9)", "UBF8T346G9"},
		{"Developer ID Application: VideoLAN (75GAHG3SZQ)", "75GAHG3SZQ"},
		{"Developer ID Application: Paul Chote (J9RC5GHDAV)", "J9RC5GHDAV"},
		// Signed by Apple, no team.
		{"Software Signing", ""},
		{"Apple Mac OS Application Signing", ""},
		// A development certificate's parenthesized id names the certificate
		// holder, not the team.
		{"Apple Development: alice@example.com (ABCDE12345)", ""},
		// Not a ten-character team id.
		{"Developer ID Application: Example (ABC)", ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.signer, func(t *testing.T) {
			assert.Equal(t, tc.want, teamIDFromSigner(tc.signer))
		})
	}
}

// The fixture is system_profiler output and bundle files captured on one Mac:
// seven applications system_profiler reported, and five it missed although
// they are installed in the application folders (Slack, Telegram, WhatsApp,
// zoom.us and News).
func TestMacOSAppIdentity(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_macos_identity.toml"))
	require.NoError(t, err)
	c, err := conn.RunCommand("system_profiler SPApplicationsDataType -xml")
	require.NoError(t, err)

	pf := &inventory.Platform{Name: "macos", Version: "26.5", Arch: "arm64", Family: []string{"darwin", "bsd", "unix", "os"}}
	pkgs, err := ParseMacOSPackages(conn, pf, c.Stdout)
	require.NoError(t, err)

	byPath := map[string]Package{}
	for _, p := range pkgs {
		require.Len(t, p.Files, 1)
		require.NotNil(t, p.MacOS, "every application carries its macOS details: %s", p.Files[0].Path)
		_, dup := byPath[p.Files[0].Path]
		require.False(t, dup, "bundle reported twice: %s", p.Files[0].Path)
		byPath[p.Files[0].Path] = p
	}
	require.Len(t, byPath, 12)

	t.Run("Developer ID application", func(t *testing.T) {
		edge := byPath["/Applications/Microsoft Edge.app"]
		assert.Equal(t, "Microsoft Edge", edge.Name)
		assert.Equal(t, "154.0.4258.37", edge.Version)
		assert.Equal(t, "com.microsoft.edgemac", edge.MacOS.BundleID)
		assert.Equal(t, "Developer ID Application: Microsoft Corporation (UBF8T346G9)", edge.MacOS.Signer)
		assert.Equal(t, "UBF8T346G9", edge.MacOS.TeamID)
		assert.False(t, edge.MacOS.AppStore)
		assert.Equal(t, "identified_developer", edge.Origin)
		assert.Equal(t, "arm64", edge.Arch)
		assert.Equal(t, "pkg:macos/macos/Microsoft%20Edge@154.0.4258.37?arch=arm64&bundle-id=com.microsoft.edgemac&team-id=UBF8T346G9", edge.PUrl)
		assert.Equal(t, "machine", edge.InstallScope)
		assert.Empty(t, edge.InstallUser)
	})

	t.Run("Mac App Store application", func(t *testing.T) {
		monodraw := byPath["/Applications/Monodraw.app"]
		assert.Equal(t, "com.helftone.monodraw", monodraw.MacOS.BundleID)
		assert.Equal(t, "Apple Mac OS Application Signing", monodraw.MacOS.Signer)
		assert.Empty(t, monodraw.MacOS.TeamID, "Apple re-signs App Store apps, no team in the certificate")
		assert.True(t, monodraw.MacOS.AppStore)
		assert.Equal(t, "mac_app_store", monodraw.Origin)
		assert.Equal(t, "universal", monodraw.Arch)
		assert.Equal(t, "pkg:macos/macos/Monodraw@1.7.1?app-store=true&arch=arm64&bundle-id=com.helftone.monodraw", monodraw.PUrl)
	})

	t.Run("application shipped with macOS", func(t *testing.T) {
		textEdit := byPath["/System/Applications/TextEdit.app"]
		assert.Equal(t, "com.apple.TextEdit", textEdit.MacOS.BundleID)
		assert.Equal(t, "Software Signing", textEdit.MacOS.Signer)
		assert.Empty(t, textEdit.MacOS.TeamID)
		assert.False(t, textEdit.MacOS.AppStore)
		assert.Equal(t, "universal", textEdit.Arch)
		assert.Equal(t, "pkg:macos/macos/TextEdit@1.20?arch=arm64&bundle-id=com.apple.TextEdit", textEdit.PUrl)
	})

	t.Run("architectures", func(t *testing.T) {
		assert.Equal(t, "arm64", byPath["/Applications/VLC.app"].Arch)
		assert.Equal(t, "x86_64", byPath["/Applications/Oracle Secure Global Desktop Client.app"].Arch)
		assert.Equal(t, "pkg:macos/macos/Oracle%20Secure%20Global%20Desktop%20Client@5.60.567?arch=arm64&bundle-id=com.oracle.sgd.ttatcc&team-id=VB5E2TV963",
			byPath["/Applications/Oracle Secure Global Desktop Client.app"].PUrl)
		// A shell script launcher has no Mach-O architecture, so package.arch
		// is empty. The purl keeps the host's architecture for now (#11113).
		zap := byPath["/Applications/ZAP.app"]
		assert.Empty(t, zap.Arch)
		assert.Equal(t, "pkg:macos/macos/ZAP@2.15.0?arch=arm64&bundle-id=org.zaproxy.zap.ZAP", zap.PUrl)
	})

	t.Run("application in a home directory", func(t *testing.T) {
		handler := byPath["/Users/alice/Applications/Claude Code URL Handler.app"]
		assert.Equal(t, "Claude Code URL Handler", handler.Name)
		assert.Equal(t, "user", handler.InstallScope)
		assert.Equal(t, "alice", handler.InstallUser)
		assert.Equal(t, "pkg:macos/macos/Claude%20Code%20URL%20Handler@1.0?arch=arm64&bundle-id=com.anthropic.claude-code-url-handler&install-scope=user&team-id=Q6L2SF6YDW", handler.PUrl)
	})

	t.Run("applications system_profiler missed", func(t *testing.T) {
		slack := byPath["/Applications/Slack.app"]
		assert.Equal(t, "Slack", slack.Name)
		assert.Equal(t, "4.52.162", slack.Version)
		assert.Equal(t, "com.tinyspeck.slackmacgap", slack.MacOS.BundleID)
		assert.False(t, slack.MacOS.AppStore)
		assert.Equal(t, "machine", slack.InstallScope)
		// Nothing but the bundle's own files is available: no signer and no
		// Gatekeeper origin. The architecture comes from the executable, as
		// for every other application.
		assert.Empty(t, slack.MacOS.Signer)
		assert.Empty(t, slack.Origin)
		assert.Equal(t, "arm64", slack.Arch)
		assert.Equal(t, "pkg:macos/macos/Slack@4.52.162?arch=arm64&bundle-id=com.tinyspeck.slackmacgap", slack.PUrl)

		// The receipt alone identifies an App Store app.
		telegram := byPath["/Applications/Telegram.app"]
		assert.Equal(t, "ru.keepcoder.Telegram", telegram.MacOS.BundleID)
		assert.True(t, telegram.MacOS.AppStore)
		// system_profiler reported no arch_kind for it: this is the executable.
		assert.Equal(t, "universal", telegram.Arch)
		assert.Equal(t, "pkg:macos/macos/Telegram@12.10?app-store=true&arch=arm64&bundle-id=ru.keepcoder.Telegram", telegram.PUrl)

		// Found one level down, in a vendor folder.
		whatsapp := byPath["/Applications/WhatsApp.localized/WhatsApp.app"]
		assert.Equal(t, "WhatsApp", whatsapp.Name)
		assert.Equal(t, "net.whatsapp.WhatsApp", whatsapp.MacOS.BundleID)
		assert.True(t, whatsapp.MacOS.AppStore)

		// Named after the directory, which is what system_profiler reports.
		zoom := byPath["/Applications/zoom.us.app"]
		assert.Equal(t, "zoom.us", zoom.Name)
		assert.Equal(t, "us.zoom.xos", zoom.MacOS.BundleID)

		news := byPath["/System/Applications/News.app"]
		assert.Equal(t, "News", news.Name)
		assert.Equal(t, "com.apple.news", news.MacOS.BundleID)
	})
}

// The executable is the authority on the architecture. arch_kind only stands
// in when the executable cannot be read.
func TestAppArchitecturePrefersTheExecutable(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_macos_identity.toml"))
	require.NoError(t, err)

	// TextEdit's executable is universal, whatever arch_kind claims.
	textEdit := &sysProfilerItem{Path: "/System/Applications/TextEdit.app", ArchKind: "arch_i64"}
	info, ok := entryInfoPlist(conn, textEdit)
	require.True(t, ok)
	assert.Equal(t, "universal", appArchitecture(conn, textEdit, info))

	// No such executable: arch_kind answers.
	missing := &sysProfilerItem{Path: "/Applications/Missing.app", ArchKind: "arch_i64"}
	assert.Equal(t, "x86_64", appArchitecture(conn, missing, infoPlist{Executable: "Missing"}))

	// Neither: no architecture rather than the host's.
	assert.Equal(t, "", appArchitecture(conn, &sysProfilerItem{Path: "/Applications/Missing.app"}, infoPlist{Executable: "Missing"}))
}

// Applications only the folder listing finds are named the way Finder and
// system_profiler name them: the localized name when the bundle sets
// LSHasLocalizedDisplayName, read in the bundle's development language,
// otherwise the directory name. The fixture covers each file format a
// localized name comes in.
func TestAppDisplayName(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_macos_display_name.toml"))
	require.NoError(t, err)

	cases := []struct {
		path   string
		want   string
		format string
	}{
		{"/Applications/Cisco WebEx Start.app", "Webex", "text .strings, UTF-8"},
		{"/Applications/Meeting Center.app", "Cisco Webex Meetings", "text .strings, UTF-16, English.lproj"},
		{"/Applications/Iru Self Service.app", "Iru Self Service", "XML .strings, UTF-16"},
		{"/Applications/Microsoft Word.app", "Microsoft Word", "binary .strings"},
		{"/Applications/logioptionsplus.app", "Logi Options+", "text .strings, Base.lproj"},
		// The development language's spelling, not the user's: system_profiler
		// shows "Notification Centre" on a British English system.
		{"/System/Applications/NotificationCenter.app", "Notification Center", "InfoPlist.loctable"},
		// No LSHasLocalizedDisplayName: Finder shows the directory name, not the
		// Info.plist display name "Code".
		{"/Applications/Visual Studio Code.app", "Visual Studio Code", "no localized name"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			info, isBundle := readInfoPlist(conn, tc.path)
			require.True(t, isBundle)
			assert.Equal(t, tc.want, appDisplayName(conn, tc.path, info))
		})
	}
}

func TestIsTruthy(t *testing.T) {
	for _, v := range []any{true, uint64(1), int64(1), "1", "YES", "true"} {
		assert.True(t, isTruthy(v), "%v", v)
	}
	for _, v := range []any{nil, false, uint64(0), "", "0", "NO"} {
		assert.False(t, isTruthy(v), "%v", v)
	}
}

// Content larger than a localization file is ignored before anything is
// allocated from its length.
func TestParseStringsFileIgnoresOversizedContent(t *testing.T) {
	small := []byte(`"CFBundleDisplayName" = "Webex";`)
	assert.Equal(t, map[string]string{"CFBundleDisplayName": "Webex"}, parseStringsFile(small))

	big := append([]byte{0xff, 0xfe}, make([]byte, maxInfoStringsSize)...)
	assert.Nil(t, parseStringsFile(big))
	assert.Nil(t, decodeUTF16(big))
}
