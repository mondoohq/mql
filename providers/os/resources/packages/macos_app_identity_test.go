// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// The arch_kind values and the architectures they stand for were checked
// against `lipo -archs` on the bundles' executables on an Apple Silicon Mac.
func TestAppArch(t *testing.T) {
	cases := []struct {
		archKind string
		want     string
	}{
		{"arch_arm_i64", "universal"}, // TextEdit: x86_64 arm64e
		{"arch_arm", "arm64"},         // Microsoft Edge: arm64
		{"arch_ios", "arm64"},         // VLC: arm64, printed as "Kind: iOS"
		{"arch_i64", "x86_64"},        // Oracle Secure Global Desktop Client: x86_64
		{"arch_other", "arm64"},       // ZAP: a shell script launcher
		{"", "arm64"},                 // no arch_kind at all
	}
	for _, tc := range cases {
		t.Run(tc.archKind, func(t *testing.T) {
			assert.Equal(t, tc.want, appArch(tc.archKind, "arm64"))
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
		assert.Equal(t, "pkg:macos/macos/Microsoft%20Edge@154.0.4258.37?arch=arm64", edge.PUrl)
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
		assert.Equal(t, "pkg:macos/macos/Monodraw@1.7.1?arch=universal", monodraw.PUrl)
	})

	t.Run("application shipped with macOS", func(t *testing.T) {
		textEdit := byPath["/System/Applications/TextEdit.app"]
		assert.Equal(t, "com.apple.TextEdit", textEdit.MacOS.BundleID)
		assert.Equal(t, "Software Signing", textEdit.MacOS.Signer)
		assert.Empty(t, textEdit.MacOS.TeamID)
		assert.False(t, textEdit.MacOS.AppStore)
		assert.Equal(t, "universal", textEdit.Arch)
	})

	t.Run("architectures", func(t *testing.T) {
		assert.Equal(t, "arm64", byPath["/Applications/VLC.app"].Arch)
		assert.Equal(t, "x86_64", byPath["/Applications/Oracle Secure Global Desktop Client.app"].Arch)
		assert.Equal(t, "pkg:macos/macos/Oracle%20Secure%20Global%20Desktop%20Client@5.60.567?arch=x86_64",
			byPath["/Applications/Oracle Secure Global Desktop Client.app"].PUrl)
		// A shell script launcher has no Mach-O architecture: the host's.
		assert.Equal(t, "arm64", byPath["/Applications/ZAP.app"].Arch)
	})

	t.Run("application in a home directory", func(t *testing.T) {
		handler := byPath["/Users/alice/Applications/Claude Code URL Handler.app"]
		assert.Equal(t, "Claude Code URL Handler", handler.Name)
		assert.Equal(t, "user", handler.InstallScope)
		assert.Equal(t, "alice", handler.InstallUser)
	})

	t.Run("applications system_profiler missed", func(t *testing.T) {
		slack := byPath["/Applications/Slack.app"]
		assert.Equal(t, "Slack", slack.Name)
		assert.Equal(t, "4.52.162", slack.Version)
		assert.Equal(t, "com.tinyspeck.slackmacgap", slack.MacOS.BundleID)
		assert.False(t, slack.MacOS.AppStore)
		assert.Equal(t, "machine", slack.InstallScope)
		// Nothing but the bundle's own files is available: no signer and no
		// Gatekeeper origin, and the host architecture.
		assert.Empty(t, slack.MacOS.Signer)
		assert.Empty(t, slack.Origin)
		assert.Equal(t, "arm64", slack.Arch)
		assert.Equal(t, "pkg:macos/macos/Slack@4.52.162?arch=arm64", slack.PUrl)

		// The receipt alone identifies an App Store app.
		telegram := byPath["/Applications/Telegram.app"]
		assert.Equal(t, "ru.keepcoder.Telegram", telegram.MacOS.BundleID)
		assert.True(t, telegram.MacOS.AppStore)

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
