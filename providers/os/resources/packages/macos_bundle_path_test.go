// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsApplicationBundlePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"application bundle", "/Applications/Docker.app", true},
		{"OS-shipped application", "/System/Applications/Utilities/Terminal.app", true},
		{"per-user application", "/Users/user/Applications/Chrome Apps.localized/Teams (PWA).app", true},
		{"trailing separator", "/Applications/Docker.app/", true},
		// APFS is case-insensitive by default, so this bundle launches.
		{"uppercase extension", "/Applications/Docker.APP", true},
		// Only a whole Contents segment means "inside a bundle".
		{"Contents as a name fragment", "/Applications/TableOfContents/Docker.app", true},

		// The reported bug: a renamed bundle keeps its old version forever, and
		// system_profiler names it "Docker.app" because it strips only .back.
		{"renamed bundle", "/Applications/Docker.app.back", false},
		{"disabled bundle", "/Applications/Docker.app.disabled", false},
		{"service bundle", "/System/Library/Services/Spotlight.service", false},
		{"non-bundle directory", "/Users/user/Library/HTTPStorages/com.apple.ctcategories.service", false},
		{"no path reported", "", false},

		// Helper bundles ship with, and are patched by, their container.
		{"helper in a renamed bundle", "/Applications/Docker.app.back/Contents/MacOS/Docker Desktop.app", false},
		{"login item helper", "/Applications/Docker.app.back/Contents/Library/LoginItems/DockerHelper.app", false},
		{"Finder pseudo-application", "/System/Library/CoreServices/Finder.app/Contents/Applications/AirDrop.app", false},
		{"framework XPC service", "/System/Library/Frameworks/PaperKit.framework/Contents/LinkedNotesUIService.app", false},

		// Script Editor templates are copied from to start a new script, not
		// run. Every path below was read off a real Mac except the per-user
		// one, which is where Script Editor keeps a user's own templates.
		{"Script Editor applet template", "/Library/Application Support/Script Editor/Templates/Cocoa-AppleScript Applet.app", false},
		{"Script Editor droplet template", "/Library/Application Support/Script Editor/Templates/Droplets/Recursive File Processing Droplet.app", false},
		{"per-user Script Editor template", "/Users/user/Library/Application Support/Script Editor/Templates/My Applet.app", false},
		{"Script Editor itself", "/System/Applications/Utilities/Script Editor.app", true},
		{"other Application Support app", "/Library/Application Support/Iru/Iru Menu/Iru Menu.app", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isApplicationBundlePath(test.path))
		})
	}
}

func TestWrapperBundleKind(t *testing.T) {
	tests := []struct {
		name string
		info infoPlist
		want string
	}{
		// Measured: macOS 27.0.1, 2026-10-31, bundles written by osacompile.
		// They carry no bundle identifier and no version.
		{"applescript applet", infoPlist{Executable: "applet", BundleName: "Hello"}, "applescript"},
		{"applescript droplet", infoPlist{Executable: "droplet", BundleName: "Drop"}, "applescript"},
		// Measured: macOS 27.0.1, Script Editor's Cocoa-AppleScript Applet template.
		{"applescriptobjc applet", infoPlist{Executable: "CocoaApplet", BundleID: "com.apple.ScriptEditor.id.cocoa-applet-template"}, "applescript"},
		// Measured: macOS 27.0.1, /System/Library/CoreServices/Automator Application Stub.app.
		{"automator stub", infoPlist{Executable: "Automator Application Stub", BundleID: "com.apple.Automator.Automator-Application-Stub", ShortVersion: "1.3"}, "automator"},
		// Synthetic: a saved workflow identified by its bundle identifier alone;
		// no target showed an executable other than the stub's.
		{"automator workflow by id", infoPlist{Executable: "Something Else", BundleID: "com.apple.Automator.Resize-Images"}, "automator"},
		// Measured: macOS 27.0.1, Google Chrome 156, Microsoft Teams installed as a web app.
		{"chrome web app", infoPlist{Executable: "app_mode_loader", BundleID: "com.google.Chrome.app.cifhbcnohmdccbgoicgdjpfamggdegmo", BundleVersion: "8059.85", CrAppModeShortcutID: "cifhbcnohmdccbgoicgdjpfamggdegmo"}, "web-app"},
		// Synthetic: a Chromium web app identified by its shortcut id alone.
		{"chromium web app by shortcut id", infoPlist{Executable: "launcher", BundleID: "com.microsoft.edgemac.app.abc", CrAppModeShortcutID: "abc"}, "web-app"},
		// Synthetic: Safari's Add to Dock identifier, com.apple.Safari.WebApp.<UUID>;
		// no target showed one.
		{"safari web app", infoPlist{BundleID: "com.apple.Safari.WebApp.6E1A2B9C-0F3D-4C51-9B7E-2A8D1F4C3E50"}, "web-app"},
		// Measured: macOS 27.0.1. The applications that make these bundles are
		// reported themselves.
		{"automator", infoPlist{Executable: "Automator", BundleID: "com.apple.Automator"}, ""},
		{"script editor", infoPlist{Executable: "Script Editor", BundleID: "com.apple.ScriptEditor2"}, ""},
		{"chrome", infoPlist{Executable: "Google Chrome", BundleID: "com.google.Chrome"}, ""},
		{"safari", infoPlist{Executable: "Safari", BundleID: "com.apple.Safari"}, ""},
		// Synthetic: no Info.plist could be read (a wrapped iOS app).
		{"empty info", infoPlist{}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, wrapperBundleKind(test.info))
		})
	}
}
