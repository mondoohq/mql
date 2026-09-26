// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// MacosArchUniversal is the architecture reported for an application whose
// main executable is a universal binary carrying both an arm64 and an x86_64
// slice, so it runs natively on either kind of Mac.
const MacosArchUniversal = "universal"

// appArch maps system_profiler's arch_kind to the architecture of the
// application's main executable, falling back to the host architecture when
// system_profiler did not say or reported a kind that is not a Mach-O
// architecture.
//
// The values were checked against `lipo -archs` on the bundles'
// executables:
//
//	arch_arm_i64  x86_64 and arm64(e) slices, a universal binary
//	arch_arm      arm64 or arm64e only
//	arch_ios      arm64 only. system_profiler prints "Kind: iOS" for these,
//	              but they are ordinary Mac applications (VLC, Zed, Blender),
//	              not wrapped iPhone apps
//	arch_i64      x86_64 only, which on Apple Silicon runs under Rosetta
//	arch_other    not a Mach-O executable, for example a shell script
//	              launcher
//
// Reporting the host architecture for every application hid the one case that
// matters: an Intel-only application on an Apple Silicon Mac.
func appArch(archKind string, hostArch string) string {
	switch archKind {
	case "arch_arm_i64":
		return MacosArchUniversal
	case "arch_arm", "arch_ios":
		return "arm64"
	case "arch_i64":
		return "x86_64"
	default:
		return hostArch
	}
}

// Install scopes, the same values the Windows backend reports.
const (
	InstallScopeMachine = "machine"
	InstallScopeUser    = "user"
)

// appInstallScope reports whether an application bundle is installed for one
// user or for the machine, and for a user install the account whose home
// directory holds it.
//
// A bundle under /Users/<name>/ belongs to that user: it lives in their home
// directory and nobody else can be assumed to reach it. /Users/Shared is the
// one directory under /Users that is not a home directory, it exists so every
// user can reach its contents. Everything else (/Applications,
// /System/Applications, /Library, ...) is machine-wide.
func appInstallScope(path string) (string, string) {
	if path == "" {
		return "", ""
	}
	rest, ok := strings.CutPrefix(filepath.Clean(path), "/Users/")
	if !ok {
		return InstallScopeMachine, ""
	}
	user, _, ok := strings.Cut(rest, "/")
	if !ok || user == "" || strings.EqualFold(user, "Shared") {
		return InstallScopeMachine, ""
	}
	return InstallScopeUser, user
}

// developerIDPrefix is how the leaf certificate of a Developer ID-signed
// application is named. The name ends with the team identifier in
// parentheses, for example
// "Developer ID Application: Microsoft Corporation (UBF8T346G9)".
const developerIDPrefix = "Developer ID Application: "

// teamIDSuffix matches the ten-character Apple Developer Team ID at the end of
// a certificate name.
var teamIDSuffix = regexp.MustCompile(`\(([A-Z0-9]{10})\)$`)

// teamIDFromSigner returns the Apple Developer Team ID of a Developer ID
// Application signer, or "" for any other signer.
//
// Only Developer ID Application certificates are parsed. Apple's own
// applications ("Software Signing") and Mac App Store applications ("Apple Mac
// OS Application Signing") are signed by Apple and name no team. Development
// certificates ("Apple Development: <name> (<id>)") do end in a ten-character
// identifier, but it identifies the certificate holder rather than the team,
// so reading it as a Team ID would be wrong.
func teamIDFromSigner(signer string) string {
	if !strings.HasPrefix(signer, developerIDPrefix) {
		return ""
	}
	m := teamIDSuffix.FindStringSubmatch(signer)
	if m == nil {
		return ""
	}
	return m[1]
}

// macAppStoreSigner is the leaf certificate Apple re-signs Mac App Store
// applications with.
const macAppStoreSigner = "Apple Mac OS Application Signing"

// isAppStoreManaged reports whether an application is installed and updated by
// the Mac App Store.
//
// Either signal is enough. The App Store leaves its purchase receipt at
// Contents/_MASReceipt/receipt in every bundle it installs, which is checked
// with a stat and so also works for bundles system_profiler did not report.
// The App Store signature is what system_profiler reports when it does.
func isAppStoreManaged(conn shared.Connection, path string, signer string) bool {
	if signer == macAppStoreSigner {
		return true
	}
	if conn == nil || path == "" {
		return false
	}
	_, err := conn.FileSystem().Stat(filepath.Join(path, "Contents", "_MASReceipt", "receipt"))
	return err == nil
}

// applicationFolders are the folders macOS installs applications into, the
// ones Finder's Applications item and Launchpad show. Each is listed two
// levels deep, since vendors group their applications in a subfolder
// (/Applications/Utilities, /Applications/Adobe Acrobat DC,
// /Applications/WhatsApp.localized).
var applicationFolders = []string{
	"/Applications",
	"/System/Applications",
}

// usersRoot holds the home directories. Each user's ~/Applications is listed
// the same way as applicationFolders.
const usersRoot = "/Users"

// folderApplications lists the application bundles in the standard
// application folders that system_profiler did not report.
//
// system_profiler finds applications through the Spotlight index, so an
// application Spotlight has not indexed is missing from its output. That
// happens on real machines, not only on broken ones: excluding a folder from
// Spotlight, a rebuilding index, or an index that never caught up leaves
// widely deployed applications (office suites, chat and video-conferencing
// clients, container runtimes, App Store apps) out of the inventory. Listing
// the folders directly does not depend on the index.
//
// Only what the bundle itself says is available here, so entries are named
// after their directory name without .app, which is what system_profiler
// reports for nearly every application, and carry no signer or architecture.
// Symbolic links are skipped: Safari's /Applications entry is a link into a
// cryptex, which cryptexApplications already covers, and any other link points
// at a bundle that is reported where it lives.
func folderApplications(conn shared.Connection, reported []sysProfilerItem) []sysProfilerItem {
	if conn == nil {
		return nil
	}
	fs := conn.FileSystem()

	seen := make(map[string]struct{}, len(reported))
	for _, entry := range reported {
		if entry.Path != "" {
			seen[filepath.Clean(entry.Path)] = struct{}{}
		}
	}

	folders := append([]string{}, applicationFolders...)
	if users, err := readDirNames(fs, usersRoot); err == nil {
		for _, user := range users {
			if strings.HasPrefix(user, ".") {
				continue
			}
			folders = append(folders, filepath.Join(usersRoot, user, "Applications"))
		}
	}

	var items []sysProfilerItem
	add := func(path string) {
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}

		info, isBundle := readInfoPlist(conn, path)
		if !isBundle {
			return
		}
		name := filepath.Base(path)
		items = append(items, sysProfilerItem{
			Name:     strings.TrimSuffix(name, filepath.Ext(name)),
			Version:  bundleVersionOf(info),
			Path:     path,
			info:     &info,
			isBundle: true,
		})
	}

	for _, folder := range folders {
		entries, err := readDirEntries(fs, folder)
		if err != nil {
			log.Debug().Err(err).Str("path", folder).Msg("could not list application folder")
			continue
		}
		for _, entry := range entries {
			if skipFolderEntry(entry) {
				continue
			}
			path := filepath.Join(folder, entry.Name())
			if isAppBundleName(entry.Name()) {
				add(path)
				continue
			}
			// A subfolder, or a file: listing a file fails and is skipped.
			children, err := readDirEntries(fs, path)
			if err != nil {
				continue
			}
			for _, child := range children {
				if skipFolderEntry(child) || !isAppBundleName(child.Name()) {
					continue
				}
				add(filepath.Join(path, child.Name()))
			}
		}
	}
	return items
}

func isAppBundleName(name string) bool {
	return strings.EqualFold(filepath.Ext(name), ".app")
}

func skipFolderEntry(entry os.FileInfo) bool {
	return strings.HasPrefix(entry.Name(), ".") || entry.Mode()&os.ModeSymlink != 0
}

func readDirEntries(fs afero.Fs, dir string) ([]os.FileInfo, error) {
	f, err := fs.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.Readdir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}
