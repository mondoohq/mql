// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"debug/macho"
	"encoding/binary"
	"errors"
	"io"
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

// machoHeaderPrefix bounds how much of an executable is read to find its
// architectures. A universal binary lists its slices in a header of 8 bytes
// plus 20 (or 32) per slice, a thin binary names its CPU in the first 8 bytes,
// so this is far more than enough, and the executable itself, which can be
// hundreds of megabytes, is never read.
const machoHeaderPrefix = 4096

// maxFatArches caps the slice count read from a universal header. Real
// binaries carry two or three; the cap keeps a file that merely starts with
// the universal magic (a Java class file shares it) from being read as one.
const maxFatArches = 16

// appArchitecture reports the architecture of an application: the one its
// main executable was built for, read from the executable's Mach-O header.
// The executable is Contents/MacOS/<CFBundleExecutable>.
//
// The answer never depends on the machine the application is installed on or
// on how the application was found, so the same bundle reports the same
// architecture whether system_profiler, the application folder listing, or
// the cryptex scan found it. Values:
//
//	universal  arm64 (or arm64e) and x86_64 slices
//	arm64      arm64 or arm64e only
//	x86_64     x86_64 only, which on Apple Silicon runs under Rosetta
//	""         anything else: a script launcher, a binary for another CPU
//
// When the executable cannot be read, system_profiler's arch_kind stands in
// (see archFromArchKind). When neither answers, the architecture is empty:
// the host's architecture says nothing about the application's.
func appArchitecture(conn shared.Connection, entry *sysProfilerItem, info infoPlist) string {
	if info.Executable != "" && entry.Path != "" {
		exe := filepath.Join(entry.Path, "Contents", "MacOS", info.Executable)
		if arch, ok := executableArch(conn, exe); ok {
			return arch
		}
	}
	return archFromArchKind(entry.ArchKind)
}

// executableArch reads the architecture of the executable at path. The second
// return value is false when the file could not be read, so the caller can use
// another source. A file that was read but is not a Mach-O executable, such as
// a shell script launcher, is answered with an empty architecture.
func executableArch(conn shared.Connection, path string) (string, bool) {
	if conn == nil {
		return "", false
	}
	f, err := conn.FileSystem().Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open application executable")
		return "", false
	}
	defer f.Close()

	header := make([]byte, machoHeaderPrefix)
	n, err := io.ReadFull(f, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		log.Debug().Err(err).Str("path", path).Msg("could not read application executable")
		return "", false
	}
	return machoArch(header[:n]), true
}

// machoArch reads the CPU types from a Mach-O header, thin or universal, and
// maps them to an architecture. It returns "" for anything that is not a
// Mach-O header or names no CPU it maps.
func machoArch(header []byte) string {
	cpus, ok := machoCPUs(header)
	if !ok {
		return ""
	}
	var arm, intel bool
	for _, cpu := range cpus {
		switch cpu {
		case macho.CpuArm64:
			arm = true
		case macho.CpuAmd64:
			intel = true
		}
	}
	switch {
	case arm && intel:
		return MacosArchUniversal
	case arm:
		return "arm64"
	case intel:
		return "x86_64"
	default:
		return ""
	}
}

// machoCPUs returns the CPU type of every slice a Mach-O header describes.
func machoCPUs(header []byte) ([]macho.Cpu, bool) {
	if len(header) < 8 {
		return nil, false
	}
	// A universal header is always big-endian.
	switch binary.BigEndian.Uint32(header) {
	case macho.MagicFat:
		return fatCPUs(header, 20)
	case magicFat64:
		return fatCPUs(header, 32)
	}
	// A thin header is in the byte order of the CPU it was built for.
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		switch order.Uint32(header) {
		case macho.Magic32, macho.Magic64:
			return []macho.Cpu{macho.Cpu(order.Uint32(header[4:]))}, true
		}
	}
	return nil, false
}

// magicFat64 is the universal header magic for slices at 64-bit offsets.
const magicFat64 = 0xcafebabf

// fatCPUs reads the slice table of a universal header. Each entry starts with
// the slice's CPU type, followed by fields this does not need.
func fatCPUs(header []byte, entrySize int) ([]macho.Cpu, bool) {
	count := int(binary.BigEndian.Uint32(header[4:]))
	if count == 0 || count > maxFatArches || len(header) < 8+count*entrySize {
		return nil, false
	}
	cpus := make([]macho.Cpu, 0, count)
	for i := 0; i < count; i++ {
		off := 8 + i*entrySize
		cpus = append(cpus, macho.Cpu(binary.BigEndian.Uint32(header[off:])))
	}
	return cpus, true
}

// archFromArchKind maps system_profiler's arch_kind to an architecture. It
// is only consulted when the executable cannot be read. The values were
// checked against `lipo -archs` on the bundles' executables:
//
//	arch_arm_i64  x86_64 and arm64(e) slices, a universal binary
//	arch_arm      arm64 or arm64e only
//	arch_ios      arm64 only. system_profiler prints "Kind: iOS" for these,
//	              but they are ordinary Mac applications (VLC, Zed, Blender),
//	              not wrapped iPhone apps
//	arch_i64      x86_64 only
//	arch_other    not a Mach-O executable, for example a shell script
//	              launcher, and therefore no architecture
func archFromArchKind(archKind string) string {
	switch archKind {
	case "arch_arm_i64":
		return MacosArchUniversal
	case "arch_arm", "arch_ios":
		return "arm64"
	case "arch_i64":
		return "x86_64"
	default:
		return ""
	}
}

// bundleName names an application after its bundle directory, without the
// .app extension.
func bundleName(path string) string {
	base := filepath.Base(filepath.Clean(path))
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// Package URL qualifiers carried by a macOS application's purl, next to arch.
const (
	PurlQualifierBundleID     = "bundle-id"
	PurlQualifierTeamID       = "team-id"
	PurlQualifierAppStore     = "app-store"
	PurlQualifierInstallScope = "install-scope"
)

// addMacOSPurlQualifiers adds what identifies a macOS application beyond its
// name and version to its purl qualifiers, so a consumer of the purl alone,
// such as an SBOM, gets it too. Each qualifier is present only when it says
// something: bundle-id and team-id when known, app-store only when the App
// Store manages the application, install-scope only for a per-user install.
func addMacOSPurlQualifiers(qualifiers map[string]string, app *MacOSApp, installScope string) {
	if app.BundleID != "" {
		qualifiers[PurlQualifierBundleID] = app.BundleID
	}
	if app.TeamID != "" {
		qualifiers[PurlQualifierTeamID] = app.TeamID
	}
	if app.AppStore {
		qualifiers[PurlQualifierAppStore] = "true"
	}
	if installScope == InstallScopeUser {
		qualifiers[PurlQualifierInstallScope] = InstallScopeUser
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
// Only what the bundle itself says is available here, so these entries carry
// no signer and no Gatekeeper origin. Name and architecture come from the
// bundle for every entry, so they match what system_profiler's entry would
// have reported.
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
		items = append(items, sysProfilerItem{
			Name:     bundleName(path),
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
