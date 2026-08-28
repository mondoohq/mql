// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"bytes"
	"io"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"howett.net/plist"
)

const (
	macosInstallHistoryPath = "/Library/Receipts/InstallHistory.plist"

	// macosConfigDataContentType marks the XProtect, MRT and Gatekeeper data
	// blobs that softwareupdated installs on its own schedule, often weekly.
	// They are not operating system updates, and counting them would report a
	// Mac months behind on macOS as having been patched days ago.
	macosConfigDataContentType = "config-data"

	// macosOSUpdatePackagePrefix is the receipt identifier prefix Apple gives
	// operating system and security updates (com.apple.pkg.update.os.26.5.2,
	// com.apple.pkg.update.os.SecUpd2022-004Catalina.16U4232). An identifier
	// is the strongest evidence an entry carries: unlike a display name it is
	// a machine-facing key, not marketing copy.
	macosOSUpdatePackagePrefix = "com.apple.pkg.update.os"
)

// macosSoftwareUpdateProcesses are the processes that install an update through
// Software Update. Everything else in the install history is a third-party
// package handed to installer(8), which says nothing about OS patch state.
var macosSoftwareUpdateProcesses = map[string]struct{}{
	"softwareupdated": {},
	"softwareupdate":  {},
}

// macosOSUpdateNamePrefixes are the display names the OS update channel uses:
// version updates ("macOS 26.5.2", "macOS Sonoma 14.4.1"), the standalone
// security updates of older releases ("Security Update 2022-004"), and Rapid
// Security Responses ("macOS Security Response 13.4.1 (a)"). A matching name
// must also carry a digit, so a bare product name cannot slip through.
//
// This is an allow list, not a deny list, because Software Update installs
// far more than the operating system: Rosetta, the Xcode command line tools,
// dictation and speech assets, config data. Any of those landing after the
// last real update would report a stale Mac as freshly patched, so a name
// this list does not recognize does not count, even when Apple delivered it.
var macosOSUpdateNamePrefixes = []string{
	"macOS ",
	"Security Update ",
	"Rapid Security Response",
}

func lastInstalledMacos(conn shared.Connection) (*LastInstalledUpdate, error) {
	f, err := conn.FileSystem().Open(macosInstallHistoryPath)
	if err != nil {
		// A Mac that has never installed anything through Software Update has
		// no history file. That is an absent record, not a failure.
		return nil, nil
	}
	defer f.Close()

	t, ok, err := ParseMacosInstallHistory(f)
	if err != nil {
		// A history that exists but cannot be decoded is unknown patch state,
		// and unknown reads null: one corrupt plist must not fail a fleet
		// query. Log it, because without that a damaged file looks identical
		// to a Mac that genuinely has no update history.
		log.Debug().Err(err).
			Msg("mql[os.lastUpdate]> macOS install history cannot be parsed, reporting no answer")
		return nil, nil
	}
	if !ok {
		return nil, nil
	}
	return &LastInstalledUpdate{Time: t, Source: LastUpdateSourceMacosHistory}, nil
}

type macosInstallHistoryEntry struct {
	Date               time.Time `plist:"date"`
	DisplayName        string    `plist:"displayName"`
	DisplayVersion     string    `plist:"displayVersion"`
	ProcessName        string    `plist:"processName"`
	ContentType        string    `plist:"contentType"`
	PackageIdentifiers []string  `plist:"packageIdentifiers"`
}

// ParseMacosInstallHistory returns the date of the newest macOS operating
// system or security update in /Library/Receipts/InstallHistory.plist. Dates
// in the plist are UTC.
//
// Only positive evidence counts. An entry qualifies when Software Update
// installed it and it identifies itself as an OS update: by a
// com.apple.pkg.update.os receipt identifier when it carries one, or by a
// display name the OS update channel uses. Everything else Software Update
// delivers (Rosetta, the Xcode command line tools, XProtect and other config
// data, and any Apple product this code does not recognize) is not evidence
// macOS was patched, so a history holding only such entries reads as no
// record rather than as a wrong date.
func ParseMacosInstallHistory(input io.Reader) (time.Time, bool, error) {
	r, err := plistReadSeeker(input)
	if err != nil {
		return time.Time{}, false, err
	}

	var entries []macosInstallHistoryEntry
	if err := plist.NewDecoder(r).Decode(&entries); err != nil {
		return time.Time{}, false, err
	}

	var newest time.Time
	for i := range entries {
		e := entries[i]
		if _, ok := macosSoftwareUpdateProcesses[e.ProcessName]; !ok {
			continue
		}
		if e.ContentType == macosConfigDataContentType {
			continue
		}
		if !isMacosOSUpdate(e) {
			continue
		}
		if e.Date.After(newest) {
			newest = e.Date
		}
	}

	if newest.IsZero() {
		return time.Time{}, false, nil
	}
	return newest.UTC(), true, nil
}

// isMacosOSUpdate reports whether an install-history entry is positively
// identifiable as a macOS operating system or security update. The receipt
// identifiers are checked first because they are the stabler signal; an entry
// carrying none falls back to the display-name allow list.
func isMacosOSUpdate(e macosInstallHistoryEntry) bool {
	for _, id := range e.PackageIdentifiers {
		if strings.HasPrefix(id, macosOSUpdatePackagePrefix) {
			return true
		}
	}

	name := strings.TrimSpace(e.DisplayName)
	if !strings.ContainsAny(name, "0123456789") {
		return false
	}
	for _, prefix := range macosOSUpdateNamePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// plistReadSeeker gives the plist decoder the seekable reader it needs. A file
// opened from the connection's filesystem already seeks; a command's stdout
// does not, so it is buffered in memory first.
func plistReadSeeker(input io.Reader) (io.ReadSeeker, error) {
	if r, ok := input.(io.ReadSeeker); ok {
		return r, nil
	}
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}
