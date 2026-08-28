// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"errors"
	"io"
	"io/fs"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/date"
	"go.mondoo.com/mql/providers/os/resources/logrotate"
)

// Sources a last-installed-update timestamp can come from, reported verbatim
// through os.lastUpdateSource.
//
// Every one of them names an exact, completed install event that could be
// attributed to the operating system vendor. A record that cannot carry that
// attribution is not a weaker source, it is not a source: dpkg.log names no
// repository and no command, rpm's %{INSTALLTIME} cannot tell an upgrade from
// an operator installing a package for the first time, and the mtime of the
// dpkg status file does not even say whether the change was an install. All of
// them read null rather than answering a different question than the one
// asked.
//
// They differ in how tightly the attribution holds, which is why they stay
// distinct rather than collapsing into one string. A policy that only accepts a
// vendor security channel can require LastUpdateSourceAptSecurity, while a
// looser one takes any non-null answer.
const (
	// LastUpdateSourceDnfRpmLog is the newest package upgrade dnf recorded in
	// its rpm transaction log for a package carrying an operating system
	// vendor's %{VENDOR}. The log is what separates an upgrade from a
	// first-time install; the rpm database alone records only an install
	// time, which reads the same for both.
	LastUpdateSourceDnfRpmLog = "dnf-rpm-log"
	// LastUpdateSourceAptSecurity is a completed unattended-upgrades run. Its
	// default Allowed-Origins is the distribution's -security pocket, which
	// makes it the closest an asset comes to recording "this was a vendor
	// security advisory" without an external advisory database.
	LastUpdateSourceAptSecurity = "apt-security"
	// LastUpdateSourceAptHistory is a completed operator-run full upgrade
	// (apt upgrade, dist-upgrade, full-upgrade). Vendor packages are what
	// such a run overwhelmingly moves, but it can also carry a third-party
	// repository, so it ranks below the security channel.
	LastUpdateSourceAptHistory = "apt-history"
	// LastUpdateSourceMacosHistory is the newest macOS operating system or
	// security update in /Library/Receipts/InstallHistory.plist.
	LastUpdateSourceMacosHistory = "macos-install-history"
	// LastUpdateSourceWindowsUpdate is the newest Windows Update Agent history
	// entry for an operating system product.
	LastUpdateSourceWindowsUpdate = "windows-update-agent"
)

// lastUpdateSkewTolerance is how far into the future an install timestamp may
// read and still be believed. It absorbs ordinary clock drift between the
// scanned asset and whichever clock stamped the record; anything past it is a
// skewed clock or a misread timezone, and reporting such a time would make an
// asset of unknown patch state look freshly patched. Five minutes covers NTP
// level drift while staying far below the smallest timezone misread (30
// minutes), so a zone problem cannot hide inside the tolerance.
const lastUpdateSkewTolerance = 5 * time.Minute

// LastInstalledUpdate is the most recent operating system update install a
// platform records.
type LastInstalledUpdate struct {
	// Time the update was installed, always in UTC.
	Time time.Time
	// Source is one of the LastUpdateSource* constants.
	Source string
}

// ValidateLastInstalledUpdate is the one gate every resolved timestamp passes
// before any field reads it. A zero time and a time materially in the future
// (past lastUpdateSkewTolerance) are both rejected, turning the update into
// nil so lastUpdate, lastUpdateAge and lastUpdateSource all read null
// together. Without this a future timestamp would stay visible through
// lastUpdate while its age clamps to zero, making the asset appear patched
// moments ago on the strength of a broken clock.
func ValidateLastInstalledUpdate(update *LastInstalledUpdate, now time.Time) *LastInstalledUpdate {
	if update == nil {
		return nil
	}
	if update.Time.IsZero() {
		return nil
	}
	if update.Time.After(now.Add(lastUpdateSkewTolerance)) {
		log.Debug().Time("installed", update.Time).Str("source", update.Source).
			Msg("mql[os.lastUpdate]> dropping update install recorded in the future")
		return nil
	}
	return update
}

// ResolveLastInstalledUpdate reads the newest operating system update install
// recorded by the asset's own update mechanism. It covers the platforms whose
// record lives in a file the connection can read on its own: the apt history
// log on Debian, and the install history plist on macOS. rpm-based platforms
// and Windows are resolved by the os resource instead, because both need a
// resource the runtime has likely cached (`packages` carries %{VENDOR} for
// every rpm, which attributes dnf's log lines to the OS vendor, and
// `windows.update` carries the update agent history).
//
// A platform that keeps no attributable record is not an error: the result is
// nil and os.lastUpdate reads null. A fleet query has to stay usable on the
// platforms it does not cover.
func ResolveLastInstalledUpdate(conn shared.Connection) (*LastInstalledUpdate, error) {
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return nil, nil
	}

	switch {
	case asset.Platform.IsFamily("debian"):
		return lastInstalledDebian(conn)
	case asset.Platform.Name == "macos":
		return lastInstalledMacos(conn)
	}
	return nil, nil
}

// walkRotatedLogs reads a log and its logrotate copies newest-first, handing
// each to parse until one yields an answer.
//
// The walk fails closed. Only a genuinely missing file moves it on to the
// next rotation; a file that exists but cannot be opened or read (a
// permission problem, a corrupt or truncated gzip, a line past the scanner's
// cap) ends the walk with no answer instead. At that point the newest
// evidence is unreadable, and reading on would report whatever older event
// the next rotation holds as the newest one: a stale answer dressed as a
// fresh one. The same reasoning applies when parse reports stop: it has seen
// the newest relevant record and found it unusable (an apt run with no
// End-Date), so an older rotation must not answer for it.
func walkRotatedLogs(logFS afero.Fs, base string, parse func(io.Reader) (*LastInstalledUpdate, bool, error)) (*LastInstalledUpdate, error) {
	for _, path := range logrotate.Paths(base, logrotate.DefaultMaxRotations) {
		f, err := logrotate.Open(logFS, path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			log.Debug().Err(err).Str("path", path).
				Msg("mql[os.lastUpdate]> newest update log exists but cannot be read, reporting no answer")
			return nil, nil
		}
		update, stop, err := parse(f)
		f.Close()
		if err != nil {
			log.Debug().Err(err).Str("path", path).
				Msg("mql[os.lastUpdate]> newest update log cannot be parsed, reporting no answer")
			return nil, nil
		}
		if update != nil {
			return update, nil
		}
		if stop {
			return nil, nil
		}
	}
	return nil, nil
}

// assetTimeZone returns the zone the Debian update logs are read in. apt writes
// local time with no offset, so the zone has to come from somewhere other than
// the log itself.
//
// It comes from the asset: /etc/localtime, /etc/timezone and the rest, all read
// through the connection's filesystem, so a mounted snapshot answers as well as
// a running host. That matters more than it first appears, because the machine
// scanning a snapshot is rarely in the zone of the machine it came from, and
// reading the log in the scanner's zone would shift every timestamp by that
// offset.
//
// An asset carrying no zone information at all falls back to UTC, not to the
// scanner's zone. A Unix system with neither /etc/localtime nor /etc/timezone
// runs in UTC, so UTC is a fact about the asset where the scanner's zone is
// only ever a guess about it.
func assetTimeZone(conn shared.Connection) *time.Location {
	if loc := date.LocationFromFS(conn.FileSystem()); loc != nil {
		return loc
	}
	return time.UTC
}
