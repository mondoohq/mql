// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/resources/logrotate"
)

const (
	dpkgLogPath = "/var/log/dpkg.log"

	// dpkgLogTimeLayout is the timestamp dpkg writes: local time with no zone,
	// one space between the date and the time.
	dpkgLogTimeLayout = "2006-01-02 15:04:05"
)

// DpkgInstallDates maps a package to the time its currently installed version
// was placed on the asset.
//
// The key is the package token as dpkg.log writes it, joined to the version, so
// a multi-arch asset carrying the same name for two architectures keeps two
// answers. Lookup goes through Get, which knows both spellings.
type DpkgInstallDates map[string]time.Time

func dpkgInstallDateKey(pkg, version string) string {
	return pkg + "\x00" + version
}

// Get returns the install time recorded for a package version, and whether one
// was found. The architecture-qualified token is tried first, because that is
// what dpkg writes on a multi-arch asset; the bare name covers the older logs
// that predate the qualification.
func (d DpkgInstallDates) Get(name, arch, version string) (time.Time, bool) {
	if len(d) == 0 {
		return time.Time{}, false
	}
	if arch != "" {
		if t, ok := d[dpkgInstallDateKey(name+":"+arch, version)]; ok {
			return t, true
		}
	}
	t, ok := d[dpkgInstallDateKey(name, version)]
	return t, ok
}

// ParseDpkgInstallDates reads the times dpkg recorded for the package versions
// in one dpkg.log stream.
//
// Two line shapes carry a version landing on the asset:
//
//	2026-05-01 09:14:12 install curl:amd64 <none> 8.5.0-2ubuntu10.6
//	2026-05-04 03:22:07 upgrade libpam-modules:amd64 1.5.3-5ubuntu5 1.5.3-5ubuntu5.5
//	2026-05-01 09:14:13 status installed curl:amd64 8.5.0-2ubuntu10.6
//
// The install and upgrade actions name the version being moved to in the last
// field; the `status installed` line is the one dpkg writes once a package is
// fully configured. Recording both means a run interrupted before configuration
// still yields a date, and keying on the version means a `status installed`
// emitted by trigger processing cannot advance the date of a package that did
// not actually change.
//
// Removals, purges, triggers and startup lines carry no version landing and are
// skipped. Later entries win, so the map holds the most recent time each
// version was placed.
//
// A stream that cannot be read to its end returns what was parsed alongside
// the error. Every entry read is a true placement event, so the partial map is
// worth keeping; the error is the caller's signal that anything older than
// this stream can no longer be trusted to be the newest record (see
// ReadDpkgInstallDates).
func ParseDpkgInstallDates(r io.Reader, loc *time.Location, into DpkgInstallDates) (DpkgInstallDates, error) {
	if into == nil {
		into = DpkgInstallDates{}
	}
	if loc == nil {
		loc = time.UTC
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, dpkgMaxLine)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		var pkg, version string
		switch fields[2] {
		case "install", "upgrade":
			pkg, version = fields[3], fields[5]
		case "status":
			if fields[3] != "installed" {
				continue
			}
			pkg, version = fields[4], fields[5]
		default:
			continue
		}
		if pkg == "" || version == "" || version == "<none>" {
			continue
		}

		t, err := time.ParseInLocation(dpkgLogTimeLayout, fields[0]+" "+fields[1], loc)
		if err != nil {
			continue
		}

		key := dpkgInstallDateKey(pkg, version)
		if existing, ok := into[key]; !ok || t.After(existing) {
			into[key] = t.UTC()
		}
	}

	return into, scanner.Err()
}

// ReadDpkgInstallDates walks dpkg.log and its logrotate copies newest-first and
// returns the install times they record.
//
// Coverage is bounded by what logrotate has kept, which distributions ship as
// twelve monthly copies. A package that has not been touched inside that window
// carries no date and its installDate stays null - unknown, which is what it
// was before, rather than a wrong answer. The packages an audit cares about are
// the ones that moved recently, and those are the ones the retained logs hold.
//
// The walk fails closed the way the last-update readers do: only a genuinely
// missing file moves it to the next rotation. A rotation that exists but
// cannot be opened or read to its end (a permission problem, a corrupt or
// truncated gzip) ends the walk instead. The dates already collected came from
// newer logs and stay; older rotations are not consulted, because a package
// whose newest placement sat inside the unreadable log would otherwise be
// dated by an older placement of the same version: a stale answer where null
// is the honest one.
func ReadDpkgInstallDates(logFS afero.Fs, loc *time.Location) DpkgInstallDates {
	dates := DpkgInstallDates{}
	if logFS == nil {
		return dates
	}

	for _, path := range logrotate.Paths(dpkgLogPath, logrotate.DefaultMaxRotations) {
		f, err := logrotate.Open(logFS, path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			log.Debug().Err(err).Str("path", path).
				Msg("mql[packages]> dpkg log rotation exists but cannot be read, skipping older rotations")
			break
		}
		_, err = ParseDpkgInstallDates(f, loc, dates)
		f.Close()
		if err != nil {
			log.Debug().Err(err).Str("path", path).
				Msg("mql[packages]> dpkg log rotation cannot be read to its end, skipping older rotations")
			break
		}
	}
	return dates
}
