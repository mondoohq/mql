// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"bufio"
	"errors"
	"io"
	"path"
	"strings"
	"time"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	aptHistoryPath = "/var/log/apt/history.log"

	// aptHistoryTimeLayout is the timestamp apt writes: local time with no
	// zone. apt separates the date from the time with two spaces, so the parser
	// rejoins the fields before matching this layout.
	aptHistoryTimeLayout = "2006-01-02 15:04:05"

	// aptHistoryMaxLine caps a single line. An Upgrade: line names every
	// package in the run on one line, so on a dist-upgrade of a full desktop it
	// runs well past the scanner's default 64 KB. Past the limit the scan stops
	// and the rest of the log is lost, which would silently report an older
	// update as the newest one.
	aptHistoryMaxLine = 4 * 1024 * 1024
)

// aptUpgradeVerbs are the subcommands that upgrade whatever the configured
// repositories offer. A run driven by one of them is an operating system patch
// run: it is not aimed at a package the operator named.
var aptUpgradeVerbs = map[string]struct{}{
	"upgrade":      {},
	"dist-upgrade": {},
	"full-upgrade": {},
	"safe-upgrade": {}, // aptitude's spelling
}

// aptTargetedVerbs are the subcommands aimed at packages the operator named.
// `apt install curl` moves installed software, and dpkg records it exactly the
// way it records a security upgrade, but it says nothing about patch state.
// Their presence disqualifies a run outright, even alongside an upgrade verb.
var aptTargetedVerbs = map[string]struct{}{
	"install":          {},
	"reinstall":        {},
	"remove":           {},
	"purge":            {},
	"autoremove":       {},
	"autopurge":        {},
	"build-dep":        {},
	"download":         {},
	"source":           {},
	"deselect-upgrade": {},
}

// lastInstalledDebian reads the newest operating system patch run apt recorded.
// Every source is a file read, so this answers the same way on a running host
// and on a mounted filesystem.
func lastInstalledDebian(conn shared.Connection) (*LastInstalledUpdate, error) {
	return lastInstalledDebianFS(conn.FileSystem(), assetTimeZone(conn))
}

// lastInstalledDebianFS is lastInstalledDebian's filesystem-only body, split out
// so the rotation walk can be exercised against an in-memory filesystem.
//
// Only apt's own history answers here. dpkg.log records the same package
// operations but carries neither the invoking command nor a repository, so it
// cannot tell an operator's `apt install` from a security upgrade; under a
// field that means "operating system patch" it would answer a different
// question, so a host whose apt history has rotated away reads null. The walk
// itself fails closed: a rotation that exists but cannot be read, or whose
// newest patch run never completed, nulls the answer rather than letting an
// older record stand in for the missing one (see walkRotatedLogs).
func lastInstalledDebianFS(fs afero.Fs, loc *time.Location) (*LastInstalledUpdate, error) {
	return walkRotatedLogs(fs, aptHistoryPath, func(r io.Reader) (*LastInstalledUpdate, bool, error) {
		return ParseAptHistory(r, loc)
	})
}

// ParseAptHistory returns the newest completed apt run that patched the
// operating system, timestamped by its End-Date.
//
// A run qualifies when all of these hold:
//
//   - it installed, upgraded or reinstalled something (a removal-only run is
//     not a patch),
//   - it carries no Error: line (a run that reported an error did not patch),
//   - its Commandline: is an upgrade of the configured repositories rather
//     than an operation on packages the operator named,
//   - and it closed with a parseable End-Date. apt writes the End-Date last,
//     so it is the evidence the transaction completed, and it is the returned
//     timestamp: the Start-Date says when a run began, not when the packages
//     were in place.
//
// The newest qualifying run wins regardless of its kind. An unattended-upgrades
// run from last month does not outrank an operator's dist-upgrade from
// yesterday; the source reports which one answered.
//
// stop reports that the newest qualifying run has no valid End-Date: the run
// was killed, or the log tail is partially written. Either way the newest
// relevant evidence is unusable, so the caller must answer null rather than
// let an older run, or an older rotation, stand in for it. A dangling
// non-qualifying block (a killed `apt install`) does not stop anything: it
// would not have counted even completed.
//
// A block looks like:
//
//	Start-Date: 2026-05-09  14:17:19
//	Commandline: apt-get dist-upgrade
//	Upgrade: libpam-modules:arm64 (1.5.3-5ubuntu5, 1.5.3-5ubuntu5.5)
//	End-Date: 2026-05-09  14:17:20
func ParseAptHistory(r io.Reader, loc *time.Location) (*LastInstalledUpdate, bool, error) {
	var newest *LastInstalledUpdate
	newestIncomplete := false

	// Per-block state. started gates on Start-Date so a fragment at the top of
	// a truncated file (keys with no opening line) cannot qualify.
	var end time.Time
	var source string
	started, changed, failed, haveEnd := false, false, false, false

	// Blocks are appended in transaction order, so the last qualifying block
	// is the newest relevant run and each one overwrites the outcome of those
	// before it: a completed run answers, an incomplete one voids the answer.
	flush := func() {
		if started && changed && !failed && source != "" {
			if haveEnd {
				newest = &LastInstalledUpdate{Time: end.UTC(), Source: source}
				newestIncomplete = false
			} else {
				newest = nil
				newestIncomplete = true
			}
		}
		end = time.Time{}
		source = ""
		started, changed, failed, haveEnd = false, false, false, false
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), aptHistoryMaxLine)
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), ":")
		if !ok {
			continue
		}

		switch key {
		case "Start-Date":
			// A block without an End-Date (the run was killed) still opens the
			// next one, so flush on Start-Date as well as on End-Date.
			flush()
			started = true
		case "Commandline":
			source = classifyAptCommandline(value)
		case "Install", "Upgrade", "Reinstall":
			if strings.TrimSpace(value) != "" {
				changed = true
			}
		case "Error":
			failed = true
		case "End-Date":
			if t, err := parseAptTime(value, loc); err == nil {
				end, haveEnd = t, true
			}
			flush()
		}
	}
	if err := scanner.Err(); err != nil {
		// A line past the cap or a read failure mid-file (a truncated gzip
		// body decompresses exactly this way) means the rest of the log is
		// lost. What was parsed so far cannot be trusted to contain the
		// newest run, so no answer survives.
		return nil, false, err
	}
	flush()

	return newest, newestIncomplete, nil
}

// unattendedUpgradeExecutables are the names the unattended-upgrades
// executable goes by. Its command line names no subcommand at all, so the
// executable itself is the evidence.
var unattendedUpgradeExecutables = map[string]struct{}{
	"unattended-upgrade":  {},
	"unattended-upgrades": {},
}

// classifyAptCommandline reports which source constant an apt run's command
// line earns, or "" when the run is not an operating system patch.
//
// It matches whole tokens rather than searching the string, so an operator
// installing a package whose name contains an apt subcommand (`apt-get install
// upgrade-helper`) is still read as the targeted install it is. Scanning every
// token instead of locating "the verb" keeps option values from being mistaken
// for one: `apt-get -o Dpkg::Options::=--force-confdef upgrade` carries a
// non-flag token before the subcommand.
//
// Targeted verbs disqualify before anything else is considered, and
// unattended-upgrades is recognized only as the executable (the first token,
// by its basename so an absolute path still matches). Together those keep
// `apt-get install unattended-upgrades` read as the install it is: the
// package name is an argument, not the program that ran.
//
// A block with no Commandline: at all cannot be attributed and earns "". Some
// apt front ends write none, which costs their runs; that is the conservative
// direction, because the alternative is counting an install as a patch.
func classifyAptCommandline(cmdline string) string {
	tokens := strings.Fields(cmdline)
	if len(tokens) == 0 {
		return ""
	}

	for _, token := range tokens {
		if _, ok := aptTargetedVerbs[token]; ok {
			return ""
		}
	}

	if _, ok := unattendedUpgradeExecutables[path.Base(tokens[0])]; ok {
		return LastUpdateSourceAptSecurity
	}

	for _, token := range tokens {
		if _, ok := aptUpgradeVerbs[token]; ok {
			return LastUpdateSourceAptHistory
		}
	}
	return ""
}

// parseAptTime reads the timestamp apt writes, tolerating the single-space and
// double-space separators both spellings use.
func parseAptTime(value string, loc *time.Location) (time.Time, error) {
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return time.Time{}, errors.New("not an apt timestamp: " + value)
	}
	if loc == nil {
		loc = time.UTC
	}
	return time.ParseInLocation(aptHistoryTimeLayout, fields[0]+" "+fields[1], loc)
}
