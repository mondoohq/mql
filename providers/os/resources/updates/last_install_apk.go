// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"bufio"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/afero"
)

const (
	// apkLogPath is apk-tools' transaction log. apk-tools 3 (Alpine 3.23 and
	// later) appends one block to it for every invocation that opens the
	// package database for writing:
	//
	//	Running `apk upgrade` at 2026-09-28 06:10:04
	//	apk-tools 3.0.8-r0, compiled for x86_64.
	//	(1/1) Upgrading jq (1.8.1-r0 -> 1.8.2-r0)
	//	OK: 129.7 MiB in 208 packages
	//
	// apk-tools 2 (Alpine 3.22 and earlier) writes no such log. A host on
	// those releases can still carry one, written by the apk-tools 3 that
	// bootstrapped the image, but it only ever holds the bootstrap install.
	apkLogPath = "/var/log/apk.log"

	// apkLogTimeLayout is the timestamp on a Running line. apk-tools formats
	// it with gmtime_r, so it is UTC regardless of the asset's zone.
	apkLogTimeLayout = "2006-01-02 15:04:05"

	// apkLogMaxLine caps a single line. A Running line carries the full
	// argument vector, which for an image bootstrap names every package.
	apkLogMaxLine = 1024 * 1024
)

// apkRunningLine matches the line that opens every apk.log block and captures
// the command line and its UTC timestamp.
var apkRunningLine = regexp.MustCompile("^Running `(.*)` at (\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})$")

// apkUpgradingLine matches a package moving to a newer build: `(1/5) Upgrading
// name (old -> new)`. apk writes Upgrading only when the incoming version
// compares greater than the installed one; an equal build is Replacing, a
// lower one Downgrading, and neither moves the asset forward.
var apkUpgradingLine = regexp.MustCompile(`^\(\s*\d+/\d+\) Upgrading `)

// apkErrorSummary matches the summary apk writes in place of "OK:" when any
// change in the transaction failed: `1 error; ...` or `3 errors; ...`.
var apkErrorSummary = regexp.MustCompile(`^\d+ errors?;`)

// apkTargetedApplets are the apk applets that act on packages the operator
// named rather than on whatever the configured repositories offer. `apk add
// jq` can print Upgrading lines for dependencies it pulls forward, but the run
// was an install, not an operating system patch run, so it never counts.
var apkTargetedApplets = map[string]struct{}{
	"add": {},
	"del": {},
	"fix": {},
}

// apkNarrowUpgradeFlags restrict `apk upgrade` to apk-tools itself. Such a run
// is not an upgrade of the system.
var apkNarrowUpgradeFlags = map[string]struct{}{
	"--self-upgrade-only": {},
	"--preupgrade-only":   {},
}

// lastInstalledApkFS reads the newest completed `apk upgrade` run from
// apk-tools' transaction log and its logrotate copies.
//
// Only the log answers. The mtime of /lib/apk/db/installed moves on every
// write to the package database, so `apk add jq` advances it exactly as an
// upgrade does, and it cannot say which one happened. A host whose apk-tools
// keeps no log (apk-tools 2), whose upgrades pass --no-logfile, or whose log
// has rotated away reads null.
func lastInstalledApkFS(fs afero.Fs) (*LastInstalledUpdate, error) {
	return walkRotatedLogs(fs, apkLogPath, ParseApkLog)
}

// ParseApkLog returns the newest completed apk upgrade run, timestamped by its
// Running line.
//
// A block qualifies when all of these hold:
//
//   - its command line runs the upgrade applet and no targeted applet (see
//     classifyApkCommandline),
//   - it upgraded at least one package (a run with nothing to upgrade is not
//     an install event),
//   - and it closed with apk's "OK:" summary. A run that reports errors did
//     not patch cleanly and does not count.
//
// The Running line is the only timestamp apk writes, so the returned time is
// when the run started, not when it finished; apk records no end time. A
// simulated run (`apk upgrade --simulate`) opens the database read-only and
// writes nothing to the log, so it cannot be mistaken for a real one.
//
// stop reports that the newest qualifying run never wrote a summary line: apk
// was killed, or is running right now. The newest relevant evidence is then
// unusable, and an older run, or an older rotation, must not stand in for it.
func ParseApkLog(r io.Reader) (*LastInstalledUpdate, bool, error) {
	var newest *LastInstalledUpdate
	newestIncomplete := false

	var start time.Time
	started, upgradeRun, changed, ok, failed := false, false, false, false, false

	flush := func() {
		if started && upgradeRun && changed && !failed {
			if ok {
				newest = &LastInstalledUpdate{Time: start, Source: LastUpdateSourceApkLog}
				newestIncomplete = false
			} else {
				newest = nil
				newestIncomplete = true
			}
		}
		start = time.Time{}
		started, upgradeRun, changed, ok, failed = false, false, false, false, false
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), apkLogMaxLine)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Running `") {
			// Every Running line closes the block before it, even one this
			// parser cannot read, so its changes never leak into that block.
			flush()
			m := apkRunningLine.FindStringSubmatch(line)
			if m == nil {
				// A block whose start cannot be read cannot be evidence.
				continue
			}
			t, err := time.ParseInLocation(apkLogTimeLayout, m[2], time.UTC)
			if err != nil {
				continue
			}
			start = t
			started = true
			upgradeRun = classifyApkCommandline(m[1])
			continue
		}
		if !started {
			continue
		}

		// The summary is judged only once a package has moved: apk writes
		// it after the last change, so a summary line ahead of that (the
		// repository refresh `apk -U upgrade` runs first) says nothing about
		// the transaction. ERROR: lines are not judged at all, because a
		// failure that stops the transaction before it changes anything
		// leaves no Upgrading line, and one that happens during it is counted
		// in the summary.
		switch {
		case apkUpgradingLine.MatchString(line):
			changed = true
		case changed && strings.HasPrefix(line, "OK:"):
			ok = true
		case changed && apkErrorSummary.MatchString(line):
			failed = true
		}
	}
	if err := scanner.Err(); err != nil {
		// The rest of the log is lost, and with it possibly the newest run.
		return nil, false, err
	}
	flush()

	return newest, newestIncomplete, nil
}

// classifyApkCommandline reports whether an apk command line is an upgrade of
// the configured repositories.
//
// It matches whole tokens rather than locating "the applet", because apk's
// global options can take a value before it (`apk --root /mnt upgrade`,
// `apk -X <url> upgrade`). A targeted applet anywhere disqualifies, which keeps
// `apk add upgrade-helper` read as the install it is. `apk upgrade openssl`
// counts, the same way `apt upgrade openssl` does.
func classifyApkCommandline(cmdline string) bool {
	tokens := strings.Fields(cmdline)
	if len(tokens) < 2 {
		return false
	}

	upgrade := false
	for _, token := range tokens[1:] {
		if _, ok := apkTargetedApplets[token]; ok {
			return false
		}
		if _, ok := apkNarrowUpgradeFlags[token]; ok {
			return false
		}
		if token == "upgrade" {
			upgrade = true
		}
	}
	return upgrade
}
