// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"bufio"
	"io"
	"strings"
	"time"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/core/resources/versions/rpm"
	"go.mondoo.com/mql/providers/os/resources/logrotate"
)

// dnfRpmLogPath is dnf's rpm transaction log. Each package the transaction
// touches is logged as one line when its element completes:
//
//	2026-02-14T09:30:12+0000 SUBDEBUG Upgrade: openssl-libs-1:3.2.2-6.el9.x86_64
//	2026-02-14T09:30:14+0000 SUBDEBUG Upgraded: openssl-libs-1:3.0.7-27.el9.x86_64
//
// The Upgrade/Upgraded pair records what the rpm database itself cannot: that
// a newer build replaced an older one, rather than a package being installed
// for the first time. %{INSTALLTIME} in the rpm database reads the same for
// both, which is why the database alone is not evidence of an update.
const dnfRpmLogPath = "/var/log/dnf.rpm.log"

// dnfUpgradeActions are the transaction actions that record a package moving
// to a newer build. Upgrade names the incoming build and Upgraded the one it
// replaced; both are written when the element completes, so either is
// evidence of a completed upgrade. Installed is absent (it is written for
// first-time installs, and for a new kernel; see isKernelUpdate), and so are
// Downgrade/Downgraded and Reinstall/Reinstalled, which do not move the asset
// forward.
var dnfUpgradeActions = map[string]struct{}{
	"Upgrade":  {},
	"Upgraded": {},
}

// DnfRpmLogPresent reports whether dnf's rpm transaction log, or any of its
// logrotate copies, exists. It lets a caller skip the cost of building the
// vendor attribution (a full package listing) on platforms that never write
// the log: yum-era RHEL, Photon's tdnf. A probe that cannot
// tell reads as absent, which errs toward null, the same direction the walk
// itself fails.
func DnfRpmLogPresent(fs afero.Fs) bool {
	for _, path := range logrotate.Paths(dnfRpmLogPath, logrotate.DefaultMaxRotations) {
		if ok, _ := afero.Exists(fs, path); ok {
			return true
		}
	}
	return false
}

// LastInstalledRpm reads the newest completed vendor package upgrade from
// dnf's rpm transaction log and its logrotate copies.
//
// The caller supplies the vendor attribution: isVendorPackage reports whether
// a package name belongs to the operating system vendor, which the log lines
// themselves cannot say (they carry a NEVRA and nothing else). With no way to
// attribute a package there is no evidence to read, so a nil predicate
// answers nil.
//
// A platform whose package manager keeps no such log (yum-era RHEL, Photon's
// tdnf) and an asset whose log has rotated away both read nil:
// without transaction evidence there is no way to tell an update from an
// install, and inferring one from install times is exactly the mistake this
// log exists to avoid.
//
// installedVersions returns the versions of a package the rpm database holds,
// which tells a new kernel from a first install; see isKernelUpdate.
func LastInstalledRpm(fs afero.Fs, isVendorPackage func(name string) bool, installedVersions func(name string) []string) (*LastInstalledUpdate, error) {
	if isVendorPackage == nil {
		return nil, nil
	}
	return walkRotatedLogs(fs, dnfRpmLogPath, func(r io.Reader) (*LastInstalledUpdate, bool, error) {
		update, err := ParseDnfRpmLog(r, isVendorPackage, installedVersions)
		return update, false, err
	})
}

// isKernelPackage reports whether a package is one of the kernel's, which
// dnf installs side by side (installonlypkgs) instead of upgrading.
func isKernelPackage(name string) bool {
	return name == "kernel" || strings.HasPrefix(name, "kernel-")
}

// isKernelUpdate reports whether installing version evr of the package name
// is a kernel update. dnf installs a new kernel next to the running one and
// logs it as Installed, never as Upgrade, so a kernel update has to be told
// from a first install some other way: an older version of the same package
// was installed, either still in the rpm database or named elsewhere in the
// transaction record (others). A package that can't be installed twice never
// has an older version next to it, so its installs never count.
func isKernelUpdate(name, evr string, others []string, installedVersions func(name string) []string) bool {
	if !isKernelPackage(name) || evr == "" {
		return false
	}
	if installedVersions != nil {
		others = append(others, installedVersions(name)...)
	}
	var parser rpm.Parser
	for _, other := range others {
		if cmp, err := parser.Compare(evr, other); err == nil && cmp > 0 {
			return true
		}
	}
	return false
}

// rpmNevraEVR returns the [epoch:]version-release of a NEVRA whose name is
// name.
func rpmNevraEVR(nevra, name string) string {
	evra := strings.TrimPrefix(nevra, name+"-")
	if evra == nevra {
		return ""
	}
	if dot := strings.LastIndex(evra, "."); dot > 0 {
		return evra[:dot]
	}
	return evra
}

// ParseDnfRpmLog returns the newest completed package upgrade recorded in a
// dnf rpm transaction log whose package isVendorPackage attributes to the
// operating system vendor.
//
// Only Upgrade/Upgraded lines count, and an Installed line of a new kernel
// (isKernelUpdate). Any other Installed line is an operator adding a package
// (`dnf install vim` on a vendor rpm must not advance the machine's patch
// date), and a line whose timestamp cannot be read cannot be evidence:
// ancient dnf wrote local time with no offset, and reading that as UTC would
// shift the answer by the zone, so such lines are skipped instead of guessed
// at.
func ParseDnfRpmLog(r io.Reader, isVendorPackage func(name string) bool, installedVersions func(name string) []string) (*LastInstalledUpdate, error) {
	type entry struct {
		time   time.Time
		action string
		name   string
		evr    string
	}
	var entries []entry
	// every version of a package the log names, for isKernelUpdate
	versions := map[string][]string{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		timestamp, rest, ok := strings.Cut(scanner.Text(), " ")
		if !ok {
			continue
		}
		level, message, ok := strings.Cut(rest, " ")
		if !ok || level != "SUBDEBUG" {
			continue
		}
		action, nevra, ok := strings.Cut(message, ": ")
		if !ok {
			continue
		}
		nevra = strings.TrimSpace(nevra)
		name := rpmNevraName(nevra)
		if name == "" {
			continue
		}
		evr := rpmNevraEVR(nevra, name)
		if isKernelPackage(name) && evr != "" {
			versions[name] = append(versions[name], evr)
		}
		if _, ok := dnfUpgradeActions[action]; !ok && action != "Installed" {
			continue
		}
		if !isVendorPackage(name) {
			continue
		}
		t, err := parseDnfTime(timestamp)
		if err != nil {
			continue
		}
		entries = append(entries, entry{time: t, action: action, name: name, evr: evr})
	}
	if err := scanner.Err(); err != nil {
		// A line past the scanner's cap or a read failure mid-file means the
		// rest of the log is lost, and with it possibly the newest upgrade.
		return nil, err
	}

	var newest time.Time
	for _, e := range entries {
		if e.action == "Installed" && !isKernelUpdate(e.name, e.evr, versions[e.name], installedVersions) {
			continue
		}
		if e.time.After(newest) {
			newest = e.time
		}
	}

	if newest.IsZero() {
		return nil, nil
	}
	return &LastInstalledUpdate{Time: newest.UTC(), Source: LastUpdateSourceDnfRpmLog}, nil
}

// dnfTimeLayouts are the timestamp spellings dnf has written: RFC 3339, and
// the +0000 form without a colon in the offset. Both carry the zone in the
// timestamp itself, so no external zone is needed (unlike apt's history log).
var dnfTimeLayouts = []string{
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04:05Z07:00",
}

func parseDnfTime(value string) (time.Time, error) {
	var firstErr error
	for _, layout := range dnfTimeLayouts {
		t, err := time.Parse(layout, value)
		if err == nil {
			return t, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return time.Time{}, firstErr
}

// rpmNevraName returns the package name from a NEVRA
// (name-[epoch:]version-release.arch): everything before the second-to-last
// hyphen. The name is the only part of a log line that survives an upgrade
// unchanged, which is what makes it the key for vendor attribution against
// the rpm database.
func rpmNevraName(nevra string) string {
	release := strings.LastIndex(nevra, "-")
	if release <= 0 {
		return ""
	}
	version := strings.LastIndex(nevra[:release], "-")
	if version <= 0 {
		return ""
	}
	return nevra[:version]
}
