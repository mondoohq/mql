// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/providers/os/resources/date"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

const (
	DpkgPkgFormat = "deb"
)

// dpkgMaxLine caps how long a single line of a dpkg control stream may be. The
// Depends and Conffiles lines of a metapackage are the long ones, and they grow
// with the number of packages a distribution ships.
const dpkgMaxLine = 4 * 1024 * 1024

var (
	// e.g. source with version: samba (2:4.17.12+dfsg-0+deb12u1)
	DPKG_ORIGIN_REGEX = regexp.MustCompile(`^\s*([^\(]*)(?:\((.*)\))?\s*$`)
)

// isDpkgFieldSpace reports whether c belongs to the regexp `\s` class. Go
// defines that class as [\t\n\f\r ].
func isDpkgFieldSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

// dpkgControlField splits a dpkg control line into its field name and value,
// following the Debian control file format: a field name carries neither space
// nor colon, so the first colon ends it, and a line that starts with a space or
// a tab is a continuation of the field above it rather than a field of its own.
//
// At least one byte must precede the colon, and at least one byte must follow
// the whitespace that separates the name from the value.
//
// The colon and the whitespace bytes are ASCII, so they never appear inside a
// multi-byte UTF-8 sequence. A byte scan therefore finds the same split point
// as a rune scan. The caller passes one line from a bufio.Scanner, so the input
// carries no newline.
//
// The returned slices alias line. The caller must copy what it keeps.
func dpkgControlField(line []byte) (key []byte, value []byte, ok bool) {
	// a continuation line belongs to the field above it
	if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
		return nil, nil, false
	}
	i := bytes.IndexByte(line, ':')
	if i < 1 || i+2 > len(line)-1 || !isDpkgFieldSpace(line[i+1]) {
		return nil, nil, false
	}
	return line[:i], line[i+2:], true
}

// dpkgFilesInstalled reports whether a dpkg Status field ("want flag
// state") describes a package whose files are on disk. The states
// "not-installed" and "config-files" have none; every other state has at
// least part of the package unpacked. An empty status (status.d entries of
// distroless images) counts as installed.
func dpkgFilesInstalled(status string) bool {
	fields := strings.Fields(status)
	if len(fields) < 3 {
		return true
	}
	switch fields[2] {
	case "not-installed", "config-files":
		return false
	}
	return true
}

// ParseDpkgPackages parses the dpkg database content located in /var/lib/dpkg/status
func ParseDpkgPackages(pf *inventory.Platform, input io.Reader) ([]Package, error) {
	const STATE_RESET = 0
	const STATE_DESC = 1
	pkgs := []Package{}

	add := func(pkg Package) {
		// A package that was removed but not purged stays in the status file
		// as "deinstall ok config-files": its files are gone, only its
		// configuration is left. It is not installed.
		if !dpkgFilesInstalled(pkg.Status) {
			log.Debug().Str("package", pkg.Name).Str("status", pkg.Status).Msg("ignored deb package that is not installed")
			return
		}
		// do sanitization checks to ensure we have minimal information
		if pkg.Name != "" && pkg.Version != "" {
			// A hold lives in the status triple that was just parsed, so it
			// costs no extra read and is answered the same way on an image.
			pkg.Pinned = isHeldStatus(pkg.Status)
			// dpkg keeps the epoch inside Version. Version stays as dpkg
			// wrote it, the way the rpm reader keeps its epoch-prefixed
			// version, and Epoch carries the value on its own so the purl
			// and CPE below can use it.
			pkg.Epoch = epochFromVersion(pkg.Version)
			pkg.PUrl = purl.NewPackageURL(pf, purl.TypeDebian, pkg.Name, pkg.Version,
				purl.WithArch(pkg.Arch),
				purl.WithEpoch(pkg.Epoch),
			).String()
			cpes, _ := cpe.NewPackage2Cpe(pkg.Name, pkg.Name, pkg.Version, pkg.Epoch, pkg.Arch)
			cpesWithoutArch, _ := cpe.NewPackage2Cpe(pkg.Name, pkg.Name, pkg.Version, pkg.Epoch, "")
			cpes = append(cpes, cpesWithoutArch...)
			pkg.CPEs = cpes
			pkgs = append(pkgs, pkg)
		} else {
			log.Debug().Msg("ignored deb packages since information is missing")
		}
	}

	scanner := bufio.NewScanner(input)
	// A line longer than the 64KB default ends the scan, and the packages that
	// follow it are lost. Raise the cap so a long Depends line cannot shorten
	// the package list.
	scanner.Buffer(nil, dpkgMaxLine)
	pkg := Package{Format: DpkgPkgFormat}
	state := STATE_RESET
	for scanner.Scan() {
		// Bytes avoids one string allocation per line. Every field we keep is
		// copied into the package below, so nothing aliases the scanner buffer.
		line := scanner.Bytes()

		// reset package definition once we reach a newline
		if len(line) == 0 {
			add(pkg)
			pkg = Package{
				Format:         DpkgPkgFormat,
				FilesAvailable: PkgFilesAsync,
			}
		}

		key, value, ok := dpkgControlField(line)
		if ok {
			state = STATE_RESET
		}
		switch {
		case string(key) == "Package":
			pkg.Name = string(bytes.TrimSpace(value))
		case string(key) == "Version":
			pkg.Version = string(bytes.TrimSpace(value))
		case string(key) == "Architecture":
			pkg.Arch = string(bytes.TrimSpace(value))
		case string(key) == "Status":
			pkg.Status = string(bytes.TrimSpace(value))
		case string(key) == "Source":
			pkg.Origin = string(bytes.TrimSpace(value))
		// description supports multi-line statements, start desc
		case string(key) == "Description":
			pkg.Description = string(bytes.TrimSpace(value))
			state = STATE_DESC
		// next desc line, append to previous one
		case state == STATE_DESC:
			pkg.Description += "\n" + string(bytes.TrimSpace(line))
		}
	}

	// A read that stopped early leaves the package list short. Reporting that
	// as a successful parse would present a partial inventory as a complete
	// one, so it is an error rather than a shorter answer.
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read the dpkg status stream to its end: %w", err)
	}

	// if the last line is not an empty line we have things in flight, lets check it
	// a stream that ends with an empty line has nothing left, and reporting
	// that empty package as ignored only reads like data loss
	if pkg.Name != "" {
		add(pkg)
	}

	return pkgs, nil
}

// ParseDpkgCopyrightLicense reads the per-package DEP-5 copyright file at
// /usr/share/doc/<pkg>/copyright and returns the first `License:` value
// found anywhere in the file. Returns the empty string when the file is
// missing, not DEP-5, or no License field is present. Called lazily
// from the `license()` method on the `package` resource — only when
// MQL actually asks for the license, so we don't pay the per-package
// read cost on every `packages` enumeration.
//
// DEP-5 reference: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
// A top-level `License:` is rare in practice; most Ubuntu/Debian
// packages carry their license expression in the first `Files: *`
// paragraph (after the header's blank line). We scan the whole file
// and take the first `License:` regardless of paragraph — that yields
// the package's primary license for typical DEP-5 files and the only
// license present for single-paragraph ones.
//
// Many older packages use free-form copyright files with no `License:`
// field at all (just a `See /usr/share/common-licenses/X` pointer);
// those return empty rather than us guessing.
func ParseDpkgCopyrightLicense(fs afero.Fs, pkgName string) string {
	if fs == nil || pkgName == "" {
		return ""
	}
	path := "/usr/share/doc/" + pkgName + "/copyright"
	f, err := fs.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// DEP-5 allows multi-line license bodies indented under the
		// short name; the short name is on the same line as
		// `License:`. We only return that short name. Lines beginning
		// with whitespace are continuation/body and are skipped.
		if strings.HasPrefix(line, "License:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "License:"))
		}
	}
	return ""
}

// DPKG_UPDATE_REGEX splits one `Inst` line of `apt-get upgrade --dry-run`:
//
//	Inst libc6 [2.39-0ubuntu8.8] (2.39-0ubuntu8.9 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
//	Inst python3-pyasn1 [0.4.8-3+deb12u2] (0.4.8-3+deb12u3 Debian-Security:12/oldstable-security [all])
//
// The architecture is the bracketed token that closes the parenthesis, and it
// is what makes the update joinable to the installed package: packages.list
// keys available updates by "<name>/<arch>", so an update parsed without one
// never matches and every deb package reports no available version.
//
// A line can carry a further bracketed group after the parenthesis (apt's
// "because of" note, e.g. `[perl:amd64 ]`), so the arch is taken from the
// first `[...])` rather than the last `[...]` on the line.
//
// Name, version and origin are matched as runs of non-space rather than by
// enumerating characters. The enumerated classes this replaces had no `:` or
// `~`, so an epoch-bearing update (`1:1.54.3-5.el9_8`) or a tilde pre-release
// did not match at all and was dropped.
var DPKG_UPDATE_REGEX = regexp.MustCompile(`^Inst\s+(\S+)\s+\[([^\]]+)\]\s+\((\S+)\s+(.*?)\s*\[([^\]]+)\]\)`)

func ParseDpkgUpdates(input io.Reader) (map[string]PackageUpdate, error) {
	pkgs := map[string]PackageUpdate{}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(nil, dpkgMaxLine)
	for scanner.Scan() {
		line := scanner.Text()
		m := DPKG_UPDATE_REGEX.FindStringSubmatch(line)
		if m != nil {
			// apt qualifies a foreign-architecture package as "<name>:<arch>"
			// (`Inst g03-ma:i386 [...]`), while dpkg's status file lists it
			// under its bare name. The map key keeps apt's spelling so the
			// native and foreign entries stay apart; Name is the bare name so
			// packages.list's "<name>/<arch>" join finds it.
			pkgs[m[1]] = PackageUpdate{
				Name:      stripDebArchQualifier(m[1]),
				Version:   m[2],
				Available: m[3],
				Arch:      m[5],
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read the dpkg update list to its end: %w", err)
	}

	return pkgs, nil
}

// stripDebArchQualifier drops apt's ":<arch>" multi-arch qualifier from a
// package name. A Debian package name cannot contain a colon, so everything
// from the first one on is the qualifier.
func stripDebArchQualifier(name string) string {
	if i := strings.IndexByte(name, ':'); i > 0 {
		return name[:i]
	}
	return name
}

// APT_LIST_UPGRADABLE_REGEX splits one line of `apt list --upgradable`:
//
//	linux-aws/noble-updates 7.0.0-1014.14~24.04.1 amd64 [upgradable from: 7.0.0-1013.13~24.04.1]
//	g03-ma/unknown 1.1-1 i386 [upgradable from: 1.0-1]
//	libaudit-common/noble-updates,noble-updates 1:3.1.2-2.1ubuntu0.1 all [upgradable from: 1:3.1.2-2.1build1.1]
//
// The groups are name, suites, candidate version, architecture and the
// installed version. Versions are runs of non-space so epochs and tildes match.
var APT_LIST_UPGRADABLE_REGEX = regexp.MustCompile(`^(\S+?)/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from:\s+([^\]\s]+)\]`)

// ParseAptListUpgradable reads `apt list --upgradable`. Unlike a simulated
// `apt-get upgrade`, it lists every installed package whose candidate is newer:
// held packages, packages an upgrade keeps back because they need a new
// dependency (every kernel update), phased updates, and foreign-architecture
// packages.
//
// The result is keyed by "<name>/<arch>": a multi-arch package installed for
// two architectures appears on two lines under the same name.
func ParseAptListUpgradable(input io.Reader) (map[string]PackageUpdate, error) {
	pkgs := map[string]PackageUpdate{}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(nil, dpkgMaxLine)
	for scanner.Scan() {
		m := APT_LIST_UPGRADABLE_REGEX.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		name := stripDebArchQualifier(m[1])
		pkgs[name+"/"+m[4]] = PackageUpdate{
			Name:      name,
			Version:   m[5],
			Available: m[3],
			Arch:      m[4],
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read the apt upgradable list to its end: %w", err)
	}
	return pkgs, nil
}

// mergeDebUpdates joins the updates `apt list --upgradable` and the simulated
// `apt-get upgrade` report into one map keyed by "<name>/<arch>".
//
// apt list is the complete source on apt 2.0 and later, but apt 1.2 and 1.6
// (Ubuntu 16.04 and 18.04) print a multi-arch package once per name, so a
// package installed for amd64 and i386 shows only one of the two. The simulated upgrade still names both
// when neither is held, which is what the merge recovers. Where both report a
// package, apt list wins: it is the candidate apt would install.
func mergeDebUpdates(aptList, dryRun map[string]PackageUpdate) map[string]PackageUpdate {
	res := make(map[string]PackageUpdate, len(aptList)+len(dryRun))
	for _, u := range dryRun {
		res[u.Name+"/"+u.Arch] = u
	}
	for _, u := range aptList {
		res[u.Name+"/"+u.Arch] = u
	}
	return res
}

// Debian, Ubuntu
type DebPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (dpm *DebPkgManager) Name() string {
	return "Debian Package Manager"
}

func (dpm *DebPkgManager) Format() string {
	return DpkgPkgFormat
}

func (dpm *DebPkgManager) List() ([]Package, error) {
	fs := dpm.conn.FileSystem()
	dpkgStatusFile := "/var/lib/dpkg/status"
	dpkgStatusDir := "/var/lib/dpkg/status.d"
	_, fErr := fs.Stat(dpkgStatusFile)
	dStat, dErr := fs.Stat(dpkgStatusDir)

	if fErr != nil && dErr != nil {
		log.Debug().Err(fErr).Str("path", dpkgStatusFile).Msg("cannot find status file")
		log.Debug().Err(dErr).Str("path", dpkgStatusDir).Msg("cannot find status dir")
		return nil, fmt.Errorf("could not find dpkg package list")
	}

	pkgList := []Package{}
	// main pkg file for debian systems
	if fErr == nil {
		log.Debug().Str("file", dpkgStatusFile).Msg("parse dpkg status file")
		fi, err := fs.Open(dpkgStatusFile)
		if err != nil {
			return nil, fmt.Errorf("could not read dpkg package list")
		}
		defer fi.Close()

		list, err := ParseDpkgPackages(dpm.platform, fi)
		if err != nil {
			return nil, fmt.Errorf("could not parse dpkg package list: %w", err)
		}
		pkgList = append(pkgList, list...)
	}

	// e.g. google distroless images stores their pkg data in /var/lib/dpkg/status.d/
	if dErr == nil && dStat.IsDir() {
		afutil := afero.Afero{Fs: fs}
		wErr := afutil.Walk(dpkgStatusDir, func(path string, f os.FileInfo, fErr error) error {
			if f == nil || f.IsDir() {
				return nil
			}

			log.Debug().Str("path", path).Msg("walk file")
			fi, err := fs.Open(path)
			if err != nil {
				log.Debug().Err(err).Str("path", path).Msg("could open file")
				return fmt.Errorf("could not read dpkg package list")
			}

			list, err := ParseDpkgPackages(dpm.platform, fi)
			fi.Close()
			if err != nil {
				log.Debug().Err(err).Str("path", path).Msg("could not parse")
				return fmt.Errorf("could not parse dpkg package list %q: %w", path, err)
			}

			log.Debug().Int("pkgs", len(list)).Msg("completed parsing")
			pkgList = append(pkgList, list...)
			return nil
		})
		if wErr != nil {
			return nil, wErr
		}
	}

	dpm.applyInstallDates(fs, pkgList)

	return pkgList, nil
}

// applyInstallDates fills in the install time dpkg recorded for each package.
//
// dpkg keeps no install time in its status file the way rpm keeps
// %{INSTALLTIME} in the rpm header, so the only record is the log of the
// operations that placed the packages. Reading it here rather than lazily on
// the resource keeps installDate an eager field: it ships today, and turning it
// into a computed method would change a released field's shape.
//
// A package the retained logs do not mention keeps its zero time, which the
// resource layer surfaces as null. That is the same answer it gave before this
// read existed, so a stripped or rotated-away log costs nothing that was
// previously there.
func (dpm *DebPkgManager) applyInstallDates(fs afero.Fs, pkgList []Package) {
	dates := ReadDpkgInstallDates(fs, dpm.timeZone(fs))
	if len(dates) == 0 {
		return
	}

	for i := range pkgList {
		if !pkgList[i].InstallDate.IsZero() {
			continue
		}
		if t, ok := dates.Get(pkgList[i].Name, pkgList[i].Arch, pkgList[i].Version); ok {
			pkgList[i].InstallDate = t
		}
	}
}

// timeZone returns the zone dpkg's log is read in. dpkg writes local time with
// no offset, so the zone has to come from the asset rather than from the log or
// from the machine running the scan: a mounted snapshot is rarely in the zone
// of the host that produced it, and reading the log in the scanner's zone would
// shift every install date by that offset.
//
// An asset carrying no zone information runs in UTC, so UTC is the fallback.
func (dpm *DebPkgManager) timeZone(fs afero.Fs) *time.Location {
	if loc := date.LocationFromFS(fs); loc != nil {
		return loc
	}
	return time.UTC
}

func (dpm *DebPkgManager) Available() (map[string]PackageUpdate, error) {
	if !dpm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, errors.New("cannot check for deb package updates without running commands")
	}

	// TODO: run this as a complete shell script in motor
	// DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1
	// readlock() { cat /proc/locks | awk '{print $5}' | grep -v ^0 | xargs -I {1} find /proc/{1}/fd -maxdepth 1 -exec readlink {} \; | grep '^/var/lib/dpkg/lock$'; }
	// while test -n "$(readlock)"; do sleep 1; done
	// DEBIAN_FRONTEND=noninteractive apt-get upgrade --dry-run
	//
	// The refresh's exit status is not checked. As non-root it always fails
	// on the lock, while the indexes the system's own apt timers refresh are
	// still current, and a single unreachable repository fails it as root.
	// What matters is whether apt has any indexes to read, which
	// checkAptIndexes answers when nothing is pending.
	_, _ = dpm.conn.RunCommand("DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1")

	// A simulated upgrade only names what `apt-get upgrade` would install:
	// it leaves out held packages, packages kept back because they need a
	// new dependency (every kernel update), and phased updates. apt list
	// reports them all and needs no root.
	aptList, listErr := runAptUpdateSource(dpm.conn, aptListUpgradableCmd, ParseAptListUpgradable)
	if listErr != nil {
		log.Debug().Err(listErr).Msg("mql[packages]> could not run apt list --upgradable")
	}
	dryRun, dryErr := runAptUpdateSource(dpm.conn, aptUpgradeDryRunCmd, ParseDpkgUpdates)
	if dryErr != nil {
		log.Debug().Err(dryErr).Msg("mql[packages]> could not run apt-get upgrade --dry-run")
	}

	if listErr != nil && dryErr != nil {
		// Without apt there is no update check, as on a container that
		// had it removed. That is not a failed check.
		if errors.Is(listErr, errAptNotFound) && errors.Is(dryErr, errAptNotFound) {
			return nil, errAptNotFound
		}
		return nil, fmt.Errorf("%w: %w; %w", ErrUpdateCheckFailed, listErr, dryErr)
	}

	res := mergeDebUpdates(aptList, dryRun)
	if len(res) == 0 {
		if err := dpm.checkAptIndexes(); err != nil {
			return nil, err
		}
	}
	return res, nil
}

const (
	// aptListUpgradableCmd lists every installed package that has a newer
	// candidate. LC_ALL=C keeps the "[upgradable from: ...]" marker
	// untranslated.
	aptListUpgradableCmd = "LC_ALL=C apt list --upgradable"
	aptUpgradeDryRunCmd  = "DEBIAN_FRONTEND=noninteractive apt-get upgrade --dry-run"
	// aptPolicyCmd lists the package files apt has read into its cache.
	aptPolicyCmd = "LC_ALL=C apt-cache policy"
)

// errAptNotFound is returned when the host has no apt to ask.
var errAptNotFound = errors.New("apt is not installed")

// aptMaxErr caps how much of apt's stderr goes into an error.
const aptMaxErr = 512

// runAptUpdateSource runs one apt command that reports pending updates and
// parses its output. A non-zero exit status is an error: apt prints nothing
// to stdout when it cannot open its cache, and reading that as "no updates"
// reported every package as up to date.
func runAptUpdateSource(conn shared.Connection, command string, parse func(io.Reader) (map[string]PackageUpdate, error)) (map[string]PackageUpdate, error) {
	cmd, err := conn.RunCommand(command)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", command, err)
	}
	if cmd.ExitStatus == 127 {
		return nil, errAptNotFound
	}
	if cmd.ExitStatus != 0 {
		return nil, fmt.Errorf("%s exited with status %d%s", command, cmd.ExitStatus, aptStderr(cmd))
	}
	return parse(cmd.Stdout)
}

// aptStderr returns ": <stderr>" for an error message, trimmed and capped,
// or "" when apt printed nothing.
func aptStderr(cmd *shared.Command) string {
	if cmd.Stderr == nil {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(cmd.Stderr, 64*1024))
	if err != nil {
		return ""
	}
	msg := strings.TrimSpace(string(b))
	if len(msg) > aptMaxErr {
		msg = strings.ToValidUTF8(msg[:aptMaxErr], "") + "..."
	}
	if msg == "" {
		return ""
	}
	return ": " + msg
}

// checkAptIndexes tells "nothing is pending" apart from "apt knows of no
// repository". A stock cloud image ships with an empty /var/lib/apt/lists,
// and as non-root `apt-get update` cannot fill it (it fails on the lock).
// apt list and the simulated upgrade then both succeed and report nothing,
// because every installed package is its own only candidate.
func (dpm *DebPkgManager) checkAptIndexes() error {
	cmd, err := dpm.conn.RunCommand(aptPolicyCmd)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrUpdateCheckFailed, aptPolicyCmd, err)
	}
	if cmd.ExitStatus != 0 {
		return fmt.Errorf("%w: %s exited with status %d%s", ErrUpdateCheckFailed, aptPolicyCmd, cmd.ExitStatus, aptStderr(cmd))
	}
	ok, err := AptHasPackageIndexes(cmd.Stdout)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUpdateCheckFailed, err)
	}
	if !ok {
		return fmt.Errorf("%w: apt has no package indexes, run apt-get update as root", ErrUpdateCheckFailed)
	}
	return nil
}

// aptPolicyPackagesRegex matches a repository's package index in the
// "Package files:" section of `apt-cache policy`:
//
//	500 http://deb.debian.org/debian bookworm/main amd64 Packages
//	500 file:/srv/repo ./ Packages
//
// dpkg's status file (" 100 /var/lib/dpkg/status") is listed there too, and
// is the only entry when apt has no indexes.
var aptPolicyPackagesRegex = regexp.MustCompile(`^\s*-?\d+\s+\S.*\sPackages\s*$`)

// AptHasPackageIndexes reads `apt-cache policy` and reports whether apt has
// read at least one repository's package index.
func AptHasPackageIndexes(input io.Reader) (bool, error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(nil, dpkgMaxLine)
	for scanner.Scan() {
		if aptPolicyPackagesRegex.MatchString(scanner.Text()) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("could not read apt-cache policy to its end: %w", err)
	}
	return false, nil
}

// FindFileOwner implements PkgFileOwnershipResolver via `dpkg -S`, which prints
// "<name>[:<arch>]: <path>" (possibly across several lines, including diversion
// notes) and exits non-zero when no package owns the path.
func (dpm *DebPkgManager) FindFileOwner(path string) (string, error) {
	if !dpm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return "", nil
	}
	cmd, err := dpm.conn.RunCommand("dpkg -S " + shellQuote(path))
	if err != nil {
		return "", err
	}
	if cmd.ExitStatus != 0 {
		return "", nil
	}
	return parseDpkgOwner(readCommandOutput(cmd.Stdout)), nil
}

// parseDpkgOwner extracts the package name from `dpkg -S` output. Lines look
// like "<name>[:<arch>]: <path>"; the output may include diversion notes
// ("diversion by X from: …") which are skipped because a package spec never
// contains a space. The optional ":<arch>" multiarch qualifier is stripped to
// match the names reported by List().
func parseDpkgOwner(output string) string {
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, ": ")
		if idx <= 0 {
			continue
		}
		spec := strings.TrimSpace(line[:idx])
		if c := strings.IndexByte(spec, ':'); c >= 0 {
			spec = spec[:c]
		}
		if spec != "" && !strings.ContainsRune(spec, ' ') {
			return spec
		}
	}
	return ""
}

func (dpm *DebPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	fs := dpm.conn.FileSystem()

	dpkgListFiles := []string{
		"/var/lib/dpkg/info/" + name + ".list",
	}

	if arch != "" {
		dpkgListFiles = append(dpkgListFiles, "/var/lib/dpkg/info/"+name+":"+arch+".list")
	}

	fileRecords := []FileRecord{}
	for _, file := range dpkgListFiles {
		if _, err := fs.Stat(file); err != nil {
			continue
		}
		fileRecords = append(fileRecords, FileRecord{Path: file})
	}

	return fileRecords, nil
}
