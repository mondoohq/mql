// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mondoo.com/mql/providers/core/resources/versions/semver"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/providers/os/resources/purl"

	"github.com/cockroachdb/errors"
	_ "github.com/glebarez/go-sqlite" // required for sqlite3 rpm support
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	RpmPkgFormat = "rpm"

	// rpmMaxLineSize caps a single line of `rpm -qa` output. The fields are
	// free-form text with no length bound of their own, so this only exists to
	// keep a pathological line from growing the buffer without limit.
	rpmMaxLineSize = 1024 * 1024
)

// RPM_REGEX splits one line of the queryFormat() output documented on
// ParseRpmPackages below.
//
// NAME, EPOCH:VERSION-RELEASE and ARCH are space-separated and none of them
// can contain whitespace, so they are matched as runs of non-space rather than
// by enumerating the characters they may contain. Enumerating is what broke
// here before: the name class was `[\w-+]`, which has no dot, so every package
// whose name contains one — java-1.8.0-openjdk, python3.11, dotnet-sdk-8.0,
// libstdc++ via the missing `+` in other positions — failed to match and was
// silently dropped from the inventory.
//
// For reference, rpm itself places almost no restriction on these fields:
// names and version/release strings may contain letters, digits and any of
// `. _ + - ~ ^` (`~` since rpm 4.10, `^` since 4.15), and vendor/summary/
// license are free-form text. The only structural invariants are that the
// first three fields contain no whitespace and that the remaining fields are
// delimited by `__`.
//
// Arch is matched non-greedily on purpose. Arch itself contains underscores
// (x86_64), so a greedy run of word characters happily spans the `__`
// separator: on `x86_64__Microsoft__dotnet sdk__MIT__1704067200__(none)` it
// takes `x86_64__Microsoft` as the arch and every later field shifts by one,
// yielding a license of `1704067200`. Non-greedy stops arch at the first
// separator, which is the only correct reading.
var RPM_REGEX = regexp.MustCompile(`^(\S+)\s(\d*|\(none\)):(\S+)\s(\S*?)__(.*?)__(.*?)__(.*?)__(\d+|\(none\))(?:__(.*))?$`)

// rpmFieldSep separates the free-text fields in queryFormat(): the ASCII unit
// separator, which no vendor, summary or license contains. The "__" it
// replaces does occur in summaries ("weird __ summary __ with separators"),
// and every such package came back with part of its summary as the license.
// rpm's queryformat has no escape for it, so the byte is in the format as is.
const rpmFieldSep = "\x1f"

// rpmUnitSepRegex splits one line of the queryFormat() output: the same
// fields as RPM_REGEX, separated by rpmFieldSep. A field cannot contain the
// separator, so there is no ambiguity left for a non-greedy match to resolve.
var rpmUnitSepRegex = regexp.MustCompile(`^(\S+)\s(\d*|\(none\)):(\S+)\s([^\s\x1f]*)\x1f([^\x1f]*)\x1f([^\x1f]*)\x1f([^\x1f]*)\x1f(\d+|\(none\))(?:\x1f(.*))?$`)

// ParseRpmPackages parses output from:
// %{MODULARITYLABEL} is only added on supported systems
// rpm -qa --queryformat '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}<US>%{VENDOR}<US>%{SUMMARY}<US>%{LICENSE}<US>%{INSTALLTIME}<US>%{MODULARITYLABEL}\n'
//
// where <US> is rpmFieldSep. Lines in the older "__"-separated format (still
// used by other callers and by captured test data) are read with RPM_REGEX.
func ParseRpmPackages(pf *inventory.Platform, input io.Reader) []Package {
	pkgs := []Package{}
	dropped := 0
	scanner := bufio.NewScanner(input)
	// A single package line is normally a few hundred bytes, but %{LICENSE} on
	// packages like java-*-openjdk already runs past 250 characters and nothing
	// bounds it. Past the scanner's default 64 KB the scan stops and the rest of
	// the package list is lost, so give it room.
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), rpmMaxLineSize)
	for scanner.Scan() {
		line := scanner.Text()
		re := RPM_REGEX
		if strings.Contains(line, rpmFieldSep) {
			re = rpmUnitSepRegex
		}
		m := re.FindStringSubmatch(line)
		if m != nil {
			name := m[1]
			epoch := normalizeRpmEpoch(m[2])
			version := m[3]

			// only prefix the epoch if we have a non-zero value
			if epoch != "" {
				version = epoch + ":" + version
			}

			arch := m[4]
			// if no arch provided, remove it completely
			if arch == "(none)" {
				arch = ""
			}

			vendor := m[5]
			// "(none)" is rpm's sentinel for a package built without a
			// Vendor tag, not a vendor name
			if vendor == "(none)" {
				vendor = ""
			}
			vendor = cleanupVendorName(vendor)

			license := m[7]
			// "(none)" is the rpm-format sentinel for missing fields;
			// surface it as empty so we never ship "(none)" as a license.
			if license == "(none)" {
				license = ""
			}

			// %{INSTALLTIME} is an integer epoch in seconds; "(none)"
			// only appears on packages that have never been recorded
			// with a sane installtime (rare; gpg-pubkey is one such).
			var installTime int64
			if m[8] != "" && m[8] != "(none)" {
				if v, err := strconv.ParseInt(m[8], 10, 64); err == nil {
					installTime = v
				}
			}

			// The trailing group is "src=<SOURCERPM>" then, optionally, the
			// modularity label; a line from the format before the source was
			// added (captured output, the "__" format) carries only the label.
			rest, modularity, sourceRpm := "", "", ""
			if len(m) > 9 {
				rest = m[9]
			}
			if src, ok := strings.CutPrefix(rest, rpmSourceTag); ok {
				sourceRpm, modularity, _ = strings.Cut(src, rpmFieldSep)
			} else {
				modularity = rest
			}

			pkg := newRpmPackage(pf, name, version, arch, epoch, vendor, m[6], license, modularity, installTime)
			pkg.Origin = rpmSourceName(sourceRpm)
			pkg.FilesAvailable = PkgFilesAsync // when we use commands we need to fetch the files async
			pkgs = append(pkgs, pkg)

		} else if strings.TrimSpace(line) != "" {
			// A package that does not match is dropped from the inventory
			// entirely, and an absent package is exactly what a vulnerability
			// scan cannot detect. Log it so format drift is visible instead of
			// showing up as a quietly shorter package list.
			dropped++
			log.Debug().Str("line", line).Msg("mql[rpm]> could not parse package line")
		}
	}
	if err := scanner.Err(); err != nil {
		// A line longer than the buffer above ends the scan early, which
		// truncates the package list silently. Surface it for the same reason.
		log.Warn().Err(err).Msg("mql[rpm]> package list was truncated while scanning")
	}
	if dropped > 0 {
		// The per-line detail above is debug, which is off by default -- so on
		// its own it would leave the exact failure this parser keeps hitting
		// (a silently shorter package list) invisible to the person running the
		// scan. Report the count where they will actually see it.
		log.Warn().Int("dropped", dropped).Int("parsed", len(pkgs)).
			Msg("mql[rpm]> some package lines could not be parsed, packages are missing from the inventory")
	}
	return pkgs
}

// rpmSourceTag marks the %{SOURCERPM} field in queryFormat() output. It is a
// tag rather than a bare position because the field after it, the modularity
// label, is only present on some platforms, and output from before the field
// existed must still parse; a modularity label (name:stream:version:context)
// never contains "=".
const rpmSourceTag = "src="

// rpmSourceName is the source package an rpm was built from, read from its
// SOURCERPM tag: "openssl-3.0.1-23.el9_0.src.rpm" -> "openssl".
//
// It becomes the package's Origin. rpm advisories are filed against the source
// package -- Microsoft's Azure Linux feed and Rocky's both name `openssl`,
// never `openssl-libs` -- so without it a subpackage built from a
// differently-named source can only be looked up by its own name, under which
// no advisory is ever filed.
//
// The tag is <name>-<version>-<release>.src.rpm (or .nosrc.rpm). A name may
// contain hyphens, a version and a release cannot, so the name is everything
// before the last two. Anything else -- "(none)", the empty tag gpg-pubkey
// carries -- is no source.
func rpmSourceName(sourceRpm string) string {
	s := strings.TrimSpace(strings.TrimRight(sourceRpm, "\x00"))
	var ok bool
	if s, ok = strings.CutSuffix(s, ".src.rpm"); !ok {
		if s, ok = strings.CutSuffix(s, ".nosrc.rpm"); !ok {
			return ""
		}
	}
	for range 2 { // drop the release, then the version
		before, _, found := strings.CutLast(s, "-")
		if !found || before == "" {
			return ""
		}
		s = before
	}
	return s
}

// normalizeRpmEpoch collapses rpm's spellings of "this package has no epoch"
// -- "0", "(none)" and the empty string -- to the empty string.
//
// Zero is rpm's default epoch and carries no information, so it belongs in
// neither the version string nor the purl. Both collection paths (the rpm
// command and the rpmdb parser) must agree on this: the version ends up in the
// purl, so a package that renders as "0:3.9.25-7.el9" when read from an image
// and "3.9.25-7.el9" when read from a live host looks like two different
// packages to everything downstream.
func normalizeRpmEpoch(epoch string) string {
	epoch = strings.TrimSpace(epoch)
	if epoch == "0" || epoch == "(none)" {
		return ""
	}
	return epoch
}

// newRpmPackageFromDB builds a Package from an rpmdb entry. This is the static
// analysis path, used whenever the rpm command is unavailable -- container
// images, filesystem and device scans.
func newRpmPackageFromDB(pf *inventory.Platform, pkg *rpmdb.PackageInfo, rpmDBPath string) Package {
	epoch := normalizeRpmEpoch(strconv.Itoa(pkg.EpochNum()))

	version := pkg.Version
	if epoch != "" {
		version = epoch + ":" + version
	}
	if pkg.Release != "" {
		version = version + "-" + pkg.Release
	}

	rpmPkg := newRpmPackage(pf, pkg.Name, version, pkg.Arch, epoch, cleanupVendorName(pkg.Vendor),
		pkg.Summary, pkg.License, pkg.Modularitylabel, int64(pkg.InstallTime))
	rpmPkg.Origin = rpmSourceName(pkg.SourceRpm)

	rpmPkg.FilesAvailable = PkgFilesIncluded
	rpmPkg.Files = []FileRecord{
		{
			Path: rpmDBPath,
		},
	}
	return rpmPkg
}

func newRpmPackage(pf *inventory.Platform, name, version, arch, epoch, vendor, description, license, modularity string, installTime int64) Package {
	// NOTE that we do not have the vendor of the package itself, we could try to parse it from the vendor
	// but that will also not be reliable. We may incorporate the cpe dictionary in the future but that would
	// increase the binary.
	if epoch == "0" {
		epoch = ""
	}
	cpes, _ := cpe.NewPackage2Cpe(vendor, name, version, epoch, arch)
	cpesWithoutEpoch := []string{}
	if epoch != "" {
		// I searched https://security.access.redhat.com/data/metrics/repository-to-cpe.json for the epoch
		// and it seems that the epoch is not part of the CPE, so we need to add it without the epoch
		cpesWithoutEpoch, _ = cpe.NewPackage2Cpe(vendor, name, version, "", arch)
	}
	cpesWithoutEpochAndArch, _ := cpe.NewPackage2Cpe(vendor, name, version, "", "")
	cpes = append(cpes, cpesWithoutEpoch...)
	cpes = append(cpes, cpesWithoutEpochAndArch...)
	// Only packages from a module stream carry a qualifier. Allocating an empty
	// map for every other package, and threading it through a WithQualifiers
	// closure, was pure overhead: the purl renderer builds its own map when
	// there is nothing to hand it.
	purlModifiers := []purl.Modifier{
		purl.WithArch(arch),
		purl.WithEpoch(epoch),
	}
	if modularity != "" && modularity != "(none)" {
		purlModifiers = append(purlModifiers, purl.WithQualifiers(map[string]string{
			"rpmmod": modularity,
		}))
	}

	pkg := Package{
		Name:        name,
		Version:     version,
		Epoch:       epoch,
		Arch:        arch,
		Description: description,
		Format:      RpmPkgFormat,
		CPEs:        cpes,
		Vendor:      vendor,
		License:     license,
		PUrl:        purl.NewPackageURL(pf, purl.TypeRPM, name, version, purlModifiers...).String(),
	}
	if installTime > 0 {
		pkg.InstallDate = time.Unix(installTime, 0).UTC()
	}
	return pkg
}

// matches a closed pair of angle brackets with any number of characters inside.
var CLEANUP_VENDOR_REGEX = regexp.MustCompile(`<.*>`)

// it is possible for the vendor name to contain a HTML tag with a website inside, e.g. SUSE.
// we remove it because it is not necessary and later causes troubles for the CPE generation.
// this assumes angle brackets are not used anywhere else in the names of vendors which is already the case.
func cleanupVendorName(vendor string) string {
	cleaned := CLEANUP_VENDOR_REGEX.ReplaceAllString(vendor, "")
	return strings.TrimRight(cleaned, " ")
}

// RpmPkgManager is the package manager for Redhat, CentOS, Oracle, Photon and Suse
// it supports two modes: runtime where the rpm command is available and static analysis for images (e.g. container tar)
// If the RpmPkgManager is used in static mode, it extracts the rpm database from the system and copies it to the local
// filesystem to run a local rpm command to extract the data. The static analysis is always slower than using the running
// one since more data need to copied. Therefore the runtime check should be preferred over the static analysis
type RpmPkgManager struct {
	conn          shared.Connection
	platform      *inventory.Platform
	staticChecked bool
	static        bool

	// The rpm database path (`%{_dbpath}`) is a system-wide constant, so it is
	// resolved once via `rpm -E` and reused for every package that asks for its
	// files instead of spawning one identical command per package.
	dbPathMu       sync.Mutex
	dbPathResolved bool
	dbPathFiles    []FileRecord
}

func (rpm *RpmPkgManager) Name() string {
	return "Rpm Package Manager"
}

func (rpm *RpmPkgManager) Format() string {
	return RpmPkgFormat
}

// rpmProbeCommand tells a host that can run rpm from one that cannot.
const rpmProbeCommand = "rpm --version"

// determine if we running against a static image, where we cannot execute the rpm command
// once executed, it caches its result to prevent the execution of the checks many times
func (rpm *RpmPkgManager) isStaticAnalysis() bool {
	if rpm.staticChecked {
		return rpm.static
	}

	rpm.static = false

	// check if the rpm command runs, e.g it is not available on tar backend.
	// The probe runs rpm itself. `command -v rpm` runs the shell builtin
	// `command`, which sudo cannot run ("sudo: command: command not found"),
	// so every scan with --sudo fell back to the static rpmdb read, which has
	// no update check: every package read as up to date.
	c, err := rpm.conn.RunCommand(rpmProbeCommand)
	if err != nil || c.ExitStatus != 0 {
		log.Debug().Msg("mql[packages]> fallback to static rpm package manager")
		rpm.static = true
	}

	// the root problem is that the docker transport (for running containers) cannot easily get the exit code so
	// we cannot always rely on that, a running photon container return non-zero exit code but it will be -1 on the system
	// we probably cannot fix this easily, see dockers approach:
	// https://docs.docker.com/reference/cli/docker/container/attach/#get-the-exit-code-of-the-containers-command
	if c != nil {
		rpmCmdPath, err := io.ReadAll(c.Stdout)
		if err != nil || len(rpmCmdPath) == 0 {
			rpm.static = true
		}
	}
	rpm.staticChecked = true
	return rpm.static
}

func (rpm *RpmPkgManager) List() ([]Package, error) {
	var pkgs []Package
	var err error
	if rpm.isStaticAnalysis() {
		pkgs, err = rpm.staticList()
	} else {
		pkgs, err = rpm.runtimeList()
	}
	if err != nil {
		return nil, err
	}
	locks, lockErr := rpm.lockedPackages()
	return markPinned(pkgs, locks, lockErr), nil
}

// lockedPackages reads the versionlock store. Overridden by SusePkgManager,
// which locks through zypper instead.
func (rpm *RpmPkgManager) lockedPackages() (lockedNames, error) {
	return readVersionlock(rpm.conn.FileSystem())
}

// lockedPackages reads zypper's lock store. SUSE has no versionlock plugin, so
// reading the dnf paths there would always come back empty.
func (spm *SusePkgManager) lockedPackages() (zypperLocks, error) {
	return readZypperLocks(spm.conn.FileSystem())
}

// List reads the rpm database and marks the packages zypper holds. The
// embedded RpmPkgManager.List cannot be reused for this: it calls
// lockedPackages on the embedded value, which resolves to the versionlock
// reader rather than this override.
func (spm *SusePkgManager) List() ([]Package, error) {
	var pkgs []Package
	var err error
	if spm.isStaticAnalysis() {
		pkgs, err = spm.staticList()
	} else {
		pkgs, err = spm.runtimeList()
	}
	if err != nil {
		return nil, err
	}
	locks, lockErr := spm.lockedPackages()
	return markPinned(pkgs, locks, lockErr), nil
}

func (rpm *RpmPkgManager) Available() (map[string]PackageUpdate, error) {
	if rpm.isStaticAnalysis() {
		return rpm.staticAvailable()
	} else {
		return rpm.runtimeAvailable()
	}
}

func (rpm *RpmPkgManager) queryFormat() string {
	modularity := ""
	// Not all rpm based distros support modules, only query when applicable, otherwise we get an error
	if modularitySupportedByPlatform(rpm.platform) {
		modularity = rpmFieldSep + "%{MODULARITYLABEL}"
	}
	// this format should work everywhere
	// fall-back to epoch instead of epochnum for 6 ish platforms, latest 6 platforms also support epochnum, but we
	// save 1 call by not detecting the available keyword via rpm --querytags
	format := "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE} %{ARCH}" + rpmFieldSep + "%{VENDOR}" + rpmFieldSep + "%{SUMMARY}" + rpmFieldSep + "%{LICENSE}" + rpmFieldSep + "%{INSTALLTIME}" + rpmFieldSep + rpmSourceTag + "%{SOURCERPM}" + modularity + "\\n"

	// ATTENTION: EPOCHNUM is only available since later version of rpm in RedHat 6 and Suse 12
	// we can only expect if for rhel 7+, therefore we need to run an extra test
	// be aware that this method is also used for non-redhat systems like suse
	i, err := strconv.ParseInt(rpm.platform.Version, 0, 32)
	if err == nil && (rpm.platform.Name == "centos" || rpm.platform.Name == "centos-stream" || rpm.platform.Name == "redhat") && i >= 7 {
		format = "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}" + rpmFieldSep + "%{VENDOR}" + rpmFieldSep + "%{SUMMARY}" + rpmFieldSep + "%{LICENSE}" + rpmFieldSep + "%{INSTALLTIME}" + rpmFieldSep + rpmSourceTag + "%{SOURCERPM}" + modularity + "\\n"
	}

	return format
}

func (rpm *RpmPkgManager) runtimeList() ([]Package, error) {
	command := fmt.Sprintf("rpm -qa --queryformat '%s'", rpm.queryFormat())
	cmd, err := rpm.conn.RunCommand(command)
	if err != nil {
		return nil, errors.Wrap(err, "could not read rpm package list")
	}
	return ParseRpmPackages(rpm.platform, cmd.Stdout), nil
}

// fetch all available packages, is that working with centos 6?
// rpmCheckUpdateCommand asks the package manager which updates are pending.
//
// It replaces a Python 2 snippet that imported yum's `cli` module from
// /usr/share/yum-cli. Neither survives on a current rpm distro: RHEL 9 has no
// python2 and no yum-cli, AlmaLinux 9 and Amazon Linux 2023 have no python at
// all. The snippet therefore produced nothing and every package reported no
// available update -- silently, because a failure here is logged at debug and
// the list falls back to empty. Measured on 2026-09-18: RHEL 9 with 602
// pending updates and AlmaLinux 9 with 56 both reported `outdated` 0.
//
// `check-update` is the supported interface on both, and yum keeps it as an
// alias for compatibility, so one command covers dnf and yum hosts.
//
// Exit status 100 means "updates are available" and 0 means "none"; any
// other status is a failure, see parseRpmCheckUpdateResult.
const rpmCheckUpdateCommand = "if command -v dnf >/dev/null 2>&1; then dnf -q check-update; else yum -q check-update; fi"

func (rpm *RpmPkgManager) runtimeAvailable() (map[string]PackageUpdate, error) {
	cmd, err := rpm.conn.RunCommand(rpmCheckUpdateCommand)
	if err != nil {
		log.Debug().Err(err).Msg("mql[packages]> could not read rpm package updates")
		return nil, fmt.Errorf("%w: %w", ErrUpdateCheckFailed, err)
	}
	return parseRpmCheckUpdateResult(cmd)
}

// rpmCheckUpdateMaxErr caps how much of dnf's stderr goes into the error.
const rpmCheckUpdateMaxErr = 512

// parseRpmCheckUpdateResult reads a finished check-update run. dnf and yum
// exit 0 when nothing is pending and 100 when updates are; anything else
// means the check failed. A repository whose metadata cannot be downloaded
// fails the whole run (exit 1, and nothing on stdout): as non-root on RHEL 8
// to 10 the RHUI client certificate is unreadable, and a repository that
// requires a signature it does not carry fails as root too. Reading that empty
// stdout as "no updates" reported every package as up to date.
func parseRpmCheckUpdateResult(cmd *shared.Command) (map[string]PackageUpdate, error) {
	switch cmd.ExitStatus {
	case 0, 100:
		return ParseRpmCheckUpdate(cmd.Stdout)
	}
	msg := ""
	if cmd.Stderr != nil {
		if b, err := io.ReadAll(io.LimitReader(cmd.Stderr, 64*1024)); err == nil {
			msg = strings.TrimSpace(string(b))
		}
	}
	if len(msg) > rpmCheckUpdateMaxErr {
		msg = strings.ToValidUTF8(msg[:rpmCheckUpdateMaxErr], "") + "..."
	}
	if msg == "" {
		return nil, fmt.Errorf("%w: check-update exited with status %d", ErrUpdateCheckFailed, cmd.ExitStatus)
	}
	return nil, fmt.Errorf("%w: check-update exited with status %d: %s", ErrUpdateCheckFailed, cmd.ExitStatus, msg)
}

// rpmDBPaths are where rpm keeps its database, in the order they are read.
var rpmDBPaths = []string{
	"/usr/lib/sysimage/rpm/Packages",     // used on opensuse container
	"/usr/lib/sysimage/rpm/Packages.db",  // used on SLES bci-base container
	"/usr/lib/sysimage/rpm/rpmdb.sqlite", // used on fedora 36+ and photon4
	"/var/lib/rpm/rpmdb.sqlite",          // used on fedora 33-35 and mageia
	"/var/lib/rpm/Packages",              // used on fedora 32
	"/var/lib/rpm/Packages.db",           // used on openeuler
	"/usr/share/rpm/rpmdb.sqlite",        // used on ostree images (fedora coreos, bootc, uBlue)
}

func (rpm *RpmPkgManager) staticList() ([]Package, error) {
	fs := rpm.conn.FileSystem()
	afs := &afero.Afero{Fs: fs}

	var found []string
	for _, path := range rpmDBPaths {
		if ok, err := afs.Exists(path); err == nil && ok {
			found = append(found, path)
		}
	}

	if len(found) == 0 {
		// Azure Linux and CBL-Mariner distroless images drop the rpm
		// database and keep a manifest of what they installed.
		if f, err := fs.Open(rpmManifestPath); err == nil {
			defer f.Close()
			log.Debug().Str("path", rpmManifestPath).Msg("found rpm manifest")
			return parseRpmManifest(rpm.platform, f)
		}
		// err was nil here, so errors.Wrap returned nil and an image without
		// an rpm database listed no packages and no error
		return nil, llx.NotFound(fmt.Errorf("could not find an rpm database on %s", rpm.platform.Name))
	}

	// The first database that exists is not necessarily the one rpm uses. The
	// oraclelinux:9 image (Oracle Linux 9.8, rpm 4.16, %_dbpath /var/lib/rpm)
	// also carries an rpmdb.sqlite under /usr/lib/sysimage/rpm that no package
	// owns and that holds no packages; reading only that one made the whole
	// inventory empty, with no error. A database with packages is the one in
	// use. An empty one is the answer only when no other database has any, and
	// an unreadable one is an error only when no other can be read.
	var empty []Package
	var firstErr error
	for _, path := range found {
		pkgs, err := rpm.readRpmDB(path)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("mql[packages]> could not read rpm database")
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(pkgs) > 0 {
			return pkgs, nil
		}
		log.Debug().Str("path", path).Msg("mql[packages]> rpm database has no packages")
		if empty == nil {
			empty = pkgs
		}
	}
	if empty != nil {
		return empty, nil
	}
	return nil, firstErr
}

// readRpmDB lists the packages in the rpm database at path on the target. The
// database is copied to a local temp file first, because the rpmdb reader
// needs a local path.
func (rpm *RpmPkgManager) readRpmDB(path string) ([]Package, error) {
	rpmTmpDir, err := os.MkdirTemp(os.TempDir(), "mondoo-rpmdb")
	if err != nil {
		return nil, errors.Wrap(err, "could not create local temp directory")
	}
	log.Debug().Str("path", rpmTmpDir).Msg("mql[packages]> cache rpm library locally")
	defer os.RemoveAll(rpmTmpDir)

	log.Debug().Str("path", path).Msg("found rpm packages location")
	f, err := rpm.conn.FileSystem().Open(path)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch rpm package list")
	}
	defer f.Close()

	tmpRpmDBFile := filepath.Join(rpmTmpDir, filepath.Base(path))
	fWriter, err := os.Create(tmpRpmDBFile)
	if err != nil {
		log.Error().Err(err).Msg("mql[packages]> could not create tmp file for rpm database")
		return nil, errors.Wrap(err, "could not create local temp file")
	}
	defer fWriter.Close()
	_, err = io.Copy(fWriter, f)
	if err != nil {
		log.Error().Err(err).Msg("mql[packages]> could not copy rpm to tmp file")
		return nil, fmt.Errorf("could not cache rpm package list")
	}

	log.Debug().Str("rpmdb", rpmTmpDir).Msg("mql[packages]> cached rpm database locally")
	db, err := rpmdb.Open(tmpRpmDBFile)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	pkgList, err := db.ListPackages()
	if err != nil {
		return nil, err
	}

	resultList := []Package{}
	for _, pkg := range pkgList {
		resultList = append(resultList, newRpmPackageFromDB(rpm.platform, pkg, path))
	}
	return resultList, nil
}

// staticAvailable is the update check when rpm cannot be run, so there is
// none. An image or a filesystem has no package manager to ask, and reports
// no newer version, as it always has. A host that can run commands but where
// rpm did not run cannot say which updates are pending: an empty map there
// read as "every package is up to date".
func (rpm *RpmPkgManager) staticAvailable() (map[string]PackageUpdate, error) {
	if rpm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, fmt.Errorf("%w: the rpm command could not be run on this host", ErrUpdateCheckFailed)
	}
	return map[string]PackageUpdate{}, nil
}

// FindFileOwner implements PkgFileOwnershipResolver via `rpm -qf`, using a
// queryformat so only the bare package name is printed. The `\n` is an rpm
// format escape (interpreted by rpm, not the shell — it stays literal inside
// the single-quoted argument until rpm parses it); it delimits owners when a
// path is owned by more than one package, so parseRpmOwner takes the first
// line. rpm exits non-zero with "file <path> is not owned by any package" when
// the path is unowned. Requires the rpm CLI (unavailable in static-analysis
// mode, in which case the query just fails and falls through).
func (rpm *RpmPkgManager) FindFileOwner(path string) (string, error) {
	if !rpm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return "", nil
	}
	cmd, err := rpm.conn.RunCommand("rpm -qf --queryformat '%{NAME}\\n' " + shellQuote(path))
	if err != nil {
		return "", err
	}
	if cmd.ExitStatus != 0 {
		return "", nil
	}
	return parseRpmOwner(readCommandOutput(cmd.Stdout)), nil
}

// parseRpmOwner extracts the package name from `rpm -qf --queryformat '%{NAME}'`
// output. It guards against builds that still print a "file … is not owned by
// any package" notice on stdout (such lines contain spaces).
func parseRpmOwner(output string) string {
	name := strings.TrimSpace(firstLine(output))
	if name == "" || strings.ContainsRune(name, ' ') {
		return ""
	}
	return name
}

func (rpm *RpmPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	if rpm.isStaticAnalysis() {
		// nothing to do since the data is already attached to the package
		return nil, nil
	}

	// `%{_dbpath}` is the same for every package on the system, so we resolve it
	// once and hand the cached result to every package that asks for its files.
	// This avoids running one `rpm -E '%{_dbpath}'` command per package (an N+1
	// on hosts with hundreds of packages).
	records, err := rpm.dbPathFileRecords()
	if err != nil {
		return nil, err
	}

	// Return a copy so callers can't mutate the cached slice. A shallow copy is
	// enough because FileRecord is transitively value-typed: Path is a string,
	// and PkgDigest and PkgFileInfo hold only strings and fixed-width integers.
	// Adding a pointer, slice, or map to any of the three would make the copy
	// share state with the cache again, and this would need to deep copy.
	out := make([]FileRecord, len(records))
	copy(out, records)
	return out, nil
}

// dbPathFileRecords resolves the rpm database path (`%{_dbpath}`) once and caches
// the resulting file records on the manager, so repeated calls reuse the cached
// value instead of re-running the `rpm -E` command. A failed resolution is not
// cached, so a transient error can be retried on the next call.
func (rpm *RpmPkgManager) dbPathFileRecords() ([]FileRecord, error) {
	rpm.dbPathMu.Lock()
	defer rpm.dbPathMu.Unlock()

	if rpm.dbPathResolved {
		return rpm.dbPathFiles, nil
	}

	// This returns the path to the RPM database
	cmd, err := rpm.conn.RunCommand("rpm -E '%{_dbpath}'")
	if err != nil {
		return nil, errors.Wrap(err, "could not rpm database path")
	}
	fileRecords := []FileRecord{}
	scanner := bufio.NewScanner(cmd.Stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fileRecords = append(fileRecords, FileRecord{
			Path: line,
		})
	}

	rpm.dbPathFiles = fileRecords
	rpm.dbPathResolved = true
	return fileRecords, nil
}

// SusePkgManager overwrites the normal RPM handler
type SusePkgManager struct {
	RpmPkgManager
}

func (spm *SusePkgManager) Available() (map[string]PackageUpdate, error) {
	if spm.isStaticAnalysis() {
		return spm.staticAvailable()
	}
	cmd, err := spm.conn.RunCommand(zypperListUpdatesCommand)
	if err != nil {
		log.Debug().Err(err).Msg("mql[packages]> could not read package updates")
		return nil, fmt.Errorf("%w: %w", ErrUpdateCheckFailed, err)
	}
	return parseZypperListUpdatesResult(cmd)
}

const zypperListUpdatesCommand = "zypper -n --xmlout list-updates"

// modularitySupportedByPlatform checks if the platform supports modularity
// Not every rpm based distro supports modules.
// E.g. SLES and Amazon Linux 2023 do not support modularity.
// Amazon Linux 2 supports modularity.
// No more modules starting with RHEL v10: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/considerations_in_adopting_rhel_10/application-streams
func modularitySupportedByPlatform(platform *inventory.Platform) bool {
	supported := false

	// The names are the detector's platform names, not os-release IDs: Rocky Linux
	// is "rockylinux" (its os-release ID "rocky" is renamed during detection).
	switch platform.Name {
	case "oraclelinux", "almalinux", "redhat", "centos", "centos-stream", "rockylinux":
		// The window is [8, 10): modularity was introduced with RHEL 8 and
		// removed again in RHEL 10. Do not widen it. On RHEL 7 and older rpm is
		// 4.11, which has no %{MODULARITYLABEL} tag: it writes an error per
		// package to stderr, writes nothing to stdout, and still exits 0, so
		// asking for the tag there returns an empty package list with no error.
		vParser := semver.Parser{}
		lower, err := vParser.Compare(platform.Version, "8")
		if err != nil {
			return false
		}
		upper, err := vParser.Compare(platform.Version, "10")
		if err != nil {
			return false
		}
		supported = lower >= 0 && upper < 0
	}

	return supported
}
