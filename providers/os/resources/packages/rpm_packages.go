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
	"time"

	"go.mondoo.com/mql/v13/providers/core/resources/versions/semver"
	"go.mondoo.com/mql/v13/providers/os/resources/cpe"
	"go.mondoo.com/mql/v13/providers/os/resources/purl"

	"github.com/cockroachdb/errors"
	_ "github.com/glebarez/go-sqlite" // required for sqlite3 rpm support
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
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

// ParseRpmPackages parses output from:
// %{MODULARITYLABEL} is only added on supported systems
// rpm -qa --queryformat '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}__%{VENDOR}__%{SUMMARY}__%{LICENSE}__%{INSTALLTIME}__%{MODULARITYLABEL}\n'
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
		m := RPM_REGEX.FindStringSubmatch(line)
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

			vendor := cleanupVendorName(m[5])

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

			modularity := ""
			if len(m) > 9 {
				modularity = m[9]
			}

			pkg := newRpmPackage(pf, name, version, arch, epoch, vendor, m[6], license, modularity, installTime)
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
		// I searched https://www.redhat.com/security/data/metrics/repository-to-cpe.json for the epoch
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
}

func (rpm *RpmPkgManager) Name() string {
	return "Rpm Package Manager"
}

func (rpm *RpmPkgManager) Format() string {
	return RpmPkgFormat
}

// determine if we running against a static image, where we cannot execute the rpm command
// once executed, it caches its result to prevent the execution of the checks many times
func (rpm *RpmPkgManager) isStaticAnalysis() bool {
	if rpm.staticChecked {
		return rpm.static
	}

	rpm.static = false

	// check if the rpm command exists, e.g it is not available on tar backend
	c, err := rpm.conn.RunCommand("command -v rpm")
	if err != nil || c.ExitStatus != 0 {
		log.Debug().Msg("mql[packages]> fallback to static rpm package manager")
		rpm.static = true
	}

	// the root problem is that the docker transport (for running containers) cannot easily get the exit code so
	// we cannot always rely on that, a running photon container return non-zero exit code but it will be -1 on the system
	// we probably cannot fix this easily, see dockers approach:
	// https://docs.docker.com/engine/reference/commandline/attach/#get-the-exit-code-of-the-containers-command
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
	return markPinned(pkgs, rpm.lockedPackages()), nil
}

// lockedPackages reads the versionlock store. Overridden by SusePkgManager,
// which locks through zypper instead.
func (rpm *RpmPkgManager) lockedPackages() lockedNames {
	return readVersionlock(rpm.conn.FileSystem())
}

// lockedPackages reads zypper's lock store. SUSE has no versionlock plugin, so
// reading the dnf paths there would always come back empty.
func (spm *SusePkgManager) lockedPackages() lockedNames {
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
	return markPinned(pkgs, spm.lockedPackages()), nil
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
		modularity = "__%{MODULARITYLABEL}"
	}
	// this format should work everywhere
	// fall-back to epoch instead of epochnum for 6 ish platforms, latest 6 platforms also support epochnum, but we
	// save 1 call by not detecting the available keyword via rpm --querytags
	format := "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE} %{ARCH}__%{VENDOR}__%{SUMMARY}__%{LICENSE}__%{INSTALLTIME}" + modularity + "\\n"

	// ATTENTION: EPOCHNUM is only available since later version of rpm in RedHat 6 and Suse 12
	// we can only expect if for rhel 7+, therefore we need to run an extra test
	// be aware that this method is also used for non-redhat systems like suse
	i, err := strconv.ParseInt(rpm.platform.Version, 0, 32)
	if err == nil && (rpm.platform.Name == "centos" || rpm.platform.Name == "redhat") && i >= 7 {
		format = "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}__%{VENDOR}__%{SUMMARY}__%{LICENSE}__%{INSTALLTIME}" + modularity + "\\n"
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
func (rpm *RpmPkgManager) runtimeAvailable() (map[string]PackageUpdate, error) {
	// python script:
	// import sys;sys.path.insert(0, "/usr/share/yum-cli");import cli;list = cli.YumBaseCli().returnPkgLists(["updates"]);
	// print ''.join(["{\"name\":\""+x.name+"\", \"available\":\""+x.evr+"\",\"arch\":\""+x.arch+"\",\"repo\":\""+x.repo.id+"\"}\n" for x in list.updates]);
	script := "python -c 'import sys;sys.path.insert(0, \"/usr/share/yum-cli\");import cli;list = cli.YumBaseCli().returnPkgLists([\"updates\"]);print \"\".join([ \"{\\\"name\\\":\\\"\"+x.name+\"\\\",\\\"available\\\":\\\"\"+x.evr+\"\\\",\\\"arch\\\":\\\"\"+x.arch+\"\\\",\\\"repo\\\":\\\"\"+x.repo.id+\"\\\"}\\n\" for x in list.updates]);'"

	cmd, err := rpm.conn.RunCommand(script)
	if err != nil {
		log.Debug().Err(err).Msg("mql[packages]> could not read rpm package updates")
		return nil, errors.Wrap(err, "could not read rpm package update list")
	}
	return ParseRpmUpdates(cmd.Stdout)
}

func (rpm *RpmPkgManager) staticList() ([]Package, error) {
	rpmTmpDir, err := os.MkdirTemp(os.TempDir(), "mondoo-rpmdb")
	if err != nil {
		return nil, errors.Wrap(err, "could not create local temp directory")
	}
	log.Debug().Str("path", rpmTmpDir).Msg("mql[packages]> cache rpm library locally")
	defer os.RemoveAll(rpmTmpDir)

	fs := rpm.conn.FileSystem()
	afs := &afero.Afero{Fs: fs}

	// fetch rpm database file and store it in local tmp file
	// iterate over file paths to check if one exists
	files := []string{
		"/usr/lib/sysimage/rpm/Packages",     // used on opensuse container
		"/usr/lib/sysimage/rpm/Packages.db",  // used on SLES bci-base container
		"/usr/lib/sysimage/rpm/rpmdb.sqlite", // used on fedora 36+ and photon4
		"/var/lib/rpm/rpmdb.sqlite",          // used on fedora 33-35 and mageia
		"/var/lib/rpm/Packages",              // used on fedora 32
		"/var/lib/rpm/Packages.db",           // used on openeuler
	}
	var tmpRpmDBFile string
	var detectedPath string
	for i := range files {
		ok, err := afs.Exists(files[i])
		if err == nil && ok {
			splitPath := strings.Split(files[i], "/")
			tmpRpmDBFile = filepath.Join(rpmTmpDir, splitPath[len(splitPath)-1])
			detectedPath = files[i]
			break
		}
	}

	if len(detectedPath) == 0 {
		return nil, errors.Wrap(err, "could not find rpm packages location on : "+rpm.platform.Name)
	}
	log.Debug().Str("path", detectedPath).Msg("found rpm packages location")

	f, err := fs.Open(detectedPath)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch rpm package list")
	}
	defer f.Close()
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
		resultList = append(resultList, newRpmPackageFromDB(rpm.platform, pkg, detectedPath))
	}

	return resultList, nil
}

// TODO: Available() not implemented for RpmFileSystemManager
// for now this is not an error since we can easily determine available packages
func (rpm *RpmPkgManager) staticAvailable() (map[string]PackageUpdate, error) {
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
	} else {
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
		return fileRecords, nil
	}
}

// SusePkgManager overwrites the normal RPM handler
type SusePkgManager struct {
	RpmPkgManager
}

func (spm *SusePkgManager) Available() (map[string]PackageUpdate, error) {
	if spm.isStaticAnalysis() {
		return spm.staticAvailable()
	}
	cmd, err := spm.conn.RunCommand("zypper -n --xmlout list-updates")
	if err != nil {
		log.Debug().Err(err).Msg("mql[packages]> could not read package updates")
		return nil, fmt.Errorf("could not read rpm package update list")
	}
	return ParseZypperUpdates(cmd.Stdout)
}

// modularitySupportedByPlatform checks if the platform supports modularity
// Not every rpm based distro supports modules.
// E.g. SLES and Amazon Linux 2023 do not support modularity.
// Amazon Linux 2 supports modularity.
// No more modules starting with RHEL v10: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/considerations_in_adopting_rhel_10/application-streams
func modularitySupportedByPlatform(platform *inventory.Platform) bool {
	supported := false

	switch platform.Name {
	case "oraclelinux", "almalinux", "redhat", "centos", "rocky":
		vParser := semver.Parser{}
		cmp, err := vParser.Compare(platform.Version, "10")
		if err != nil {
			return false
		}
		if cmp < 0 {
			supported = true
		} else {
			supported = false
		}
	}

	return supported
}
