// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	cpe2 "go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/providers/os/resources/purl"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	AlpinePkgFormat = "apk"

	// Known locations of the apk database. Alpine keeps it under /lib, Wolfi
	// under /usr/lib (usrmerge), and apk-tools 3, which BellSoft Alpaquita and
	// Hardened Containers ship, moved it under /var.
	ApkDbInstalled    = "/lib/apk/db/installed"
	ApkDbInstalledUsr = "/usr/lib/apk/db/installed"
	ApkDbInstalledVar = "/var/lib/apk/db/installed"
)

// ApkDbPaths is every known location of the apk database, in the order they are
// tried: most common first.
var ApkDbPaths = []string{ApkDbInstalled, ApkDbInstalledUsr, ApkDbInstalledVar}

// apkMaxLine caps how long a single line of the apk database may be. The
// dependency and provides lines of a metapackage are the long ones, and they
// grow with the number of packages a distribution ships.
const apkMaxLine = 4 * 1024 * 1024

// apkField splits a line of the apk database into its one letter field key and
// its value. It returns the same key and value as the regexp
// `^([A-Za-z]):(.*)$`, which the parser used before.
//
// The returned value aliases line, so the caller must copy what it keeps.
func apkField(line []byte) (key byte, value []byte, ok bool) {
	if len(line) < 2 || line[1] != ':' {
		return 0, nil, false
	}
	c := line[0]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return 0, nil, false
	}
	return c, line[2:], true
}

// ParseApkDbPackages parses the database of the apk package manager located in
// `/lib/apk/db/installed`
// Apk spec: https://wiki.alpinelinux.org/wiki/Apk_spec
func ParseApkDbPackages(pf *inventory.Platform, input io.Reader) []Package {
	pkgs := []Package{}

	var pkgVersion string

	add := func(pkg Package) {
		// apk has no epoch, so the version is the `V:` field verbatim.
		pkg.Version = pkgVersion

		pkg.Format = AlpinePkgFormat
		pkg.PUrl = purl.NewPackageURL(pf, purl.TypeApk, pkg.Name, pkg.Version,
			purl.WithArch(pkg.Arch),
		).String()

		cpes, _ := cpe2.NewPackage2Cpe(pkg.Vendor, pkg.Name, pkg.Version, "", pf.Arch)
		pkg.CPEs = cpes

		pkg.FilesAvailable = PkgFilesIncluded
		pkg.Files = append(pkg.Files, FileRecord{
			Path: ApkDbInstalled,
		})

		// do sanitization checks to ensure we have minimal information
		if pkg.Name != "" && pkg.Version != "" {
			pkgs = append(pkgs, pkg)
		} else {
			log.Debug().Msg("ignored apk package since information is missing")
		}
	}

	scanner := bufio.NewScanner(input)
	// A line longer than the 64KB default ends the scan, and the packages that
	// follow it are lost without a word. Raise the cap so a long dependency
	// line cannot shorten the package list.
	scanner.Buffer(nil, apkMaxLine)
	pkg := Package{}
	for scanner.Scan() {
		// Bytes avoids one string allocation per line. Most lines of the apk
		// database list files, and the parser keeps none of them. Every field
		// it does keep is copied below.
		line := scanner.Bytes()

		// reset package definition once we reach a newline
		if len(line) == 0 {
			add(pkg)
			// reset values
			pkgVersion = ""
			pkg = Package{}
		}

		// a line we cannot split carries no field, so we ignore it
		key, value, ok := apkField(line)
		if !ok {
			continue
		}

		// Parse the package name or version. The lowercase `t:` field is the
		// build timestamp of the package, not an epoch, and apk has no epoch
		// concept at all, so we do not read it.
		switch key {
		case 'P':
			pkg.Name = string(value) // package name
		case 'V':
			pkgVersion = string(value) // package version
		case 'A':
			pkg.Arch = string(value) // architecture
		case 'o':
			pkg.Origin = string(value) // origin
		case 'T':
			pkg.Description = string(value) // description
		case 'L':
			pkg.License = string(value) // license (SPDX expression)
		}
	}

	// a read that stopped early leaves the package list short, so say so
	if err := scanner.Err(); err != nil {
		log.Error().Err(err).Msg("could not read the apk database to its end, the package list is incomplete")
	}

	// if the last line is not an empty line we have things in flight, lets check it
	// a database that ends with an empty line has nothing left, and reporting
	// that empty package as ignored only reads like data loss
	if pkg.Name != "" {
		add(pkg)
	}
	return pkgs
}

var APK_UPDATE_REGEX = regexp.MustCompile(`^([a-zA-Z0-9._]+)-([a-zA-Z0-9.\-\+]+)\s+<\s([a-zA-Z0-9.\-\+]+)\s*$`)

func ParseApkUpdates(input io.Reader) (map[string]PackageUpdate, error) {
	pkgs := map[string]PackageUpdate{}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		m := APK_UPDATE_REGEX.FindStringSubmatch(line)
		if m != nil {
			pkgs[m[1]] = PackageUpdate{
				Name:      m[1],
				Version:   m[2],
				Available: m[3],
			}
		}
	}
	return pkgs, nil
}

// Arch, Manjaro
type AlpinePkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (apm *AlpinePkgManager) Name() string {
	return "apk Package Manager"
}

func (apm *AlpinePkgManager) Format() string {
	return AlpinePkgFormat
}

func (apm *AlpinePkgManager) List() ([]Package, error) {
	for _, path := range ApkDbPaths {
		fr, err := apm.conn.FileSystem().Open(path)
		if err != nil {
			continue
		}

		pkgs := ParseApkDbPackages(apm.platform, fr)
		fr.Close()
		pins := apm.worldPins()
		for i := range pkgs {
			pkgs[i].Pinned = pins[pkgs[i].Name]
		}
		return pkgs, nil
	}

	return nil, fmt.Errorf("could not read apk package list")
}

// ApkWorld lists the packages the system was asked to have, with any version
// constraint they were added with.
const ApkWorld = "/etc/apk/world"

// worldPins reads which packages /etc/apk/world holds at their version.
func (apm *AlpinePkgManager) worldPins() map[string]bool {
	f, err := apm.conn.FileSystem().Open(ApkWorld)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn().Err(err).Str("path", ApkWorld).Msg("mql[packages]> could not read apk world, package pins are not reported")
		}
		return nil
	}
	defer f.Close()
	return parseApkWorldPins(f)
}

// parseApkWorldPins reads /etc/apk/world. A package added as "name=1.2-r0"
// (exact), "name~1.2" (fuzzy) or "name<2" / "name<=2" (upper bound) is held
// back: apk upgrade keeps it within the constraint. That is how Alpine
// documents holding a package back. A lower bound, a repository tag
// ("name@edge") and a conflict ("!name") do not hold the version.
func parseApkWorldPins(r io.Reader) map[string]bool {
	pins := map[string]bool{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		for _, dep := range strings.Fields(scanner.Text()) {
			if strings.HasPrefix(dep, "!") {
				continue
			}
			i := strings.IndexAny(dep, "=<>~")
			if i <= 0 {
				continue
			}
			name, op := dep[:i], dep[i:]
			if j := strings.IndexByte(name, '@'); j >= 0 {
				name = name[:j]
			}
			switch {
			case strings.HasPrefix(op, "<"), strings.HasPrefix(op, "="), strings.HasPrefix(op, "~"):
				pins[name] = true
			}
		}
	}
	return pins
}

func (apm *AlpinePkgManager) Available() (map[string]PackageUpdate, error) {
	// Refresh the indexes first. Its exit status is not checked: as non-root
	// it always fails (it cannot open the log), and it exits 2 when a
	// repository is unreachable even though the cached index is still read.
	// Whether apk could read an index is what apkUpdateCheck answers.
	_, _ = apm.conn.RunCommand("apk update")

	// determine package updates
	cmd, err := apm.conn.RunCommand("apk version -v -l '<'")
	if err != nil {
		log.Debug().Err(err).Msg("mql[packages]> could not read package updates")
		return nil, fmt.Errorf("could not read apk package update list")
	}
	return apkUpdateCheck(cmd.Stdout, cmd.Stderr, cmd.ExitStatus)
}

// apkUnreadableIndexRegex matches the warning apk prints for a repository
// whose index it could not read, from apk-tools 2 ("opening from cache
// <repo>: No such file or directory") and 3 ("fetching <repo>/APKINDEX.tar.gz:
// DNS: transient error"). apk still exits 0 and lists no update from that
// repository.
var apkUnreadableIndexRegex = regexp.MustCompile(`^WARNING: (?:opening from cache|opening|fetching|updating and opening) (\S+): (.+)$`)

// apkUpdateCheck reads the result of `apk version -v -l '<'`. A repository
// whose index apk could not read makes the check incomplete: apk then reports
// no update for the packages that repository carries, which reads as "up to
// date". The updates it did list are real and are kept.
func apkUpdateCheck(stdout io.Reader, stderr io.Reader, exitStatus int) (map[string]PackageUpdate, error) {
	errOut := ""
	if stderr != nil {
		errOut = readCommandOutput(stderr)
	}
	if exitStatus == 127 {
		// no apk binary, as in an image that had it removed: no update check
		return nil, errors.New("apk is not installed, cannot check for package updates")
	}
	if exitStatus != 0 {
		return nil, fmt.Errorf("%w: apk version exited with status %d: %s", ErrUpdateCheckFailed, exitStatus, strings.TrimSpace(errOut))
	}

	updates, err := ParseApkUpdates(stdout)
	if err != nil {
		return nil, err
	}

	var unreadable []string
	for _, line := range strings.Split(errOut, "\n") {
		if m := apkUnreadableIndexRegex.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			unreadable = append(unreadable, m[1]+": "+m[2])
		}
	}
	if len(unreadable) > 0 {
		return updates, fmt.Errorf("%w: apk could not read the index of %s", ErrUpdateCheckFailed, strings.Join(unreadable, "; "))
	}
	return updates, nil
}

func (apm *AlpinePkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	// not yet implemented
	return nil, nil
}

var apkOwnerRegex = regexp.MustCompile(`is owned by (\S+)`)

// FindFileOwner implements PkgFileOwnershipResolver via `apk info --who-owns`,
// which prints "<path> is owned by <name>-<version>-r<rel>" and exits non-zero
// when no package owns the path.
func (apm *AlpinePkgManager) FindFileOwner(path string) (string, error) {
	if !apm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return "", nil
	}
	cmd, err := apm.conn.RunCommand("apk info --who-owns " + shellQuote(path))
	if err != nil {
		return "", err
	}
	if cmd.ExitStatus != 0 {
		return "", nil
	}
	return parseApkOwner(readCommandOutput(cmd.Stdout)), nil
}

// parseApkOwner extracts the package name from `apk info --who-owns` output of
// the form "<path> is owned by <name>-<version>-r<rel>".
func parseApkOwner(output string) string {
	m := apkOwnerRegex.FindStringSubmatch(output)
	if m == nil {
		return ""
	}
	return apkStripVersion(m[1])
}

// apkReleaseSuffix matches the trailing "-r<digits>" apk release component,
// anchored at the end so a stray "-r" inside a version segment (e.g. a
// hypothetical "1.0-rc1") is not mistaken for the release separator.
var apkReleaseSuffix = regexp.MustCompile(`-r\d+$`)

// apkStripVersion turns an apk "name-version-rREL" token into the bare package
// name. apk names can contain hyphens while versions cannot, so we strip the
// trailing "-rREL" release and then the "-version" component rather than
// splitting on the first hyphen.
func apkStripVersion(s string) string {
	if loc := apkReleaseSuffix.FindStringIndex(s); loc != nil {
		s = s[:loc[0]]
	}
	if i := strings.LastIndex(s, "-"); i >= 0 {
		s = s[:i]
	}
	return s
}
