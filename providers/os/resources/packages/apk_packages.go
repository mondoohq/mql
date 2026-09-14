// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"fmt"
	"io"
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
	// ApkDbPaths lists where the apk database is found, in the order they are
	// tried. Alpine keeps it under /lib, Wolfi under /usr/lib (usrmerge), and
	// apk-tools 3, which BellSoft Alpaquita and Hardened Containers ship, moved
	// it under /var.
	ApkDbInstalled    = "/lib/apk/db/installed"
	ApkDbInstalledUsr = "/usr/lib/apk/db/installed"
	ApkDbInstalledVar = "/var/lib/apk/db/installed"
)

// ApkDbPaths are every known location of the apk database, most common first.
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
		return pkgs, nil
	}

	return nil, fmt.Errorf("could not read apk package list")
}

func (apm *AlpinePkgManager) Available() (map[string]PackageUpdate, error) {
	// it only works if apk is updated
	_, _ = apm.conn.RunCommand("apk update")

	// determine package updates
	cmd, err := apm.conn.RunCommand("apk version -v -l '<'")
	if err != nil {
		log.Debug().Err(err).Msg("mql[packages]> could not read package updates")
		return nil, fmt.Errorf("could not read apk package update list")
	}
	return ParseApkUpdates(cmd.Stdout)
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
