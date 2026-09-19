// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"bytes"
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

// ParseDpkgPackages parses the dpkg database content located in /var/lib/dpkg/status
func ParseDpkgPackages(pf *inventory.Platform, input io.Reader) ([]Package, error) {
	const STATE_RESET = 0
	const STATE_DESC = 1
	pkgs := []Package{}

	add := func(pkg Package) {
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
			pkgs[m[1]] = PackageUpdate{
				Name:      m[1],
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
	// TODO: run this as a complete shell script in motor
	// DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1
	// readlock() { cat /proc/locks | awk '{print $5}' | grep -v ^0 | xargs -I {1} find /proc/{1}/fd -maxdepth 1 -exec readlink {} \; | grep '^/var/lib/dpkg/lock$'; }
	// while test -n "$(readlock)"; do sleep 1; done
	// DEBIAN_FRONTEND=noninteractive apt-get upgrade --dry-run
	_, _ = dpm.conn.RunCommand("DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1")

	cmd, err := dpm.conn.RunCommand("DEBIAN_FRONTEND=noninteractive apt-get upgrade --dry-run")
	if err != nil {
		log.Debug().Err(err).Msg("mql[packages]> could not run apt-get upgrade")
		return nil, fmt.Errorf("could not run apt-get upgrade")
	}
	return ParseDpkgUpdates(cmd.Stdout)
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
