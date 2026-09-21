// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

const (
	PacmanPkgFormat = "pacman"
	// PacmanLocalDB is the root of pacman's local package database. Each
	// installed package has a directory named "<name>-<version>" that holds a
	// `files` manifest listing everything the package put on disk. AUR
	// packages installed through helpers like yay or paru register here too,
	// so they're covered without any extra handling.
	PacmanLocalDB = "/var/lib/pacman/local"

	// pacmanLocalDBCommand dumps every `desc` record of the local database in
	// a single command.
	//
	// `pacman -Q` prints only "<name> <version>". Arch, description and
	// license live in the desc records and nowhere in that output, so a host
	// read through the CLI reported them empty while the same host read
	// through the filesystem reported them in full. Reading the records is
	// what makes the two agree.
	//
	// `pacman -Qi` carries the same fields but labels them in the caller's
	// locale ("Architecture" becomes "Architektur" under LANG=de_DE), so its
	// keys cannot be matched reliably. The desc format is pacman's own
	// on-disk format and is not translated.
	//
	// Each desc file begins with %NAME% and ends with a blank line, so the
	// concatenation is a well-formed sequence of records.
	pacmanLocalDBCommand = "find " + PacmanLocalDB + " -maxdepth 2 -name desc -exec cat {} +"

	// pacmanMaxLine caps a single line of a desc record. The values are short,
	// so this only keeps a corrupt database from growing the buffer without
	// limit.
	pacmanMaxLine = 1024 * 1024
)

// PACMAN_REGEX splits one line of `pacman -Q`, which prints "<name> <version>".
//
// The name class used to be `[\w-]`, which is letters, digits, `_` and `-`.
// pkgname also allows `.`, `+`, `@` -- so `db5.3`, `libstdc++` and `libc++`
// did not match, and a line that does not match is appended nowhere. The
// package left the inventory with no error and no count discrepancy, which is
// the one outcome a vulnerability scan cannot recover from: an absent package
// is an unreported CVE. On a stock `archlinux:base-devel` container that is 2
// of 170 packages.
//
// The version is deliberately matched as a run of non-space rather than by
// enumerating characters. It is `[epoch:]pkgver-pkgrel`, and pkgver alone can
// carry `.` `_` `+` `~` and VCS suffixes (`0.3.2.r13.g553691a-1`); enumerating
// that set is what broke the name in the first place. The name keeps a
// character class because `pacman -Q` output has no other structure to anchor
// on -- pacman prints its own diagnostics on the same stream ("warning:
// database file for 'core' does not exist") and those must not parse as
// packages. pkgname is a set makepkg actually enforces, unlike the version.
var PACMAN_REGEX = regexp.MustCompile(`^([A-Za-z0-9@._+][A-Za-z0-9@._+-]*)\s(\S+)$`)

func ParsePacmanPackages(pf *inventory.Platform, input io.Reader) []Package {
	pkgs := []Package{}
	dropped := 0
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		m := PACMAN_REGEX.FindStringSubmatch(line)
		if m != nil {
			name := m[1]
			version := m[2]
			// pacman keeps the epoch inside the version it prints, the way
			// dpkg does. Version stays as pacman wrote it and Epoch carries
			// the value on its own.
			epoch := epochFromVersion(version)
			pkgs = append(pkgs, Package{
				Name:           name,
				Version:        version,
				Epoch:          epoch,
				Format:         PacmanPkgFormat,
				FilesAvailable: PkgFilesAsync,
				PUrl: purl.NewPackageURL(pf, purl.TypeAlpm, name, version,
					purl.WithEpoch(epoch),
				).String(),
			})
		} else if strings.TrimSpace(line) != "" && !isPacmanDiagnostic(line) {
			// A line we cannot parse is a package we do not report. Count it,
			// so the next drift in this format shows up as a warning instead of
			// a quietly shorter package list.
			dropped++
			log.Debug().Str("line", line).Msg("mql[pacman]> could not parse package line")
		}
	}
	if err := scanner.Err(); err != nil {
		log.Warn().Err(err).Msg("mql[pacman]> package list was truncated while scanning")
	}
	if dropped > 0 {
		log.Warn().Int("dropped", dropped).Int("parsed", len(pkgs)).
			Msg("mql[pacman]> some package lines could not be parsed, packages are missing from the inventory")
	}
	return pkgs
}

// isPacmanDiagnostic reports whether a line is pacman talking about itself
// rather than a package. pacman emits these on hosts whose sync databases are
// missing, and they turn up in the same stream we parse -- counting them as
// lost packages would warn on every scan of a perfectly healthy host.
func isPacmanDiagnostic(line string) bool {
	return strings.HasPrefix(line, "warning:") ||
		strings.HasPrefix(line, "error:") ||
		strings.HasPrefix(line, "::")
}

// Arch, Manjaro
type PacmanPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (ppm *PacmanPkgManager) Name() string {
	return "Pacman Package Manager"
}

func (ppm *PacmanPkgManager) Format() string {
	return PacmanPkgFormat
}

func (ppm *PacmanPkgManager) List() ([]Package, error) {
	if ppm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		// Primary: the local database, in one command. It carries every field
		// `pacman -Q` leaves out.
		cmd, err := ppm.conn.RunCommand(pacmanLocalDBCommand)
		if err == nil && cmd.ExitStatus == 0 {
			if pkgs := ParsePacmanDescStream(ppm.platform, cmd.Stdout); len(pkgs) > 0 {
				return pkgs, nil
			}
			log.Debug().Msg("mql[pacman]> local database named no package, falling back to pacman -Q")
		}

		// Fallback: pacman -Q. Reached when the database is unreadable or the
		// image ships no find(1); name and version still answer.
		cmd, err = ppm.conn.RunCommand("pacman -Q")
		if err == nil && cmd.ExitStatus == 0 {
			return ParsePacmanPackages(ppm.platform, cmd.Stdout), nil
		}
		log.Debug().Err(err).Msg("mql[pacman]> could not run pacman -Q, falling back to filesystem")
	}

	// Fallback: parse /var/lib/pacman/local/*/desc files
	return ppm.listFromFS()
}

// ParsePacmanDescStream parses the concatenated `desc` records of pacman's
// local database, as produced by pacmanLocalDBCommand.
//
// A %NAME% header opens a record, so it is what separates one record from the
// next. Splitting on blank lines would not: a desc record contains blank lines
// of its own between sections.
func ParsePacmanDescStream(pf *inventory.Platform, input io.Reader) []Package {
	pkgs := []Package{}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(nil, pacmanMaxLine)

	var record []string
	flush := func() {
		if len(record) == 0 {
			return
		}
		fields := parsePacmanDescSections(strings.NewReader(strings.Join(record, "\n")))
		if pkg := packageFromPacmanFields(pf, fields); pkg != nil {
			pkgs = append(pkgs, *pkg)
		}
		record = record[:0]
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "%NAME%" {
			flush()
		}
		record = append(record, line)
	}
	flush()

	if err := scanner.Err(); err != nil {
		// A read that stopped early leaves the package list short, and a
		// missing package is a CVE nobody sees. Say so rather than returning
		// a quietly shorter list.
		log.Error().Err(err).Msg("mql[pacman]> could not read the local database to its end, the package list is incomplete")
	}

	return pkgs
}

func (ppm *PacmanPkgManager) listFromFS() ([]Package, error) {
	afs := &afero.Afero{Fs: ppm.conn.FileSystem()}
	return ParsePacmanDB(ppm.platform, afs, PacmanLocalDB)
}

// ParsePacmanDB parses the pacman local database directory structure.
// Each subdirectory contains a `desc` file with package metadata.
func ParsePacmanDB(pf *inventory.Platform, afs *afero.Afero, dbPath string) ([]Package, error) {
	entries, err := afs.ReadDir(dbPath)
	if err != nil {
		return nil, fmt.Errorf("could not read pacman database at %s: %w", dbPath, err)
	}

	var pkgs []Package
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// path.Join (not filepath.Join) is intentional — these are always
		// Linux filesystem paths, even when mql runs on a different OS.
		descPath := path.Join(dbPath, entry.Name(), "desc")
		pkg, err := parsePacmanDesc(pf, afs, descPath)
		if err != nil {
			log.Debug().Err(err).Str("path", descPath).Msg("mql[pacman]> could not parse desc")
			continue
		}
		if pkg != nil {
			pkgs = append(pkgs, *pkg)
		}
	}

	return pkgs, nil
}

// parsePacmanDesc parses a single pacman desc file.
// The format uses %KEY% sections followed by values on subsequent lines.
func parsePacmanDesc(pf *inventory.Platform, afs *afero.Afero, descPath string) (*Package, error) {
	f, err := afs.Open(descPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return packageFromPacmanFields(pf, parsePacmanDescSections(f)), nil
}

// packageFromPacmanFields builds a Package from one parsed desc record. Both
// readers of the local database go through it, so a package carries the same
// fields whether the record arrived over a command channel or through the
// filesystem.
//
// Returns nil for a record with no %NAME%, which is not a package.
func packageFromPacmanFields(pf *inventory.Platform, fields map[string]string) *Package {
	name := fields["%NAME%"]
	if name == "" {
		return nil
	}
	version := fields["%VERSION%"]
	// %VERSION% is "[epoch:]pkgver-pkgrel" and carries the epoch inline, as
	// `pacman -Q` does. Version stays as pacman wrote it and Epoch carries the
	// value on its own, which is the pairing the rpm and dpkg readers produce.
	epoch := epochFromVersion(version)

	return &Package{
		Name:        name,
		Version:     version,
		Epoch:       epoch,
		Arch:        fields["%ARCH%"],
		Description: fields["%DESC%"],
		// Pacman desc files carry %LICENSE% as a multi-line block, one
		// SPDX identifier per line; parsePacmanDescSections keeps only
		// the first which is correct for most packages.
		License:        fields["%LICENSE%"],
		Format:         PacmanPkgFormat,
		FilesAvailable: PkgFilesAsync,
		PUrl: purl.NewPackageURL(pf, purl.TypeAlpm, name, version,
			purl.WithEpoch(epoch),
		).String(),
	}
}

// parsePacmanDescSections reads a desc file and returns a map of section key to value.
func parsePacmanDescSections(r io.Reader) map[string]string {
	fields := make(map[string]string)
	scanner := bufio.NewScanner(r)
	var currentKey string

	for scanner.Scan() {
		line := scanner.Text()

		// Section header: %KEY% (at least 3 chars, exactly two % signs)
		if len(line) >= 3 && line[0] == '%' && line[len(line)-1] == '%' && strings.Count(line, "%") == 2 {
			currentKey = line
			continue
		}

		// Empty line ends a section value
		if line == "" {
			currentKey = ""
			continue
		}

		// Value line — only keep the first value line per section
		// (multi-value sections like %DEPENDS% are not needed for SBOM)
		if currentKey != "" && fields[currentKey] == "" {
			fields[currentKey] = line
		}
	}

	return fields
}

func (ppm *PacmanPkgManager) Available() (map[string]PackageUpdate, error) {
	return nil, errors.New("Available() not implemented for pacman")
}

// Files returns the file manifest for a pacman package. pacman records the
// files each package owns in <PacmanLocalDB>/<name>-<version>/files. The
// directory suffix is the full version including epoch (e.g. "1:1.6.7-1"),
// which is exactly what both `pacman -Q` and the desc files report, so no
// special epoch handling is needed. We return the path to that manifest,
// matching the async convention used by the dpkg and rpm package managers.
func (ppm *PacmanPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	if name == "" || version == "" {
		return nil, nil
	}

	fs := ppm.conn.FileSystem()
	// path.Join (not filepath.Join) is intentional — these are always Linux
	// filesystem paths, even when mql runs on a different OS.
	filesDB := path.Join(PacmanLocalDB, name+"-"+version, "files")
	if _, err := fs.Stat(filesDB); err != nil {
		return nil, nil
	}

	return []FileRecord{{Path: filesDB}}, nil
}

var pacmanOwnerRegex = regexp.MustCompile(`is owned by (\S+)`)

// FindFileOwner implements PkgFileOwnershipResolver via `pacman -Qo`, which
// prints "<path> is owned by <name> <version>" and exits non-zero when no
// package owns the path.
func (ppm *PacmanPkgManager) FindFileOwner(path string) (string, error) {
	if !ppm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return "", nil
	}
	cmd, err := ppm.conn.RunCommand("pacman -Qo " + shellQuote(path))
	if err != nil {
		return "", err
	}
	if cmd.ExitStatus != 0 {
		return "", nil
	}
	return parsePacmanOwner(readCommandOutput(cmd.Stdout)), nil
}

// parsePacmanOwner extracts the package name from `pacman -Qo` output of the
// form "<path> is owned by <name> <version>".
func parsePacmanOwner(output string) string {
	m := pacmanOwnerRegex.FindStringSubmatch(output)
	if m == nil {
		return ""
	}
	return m[1]
}
