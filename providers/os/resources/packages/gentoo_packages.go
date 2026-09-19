// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

const (
	GentooPkgFormat = "gentoo"

	// PortageDB is the root of Portage's installed package database. Each
	// installed package has a directory CATEGORY/NAME-VERSION holding one
	// file per metadata key.
	PortageDB = "/var/db/pkg"

	// portagePkgDirsCommand lists the directory of every installed package.
	// It is the authoritative list: a package with no metadata file still has
	// a directory, so the list never depends on which files happen to exist.
	portagePkgDirsCommand = "find " + PortageDB + " -mindepth 2 -maxdepth 2 -type d"

	// portageMetaCommand prints the first line of the metadata files that
	// carry the description and the license, each prefixed with its path.
	//
	// `qlist -Iv` prints only "CATEGORY/NAME:VERSION". Description and license
	// live in these files and nowhere in that output, so a Gentoo host read
	// through the CLI reported an empty description for every package -- and
	// an empty license however it was read, because ParsePortageDB never
	// opened LICENSE at all.
	//
	// -s hides the unreadable ones, -m1 stops at the first line, and the empty
	// pattern matches every line, so the output is one
	// "<path>:<value>" line per file that exists.
	portageMetaCommand = "grep -sH -m1 '' " + PortageDB + "/*/*/DESCRIPTION " + PortageDB + "/*/*/LICENSE"

	// portageMaxLine caps a single line of the stream above. A DESCRIPTION is
	// one short sentence, so this only keeps a corrupt database from growing
	// the buffer without limit.
	portageMaxLine = 1024 * 1024
)

// ParseGentooPackages parses the output of
// `qlist -Iv --format '%{CATEGORY}/%{PN}:%{PVR}'`.
// Format: CATEGORY/NAME:VERSION (e.g., "net-misc/curl:8.4.0")
func ParseGentooPackages(pf *inventory.Platform, r io.Reader) ([]Package, error) {
	pkgs := []Package{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Split by colon delimiter
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		categoryName := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])

		pkgs = append(pkgs, Package{
			Name:    categoryName,
			Version: version,
			Format:  GentooPkgFormat,
			PUrl:    newEbuildPurl(pf, categoryName, version),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
}

// newEbuildPurl creates a PURL for a Gentoo ebuild package.
// Format: pkg:ebuild/CATEGORY/NAME@VERSION
func newEbuildPurl(pf *inventory.Platform, categoryName, version string) string {
	category, name := splitCategoryName(categoryName)
	return purl.NewPackageURL(pf, purl.TypeEbuild, name, version,
		purl.WithNamespace(category),
	).String()
}

// splitCategoryName splits "category/name" into its parts.
func splitCategoryName(categoryName string) (string, string) {
	idx := strings.LastIndex(categoryName, "/")
	if idx < 0 {
		return "", categoryName
	}
	return categoryName[:idx], categoryName[idx+1:]
}

// Gentoo
type GentooPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (f *GentooPkgManager) Name() string {
	return "Gentoo Package Manager"
}

func (f *GentooPkgManager) Format() string {
	return GentooPkgFormat
}

func (f *GentooPkgManager) List() ([]Package, error) {
	if f.conn.Capabilities().Has(shared.Capability_RunCommand) {
		// Primary: the Portage database. The directory listing is the package
		// list; the metadata read fills the fields qlist leaves out and is
		// allowed to fail on its own, since names and versions are already in
		// hand by then.
		cmd, err := f.conn.RunCommand(portagePkgDirsCommand)
		if err == nil && cmd.ExitStatus == 0 {
			pkgs, err := ParsePortageDBDirs(f.platform, cmd.Stdout)
			if err == nil && len(pkgs) > 0 {
				if meta, err := f.conn.RunCommand(portageMetaCommand); err == nil {
					// grep exits 1 when nothing matched, which is not an error
					// here: it only means no package carries either file.
					applyPortageMeta(pkgs, ParsePortageMeta(meta.Stdout))
				} else {
					log.Debug().Err(err).Msg("mql[gentoo]> could not read portage metadata")
				}
				return pkgs, nil
			}
			log.Debug().Err(err).Msg("mql[gentoo]> portage database named no package, falling back to qlist")
		}

		// Fallback: qlist. Reached when the database is unreadable or the
		// host ships no find(1); name and version still answer.
		cmd, err = f.conn.RunCommand("qlist -Iv --format '%{CATEGORY}/%{PN}:%{PVR}'")
		if err != nil {
			log.Debug().Err(err).Msg("mql[gentoo]> could not run qlist, falling back to filesystem")
		} else if cmd.ExitStatus != 0 {
			log.Debug().Int("exitStatus", cmd.ExitStatus).Msg("mql[gentoo]> qlist returned non-zero, falling back to filesystem")
		} else {
			return ParseGentooPackages(f.platform, cmd.Stdout)
		}
	}

	// Fallback: parse /var/db/pkg/ directory structure
	return f.listFromFS()
}

// ParsePortageDBDirs turns the output of portagePkgDirsCommand into packages
// carrying their name and version. Description and license are filled in
// afterwards by applyPortageMeta.
func ParsePortageDBDirs(pf *inventory.Platform, r io.Reader) ([]Package, error) {
	pkgs := []Package{}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, portageMaxLine)
	for scanner.Scan() {
		dir := strings.TrimSpace(scanner.Text())
		if dir == "" {
			continue
		}
		if pkg := packageFromPortageDir(pf, dir); pkg != nil {
			pkgs = append(pkgs, *pkg)
		}
	}

	if err := scanner.Err(); err != nil {
		// A read that stopped early leaves the package list short, and an
		// absent package is a CVE nobody sees.
		return nil, fmt.Errorf("could not read the portage database to its end: %w", err)
	}

	return pkgs, nil
}

// ParsePortageMeta turns the output of portageMetaCommand into a map from
// package directory to its metadata.
//
// Each line is "<PortageDB>/<category>/<name>-<version>/<KEY>:<value>". The
// value may contain a colon, so the split is on the last colon that precedes
// the value -- which is the one right after the key, and the key is the last
// path element.
func ParsePortageMeta(r io.Reader) map[string]map[string]string {
	meta := map[string]map[string]string{}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, portageMaxLine)
	for scanner.Scan() {
		line := scanner.Text()
		// grep separates the file name from the line with the first colon,
		// and a Portage path contains none, so the first colon is the split.
		filePath, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		dir, key := path.Split(filePath)
		dir = strings.TrimSuffix(dir, "/")
		if dir == "" || key == "" {
			continue
		}
		if meta[dir] == nil {
			meta[dir] = map[string]string{}
		}
		meta[dir][key] = strings.TrimSpace(value)
	}

	return meta
}

// applyPortageMeta fills the description and license of each package from the
// metadata read for its directory.
func applyPortageMeta(pkgs []Package, meta map[string]map[string]string) {
	for i := range pkgs {
		// The directory round-trips exactly: Name is "<category>/<name>" and
		// the directory is "<PortageDB>/<category>/<name>-<version>".
		fields, ok := meta[PortageDB+"/"+pkgs[i].Name+"-"+pkgs[i].Version]
		if !ok {
			continue
		}
		pkgs[i].Description = fields["DESCRIPTION"]
		pkgs[i].License = fields["LICENSE"]
	}
}

// packageFromPortageDir builds a Package from one Portage database directory,
// which is "<PortageDB>/<category>/<name>-<version>". Returns nil when the
// path does not name a category, package and version.
func packageFromPortageDir(pf *inventory.Platform, dir string) *Package {
	dir = strings.TrimSuffix(dir, "/")
	parent, base := path.Split(dir)
	category := path.Base(strings.TrimSuffix(parent, "/"))
	if category == "" || category == "." || category == "/" || base == "" {
		return nil
	}

	name, version := splitPortageDirName(base)
	if name == "" || version == "" {
		return nil
	}

	fullName := category + "/" + name
	return &Package{
		Name:    fullName,
		Version: version,
		Format:  GentooPkgFormat,
		PUrl:    newEbuildPurl(pf, fullName, version),
	}
}

func (f *GentooPkgManager) listFromFS() ([]Package, error) {
	fs := f.conn.FileSystem()
	if fs == nil {
		return nil, errors.New("gentoo package manager requires either command execution or filesystem access")
	}
	afs := &afero.Afero{Fs: fs}
	return ParsePortageDB(f.platform, afs, PortageDB)
}

// ParsePortageDB parses the Portage installed package database directory.
// Structure: /var/db/pkg/CATEGORY/NAME-VERSION/
func ParsePortageDB(pf *inventory.Platform, afs *afero.Afero, dbPath string) ([]Package, error) {
	categories, err := afs.ReadDir(dbPath)
	if err != nil {
		return nil, fmt.Errorf("could not read portage database at %s: %w", dbPath, err)
	}

	var pkgs []Package
	for _, cat := range categories {
		if !cat.IsDir() {
			continue
		}
		category := cat.Name()

		// path.Join (not filepath.Join) is intentional — these are always
		// Linux filesystem paths, even when mql runs on a different OS.
		catPath := path.Join(dbPath, category)
		entries, err := afs.ReadDir(catPath)
		if err != nil {
			log.Debug().Err(err).Str("path", catPath).Msg("mql[gentoo]> could not read category")
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			name, version := splitPortageDirName(entry.Name())
			if name == "" || version == "" {
				continue
			}

			fullName := category + "/" + name

			pkgDir := path.Join(catPath, entry.Name())
			pkgs = append(pkgs, Package{
				Name:    fullName,
				Version: version,
				// The same two files the command reader above reads, so a
				// package carries the same fields whichever path produced it.
				Description: readFileContent(afs, path.Join(pkgDir, "DESCRIPTION")),
				License:     readFileContent(afs, path.Join(pkgDir, "LICENSE")),
				Format:      GentooPkgFormat,
				PUrl:        newEbuildPurl(pf, fullName, version),
			})
		}
	}

	return pkgs, nil
}

// splitPortageDirName splits a directory name like "curl-8.4.0" or
// "dhcpcd-10.0.5-r1" into (name, version). The version starts at the last
// hyphen that is followed by a digit.
func splitPortageDirName(dirName string) (string, string) {
	// Walk backwards to find the last hyphen followed by a digit
	for i := len(dirName) - 1; i > 0; i-- {
		if dirName[i] == '-' && i+1 < len(dirName) && unicode.IsDigit(rune(dirName[i+1])) {
			return dirName[:i], dirName[i+1:]
		}
	}
	return dirName, ""
}

// readFileContent reads the first line of a file, returning empty string on error.
func readFileContent(afs *afero.Afero, path string) string {
	f, err := afs.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}

func (f *GentooPkgManager) Available() (map[string]PackageUpdate, error) {
	return map[string]PackageUpdate{}, nil
}

func (f *GentooPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	// not yet implemented
	return nil, nil
}
