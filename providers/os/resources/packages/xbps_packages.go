// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
	"howett.net/plist"

	cpe2 "go.mondoo.com/mql/providers/os/resources/cpe"
)

const (
	XbpsPkgFormat = "xbps"

	// xbpsDbDir holds the package database and the per-package file lists.
	xbpsDbDir = "/var/db/xbps"

	// xbpsPkgdbGlob matches the package database. The filename carries the
	// database format version ("pkgdb-0.38.plist"), which xbps bumps when the
	// format changes, so the version is matched rather than hard-coded: pinning
	// 0.38 would read as "no packages installed" on the first host that ships a
	// newer xbps.
	xbpsPkgdbGlob = xbpsDbDir + "/pkgdb-*.plist"

	// xbpsInstallDateLayout is how xbps writes install-date, e.g.
	// "2021-07-25 10:42 UTC". Note there are no seconds.
	xbpsInstallDateLayout = "2006-01-02 15:04 MST"
)

// xbpsPkgEntry is one package as the database records it. Only the fields that
// reach a Package are declared; the database also carries checksums, sizes and
// dependency lists that nothing here reads.
type xbpsPkgEntry struct {
	PkgName      string `plist:"pkgname"`
	PkgVer       string `plist:"pkgver"`
	Architecture string `plist:"architecture"`
	ShortDesc    string `plist:"short_desc"`
	License      string `plist:"license"`
	State        string `plist:"state"`
	InstallDate  string `plist:"install-date"`
	Repository   string `plist:"repository"`
}

// xbpsFileEntry is one path in a per-package file list. dirs, files and links
// are separate arrays in that plist but share this shape.
type xbpsFileEntry struct {
	File string `plist:"file"`
}

type xbpsFileList struct {
	Dirs  []xbpsFileEntry `plist:"dirs"`
	Files []xbpsFileEntry `plist:"files"`
	Links []xbpsFileEntry `plist:"links"`
}

// xbpsVersion strips the package name from an xbps "pkgver", which is written
// as "<name>-<version>_<revision>" ("base-files-0.142_11"). The name is taken
// from the entry's own pkgname field rather than by splitting on a hyphen: xbps
// names contain hyphens freely, so there is no separator to split on.
func xbpsVersion(pkgname, pkgver string) string {
	return strings.TrimPrefix(pkgver, pkgname+"-")
}

// ParseXbpsPkgdb reads the xbps package database. The database is an XML plist
// whose top-level dict is keyed by package name.
func ParseXbpsPkgdb(pf *inventory.Platform, r io.Reader) ([]Package, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("could not read the xbps package database: %w", err)
	}

	var db map[string]xbpsPkgEntry
	if _, err := plist.Unmarshal(raw, &db); err != nil {
		return nil, fmt.Errorf("could not parse the xbps package database: %w", err)
	}

	// The database is a map, so iteration order is random. Sorting keeps the
	// package list stable between scans of the same host.
	names := make([]string, 0, len(db))
	for name := range db {
		names = append(names, name)
	}
	sort.Strings(names)

	pkgs := make([]Package, 0, len(names))
	for _, name := range names {
		entry := db[name]
		// The top level of the database is not packages alone: xbps keeps a
		// bookkeeping entry, _XBPS_ALTERNATIVES_, right beside them, and it is
		// a dict like they are. Skipping on the absence of a pkgname rather
		// than on that one name means a bookkeeping key added later is skipped
		// too, instead of becoming a package with no name and no version.
		if entry.PkgName == "" {
			continue
		}

		pkg := Package{
			Name:        entry.PkgName,
			Version:     xbpsVersion(entry.PkgName, entry.PkgVer),
			Arch:        entry.Architecture,
			Description: entry.ShortDesc,
			License:     entry.License,
			Status:      entry.State,
			Format:      XbpsPkgFormat,
			// The file list for a package is a separate plist that Files()
			// reads on demand, so it is not included here.
			FilesAvailable: PkgFilesAsync,
		}

		if entry.InstallDate != "" {
			if t, err := time.Parse(xbpsInstallDateLayout, entry.InstallDate); err == nil {
				pkg.InstallDate = t.UTC()
			} else {
				log.Debug().Str("package", pkg.Name).Str("value", entry.InstallDate).
					Msg("mql[packages]> could not parse the xbps install date")
			}
		}

		// purl has no xbps type, so the generic type carries the name and
		// version rather than inventing one.
		pkg.PUrl = purl.NewPackageURL(pf, purl.TypeGeneric, pkg.Name, pkg.Version,
			purl.WithArch(pkg.Arch),
		).String()
		cpes, _ := cpe2.NewPackage2Cpe(pkg.Vendor, pkg.Name, pkg.Version, "", pkg.Arch)
		pkg.CPEs = cpes

		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

// ParseXbpsFileList reads a per-package file list. dirs, files and links are
// returned together, which is what the package's file set means to a caller.
func ParseXbpsFileList(r io.Reader) ([]FileRecord, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("could not read the xbps file list: %w", err)
	}

	var list xbpsFileList
	if _, err := plist.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("could not parse the xbps file list: %w", err)
	}

	records := make([]FileRecord, 0, len(list.Dirs)+len(list.Files)+len(list.Links))
	for _, group := range [][]xbpsFileEntry{list.Dirs, list.Files, list.Links} {
		for _, entry := range group {
			if entry.File != "" {
				records = append(records, FileRecord{Path: entry.File})
			}
		}
	}
	return records, nil
}

type XbpsPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (xpm *XbpsPkgManager) Name() string {
	return "xbps Package Manager"
}

func (xpm *XbpsPkgManager) Format() string {
	return XbpsPkgFormat
}

// List reads the package database off disk rather than shelling out to
// xbps-query. The database is the same file on a live host, a mounted volume
// and a container image, so one path covers every connection, including the
// ones that cannot run a command at all.
func (xpm *XbpsPkgManager) List() ([]Package, error) {
	fs := xpm.conn.FileSystem()

	matches, err := afero.Glob(fs, xbpsPkgdbGlob)
	if err != nil {
		return nil, fmt.Errorf("could not look for the xbps package database: %w", err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("could not find an xbps package database at %s", xbpsPkgdbGlob)
	}
	// More than one only happens mid-upgrade, when xbps has written the new
	// database but not yet removed the old. The highest version is the live one.
	sort.Strings(matches)
	dbPath := matches[len(matches)-1]

	f, err := fs.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("could not read the xbps package database: %w", err)
	}
	defer f.Close()

	return ParseXbpsPkgdb(xpm.platform, f)
}

func (xpm *XbpsPkgManager) Available() (map[string]PackageUpdate, error) {
	if !xpm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		// Available updates are a question about the remote repositories, which
		// only xbps-install can answer. There is nothing on disk to fall back to.
		return map[string]PackageUpdate{}, nil
	}

	cmd, err := xpm.conn.RunCommand("xbps-install -Sun")
	if err != nil {
		log.Debug().Err(err).Msg("mql[packages]> could not read xbps package updates")
		return nil, fmt.Errorf("could not read the xbps package update list: %w", err)
	}
	if cmd.ExitStatus != 0 {
		log.Debug().Int("exit", cmd.ExitStatus).
			Msg("mql[packages]> xbps-install exited non-zero, reporting no available updates")
		return map[string]PackageUpdate{}, nil
	}

	return ParseXbpsUpdates(cmd.Stdout)
}

// ParseXbpsUpdates reads `xbps-install -Sun`, which prints one candidate per
// line as "<name>-<version>_<rev> update x86_64 <repo> <sizes>". Only the
// leading token is read; the rest describes the download rather than the
// package.
func ParseXbpsUpdates(r io.Reader) (map[string]PackageUpdate, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	updates := map[string]PackageUpdate{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pkgver := fields[0]
		// The revision separator is the last "_", and the version starts after
		// the last "-" before it. Splitting on the first hyphen would cut
		// "base-files-0.142_11" in the wrong place.
		//
		// Searching from the right rather than the left is also what makes an
		// underscore inside the name harmless: in "my_pkg-1.0_1" the last "_"
		// is still the revision separator, so the name survives intact.
		sep := strings.LastIndex(pkgver, "_")
		if sep < 0 {
			continue
		}
		dash := strings.LastIndex(pkgver[:sep], "-")
		if dash < 0 {
			continue
		}
		name := pkgver[:dash]
		if name == "" {
			continue
		}
		updates[name] = PackageUpdate{
			Name:      name,
			Available: pkgver[dash+1:],
		}
	}
	return updates, nil
}

// Files reads the per-package file list, which xbps stores next to the database
// as ".<pkgname>-files.plist". The name alone identifies it; version and arch
// are part of the interface but are not used here.
func (xpm *XbpsPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	if name == "" {
		return nil, nil
	}

	listPath := path.Join(xbpsDbDir, "."+name+"-files.plist")
	f, err := xpm.conn.FileSystem().Open(listPath)
	if err != nil {
		// A package with no payload of its own, a metapackage such as
		// base-minimal, has no file list. That is an empty set, not a failure.
		log.Debug().Str("package", name).Str("path", listPath).
			Msg("mql[packages]> no xbps file list for this package")
		return nil, nil
	}
	defer f.Close()

	return ParseXbpsFileList(f)
}
