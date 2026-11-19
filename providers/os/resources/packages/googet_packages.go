// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cockroachdb/errors"
	_ "github.com/glebarez/go-sqlite" // registers the "sqlite" database/sql driver
	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

// GooGetPkgFormat is the format of packages installed by GooGet, Google's
// package manager for Windows. Every Compute Engine Windows image ships it, and
// the guest environment (google-compute-engine-windows, google-osconfig-agent,
// the metadata scripts, sysprep and the virtio drivers) is installed and
// updated through it rather than through an MSI with an Add/Remove Programs
// entry.
const GooGetPkgFormat = "googet"

// GooGet keeps its state under %ProgramData%\GooGet (install.ps1 sets GooGetRoot
// to exactly that). Since googet 2.x the installed packages are in the sqlite
// database googet.db; older releases wrote the JSON file googet.state.
// Converting to the database leaves the JSON file in place, so the database
// wins whenever both exist: the JSON file is then a stale snapshot.
//
// Each file is listed twice: as the drive-absolute path a live connection
// (local, WinRM, SSH) resolves, and relative to the volume root, which is how a
// mounted system volume (disk snapshot, device scan) addresses it.
var (
	googetDBPaths    = []string{`C:\ProgramData\GooGet\googet.db`, "ProgramData/GooGet/googet.db"}
	googetStatePaths = []string{`C:\ProgramData\GooGet\googet.state`, "ProgramData/GooGet/googet.state"}
)

// GooGetPkgManager lists the packages GooGet installed on a Windows system.
type GooGetPkgManager struct {
	conn shared.Connection
}

// googetPackageState is the subset of googet's client.PackageState this reader
// uses. Both googet.state (a JSON array of these) and each pkg_json row of
// googet.db hold the same encoding. Go's json is case-insensitive on keys, but
// the tags spell googet's field names exactly so the mapping is explicit.
type googetPackageState struct {
	SourceRepo     string            `json:"SourceRepo"`
	PackageSpec    *googetPkgSpec    `json:"PackageSpec"`
	InstalledFiles map[string]string `json:"InstalledFiles"`
	InstallDate    int64             `json:"InstallDate"`
}

type googetPkgSpec struct {
	Name        string `json:"Name"`
	Version     string `json:"Version"`
	Arch        string `json:"Arch"`
	Description string `json:"Description"`
	License     string `json:"License"`
	Authors     string `json:"Authors"`
}

func (g *GooGetPkgManager) Name() string {
	return "GooGet Package Manager"
}

func (g *GooGetPkgManager) Format() string {
	return GooGetPkgFormat
}

// hasGooGet reports whether the target has GooGet state on disk.
func hasGooGet(fs afero.Fs) bool {
	return firstExisting(fs, googetDBPaths) != "" || firstExisting(fs, googetStatePaths) != ""
}

func firstExisting(fs afero.Fs, paths []string) string {
	for _, p := range paths {
		if fi, err := fs.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// List returns the installed GooGet packages.
//
// A state GooGet itself could not have written (unreadable database, broken
// JSON) is logged and reported as no GooGet packages instead of an error: the
// package list fails as a whole when any package manager fails, and the
// Windows inventory beside it must not be lost over GooGet's state.
func (g *GooGetPkgManager) List() ([]Package, error) {
	fs := g.conn.FileSystem()

	var states []googetPackageState
	var err error
	var src string
	if src = firstExisting(fs, googetDBPaths); src != "" {
		states, err = readGooGetDB(fs, src)
	} else if src = firstExisting(fs, googetStatePaths); src != "" {
		states, err = readGooGetStateFile(fs, src)
	}
	if err != nil {
		log.Warn().Err(err).Str("path", src).Msg("mql[packages]> could not read googet package state")
		return []Package{}, nil
	}
	return googetPackages(states), nil
}

func (g *GooGetPkgManager) Available() (map[string]PackageUpdate, error) {
	return map[string]PackageUpdate{}, nil
}

func (g *GooGetPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	return nil, nil
}

// readGooGetStateFile reads the JSON state googet wrote before the database.
func readGooGetStateFile(fs afero.Fs, path string) ([]googetPackageState, error) {
	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return nil, err
	}
	return parseGooGetState(data)
}

func parseGooGetState(data []byte) ([]googetPackageState, error) {
	var states []googetPackageState
	if err := json.Unmarshal(data, &states); err != nil {
		return nil, errors.Wrap(err, "could not parse googet state file")
	}
	return states, nil
}

// readGooGetDB reads the InstalledPackages table of googet.db. The database is
// copied to a local temp file first, since sqlite needs a local path and the
// target may be remote.
func readGooGetDB(fs afero.Fs, path string) ([]googetPackageState, error) {
	src, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	tmpDir, err := os.MkdirTemp("", "mondoo-googet")
	if err != nil {
		return nil, errors.Wrap(err, "could not create local temp directory")
	}
	defer os.RemoveAll(tmpDir)

	local := filepath.Join(tmpDir, "googet.db")
	dst, err := os.Create(local)
	if err != nil {
		return nil, errors.Wrap(err, "could not create local temp file")
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return nil, errors.Wrap(err, "could not copy googet database")
	}
	if err := dst.Close(); err != nil {
		return nil, err
	}

	return queryGooGetDB(local)
}

func queryGooGetDB(localPath string) ([]googetPackageState, error) {
	db, err := sql.Open("sqlite", "file:"+localPath+"?mode=ro&immutable=1")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT pkg_json FROM InstalledPackages ORDER BY pkg_name, pkg_arch`)
	if err != nil {
		return nil, errors.Wrap(err, "could not query googet database")
	}
	defer rows.Close()

	var states []googetPackageState
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var s googetPackageState
		if err := json.Unmarshal(raw, &s); err != nil {
			// One bad row should not hide every other package.
			log.Debug().Err(err).Msg("mql[packages]> could not parse googet package row")
			continue
		}
		states = append(states, s)
	}
	return states, rows.Err()
}

// googetPackages converts googet package state into packages. Entries without
// a package spec are skipped, as googet itself skips them.
func googetPackages(states []googetPackageState) []Package {
	pkgs := make([]Package, 0, len(states))
	for _, s := range states {
		spec := s.PackageSpec
		if spec == nil || spec.Name == "" {
			continue
		}
		pkg := Package{
			Name:           spec.Name,
			Version:        spec.Version,
			Arch:           spec.Arch,
			Description:    spec.Description,
			License:        spec.License,
			Vendor:         spec.Authors,
			Format:         GooGetPkgFormat,
			PUrl:           newGooGetPurl(spec.Name, spec.Version, spec.Arch, s.SourceRepo),
			FilesAvailable: PkgFilesIncluded,
			Files:          googetFiles(s.InstalledFiles),
		}
		if s.InstallDate > 0 {
			pkg.InstallDate = time.Unix(s.InstallDate, 0).UTC()
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

// googetFiles turns googet's installed-file map (path to SHA-256) into file
// records. googet records directories with an empty checksum; they are not
// files the package owns content for, so they are left out.
func googetFiles(installed map[string]string) []FileRecord {
	paths := make([]string, 0, len(installed))
	for p, sum := range installed {
		if sum != "" {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)

	files := make([]FileRecord, 0, len(paths))
	for _, p := range paths {
		files = append(files, FileRecord{
			Path:   p,
			Digest: PkgDigest{Value: installed[p], Algorithm: "sha256"},
		})
	}
	return files
}

// newGooGetPurl returns pkg:googet/<name>@<version>?arch=<arch>, with the
// repository the package came from as repository_url. A googet version keeps
// the package release after an "@" (20240109.00.0@1), which the purl encodes.
func newGooGetPurl(name, version, arch, repo string) string {
	var qualifiers packageurl.Qualifiers
	if arch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: purl.QualifierArch, Value: arch})
	}
	if repo != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: "repository_url", Value: repo})
	}
	return packageurl.NewPackageURL(string(purl.TypeGooGet), "", name, version, qualifiers, "").String()
}

// googetUninstallPrefix is the DisplayName prefix of the Add/Remove Programs
// entry googet writes for every package it installs (system_windows.go:
// addUninstallEntry, "GooGet - <name>").
const googetUninstallPrefix = "GooGet - "

// DropGooGetRegistryDuplicates removes the Add/Remove Programs rows googet
// wrote for packages the googet state also lists, so each googet package is
// reported once, with its googet identity. aligned holds one value per package
// and is filtered the same way.
//
// A registry row is only dropped when the googet state names its package: if
// the state could not be read, the registry rows stay and the packages are
// still reported.
func DropGooGetRegistryDuplicates[T any](pkgs []Package, aligned []T) ([]Package, []T) {
	googet := map[string]struct{}{}
	for i := range pkgs {
		if pkgs[i].Format == GooGetPkgFormat {
			googet[googetUninstallPrefix+pkgs[i].Name] = struct{}{}
		}
	}
	if len(googet) == 0 {
		return pkgs, aligned
	}

	keptPkgs := pkgs[:0:0]
	keptAligned := aligned[:0:0]
	for i := range pkgs {
		if pkgs[i].Format == "windows/app" {
			if _, ok := googet[pkgs[i].Name]; ok {
				continue
			}
		}
		keptPkgs = append(keptPkgs, pkgs[i])
		keptAligned = append(keptAligned, aligned[i])
	}
	return keptPkgs, keptAligned
}
