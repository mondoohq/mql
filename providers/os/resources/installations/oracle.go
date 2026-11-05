// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package installations

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/package-url/packageurl-go"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/resources/cpe"
)

// oracleDatabase finds Oracle Database homes, however they were installed: a
// zip archive unpacked and registered with runInstaller, a cloned home, or an
// RPM. The installer records every home in the central inventory, which
// oraInst.loc points to. oratab lists the homes databases run from, and the
// documented <ORACLE_BASE>/product/<release>/<home> layout finds a home that
// neither names, which also covers a scan that may not read the inventory
// (it is usually readable only by the Oracle install group).
var oracleDatabase = Detector{
	Name:   "oracle-database",
	Vendor: "Oracle",
	Locate: []Locator{
		oracleCentralInventory("/etc/oraInst.loc", "/var/opt/oracle/oraInst.loc"),
		oracleOratab("/etc/oratab", "/var/opt/oracle/oratab"),
		pathPattern("/u01/app/oracle/product/*/*", "/opt/oracle/product/*/*"),
	},
	Accept: isOracleDatabaseHome,
	Version: []VersionReader{
		oracleReleaseUpdate,
		oracleUSMVersion,
		oracleBaseRelease,
	},
	Identify: func(version string) (string, []string) {
		return genericPurl("oracle", "database", version), cpes("oracle", "database_server", version)
	},
}

// oracleCentralInventory returns the homes recorded in the central inventory
// named by the first oraInst.loc that exists.
func oracleCentralInventory(locFiles ...string) Locator {
	return func(fs afero.Fs) ([]Candidate, error) {
		for _, loc := range locFiles {
			f, err := fs.Open(loc)
			if err != nil {
				if isAbsent(err) {
					continue
				}
				return nil, fmt.Errorf("cannot read %s: %w", loc, err)
			}
			inv := parseOraInstLoc(f)
			f.Close()
			if inv == "" {
				continue
			}

			invFile := path.Join(inv, "ContentsXML", "inventory.xml")
			homes, err := readOracleInventory(fs, invFile)
			if err != nil {
				return nil, err
			}
			res := make([]Candidate, 0, len(homes))
			for _, h := range homes {
				res = append(res, Candidate{Root: h, LocatedBy: LocatedByRegistry})
			}
			return res, nil
		}
		return nil, nil
	}
}

// parseOraInstLoc returns the inventory_loc of an oraInst.loc file.
func parseOraInstLoc(r io.Reader) string {
	s := bufio.NewScanner(r)
	for s.Scan() {
		key, val, ok := strings.Cut(strings.TrimSpace(s.Text()), "=")
		if ok && strings.TrimSpace(key) == "inventory_loc" {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

type oracleInventoryXML struct {
	Homes []struct {
		Loc     string `xml:"LOC,attr"`
		Removed string `xml:"REMOVED,attr"`
	} `xml:"HOME_LIST>HOME"`
}

// readOracleInventory returns the homes of a central inventory.xml, leaving
// out those detached from it, which the inventory keeps marked REMOVED="T".
func readOracleInventory(fs afero.Fs, file string) ([]string, error) {
	data, err := afero.ReadFile(fs, file)
	if err != nil {
		if isAbsent(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read the Oracle central inventory %s: %w", file, err)
	}
	return parseOracleInventory(data)
}

func parseOracleInventory(data []byte) ([]string, error) {
	var inv oracleInventoryXML
	if err := xml.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("cannot parse the Oracle central inventory: %w", err)
	}
	homes := []string{}
	for _, h := range inv.Homes {
		if h.Loc == "" || strings.EqualFold(h.Removed, "T") {
			continue
		}
		homes = append(homes, h.Loc)
	}
	return homes, nil
}

// oracleOratab returns the homes of the first oratab that exists. Each line
// is <SID>:<ORACLE_HOME>:<Y|N>[:...]; # starts a comment.
func oracleOratab(files ...string) Locator {
	return func(fs afero.Fs) ([]Candidate, error) {
		for _, file := range files {
			f, err := fs.Open(file)
			if err != nil {
				if isAbsent(err) {
					continue
				}
				return nil, fmt.Errorf("cannot read %s: %w", file, err)
			}
			homes := parseOratab(f)
			f.Close()
			res := make([]Candidate, 0, len(homes))
			for _, h := range homes {
				res = append(res, Candidate{Root: h, LocatedBy: LocatedByRegistry})
			}
			return res, nil
		}
		return nil, nil
	}
}

func parseOratab(r io.Reader) []string {
	homes := []string{}
	s := bufio.NewScanner(r)
	for s.Scan() {
		line, _, _ := strings.Cut(s.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		home := strings.TrimSpace(fields[1])
		if !path.IsAbs(home) {
			continue
		}
		homes = append(homes, home)
	}
	return homes
}

type oracleCompsXML struct {
	Components []struct {
		Name string `xml:"NAME,attr"`
		Ver  string `xml:"VER,attr"`
	} `xml:"TL_LIST>COMP"`
}

// oracleServerComponent is the top-level component of a database server
// home. A client home installs oracle.client and a Grid Infrastructure home
// oracle.crs.
const oracleServerComponent = "oracle.server"

func oracleCompsFile(root string) string {
	return path.Join(root, "inventory", "ContentsXML", "comps.xml")
}

// readOracleServerComponent returns the version of the oracle.server
// component of the home at root, and whether the home installs it.
func readOracleServerComponent(fs afero.Fs, root string) (string, bool, error) {
	file := oracleCompsFile(root)
	data, err := afero.ReadFile(fs, file)
	if err != nil {
		if isAbsent(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("cannot read %s: %w", file, err)
	}
	return parseOracleServerComponent(data)
}

func parseOracleServerComponent(data []byte) (string, bool, error) {
	var comps oracleCompsXML
	if err := xml.Unmarshal(data, &comps); err != nil {
		return "", false, fmt.Errorf("cannot parse the Oracle home inventory: %w", err)
	}
	for _, c := range comps.Components {
		if c.Name == oracleServerComponent {
			return c.Ver, true, nil
		}
	}
	return "", false, nil
}

func isOracleDatabaseHome(fs afero.Fs, root string) (bool, error) {
	_, ok, err := readOracleServerComponent(fs, root)
	return ok, err
}

// oracleBaseRelease is the release the home was installed at, e.g.
// "19.0.0.0.0". It does not move when a Release Update is applied.
func oracleBaseRelease(fs afero.Fs, root string) (Version, bool, error) {
	v, ok, err := readOracleServerComponent(fs, root)
	if err != nil || !ok || v == "" {
		return Version{}, false, err
	}
	return Version{Value: v, Source: SourceBaseRelease, File: oracleCompsFile(root)}, true, nil
}

func oracleUSMVersionFile(root string) string {
	return path.Join(root, "lib", "usmvsn.pm")
}

// oracleUSMVersionLine is the comment lib/usmvsn.pm carries with the full
// release, e.g. "# USM VERSION FULL: 23.5.0.24.07".
var oracleUSMVersionLine = regexp.MustCompile(`USM VERSION FULL:\s*(\d+(?:\.\d+){4})\b`)

// oracleUSMVersion is the full release lib/usmvsn.pm names. A home installed
// whole at its release, such as Oracle Database Free, records no Release
// Update in its patch inventory, and this file is where its release is
// written. It belongs to the storage management (ACFS) component, which a
// patched home updates separately from the database, so it is read only
// after the patch inventory found no database Release Update.
func oracleUSMVersion(fs afero.Fs, root string) (Version, bool, error) {
	file := oracleUSMVersionFile(root)
	data, err := afero.ReadFile(fs, file)
	if err != nil {
		if isAbsent(err) {
			return Version{}, false, nil
		}
		return Version{}, false, fmt.Errorf("cannot read %s: %w", file, err)
	}
	m := oracleUSMVersionLine.FindSubmatch(data)
	if m == nil {
		return Version{}, false, nil
	}
	return Version{Value: oracleVersionFull(string(m[1])), Source: SourceReleaseMetadata, File: file}, true, nil
}

func oraclePatchFile(root string) string {
	return path.Join(root, "inventory", "ContentsXML", "oui-patch.xml")
}

type oraclePatchesXML struct {
	Patches []struct {
		Desc string `xml:"DESC"`
	} `xml:"ONEOFF"`
}

// oracleReleaseUpdateDesc matches the description OPatch records for a
// database Release Update or Release Update Revision, e.g.
// "Database Release Update : 19.3.0.0.190416 (29517242)" or
// "Database Release Update Revision : 19.9.1.0.210119 (32072711)". The
// Release Update of the clusterware ("OCW RELEASE UPDATE") does not match.
var oracleReleaseUpdateDesc = regexp.MustCompile(`^Database Release Update(?: Revision)? : (\d+(?:\.\d+){4})\b`)

// oracleReleaseUpdate is the highest database Release Update or Release
// Update Revision recorded as applied to the home. A home keeps the Release
// Update it was installed with in the record after a later one is applied,
// so the highest wins, not the first or the last.
func oracleReleaseUpdate(fs afero.Fs, root string) (Version, bool, error) {
	file := oraclePatchFile(root)
	data, err := afero.ReadFile(fs, file)
	if err != nil {
		if isAbsent(err) {
			return Version{}, false, nil
		}
		return Version{}, false, fmt.Errorf("cannot read %s: %w", file, err)
	}
	v, err := parseOracleReleaseUpdate(data)
	if err != nil || v == "" {
		return Version{}, false, err
	}
	return Version{Value: v, Source: SourcePatchInventory, File: file}, true, nil
}

func parseOracleReleaseUpdate(data []byte) (string, error) {
	var patches oraclePatchesXML
	if err := xml.Unmarshal(data, &patches); err != nil {
		return "", fmt.Errorf("cannot parse the Oracle patch inventory: %w", err)
	}
	best := ""
	for _, p := range patches.Patches {
		m := oracleReleaseUpdateDesc.FindStringSubmatch(strings.TrimSpace(p.Desc))
		if m == nil {
			continue
		}
		v := oracleVersionFull(m[1])
		if best == "" || compareDotted(v, best) > 0 {
			best = v
		}
	}
	return best, nil
}

// oracleVersionFull turns a Release Update number into the form the database
// reports as v$instance.version_full. From 18c to 21c the fifth field of the
// number is the build date (19.3.0.0.190416), which version_full reports as
// 0 (19.3.0.0.0). From 23ai on the fifth field is part of the release
// (23.5.0.24.07) and stays.
func oracleVersionFull(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) == 5 && len(parts[4]) == 6 {
		parts[4] = "0"
	}
	return strings.Join(parts, ".")
}

// compareDotted compares two versions of dot-separated decimal fields.
func compareDotted(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// pathPattern returns the directories matching the patterns, in which only
// path segments may hold wildcards.
func pathPattern(patterns ...string) Locator {
	return func(fs afero.Fs) ([]Candidate, error) {
		res := []Candidate{}
		var errs []error
		for _, p := range patterns {
			dirs, err := globDirs(fs, p)
			if err != nil {
				errs = append(errs, err)
			}
			for _, d := range dirs {
				res = append(res, Candidate{Root: d, LocatedBy: LocatedByPath})
			}
		}
		return res, errors.Join(errs...)
	}
}

// globDirs expands pattern one segment at a time. Unlike afero.Glob, a
// directory that exists but cannot be listed is an error rather than no
// matches, so an unreadable directory never reads as an empty one.
func globDirs(fs afero.Fs, pattern string) ([]string, error) {
	dirs := []string{"/"}
	for _, seg := range strings.Split(strings.TrimPrefix(path.Clean(pattern), "/"), "/") {
		next := []string{}
		for _, dir := range dirs {
			if !strings.ContainsAny(seg, "*?[") {
				p := path.Join(dir, seg)
				if st, err := fs.Stat(p); err == nil && st.IsDir() {
					next = append(next, p)
				} else if err != nil && !isAbsent(err) {
					return nil, fmt.Errorf("cannot read %s: %w", p, err)
				}
				continue
			}
			entries, err := afero.ReadDir(fs, dir)
			if err != nil {
				if isAbsent(err) {
					continue
				}
				return nil, fmt.Errorf("cannot list %s: %w", dir, err)
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				if ok, err := path.Match(seg, e.Name()); err != nil {
					return nil, err
				} else if ok {
					next = append(next, path.Join(dir, e.Name()))
				}
			}
		}
		dirs = next
	}
	return dirs, nil
}

// isAbsent reports whether err says the path is not there, including a path
// below a file that is not a directory.
func isAbsent(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

func genericPurl(namespace, name, version string) string {
	return packageurl.NewPackageURL(packageurl.TypeGeneric, namespace, name, version, nil, "").ToString()
}

func cpes(vendor, product, version string) []string {
	res, err := cpe.NewPackage2Cpe(vendor, product, version, "", "")
	if err != nil {
		return nil
	}
	return res
}
