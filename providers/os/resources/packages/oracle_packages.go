// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

// Oracle Database, installed the way enterprises install it (unzip the
// software, run runInstaller; this includes RAC, ASM and Grid Infrastructure),
// registers with neither rpm, dpkg nor Windows Add/Remove Programs. Release
// Updates are applied with OPatch, which is just as invisible. Without this
// manager `packages` reports no Oracle at all and nothing can be matched.
//
// Every Oracle home is reported as generic packages:
//
//	pkg:generic/oracle/database-server@<V>      a database home
//	pkg:generic/oracle/database-ojvm@<V>        the home's Oracle JVM component
//	pkg:generic/oracle/grid-infrastructure@<V>  a Grid Infrastructure home
//
// The purl type is "generic" because the purl spec has no Oracle type and the
// server maps every type it does not know to generic; the namespace is the
// fixed vendor "oracle" (never the platform name purl.NewPackageURL would
// inject), because the vulnerability catalog matches on type, namespace and
// name.
//
// Only database and Grid Infrastructure homes are reported. Client homes
// (oracle.client), the Enterprise Manager agent and WebLogic/Middleware homes
// are recognised and skipped: the catalog has no rows for them yet, and a
// package nothing can match is noise.
//
// Everything is read from files, never by running opatch or oraversion: that
// is cheap, needs no Oracle environment and works on offline images.
//
//   - Home discovery is the union of the central inventory (oraInst.loc ->
//     ContentsXML/inventory.xml), oratab, and on Windows the registry
//     (HKLM\SOFTWARE\ORACLE\KEY_<name>\ORACLE_HOME). Homes are deduplicated by
//     cleaned path.
//   - The home type comes from <home>/inventory/ContentsXML/comps.xml. Its
//     oracle.server version is the BASE release ("23.0.0.0.0"), never the
//     Release Update.
//   - The Release Update is in <home>/rdbms/admin/catconst.pm, which OPatch
//     replaces with every RU. Fallback: the applied one-off patches under
//     <home>/inventory/oneoffs. Last resort: the base release of comps.xml.
//
// Versions are normalised to the first three numeric components followed by
// ".0.0" (19.31.0.0.260421 -> 19.31.0.0.0), which is the shape of the
// catalog's ranges. The un-normalised value is kept in the "ru" qualifier.

// OraclePkgFormat is the format of the packages reported for Oracle homes.
const OraclePkgFormat = "oracle"

// oracleVendor is the publisher Oracle's own installers and Windows Add/Remove
// Programs name.
const oracleVendor = "Oracle Corporation"

// oracleSource is where every Oracle home comes from: the Oracle Universal
// Installer (runInstaller, setup.exe, gridSetup), whichever way the software
// reached the host (zip, RPM or a cloud image). The installer is not part of the
// operating system.
var oracleSource = Source{OSProvided: osProvided(false), Channel: ChannelInstaller, Name: "oracle-universal-installer"}

// oracleCPEs returns the NVD CPE of a component. NVD files every Oracle
// Database CVE, Grid Infrastructure (Clusterware, ASM) included, under the one
// product database_server, with Release Update ranges such as 19.3 to 19.23. It
// has no product for OJVM, and the database_server CPE at the OJVM version would
// claim every database CVE for a home whose database RU is newer, so OJVM gets
// none.
func oracleCPEs(name, version string) []string {
	if name == oracleNameOJVM {
		return nil
	}
	cpes, err := cpe.NewPackage2Cpe("oracle", "database_server", version, "", "")
	if err != nil {
		log.Debug().Err(err).Str("version", version).Msg("mql[packages]> oracle: could not build a CPE")
		return nil
	}
	return cpes
}

const (
	oracleNamespace = "oracle"

	oracleNameDatabase = "database-server"
	oracleNameOJVM     = "database-ojvm"
	oracleNameGrid     = "grid-infrastructure"

	// oracleMaxFileSize bounds every file read. comps.xml of a database home is
	// about 400 KB; nothing here is legitimately larger than a few MB.
	oracleMaxFileSize = 16 << 20
	// oracleMaxHomes and oracleMaxOneoffs bound a corrupt or hostile inventory.
	oracleMaxHomes   = 64
	oracleMaxOneoffs = 4096
)

// oracleUnixInstLocs and oracleUnixOratabs are where Oracle keeps the pointer
// to the central inventory and the list of database homes. Solaris uses
// /var/opt/oracle, everything else /etc.
var (
	oracleUnixInstLocs = []string{"/etc/oraInst.loc", "/var/opt/oracle/oraInst.loc"}
	oracleUnixOratabs  = []string{"/etc/oratab", "/var/opt/oracle/oratab"}
	oracleUnixMarkers  = slices.Concat(oracleUnixInstLocs, oracleUnixOratabs)
)

// oracleWindowsDefaultInventory is the central inventory the Windows installer
// uses when the registry does not say otherwise.
const oracleWindowsDefaultInventory = `C:\Program Files\Oracle\Inventory`

// hasOracleUnixMarkers reports whether the host has a file that can lead to an
// Oracle home. It is the cheap Stat that keeps hosts without Oracle from
// paying for anything else.
func hasOracleUnixMarkers(fs afero.Fs) bool {
	for _, p := range oracleUnixMarkers {
		if _, err := fs.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// OraclePkgManager reports the Oracle Database and Grid Infrastructure homes
// of a host.
type OraclePkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
	// windows selects the Windows layout: registry discovery and backslash paths.
	windows bool
}

func (o *OraclePkgManager) Name() string   { return "Oracle Home Package Manager" }
func (o *OraclePkgManager) Format() string { return OraclePkgFormat }

func (o *OraclePkgManager) Available() (map[string]PackageUpdate, error) {
	return map[string]PackageUpdate{}, nil
}

func (o *OraclePkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	return nil, nil
}

// List never fails: an Oracle home that cannot be read is logged and left out
// instead of failing the package list, which fails as a whole when any
// manager does, and the rest of the inventory must not be lost over Oracle.
func (o *OraclePkgManager) List() ([]Package, error) {
	var host *oracleHost
	var homes []oracleHome
	if o.windows {
		host = newOracleWindowsHost(o.conn)
		homes = discoverOracleWindowsHomes(host, readOracleWindowsRegistry(o.conn))
	} else {
		host = &oracleHost{fs: o.conn.FileSystem(), sep: "/", toFs: func(p string) (string, bool) { return p, true }}
		homes = discoverOracleUnixHomes(host)
	}
	return oraclePackages(host, homes, o.platform), nil
}

// oracleHost reads the files of a host. Paths are in the host's own spelling;
// toFs maps one to the path on fs (an offline Windows volume is addressed
// without its drive letter).
type oracleHost struct {
	fs   afero.Fs
	sep  string
	toFs func(string) (string, bool)
}

func (h *oracleHost) join(elem ...string) string {
	if h.sep == "/" {
		return path.Join(elem...)
	}
	out := strings.TrimRight(elem[0], `\/`)
	for _, e := range elem[1:] {
		out += `\` + strings.Trim(strings.ReplaceAll(e, "/", `\`), `\`)
	}
	return out
}

// clean returns p with one separator style and no trailing separator, so the
// same home reached through two sources compares equal. Windows paths compare
// case-insensitively, so the key is lower-cased there.
func (h *oracleHost) clean(p string) string {
	p = strings.TrimSpace(strings.Trim(strings.TrimSpace(p), `"`))
	if p == "" {
		return ""
	}
	if h.sep == "/" {
		if !strings.HasPrefix(p, "/") {
			return ""
		}
		return path.Clean(p)
	}
	p = strings.ReplaceAll(p, "/", `\`)
	for strings.Contains(p, `\\`) {
		p = strings.ReplaceAll(p, `\\`, `\`)
	}
	return strings.TrimRight(p, `\`)
}

func (h *oracleHost) key(p string) string {
	if h.sep == "/" {
		return p
	}
	return strings.ToLower(p)
}

// read returns the content of a file, or an error that says why not.
func (h *oracleHost) read(p string) ([]byte, error) {
	fp, ok := h.toFs(p)
	if !ok {
		return nil, afero.ErrFileNotFound
	}
	f, err := h.fs.Open(fp)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, oracleMaxFileSize))
}

func (h *oracleHost) dirNames(p string) ([]string, error) {
	fp, ok := h.toFs(p)
	if !ok {
		return nil, afero.ErrFileNotFound
	}
	return readDirNames(h.fs, fp)
}

// oracleHome is a home found by discovery, before it is looked at.
type oracleHome struct {
	Path string
	// CRS is set when the central inventory marks the home as Grid
	// Infrastructure.
	CRS bool
}

// oracleHomeSet collects homes, deduplicated by path.
type oracleHomeSet struct {
	host  *oracleHost
	seen  map[string]int
	homes []oracleHome
}

func newOracleHomeSet(h *oracleHost) *oracleHomeSet {
	return &oracleHomeSet{host: h, seen: map[string]int{}}
}

func (s *oracleHomeSet) add(p string, crs bool) {
	p = s.host.clean(p)
	if p == "" || len(s.homes) >= oracleMaxHomes {
		return
	}
	k := s.host.key(p)
	if i, ok := s.seen[k]; ok {
		s.homes[i].CRS = s.homes[i].CRS || crs
		return
	}
	s.seen[k] = len(s.homes)
	s.homes = append(s.homes, oracleHome{Path: p, CRS: crs})
}

// discoverOracleUnixHomes unions the central inventory and oratab.
func discoverOracleUnixHomes(h *oracleHost) []oracleHome {
	set := newOracleHomeSet(h)
	for _, loc := range oracleUnixInstLocs {
		data, err := h.read(loc)
		if err != nil {
			logOracleReadError(err, loc)
			continue
		}
		if inv := parseOraInstLoc(data); inv != "" {
			addInventoryHomes(h, set, inv)
		}
	}
	for _, tab := range oracleUnixOratabs {
		data, err := h.read(tab)
		if err != nil {
			logOracleReadError(err, tab)
			continue
		}
		for _, home := range parseOratab(data) {
			set.add(home, false)
		}
	}
	return set.homes
}

// logOracleReadError logs a read that failed. A file that does not exist is
// expected (only some of the candidate locations exist on any host) and stays
// at debug; a file that exists and cannot be read is a scan running without
// the rights to see Oracle, which the operator needs to hear about.
func logOracleReadError(err error, p string) {
	if isNotExist(err) {
		log.Debug().Str("path", p).Msg("mql[packages]> oracle: file not present")
		return
	}
	log.Warn().Err(err).Str("path", p).Msg("mql[packages]> oracle: could not read file, Oracle homes that depend on it are not reported")
}

func isNotExist(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, afero.ErrFileNotFound) {
		return true
	}
	// remote file systems report a missing file in their own words
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such file") || strings.Contains(msg, "not exist") ||
		strings.Contains(msg, "not found") || strings.Contains(msg, "cannot find")
}

// parseOraInstLoc returns the inventory_loc of an oraInst.loc file.
func parseOraInstLoc(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "inventory_loc") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parseOratab returns the home of every entry of an oratab file:
// "SID:ORACLE_HOME:Y|N". Comments and blank lines are ignored. The "*" SID
// and entries without an absolute home are kept out by the caller's cleaning.
func parseOratab(data []byte) []string {
	var homes []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		if home := strings.TrimSpace(parts[1]); home != "" {
			homes = append(homes, home)
		}
	}
	return homes
}

// addInventoryHomes reads <inventory>/ContentsXML/inventory.xml:
//
//	<HOME NAME="OraDB19Home1" LOC="/u01/app/oracle/product/19.0.0/dbhome_1" TYPE="O" IDX="1"/>
//	<HOME NAME=".." LOC=".." TYPE="O" IDX="2" CRS="true"/>
//	<HOME NAME=".." LOC=".." TYPE="O" IDX="3" REMOVED="T"/>
//
// A removed home is skipped: its entry stays in the inventory after
// deinstallation. Only the attributes are read, so the parse tolerates the
// rest of the file.
func addInventoryHomes(h *oracleHost, set *oracleHomeSet, inventoryDir string) {
	p := h.join(inventoryDir, "ContentsXML", "inventory.xml")
	data, err := h.read(p)
	if err != nil {
		logOracleReadError(err, p)
		return
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			if err != io.EOF {
				log.Debug().Err(err).Str("path", p).Msg("mql[packages]> oracle: could not parse the central inventory")
			}
			return
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "HOME" {
			continue
		}
		var loc string
		var crs, removed bool
		for _, a := range se.Attr {
			switch strings.ToUpper(a.Name.Local) {
			case "LOC":
				loc = a.Value
			case "CRS":
				crs = strings.EqualFold(a.Value, "true")
			case "REMOVED":
				removed = strings.EqualFold(a.Value, "t") || strings.EqualFold(a.Value, "true")
			}
		}
		if loc != "" && !removed {
			set.add(loc, crs)
		}
	}
}

// oracleComps is what the home's comps.xml tells.
type oracleComps struct {
	// Server, JavaVM and CRS are the versions of the top-level components
	// oracle.server, oracle.javavm.server and oracle.crs, "" when absent.
	Server, JavaVM, CRS string
	// Client is set when the home has the oracle.client component.
	Client bool
	// Edition is "ee", "se2", "se" or "" when the file does not say.
	Edition     string
	InstallTime time.Time
}

// parseOracleComps reads <home>/inventory/ContentsXML/comps.xml. The file has
// two lists: <TL_LIST> holds the top-level components of the home
// (oracle.server, oracle.crs, oracle.client) and <COMP_LIST> everything they
// are made of (oracle.javavm.server, oracle.options). Only <COMP> elements that
// are direct children of one of them count; the same names also appear as
// <REF> elements inside other components.
func parseOracleComps(data []byte) oracleComps {
	var c oracleComps
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false

	var depth int
	var listDepth int // depth of the TL_LIST or COMP_LIST element, 0 when not inside
	var topLevel bool // the list is TL_LIST
	var comp string   // NAME of the top-level COMP being read
	var compDepth int
	var inExtName bool
	var optionsText string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch t.Name.Local {
			case "TL_LIST", "COMP_LIST":
				listDepth, topLevel = depth, t.Name.Local == "TL_LIST"
			case "COMP":
				if listDepth == 0 || depth != listDepth+1 {
					continue
				}
				compDepth = depth
				var name, ver, installed string
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "NAME":
						name = a.Value
					case "VER":
						ver = a.Value
					case "INSTALL_TIME":
						installed = a.Value
					}
				}
				comp = name
				switch {
				case !topLevel && (name == "oracle.server" || name == "oracle.crs" || name == "oracle.client"):
					// a top-level component listed as a part of another
				case name == "oracle.server":
					c.Server = ver
					if tm, err := time.Parse("2006.Jan.02 15:04:05 MST", installed); err == nil {
						c.InstallTime = tm
					}
				case name == "oracle.javavm.server":
					c.JavaVM = ver
				case name == "oracle.crs":
					c.CRS = ver
				case name == "oracle.client":
					c.Client = true
				}
			case "EXT_NAME":
				inExtName = comp == "oracle.options" && depth == compDepth+1
			case "VAR":
				// Unverified on a real installer-written file: the response
				// file name of the edition. Kept because it is exact when
				// present; the EXT_NAME of oracle.options is the verified source.
				var name, value string
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "NAME":
						name = a.Value
					case "VALUE":
						value = a.Value
					}
				}
				if name == "oracle_install_db_InstallEdition" {
					if e := oracleEdition(value); e != "" {
						c.Edition = e
					}
				}
			}
		case xml.CharData:
			if inExtName {
				optionsText += string(t)
			}
		case xml.EndElement:
			if t.Name.Local == "EXT_NAME" {
				inExtName = false
			}
			if t.Name.Local == "COMP" && depth == compDepth {
				comp = ""
			}
			if (t.Name.Local == "TL_LIST" || t.Name.Local == "COMP_LIST") && depth == listDepth {
				listDepth = 0
			}
			depth--
		}
	}
	if c.Edition == "" {
		// Verified on Oracle Database 26ai: the oracle.options component is
		// titled "Enterprise Edition Options".
		c.Edition = oracleEdition(optionsText)
	}
	return c
}

// oracleEdition maps an edition spelling ("EE", "SE2", "Enterprise Edition
// Options", "Standard Edition 2 Options") to the qualifier value.
func oracleEdition(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	switch {
	case l == "":
		return ""
	case l == "ee" || strings.Contains(l, "enterprise"):
		return "ee"
	case l == "se2" || strings.Contains(l, "standard edition 2"):
		return "se2"
	case l == "se" || l == "see" || strings.Contains(l, "standard"):
		return "se"
	}
	return ""
}

var (
	oracleFullVersionRe = regexp.MustCompile(`CATCONST_FULL_VERSION\s*=>\s*'(\d+(?:\.\d+)+)'`)
	oracleBuildLabelRe  = regexp.MustCompile(`CATCONST_BUILD_LABEL\s*=>\s*'RDBMS_(\d+(?:\.\d+)+)`)

	oracleVersionRe = `(\d+\.\d+\.\d+\.\d+\.\d+)`
	// The descriptions of applied patches, from the <patch_description> of
	// inventory/oneoffs/<id>/etc/config/inventory.xml (layout verified on a real
	// 19.3 home: "Database Release Update : 19.3.0.0.190416 (29517242)",
	// "OCW RELEASE UPDATE 19.3.0.0.0 (29585399)"). Only the description is read:
	// the same file lists the fixed bugs, whose free text can name other
	// releases. The wording is matched case-insensitively:
	//
	//   Database Release Update : 19.25.0.0.241015 (36912597)
	//   WINDOWS DATABASE BUNDLE PATCH 19.25.0.0.241015
	//   GI RELEASE UPDATE 19.25.0.0.241015
	//   OJVM RELEASE UPDATE: 19.25.0.0.241015 (36878697)
	oracleDBPatchRe   = regexp.MustCompile(`(?i)(?:DATABASE\s+(?:RELEASE\s+UPDATE(?:\s+REVISION)?|BUNDLE\s+PATCH|RU)|GI\s+RELEASE\s+UPDATE(?:\s+REVISION)?)\s*:?\s*` + oracleVersionRe)
	oraclePatchDescRe = regexp.MustCompile(`<patch_description>([^<]*)</patch_description>`)
	oracleOJVMPatchRe = regexp.MustCompile(`(?i)OJVM\s+(?:RELEASE\s+UPDATE|BUNDLE\s+PATCH|PATCH)\s*:?\s*` + oracleVersionRe)

	// oracleBaseRelease is the first release update of a release, which is
	// what a home of that release runs before any patch. Oracle's ranges start
	// there ("19.3-19.31"), so the base release from comps.xml (19.0.0.0.0)
	// would sit below every range and hide every finding.
	oracleBaseRelease = map[int]string{19: "19.3.0", 21: "21.3.0"}
)

// parseCatconst returns the release update version of rdbms/admin/catconst.pm:
//
//	use constant CATCONST_FULL_VERSION => '23.26.4.0.0';
//	use constant CATCONST_BUILD_LABEL   => 'RDBMS_19.21.0.0.0DBRU_LINUX.X64_230923';
//
// CATCONST_FULL_VERSION may be absent (19c) or carry only the base release,
// so the version in the build label is read too and the higher of the two wins.
func parseCatconst(data []byte) string {
	best := ""
	for _, re := range []*regexp.Regexp{oracleFullVersionRe, oracleBuildLabelRe} {
		if m := re.FindSubmatch(data); m != nil {
			if v := string(m[1]); best == "" || compareOracleVersions(v, best) > 0 {
				best = v
			}
		}
	}
	return best
}

// compareOracleVersions compares dotted numeric versions component-wise.
func compareOracleVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
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

// normalizeOracleVersion keeps the first three numeric components:
// 19.31.0.0.260421 -> 19.31.0, 23.5.0.24.07 -> 23.5.0, 23.26.4.0.0 -> 23.26.4.
// Oracle's advisories bound by release update (last affected 19.31), and the
// server compares Generic versions as semver, which takes three components. It reports false for a value with fewer than three
// numeric components.
func normalizeOracleVersion(v string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) < 3 {
		return "", false
	}
	for _, p := range parts[:3] {
		if p == "" {
			return "", false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return "", false
		}
	}
	n := func(p string) string { i, _ := strconv.Atoi(p); return strconv.Itoa(i) }
	return n(parts[0]) + "." + n(parts[1]) + "." + n(parts[2]), true
}

// trimOracleZeros drops all-zero components after the third ("23.26.4.0.0"
// becomes "23.26.4"), so a label that only pads the version is not repeated.
func trimOracleZeros(v string) string {
	parts := strings.Split(v, ".")
	for len(parts) > 3 && parts[len(parts)-1] == "0" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, ".")
}

func oracleFeatureRelease(v string) int {
	major, _, _ := strings.Cut(v, ".")
	n, _ := strconv.Atoi(major)
	return n
}

// oracleOneoffs holds the highest release update versions found in the applied
// patches of a home.
type oracleOneoffs struct {
	DB, OJVM string
}

// readOracleOneoffs scans <home>/inventory/oneoffs/*/etc/config/inventory.xml.
func readOracleOneoffs(h *oracleHost, home string) oracleOneoffs {
	var res oracleOneoffs
	dir := h.join(home, "inventory", "oneoffs")
	names, err := h.dirNames(dir)
	if err != nil {
		return res
	}
	if len(names) > oracleMaxOneoffs {
		names = names[:oracleMaxOneoffs]
	}
	sort.Strings(names)
	for _, n := range names {
		data, err := h.read(h.join(dir, n, "etc", "config", "inventory.xml"))
		if err != nil {
			continue
		}
		for _, d := range oraclePatchDescRe.FindAllSubmatch(data, -1) {
			desc := d[1]
			for _, m := range oracleDBPatchRe.FindAllSubmatch(desc, -1) {
				if v := string(m[1]); res.DB == "" || compareOracleVersions(v, res.DB) > 0 {
					res.DB = v
				}
			}
			for _, m := range oracleOJVMPatchRe.FindAllSubmatch(desc, -1) {
				if v := string(m[1]); res.OJVM == "" || compareOracleVersions(v, res.OJVM) > 0 {
					res.OJVM = v
				}
			}
		}
	}
	return res
}

// oraclePackages turns the homes into packages. Nothing here fails: a home
// that cannot be read or typed is logged and skipped.
func oraclePackages(h *oracleHost, homes []oracleHome, platform *inventory.Platform) []Package {
	var pkgs []Package
	for _, home := range homes {
		pkgs = append(pkgs, oracleHomePackages(h, home, platform)...)
	}
	return pkgs
}

func oracleHomePackages(h *oracleHost, home oracleHome, platform *inventory.Platform) []Package {
	compsPath := h.join(home.Path, "inventory", "ContentsXML", "comps.xml")
	data, err := h.read(compsPath)
	if err != nil {
		// Without comps.xml the home cannot be typed. oratab also lists homes
		// that are gone or that belong to products with no comps.xml.
		logOracleReadError(err, compsPath)
		return nil
	}
	comps := parseOracleComps(data)

	grid := home.CRS || comps.CRS != ""
	switch {
	case grid:
	case comps.Server != "":
	default:
		// oracle.client, the Enterprise Manager agent, WebLogic/Middleware and
		// anything else: not reported, the catalog has no rows for them.
		log.Debug().Str("home", home.Path).Bool("client", comps.Client).Msg("mql[packages]> oracle: home is not a database or grid home, skipping")
		return nil
	}

	base := comps.Server
	if grid && comps.CRS != "" {
		base = comps.CRS
	}

	// Release update: catconst.pm, then the applied patches, then the base
	// release of the home.
	var ru string
	if cat, err := h.read(h.join(home.Path, "rdbms", "admin", "catconst.pm")); err == nil {
		ru = parseCatconst(cat)
	} else {
		logOracleReadError(err, h.join(home.Path, "rdbms", "admin", "catconst.pm"))
	}
	oneoffs := readOracleOneoffs(h, home.Path)
	if ru == "" {
		ru = oneoffs.DB
	}
	if ru == "" {
		ru = base
		if b, ok := oracleBaseRelease[oracleFeatureRelease(base)]; ok {
			ru = b
		}
	}
	version, ok := normalizeOracleVersion(ru)
	if !ok {
		log.Warn().Str("home", home.Path).Str("version", ru).Msg("mql[packages]> oracle: could not read a version for the home, skipping")
		return nil
	}

	arch := ""
	if platform != nil {
		arch = platform.Arch
	}
	build := func(name, title, ver, ruLabel string) Package {
		q := map[string]string{}
		if comps.Edition != "" && name != oracleNameGrid {
			q["edition"] = comps.Edition
		}
		// The RU label is kept only when it says more than the version: the
		// date stamp of 19.25.0.0.241015, not the zeros of 23.26.4.0.0.
		if ruLabel != "" && trimOracleZeros(ruLabel) != ver {
			q["ru"] = ruLabel
		}
		// A nil platform on purpose: the namespace is the fixed vendor, and the
		// platform would add a distro qualifier that means nothing here.
		src := oracleSource
		opts := []purl.Modifier{purl.WithNamespace(oracleNamespace), purl.WithQualifiers(q)}
		if arch != "" {
			opts = append(opts, purl.WithArch(arch))
		}
		return Package{
			// The name IS the purl name. The server rebuilds the purl it matches
			// with from the package name (it restores the name's casing that
			// way), so a display name here ("Oracle Database Server") would turn
			// pkg:generic/oracle/database-server into
			// pkg:generic/oracle/Oracle%20Database%20Server and match nothing.
			// The display name is the catalog's; the title goes in Description.
			Name:        name,
			Version:     ver,
			Arch:        arch,
			Format:      OraclePkgFormat,
			Vendor:      oracleVendor,
			CPEs:        oracleCPEs(name, ver),
			Description: title + " home " + home.Path,
			InstallDate: comps.InstallTime,
			PUrl:        purl.NewPackageURL(nil, purl.TypeGeneric, name, ver, opts...).String(),
			Files:       []FileRecord{{Path: home.Path}},
			// the home is the only "file" listed; without this the files field stays
			// empty, because it is only read when the manager says it has them
			FilesAvailable: PkgFilesIncluded,
			source:         &src,
		}
	}

	if grid {
		return []Package{build(oracleNameGrid, "Oracle Grid Infrastructure", version, ru)}
	}

	pkgs := []Package{build(oracleNameDatabase, "Oracle Database Server", version, ru)}
	if comps.JavaVM != "" {
		if jv, jru, ok := oracleJVMVersion(comps, oneoffs, ru); ok {
			pkgs = append(pkgs, build(oracleNameOJVM, "Oracle Database OJVM", jv, jru))
		}
	}
	return pkgs
}

// oracleJVMVersion decides the version of the Oracle JVM component:
//
//  1. an applied OJVM patch (OJVM RELEASE UPDATE / BUNDLE PATCH) names it;
//  2. from feature release 23 the database RU updates the OJVM itself (verified
//     on 26ai: javavm/install/jvmrui.sql carries the same version as the DB
//     RU), so it is the DB RU;
//  3. on 19c and 21c, without an OJVM patch, the OJVM is still at the base
//     release: 19.3.0.0.0 / 21.3.0.0.0, the first RU numbers of those
//     releases. That is intentional: an unpatched OJVM must produce findings
//     even when the database itself is patched.
//
// Other releases fall back to the version of the oracle.javavm.server
// component, normalised.
func oracleJVMVersion(comps oracleComps, oneoffs oracleOneoffs, dbRU string) (version, ruLabel string, ok bool) {
	pick := func(raw string) (string, string, bool) {
		v, ok := normalizeOracleVersion(raw)
		return v, raw, ok
	}
	if oneoffs.OJVM != "" {
		return pick(oneoffs.OJVM)
	}
	if oracleFeatureRelease(comps.JavaVM) >= 23 {
		return pick(dbRU)
	}
	if base, ok := oracleBaseRelease[oracleFeatureRelease(comps.JavaVM)]; ok {
		return base, "", true
	}
	return pick(comps.JavaVM)
}

// resolveOraclePkgManager returns the manager for Oracle homes when the target
// can have any, nil otherwise. Oracle Database runs on Linux, Solaris, AIX and
// Windows (also HP-UX, which this scanner does not support); macOS and the
// BSDs have no Oracle Database server. On Unix the probe is a Stat, so a host
// without Oracle pays nothing more. On Windows there is no cheap probe, so the
// manager is always returned there and its List reads two registry keys (one
// small PowerShell run on a remote target, a hive read on an offline image).
func resolveOraclePkgManager(conn shared.Connection, platform *inventory.Platform) OperatingSystemPkgManager {
	switch {
	case platform.Name == "windows":
		if conn.Capabilities().Has(shared.Capability_RunCommand) || conn.Type() == shared.Type_FileSystem || conn.Type() == shared.Type_Device {
			return &OraclePkgManager{conn: conn, platform: platform, windows: true}
		}
	case platform.IsFamily("linux") || platform.Name == "solaris" || platform.Name == "aix":
		if hasOracleUnixMarkers(conn.FileSystem()) {
			return &OraclePkgManager{conn: conn, platform: platform}
		}
	}
	return nil
}
