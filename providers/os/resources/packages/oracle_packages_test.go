// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	packageurl "github.com/package-url/packageurl-go"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
)

// testdata/oracle/linux26ai and testdata/oracle/linux19c are hand-written. They
// reproduce the layout, element names and values (versions, build labels, patch
// descriptions, paths) that were read from two real hosts: an Oracle Database
// 26ai Free container (aarch64) and a 19.3 home installed from the zip (x86_64,
// with the RU 19.3 and OCW 19.3 patch records). Comments, Oracle's file headers
// and every element the code does not read are left out; the fixed-bug texts
// are placeholders. The other tests write their files inline, following the
// layouts documented in oracle_packages.go, because no OPatch-patched, Grid
// Infrastructure or Windows home was available.

// oracleTestConn is a connection over an in-memory file system.
type oracleTestConn struct {
	shared.Connection
	fs    afero.Fs
	asset *inventory.Asset
	typ   shared.ConnectionType
}

func (c *oracleTestConn) FileSystem() afero.Fs              { return c.fs }
func (c *oracleTestConn) Asset() *inventory.Asset           { return c.asset }
func (c *oracleTestConn) Capabilities() shared.Capabilities { return shared.Capability_File }
func (c *oracleTestConn) Type() shared.ConnectionType       { return c.typ }

func newOracleFs(t *testing.T, files map[string]string) afero.Fs {
	t.Helper()
	mem := afero.NewMemMapFs()
	for p, content := range files {
		require.NoError(t, afero.WriteFile(mem, p, []byte(content), 0o644))
	}
	return mem
}

// copyOracleFixture copies testdata/oracle/<name> into an in-memory file
// system at its mirrored absolute paths.
func copyOracleFixture(t *testing.T, mem afero.Fs, name string) {
	t.Helper()
	root := filepath.Join("testdata", "oracle", name)
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		return afero.WriteFile(mem, "/"+filepath.ToSlash(rel), data, 0o644)
	}))
}

func linuxHost(fsys afero.Fs) (*oracleHost, *inventory.Platform) {
	return &oracleHost{fs: fsys, sep: "/", toFs: func(p string) (string, bool) { return p, true }},
		&inventory.Platform{Name: "oraclelinux", Family: []string{"redhat", "linux", "unix", "os"}, Arch: "aarch64"}
}

func listOracle(t *testing.T, fsys afero.Fs) []Package {
	t.Helper()
	host, platform := linuxHost(fsys)
	return oraclePackages(host, discoverOracleUnixHomes(host), platform)
}

func purls(pkgs []Package) []string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = p.PUrl
	}
	return out
}

func TestOracle26aiFreeHome(t *testing.T) {
	mem := afero.NewMemMapFs()
	copyOracleFixture(t, mem, "linux26ai")

	pkgs := listOracle(t, mem)
	require.Len(t, pkgs, 2)

	assert.Equal(t, "database-server", pkgs[0].Name)
	assert.Equal(t, "23.26.4", pkgs[0].Version)
	assert.Equal(t, "aarch64", pkgs[0].Arch)
	assert.Equal(t, OraclePkgFormat, pkgs[0].Format)
	assert.Equal(t, "pkg:generic/oracle/database-server@23.26.4?arch=aarch64&edition=ee", pkgs[0].PUrl)
	assert.Equal(t, []FileRecord{{Path: "/opt/oracle/product/26ai/dbhomeFree"}}, pkgs[0].Files)
	assert.False(t, pkgs[0].InstallDate.IsZero())

	// from feature release 23 the DB RU updates the OJVM itself
	assert.Equal(t, "database-ojvm", pkgs[1].Name)
	assert.Equal(t, "pkg:generic/oracle/database-ojvm@23.26.4?arch=aarch64&edition=ee", pkgs[1].PUrl)
}

const oracleCompsHeader = `<?xml version="1.0" standalone="yes" ?>
<PRD_LIST>
<TL_LIST>
`

func compsXML(server, javavm, crs, client string) string {
	var b strings.Builder
	b.WriteString(oracleCompsHeader)
	if server != "" {
		b.WriteString(`<COMP NAME="oracle.server" VER="` + server + `" INSTALL_TIME="2024.Jan.10 10:00:00 UTC">` + "\n   <EXT_NAME>Oracle Database</EXT_NAME>\n</COMP>\n")
	}
	if crs != "" {
		b.WriteString(`<COMP NAME="oracle.crs" VER="` + crs + `">` + "\n</COMP>\n")
	}
	if client != "" {
		b.WriteString(`<COMP NAME="oracle.client" VER="` + client + `">` + "\n</COMP>\n")
	}
	b.WriteString("</TL_LIST>\n<COMP_LIST>\n")
	if javavm != "" {
		b.WriteString(`<COMP NAME="oracle.javavm.server" VER="` + javavm + `">` + "\n   <REF NAME=\"oracle.server\" VER=\"" + server + "\"/>\n</COMP>\n")
	}
	b.WriteString(`<COMP NAME="oracle.options" VER="19.0.0.0.0">` + "\n   <EXT_NAME>Enterprise Edition Options</EXT_NAME>\n</COMP>\n")
	b.WriteString("</COMP_LIST>\n</PRD_LIST>\n")
	return b.String()
}

func catconstLabel(label string) string {
	return "package catconst;\nuse constant CATCONST_BUILD_LABEL   => '" + label + "';\n"
}

func inventoryXML(homes ...string) string {
	return `<INVENTORY><HOME_LIST>` + strings.Join(homes, "\n") + `</HOME_LIST></INVENTORY>`
}

func TestOracle19cBuildLabelOnly(t *testing.T) {
	// 19c: no CATCONST_FULL_VERSION, the RU is only in the build label.
	home := "/u01/app/oracle/product/19.0.0/dbhome_1"
	pkgs := listOracle(t, newOracleFs(t, map[string]string{
		"/etc/oraInst.loc": "inventory_loc=/u01/app/oraInventory\ninst_group=oinstall\n",
		"/u01/app/oraInventory/ContentsXML/inventory.xml": inventoryXML(`<HOME NAME="OraDB19Home1" LOC="` + home + `" TYPE="O" IDX="1"/>`),
		home + "/inventory/ContentsXML/comps.xml":         compsXML("19.0.0.0.0", "19.0.0.0.0", "", ""),
		home + "/rdbms/admin/catconst.pm":                 catconstLabel("RDBMS_19.21.0.0.0DBRU_LINUX.X64_230923"),
	}))
	require.Len(t, pkgs, 2)
	assert.Equal(t, "pkg:generic/oracle/database-server@19.21.0?arch=aarch64&edition=ee", pkgs[0].PUrl)
	// no OJVM patch applied: the OJVM sits at the base release on purpose
	assert.Equal(t, "pkg:generic/oracle/database-ojvm@19.3.0?arch=aarch64&edition=ee", pkgs[1].PUrl)
}

func TestOracleOneoffFallback(t *testing.T) {
	home := "/u01/app/oracle/product/19.0.0/dbhome_1"
	files := map[string]string{
		"/etc/oratab": "# comment\n\nORCL:" + home + ":Y\n",
		home + "/inventory/ContentsXML/comps.xml": compsXML("19.0.0.0.0", "19.0.0.0.0", "", ""),
		// older and newer RU, and an OJVM patch; the highest of each wins
		home + "/inventory/oneoffs/36912597/etc/config/inventory.xml": `<oneoff_inventory><patch_description>Database Release Update : 19.25.0.0.241015 (36912597)</patch_description></oneoff_inventory>`,
		home + "/inventory/oneoffs/35320081/etc/config/inventory.xml": `<oneoff_inventory><patch_description>Database Release Update : 19.20.0.0.230718 (35320081)</patch_description></oneoff_inventory>`,
		home + "/inventory/oneoffs/36878697/etc/config/inventory.xml": `<oneoff_inventory><patch_description>OJVM RELEASE UPDATE: 19.24.0.0.240716 (36878697)</patch_description></oneoff_inventory>`,
	}
	pkgs := listOracle(t, newOracleFs(t, files))
	require.Len(t, pkgs, 2)
	assert.Equal(t, "pkg:generic/oracle/database-server@19.25.0?arch=aarch64&edition=ee&ru=19.25.0.0.241015", pkgs[0].PUrl)
	assert.Equal(t, "pkg:generic/oracle/database-ojvm@19.24.0?arch=aarch64&edition=ee&ru=19.24.0.0.240716", pkgs[1].PUrl)

	// Windows wording of the same
	files[home+"/inventory/oneoffs/36912597/etc/config/inventory.xml"] = `<patch_description>WINDOWS DATABASE BUNDLE PATCH 19.26.0.0.250121</patch_description>`
	pkgs = listOracle(t, newOracleFs(t, files))
	assert.Contains(t, pkgs[0].PUrl, "database-server@19.26.0?")
}

func TestOracleNoRUFallsBackToBaseRelease(t *testing.T) {
	home := "/opt/oracle/product/21c/dbhome_1"
	pkgs := listOracle(t, newOracleFs(t, map[string]string{
		"/etc/oratab": "X:" + home + ":N\n",
		home + "/inventory/ContentsXML/comps.xml": compsXML("21.0.0.0.0", "21.0.0.0.0", "", ""),
	}))
	require.Len(t, pkgs, 2)
	// the base release maps to the first RU, which Oracle's ranges start at
	assert.Equal(t, "21.3.0", pkgs[0].Version)
	assert.Equal(t, "21.3.0", pkgs[1].Version)
}

func TestOracleGridInfrastructure(t *testing.T) {
	grid := "/u01/app/19.0.0/grid"
	pkgs := listOracle(t, newOracleFs(t, map[string]string{
		"/etc/oraInst.loc": "inventory_loc=/u01/app/oraInventory\n",
		"/etc/oratab":      "+ASM:" + grid + ":N\n",
		"/u01/app/oraInventory/ContentsXML/inventory.xml": inventoryXML(`<HOME NAME="OraGI19Home1" LOC="` + grid + `" TYPE="O" IDX="1" CRS="true"/>`),
		grid + "/inventory/ContentsXML/comps.xml":         compsXML("", "", "19.0.0.0.0", ""),
		grid + "/rdbms/admin/catconst.pm":                 catconstLabel("RDBMS_19.27.0.0.0DBRU_LINUX.X64_250415"),
	}))
	// reached through both the inventory and oratab, reported once, no OJVM
	require.Len(t, pkgs, 1)
	assert.Equal(t, "grid-infrastructure", pkgs[0].Name)
	assert.Equal(t, "pkg:generic/oracle/grid-infrastructure@19.27.0?arch=aarch64", pkgs[0].PUrl)
}

func TestOracleRemovedClientAndMultipleHomes(t *testing.T) {
	db1 := "/u01/app/oracle/product/19.0.0/dbhome_1"
	db2 := "/u01/app/oracle/product/19.0.0/dbhome_2"
	gone := "/u01/app/oracle/product/12.2.0/dbhome_1"
	client := "/u01/app/oracle/product/19.0.0/client_1"
	pkgs := listOracle(t, newOracleFs(t, map[string]string{
		"/etc/oraInst.loc": "inventory_loc=/u01/app/oraInventory\n",
		"/u01/app/oraInventory/ContentsXML/inventory.xml": inventoryXML(
			`<HOME NAME="a" LOC="`+db1+`" TYPE="O" IDX="1"/>`,
			`<HOME NAME="b" LOC="`+db2+`/" TYPE="O" IDX="2"/>`,
			`<HOME NAME="c" LOC="`+gone+`" TYPE="O" IDX="3" REMOVED="T"/>`,
			`<HOME NAME="d" LOC="`+client+`" TYPE="O" IDX="4"/>`,
		),
		db1 + "/inventory/ContentsXML/comps.xml":    compsXML("19.0.0.0.0", "", "", ""),
		db1 + "/rdbms/admin/catconst.pm":            catconstLabel("RDBMS_19.21.0.0.0DBRU_LINUX.X64_230923"),
		db2 + "/inventory/ContentsXML/comps.xml":    compsXML("19.0.0.0.0", "", "", ""),
		db2 + "/rdbms/admin/catconst.pm":            catconstLabel("RDBMS_19.25.0.0.0DBRU_LINUX.X64_241015"),
		gone + "/inventory/ContentsXML/comps.xml":   compsXML("12.2.0.1.0", "", "", ""),
		client + "/inventory/ContentsXML/comps.xml": compsXML("", "", "", "19.0.0.0.0"),
	}))
	// the removed home and the client home are not reported; no OJVM component
	require.Len(t, pkgs, 2)
	assert.Equal(t, "19.21.0", pkgs[0].Version)
	assert.Equal(t, "19.25.0", pkgs[1].Version)
	assert.NotEqual(t, pkgs[0].Files, pkgs[1].Files)
}

func TestOracleUnreadableFileDoesNotFail(t *testing.T) {
	home := "/u01/app/oracle/product/19.0.0/dbhome_1"
	mem := newOracleFs(t, map[string]string{
		"/etc/oratab": "ORCL:" + home + ":Y\n",
		home + "/inventory/ContentsXML/comps.xml": compsXML("19.0.0.0.0", "", "", ""),
	})
	host, platform := linuxHost(&denyFs{Fs: mem, deny: "comps.xml"})
	pkgs := oraclePackages(host, discoverOracleUnixHomes(host), platform)
	assert.Empty(t, pkgs)

	// an unreadable catconst.pm falls back to the base release
	host, platform = linuxHost(&denyFs{Fs: mem, deny: "catconst.pm"})
	pkgs = oraclePackages(host, discoverOracleUnixHomes(host), platform)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "19.3.0", pkgs[0].Version)
}

type denyFs struct {
	afero.Fs
	deny string
}

func (d *denyFs) Open(name string) (afero.File, error) {
	if strings.HasSuffix(name, d.deny) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return d.Fs.Open(name)
}

func TestNormalizeOracleVersion(t *testing.T) {
	for in, want := range map[string]string{
		"19.31.0.0.260421": "19.31.0",
		"23.5.0.24.07":     "23.5.0",
		"23.26.4.0.0":      "23.26.4",
		"19.0.0.0.0":       "19.0.0",
		"21.3.0":           "21.3.0",
	} {
		got, ok := normalizeOracleVersion(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, got, in)
	}
	for _, bad := range []string{"", "19", "19.x.0.0.0", "19.3"} {
		_, ok := normalizeOracleVersion(bad)
		assert.False(t, ok, bad)
	}
}

func TestParseCatconst(t *testing.T) {
	// the two constants as the 26ai home declares them
	assert.Equal(t, "23.26.4.0.0", parseCatconst([]byte("use constant CATCONST_FULL_VERSION => '23.26.4.0.0';\nuse constant CATCONST_BUILD_LABEL   => 'RDBMS_23.26.4.0.0DBRU_LINUX.ARM64_261007.1';\n")))
	// a base-only FULL_VERSION does not hide the RU in the label
	assert.Equal(t, "19.21.0.0.0", parseCatconst([]byte("CATCONST_FULL_VERSION => '19.0.0.0.0';\nCATCONST_BUILD_LABEL   => 'RDBMS_19.21.0.0.0DBRU_LINUX.X64_230923';")))
	assert.Equal(t, "19.21.0.0.0", parseCatconst([]byte("CATCONST_BUILD_LABEL   => 'RDBMS_19.21.0.0.0DBRU_WINDOWS.X64_230923';")))
	assert.Equal(t, "", parseCatconst([]byte("nothing")))
}

func TestOracleSolarisInstLoc(t *testing.T) {
	home := "/u01/oracle/product/19c"
	pkgs := listOracle(t, newOracleFs(t, map[string]string{
		"/var/opt/oracle/oratab":                  "ORCL:" + home + ":N\n",
		home + "/inventory/ContentsXML/comps.xml": compsXML("19.0.0.0.0", "", "", ""),
	}))
	require.Len(t, pkgs, 1)
}

func TestResolveSystemPkgManagersOracle(t *testing.T) {
	platform := &inventory.Platform{Name: "someotherrpmdistro", Family: []string{"linux", "unix", "os"}}
	mk := func(files map[string]string) *oracleTestConn {
		return &oracleTestConn{fs: newOracleFs(t, files), asset: &inventory.Asset{Platform: platform}}
	}

	pms, err := ResolveSystemPkgManagers(mk(map[string]string{"/var/lib/rpm/x": "", "/etc/oratab": "X:/u01:N\n"}))
	require.NoError(t, err)
	assert.Equal(t, []string{"Rpm Package Manager", "Oracle Home Package Manager"}, managerNames(pms))

	pms, err = ResolveSystemPkgManagers(mk(map[string]string{"/var/lib/rpm/x": ""}))
	require.NoError(t, err)
	assert.Len(t, pms, 1)
}

// fakeOracleRegistry serves the Oracle keys of a SOFTWARE hive.
type fakeOracleRegistry map[string][]registry.RegistryKeyItem

func (f fakeOracleRegistry) Items(p string) ([]registry.RegistryKeyItem, error) {
	if i, ok := f[p]; ok {
		return i, nil
	}
	return nil, os.ErrNotExist
}

func (f fakeOracleRegistry) Children(p string) ([]registry.RegistryKeyChild, error) {
	var out []registry.RegistryKeyChild
	prefix := p + `\`
	found := false
	for k := range f {
		if k == p {
			found = true
		}
		if strings.HasPrefix(k, prefix) && !strings.Contains(k[len(prefix):], `\`) {
			out = append(out, registry.RegistryKeyChild{Name: k[len(prefix):]})
		}
	}
	if !found && len(out) == 0 {
		return nil, os.ErrNotExist
	}
	return out, nil
}

func regStr(k, v string) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{Key: k, Value: registry.RegistryKeyValue{Kind: registry.SZ, String: v}}
}

func TestOracleWindowsRegistryDiscovery(t *testing.T) {
	// SYNTHETIC registry and home, offline layout: the volume is addressed
	// without its drive letter.
	home := `C:\app\oracle\product\19.0.0\dbhome_1`
	removed := `C:\app\oracle\product\12.2.0\dbhome_1`
	reg := readOracleRegistry(fakeOracleRegistry{
		`ORACLE`:                     {regStr("inst_loc", `C:\Oracle\Inventory`)},
		`ORACLE\KEY_OraDB19Home1`:    {regStr("ORACLE_HOME", home), regStr("ORACLE_HOME_NAME", "OraDB19Home1")},
		`ORACLE\KEY_OraDb12Home1`:    {regStr("ORACLE_HOME", removed)},
		`WOW6432Node\ORACLE`:         nil,
		`WOW6432Node\ORACLE\KEY_Cli`: {regStr("ORACLE_HOME", `C:\app\client`)},
	})
	assert.Equal(t, `C:\Oracle\Inventory`, reg.InstLoc)
	assert.ElementsMatch(t, []string{home, removed, `C:\app\client`}, reg.Homes)

	mem := newOracleFs(t, map[string]string{
		"Oracle/Inventory/ContentsXML/inventory.xml": inventoryXML(
			`<HOME NAME="OraDB19Home1" LOC="`+home+`" TYPE="O" IDX="1"/>`,
			`<HOME NAME="OraDb12Home1" LOC="`+removed+`" TYPE="O" IDX="2" REMOVED="T"/>`,
		),
		"app/oracle/product/19.0.0/dbhome_1/inventory/ContentsXML/comps.xml": compsXML("19.0.0.0.0", "19.0.0.0.0", "", ""),
		// Windows build label wording, and a path with different case in the registry
		"app/oracle/product/19.0.0/dbhome_1/rdbms/admin/catconst.pm": catconstLabel("RDBMS_19.21.0.0.0DBRU_WINDOWS.X64_230923"),
	})
	host := &oracleHost{fs: mem, sep: `\`, toFs: mountedSystemDrivePath}
	// the registry still lists the removed home; it has no comps.xml, so it is
	// not reported, and the same home from the registry and the inventory is
	// reported once
	reg.Homes = []string{home, strings.ToUpper(home), removed}
	homes := discoverOracleWindowsHomes(host, reg)
	pkgs := oraclePackages(host, homes, &inventory.Platform{Name: "windows", Arch: "x86_64"})
	require.Len(t, pkgs, 2)
	assert.Equal(t, "pkg:generic/oracle/database-server@19.21.0?arch=x86_64&edition=ee", pkgs[0].PUrl)
	assert.Equal(t, "pkg:generic/oracle/database-ojvm@19.3.0?arch=x86_64&edition=ee", pkgs[1].PUrl)
	assert.Equal(t, home, pkgs[0].Files[0].Path)
}

func TestOracleWindowsDefaultInventory(t *testing.T) {
	// no registry inst_loc: the default central inventory is read
	home := `C:\oracle\19c`
	mem := newOracleFs(t, map[string]string{
		"Program Files/Oracle/Inventory/ContentsXML/inventory.xml": inventoryXML(`<HOME NAME="h" LOC="` + home + `" TYPE="O" IDX="1"/>`),
		"oracle/19c/inventory/ContentsXML/comps.xml":               compsXML("19.0.0.0.0", "", "", ""),
	})
	host := &oracleHost{fs: mem, sep: `\`, toFs: mountedSystemDrivePath}
	pkgs := oraclePackages(host, discoverOracleWindowsHomes(host, oracleWinRegistry{}), &inventory.Platform{Name: "windows"})
	require.Len(t, pkgs, 1)
	assert.Equal(t, "pkg:generic/oracle/database-server@19.3.0?edition=ee", pkgs[0].PUrl)
}

func TestParseOracleRegistryScriptOutput(t *testing.T) {
	for name, tc := range map[string]struct {
		in    string
		inst  string
		homes []string
	}{
		"array":  {`{"InstLoc":"C:\\inv","Homes":["C:\\a","C:\\b"]}`, `C:\inv`, []string{`C:\a`, `C:\b`}},
		"single": {`{"InstLoc":"","Homes":"C:\\a"}`, "", []string{`C:\a`}},
		"none":   {`{"InstLoc":"","Homes":null}`, "", nil},
		"empty":  {``, "", nil},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := parseOracleRegistry(strings.NewReader(tc.in))
			require.NoError(t, err)
			assert.Equal(t, tc.inst, r.InstLoc)
			assert.Equal(t, tc.homes, r.Homes)
		})
	}
}

// TestOraclePackageNameIsPurlName pins the platform convention the server relies
// on: it rebuilds the purl it matches with from the package name, so the two must
// be the same.
func TestOraclePackageNameIsPurlName(t *testing.T) {
	mem := afero.NewMemMapFs()
	copyOracleFixture(t, mem, "linux26ai")
	pkgs := listOracle(t, mem)
	require.NotEmpty(t, pkgs)
	for _, p := range pkgs {
		parsed, err := packageurl.FromString(p.PUrl)
		require.NoError(t, err)
		assert.Equal(t, parsed.Name, p.Name, p.PUrl)
	}
}

func linux19cHost(t *testing.T, mem afero.Fs) []Package {
	t.Helper()
	host, platform := linuxHost(mem)
	platform.Arch = "x86_64"
	return oraclePackages(host, discoverOracleUnixHomes(host), platform)
}

// TestOracleReal19cHome runs on the 19.3 home of testdata/oracle/linux19c:
// the central inventory names it, oratab is empty, catconst.pm says 19.3 and
// no OJVM patch is applied. The purls are those the scan of that host
// reported.
func TestOracle19cZipHome(t *testing.T) {
	mem := afero.NewMemMapFs()
	copyOracleFixture(t, mem, "linux19c")

	pkgs := linux19cHost(t, mem)
	assert.Equal(t, []string{
		"pkg:generic/oracle/database-server@19.3.0?arch=x86_64&edition=ee",
		"pkg:generic/oracle/database-ojvm@19.3.0?arch=x86_64&edition=ee",
	}, purls(pkgs))
	assert.Equal(t, []FileRecord{{Path: "/u01/app/oracle/product/19.0.0/dbhome_1"}}, pkgs[0].Files)
}

// TestOracleReal19cOneoffs drops catconst.pm from the 19.3 home, so the release
// update comes from the OPatch records: the database RU
// 29517242 names 19.3.0.0.190416, the OCW RU 29585399 is not a database RU.
func TestOracle19cOneoffs(t *testing.T) {
	home := "/u01/app/oracle/product/19.0.0/dbhome_1"
	mem := afero.NewMemMapFs()
	copyOracleFixture(t, mem, "linux19c")
	require.NoError(t, mem.Remove(home+"/rdbms/admin/catconst.pm"))

	assert.Equal(t, []string{
		"pkg:generic/oracle/database-server@19.3.0?arch=x86_64&edition=ee&ru=19.3.0.0.190416",
		"pkg:generic/oracle/database-ojvm@19.3.0?arch=x86_64&edition=ee",
	}, purls(linux19cHost(t, mem)))

	// A fixed-bug text naming a later RU must not raise the version;
	// only <patch_description> is read.
	ru := home + "/inventory/oneoffs/29517242/etc/config/inventory.xml"
	data, err := afero.ReadFile(mem, ru)
	require.NoError(t, err)
	bug := `<bug description="DATABASE RELEASE UPDATE 19.99.0.0.991231 REGRESSION" number="1"/>`
	data = []byte(strings.Replace(string(data), "<base_bugs>", "<base_bugs>\n        "+bug, 1))
	require.Contains(t, string(data), bug)
	require.NoError(t, afero.WriteFile(mem, ru, data, 0o644))
	assert.Contains(t, linux19cHost(t, mem)[0].PUrl, "database-server@19.3.0?")
}
