// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package installations

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The measured values below were read on 2026-11-03 by extracting the files
// from the image layers with crane and tar, and for the gvenzl images also by
// running Oracle's oraversion -compositeVersion inside them:
//
//   - 19c: an image built by Oracle's docker-images SingleInstance 19.3.0
//     Dockerfile, which unzips LINUX.X64_193000_db_home.zip and registers the
//     home with runInstaller and orainstRoot.sh. OPatch then applied the
//     Release Update Revision 19.9.1.
//   - 26ai: gvenzl/oracle-free:23-full, Oracle Database 26ai Free, whose home
//     is copied into the image with no package manager record.
//
// The fixtures keep the elements and attributes the parser reads, with the
// values copied unchanged, and leave out the rest of each file.

// Measured: 19c and 26ai, /etc/oraInst.loc
const measuredOraInstLoc = "inventory_loc=/opt/oracle/oraInventory\ninst_group=dba\n"

// Measured: 19c, <inventory>/ContentsXML/inventory.xml
const measured19cInventory = `<?xml version="1.0" standalone="yes" ?>
<INVENTORY>
<VERSION_INFO>
   <SAVED_WITH>12.2.0.7.0</SAVED_WITH>
   <MINIMUM_VER>2.1.0.6.0</MINIMUM_VER>
</VERSION_INFO>
<HOME_LIST>
<HOME NAME="OraDB19Home1" LOC="/opt/oracle/product/19c/dbhome_1" TYPE="O" IDX="1"/>
</HOME_LIST>
<COMPOSITEHOME_LIST>
</COMPOSITEHOME_LIST>
</INVENTORY>
`

// Measured: 19c, $ORACLE_HOME/inventory/ContentsXML/comps.xml (the one
// top-level component; the file lists hundreds below it)
const measured19cComps = `<?xml version="1.0" standalone="yes" ?>
<PRD_LIST>
<TL_LIST>
<COMP NAME="oracle.server" VER="19.0.0.0.0" BUILD_NUMBER="0" BUILD_TIME="20190417.011331" REP_VER="0.0.0.0.0" RELEASE="Production" INV_LOC="Components/oracle.server/19.0.0.0.0/1/" LANGS="ALL_LANGS" XML_INV_LOC="Components21/oracle.server/19.0.0.0.0/" ACT_INST_VER="12.2.0.7.0" DEINST_VER="11.2.0.0.0" INSTALL_TIME="2021.Mar.24 23:38:52 UTC" INST_LOC="/opt/oracle/product/19c/dbhome_1/oracle.server">
   <EXT_NAME>Oracle Database 19c</EXT_NAME>
</COMP>
</TL_LIST>
<PATCHSET_UPDATE_LIST>
</PATCHSET_UPDATE_LIST>
</PRD_LIST>
`

// Measured: 19c, $ORACLE_HOME/inventory/ContentsXML/oui-patch.xml, with the
// REF_LIST and BUG_LIST of each patch left out. The Release Update the zip
// shipped with (19.3) stays recorded after the 19.9.1 Revision was applied.
const measured19cPatches = `<?xml version='1.0' encoding='UTF-8'?>
<ONEOFF_LIST>
<ONEOFF REF_ID="29517242" UNIQ_ID="22862832" TYPE="upgrade" LANGS="en" ROLLBACK="F" XML_INV_LOC="oneoffs/29517242/" ACT_INST_VER="12.2.0.7.0" INSTALL_TIME="2019.Apr.18 07:21:17 UTC">
<DESC>Database Release Update : 19.3.0.0.190416 (29517242)</DESC>
<FILE_LIST/>
<PROPERTY_LIST/>
</ONEOFF>
<ONEOFF REF_ID="29585399" UNIQ_ID="22840393" TYPE="update" LANGS="en" ROLLBACK="F" XML_INV_LOC="oneoffs/29585399/" ACT_INST_VER="12.2.0.7.0" INSTALL_TIME="2019.Apr.18 07:21:33 UTC">
<DESC>OCW RELEASE UPDATE 19.3.0.0.0 (29585399)</DESC>
<FILE_LIST/>
<PROPERTY_LIST/>
</ONEOFF>
<ONEOFF REF_ID="32072711" UNIQ_ID="24023035" TYPE="upgrade" LANGS="en" ROLLBACK="F" XML_INV_LOC="oneoffs/32072711/" ACT_INST_VER="12.2.0.7.0" INSTALL_TIME="2021.Mar.24 23:35:48 UTC">
<DESC>Database Release Update Revision : 19.9.1.0.210119 (32072711)</DESC>
<FILE_LIST/>
<PROPERTY_LIST/>
</ONEOFF>
</ONEOFF_LIST>
`

// Measured: 26ai Free, /etc/oratab (its comment header left out)
const measured26aiOratab = "\n\n\n\nFREE:/opt/oracle/product/26ai/dbhomeFree:N\n"

// Measured: 26ai Free, $ORACLE_HOME/inventory/ContentsXML/comps.xml
const measured26aiComps = `<?xml version="1.0" standalone="yes" ?>
<PRD_LIST>
<TL_LIST>
<COMP NAME="oracle.server" VER="23.0.0.0.0" BUILD_NUMBER="0" BUILD_TIME="20260705.115145" REP_VER="0.0.0.0.0" RELEASE="Production" INV_LOC="Components/oracle.server/23.0.0.0.0/1/" LANGS="ALL_LANGS" XML_INV_LOC="Components21/oracle.server/23.0.0.0.0/" ACT_INST_VER="12.2.0.9.0" DEINST_VER="11.2.0.0.0" INSTALL_TIME="2026.Jul.05 20:28:52 UTC" INST_LOC="/opt/oracle/product/26ai/dbhomeFree/oracle.server">
   <EXT_NAME>Oracle Database 26ai</EXT_NAME>
</COMP>
</TL_LIST>
</PRD_LIST>
`

// Measured: 26ai Free, $ORACLE_HOME/inventory/ContentsXML/oui-patch.xml
const measured26aiPatches = `<?xml version="1.0" encoding="UTF-8"?>
<ONEOFF_LIST/>
`

func writeFiles(t *testing.T, fs afero.Fs, files map[string]string) {
	t.Helper()
	for p, content := range files {
		require.NoError(t, afero.WriteFile(fs, p, []byte(content), 0o644))
	}
}

func TestParseOraInstLoc(t *testing.T) {
	// Measured: 19c
	assert.Equal(t, "/opt/oracle/oraInventory", parseOraInstLoc(strings.NewReader(measuredOraInstLoc)))
	// Synthetic: spaces around the separator; no target showed this.
	assert.Equal(t, "/u01/app/oraInventory", parseOraInstLoc(strings.NewReader("inst_group=oinstall\n inventory_loc = /u01/app/oraInventory \n")))
	// Synthetic: no inventory_loc; no target showed this.
	assert.Equal(t, "", parseOraInstLoc(strings.NewReader("inst_group=oinstall\n")))
}

func TestParseOracleInventory(t *testing.T) {
	// Measured: 19c
	homes, err := parseOracleInventory([]byte(measured19cInventory))
	require.NoError(t, err)
	assert.Equal(t, []string{"/opt/oracle/product/19c/dbhome_1"}, homes)

	// Synthetic: a detached home stays in the inventory marked REMOVED="T";
	// no target showed this.
	homes, err = parseOracleInventory([]byte(`<INVENTORY><HOME_LIST>
<HOME NAME="OraDB19Home1" LOC="/u01/app/oracle/product/19.0.0/dbhome_1" TYPE="O" IDX="1"/>
<HOME NAME="OraDB19Home2" LOC="/u01/app/oracle/product/19.0.0/dbhome_2" TYPE="O" IDX="2" REMOVED="T"/>
</HOME_LIST></INVENTORY>`))
	require.NoError(t, err)
	assert.Equal(t, []string{"/u01/app/oracle/product/19.0.0/dbhome_1"}, homes)

	// Synthetic: a truncated file is an error, not an empty inventory.
	_, err = parseOracleInventory([]byte(`<INVENTORY><HOME_LIST><HOME LOC="/u01`))
	assert.Error(t, err)
}

func TestParseOratab(t *testing.T) {
	// Measured: 26ai Free
	assert.Equal(t, []string{"/opt/oracle/product/26ai/dbhomeFree"}, parseOratab(strings.NewReader(measured26aiOratab)))

	// Synthetic: comments, a trailing comment, the "*" SID that dbca writes
	// for a home without a database, and lines that name no absolute home;
	// no target showed these.
	got := parseOratab(strings.NewReader(`# comment
ORCL:/u01/app/oracle/product/19.0.0/dbhome_1:Y # production
*:/u01/app/oracle/product/19.0.0/dbhome_2:N
broken
REL:relative/home:N
`))
	assert.Equal(t, []string{"/u01/app/oracle/product/19.0.0/dbhome_1", "/u01/app/oracle/product/19.0.0/dbhome_2"}, got)
}

func TestParseOracleServerComponent(t *testing.T) {
	// Measured: 19c
	v, ok, err := parseOracleServerComponent([]byte(measured19cComps))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "19.0.0.0.0", v)

	// Measured: 26ai Free
	v, ok, err = parseOracleServerComponent([]byte(measured26aiComps))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "23.0.0.0.0", v)

	// Synthetic: a client home installs oracle.client, not oracle.server; no
	// target showed this.
	_, ok, err = parseOracleServerComponent([]byte(`<PRD_LIST><TL_LIST><COMP NAME="oracle.client" VER="19.0.0.0.0"/></TL_LIST></PRD_LIST>`))
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestParseOracleReleaseUpdate(t *testing.T) {
	// Measured: 19c. The 19.9.1 Revision, not the 19.3 Release Update listed
	// first, and not the clusterware update.
	v, err := parseOracleReleaseUpdate([]byte(measured19cPatches))
	require.NoError(t, err)
	assert.Equal(t, "19.9.1.0.0", v)

	// Measured: 26ai Free records no patches.
	v, err = parseOracleReleaseUpdate([]byte(measured26aiPatches))
	require.NoError(t, err)
	assert.Equal(t, "", v)

	// Synthetic: 19.10 sorts above 19.9 although it is lower as text; no
	// target showed this.
	v, err = parseOracleReleaseUpdate([]byte(`<ONEOFF_LIST>
<ONEOFF><DESC>Database Release Update : 19.10.0.0.210119 (32218454)</DESC></ONEOFF>
<ONEOFF><DESC>Database Release Update : 19.9.0.0.201020 (31771877)</DESC></ONEOFF>
</ONEOFF_LIST>`))
	require.NoError(t, err)
	assert.Equal(t, "19.10.0.0.0", v)

	// Synthetic: a 23ai Release Update, whose fifth field is part of the
	// release; no target showed this.
	v, err = parseOracleReleaseUpdate([]byte(`<ONEOFF_LIST><ONEOFF><DESC>Database Release Update : 23.5.0.24.07 (36741532)</DESC></ONEOFF></ONEOFF_LIST>`))
	require.NoError(t, err)
	assert.Equal(t, "23.5.0.24.07", v)

	// Synthetic: a truncated file is an error.
	_, err = parseOracleReleaseUpdate([]byte(`<ONEOFF_LIST><ONEOFF><DESC>Database`))
	assert.Error(t, err)
}

func TestOracleUSMVersion(t *testing.T) {
	// Measured: the gvenzl/oracle-free <tag>-full images on 2026-11-03. The
	// line is the one lib/usmvsn.pm carries; want is what oraversion
	// -compositeVersion reported in the same image.
	measured := []struct {
		image string
		line  string
		want  string
	}{
		{"23.3", "# USM VERSION FULL: 23.3.0.23.09", "23.3.0.23.09"},
		{"23.4", "# USM VERSION FULL: 23.4.0.24.05", "23.4.0.24.05"},
		{"23.5", "# USM VERSION FULL: 23.5.0.24.07", "23.5.0.24.07"},
		{"23.6", "# USM VERSION FULL: 23.6.0.24.10", "23.6.0.24.10"},
		{"23.7", "# USM VERSION FULL: 23.7.0.25.01", "23.7.0.25.01"},
		{"23.8", "# USM VERSION FULL: 23.8.0.25.04", "23.8.0.25.04"},
		{"23.9", "# USM VERSION FULL: 23.9.0.25.07", "23.9.0.25.07"},
		{"23.26.0", "# USM VERSION FULL: 23.26.0.0.0", "23.26.0.0.0"},
		{"23.26.1", "# USM VERSION FULL: 23.26.1.0.0", "23.26.1.0.0"},
		{"23.26.2", "# USM VERSION FULL: 23.26.2.0.0", "23.26.2.0.0"},
		{"23.26.3", "# USM VERSION FULL: 23.26.3.0.0", "23.26.3.0.0"},
	}
	for _, m := range measured {
		t.Run(m.image, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			writeFiles(t, fs, map[string]string{"/home/lib/usmvsn.pm": "#\n" + m.line + "\n#\n"})
			v, ok, err := oracleUSMVersion(fs, "/home")
			require.NoError(t, err)
			require.True(t, ok)
			assert.Equal(t, Version{Value: m.want, Source: SourceReleaseMetadata, File: "/home/lib/usmvsn.pm"}, v)
		})
	}

	t.Run("no USM VERSION FULL line", func(t *testing.T) {
		// Measured: the 19c home's usmvsn.pm has no such line.
		fs := afero.NewMemMapFs()
		writeFiles(t, fs, map[string]string{"/home/lib/usmvsn.pm": `our $LIBMAJVSN = "19";
our %USMVSN = (
    "MAJORVSN"      => "19",
    "MINORVSN"      => "0",
    "MIDTIERVSN"    => "0",
`})
		_, ok, err := oracleUSMVersion(fs, "/home")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("no usmvsn.pm", func(t *testing.T) {
		// Measured: the XE 18.4 and 21.3 homes have none.
		_, ok, err := oracleUSMVersion(afero.NewMemMapFs(), "/home")
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestCompareDotted(t *testing.T) {
	// Synthetic
	assert.Equal(t, 1, compareDotted("19.10.0.0.0", "19.9.1.0.0"))
	assert.Equal(t, -1, compareDotted("19.9.0.0.0", "19.9.1.0.0"))
	assert.Equal(t, 0, compareDotted("19.9.1.0.0", "19.9.1.0.0"))
	assert.Equal(t, 1, compareDotted("19.9.1", "19.9"))
}

func TestOracleVersionFull(t *testing.T) {
	// Measured: 19c, the Release Update the zip ships with
	assert.Equal(t, "19.3.0.0.0", oracleVersionFull("19.3.0.0.190416"))
	// Synthetic: 23ai keeps its fifth field
	assert.Equal(t, "23.5.0.24.07", oracleVersionFull("23.5.0.24.07"))
}

func TestDetectOracleDatabase(t *testing.T) {
	t.Run("19c zip install with a Release Update Revision", func(t *testing.T) {
		// Measured: 19c
		fs := afero.NewMemMapFs()
		writeFiles(t, fs, map[string]string{
			"/etc/oraInst.loc": measuredOraInstLoc,
			"/opt/oracle/oraInventory/ContentsXML/inventory.xml":                   measured19cInventory,
			"/opt/oracle/product/19c/dbhome_1/inventory/ContentsXML/comps.xml":     measured19cComps,
			"/opt/oracle/product/19c/dbhome_1/inventory/ContentsXML/oui-patch.xml": measured19cPatches,
		})

		got, err := Detect(fs, []Detector{oracleDatabase})
		require.NoError(t, err)
		assert.Equal(t, []Installation{{
			Name:          "oracle-database",
			Vendor:        "Oracle",
			Path:          "/opt/oracle/product/19c/dbhome_1",
			Version:       "19.9.1.0.0",
			VersionSource: SourcePatchInventory,
			VersionFile:   "/opt/oracle/product/19c/dbhome_1/inventory/ContentsXML/oui-patch.xml",
			LocatedBy:     LocatedByRegistry,
			Purl:          "pkg:generic/oracle/database@19.9.1.0.0",
			CPEs:          []string{"cpe:2.3:a:oracle:database_server:19.9.1.0.0:*:*:*:*:*:*:*"},
		}}, got)
	})

	t.Run("Free with no patches recorded reports the release usmvsn.pm names", func(t *testing.T) {
		// Measured: gvenzl/oracle-free:23.26.0-full, whose oraversion
		// -compositeVersion reports 23.26.0.0.0 while comps.xml and the
		// empty patch inventory say 23.0.0.0.0 and nothing. Only its oratab
		// is kept here, so the home is found through oratab rather than the
		// central inventory.
		fs := afero.NewMemMapFs()
		writeFiles(t, fs, map[string]string{
			"/etc/oratab": measured26aiOratab,
			"/opt/oracle/product/26ai/dbhomeFree/inventory/ContentsXML/comps.xml":     measured26aiComps,
			"/opt/oracle/product/26ai/dbhomeFree/inventory/ContentsXML/oui-patch.xml": measured26aiPatches,
			"/opt/oracle/product/26ai/dbhomeFree/lib/usmvsn.pm":                       "# USM VERSION FULL: 23.26.0.0.0\n",
		})

		got, err := Detect(fs, []Detector{oracleDatabase})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "/opt/oracle/product/26ai/dbhomeFree", got[0].Path)
		assert.Equal(t, LocatedByRegistry, got[0].LocatedBy)
		assert.Equal(t, "23.26.0.0.0", got[0].Version)
		assert.Equal(t, SourceReleaseMetadata, got[0].VersionSource)
		assert.Equal(t, "/opt/oracle/product/26ai/dbhomeFree/lib/usmvsn.pm", got[0].VersionFile)
	})

	t.Run("XE with neither reports its base release", func(t *testing.T) {
		// Measured: gvenzl/oracle-xe:21.3.0-full. Its home has no usmvsn.pm
		// and comps.xml names 21.0.0.0.0; oraversion -compositeVersion
		// reports 21.3.0.0.0, which no file read here carries.
		fs := afero.NewMemMapFs()
		writeFiles(t, fs, map[string]string{
			"/opt/oracle/product/21c/dbhomeXE/inventory/ContentsXML/comps.xml":     `<PRD_LIST><TL_LIST><COMP NAME="oracle.server" VER="21.0.0.0.0"/></TL_LIST></PRD_LIST>`,
			"/opt/oracle/product/21c/dbhomeXE/inventory/ContentsXML/oui-patch.xml": measured26aiPatches,
		})

		got, err := Detect(fs, []Detector{oracleDatabase})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "21.0.0.0.0", got[0].Version)
		assert.Equal(t, SourceBaseRelease, got[0].VersionSource)
		assert.Equal(t, "/opt/oracle/product/21c/dbhomeXE/inventory/ContentsXML/comps.xml", got[0].VersionFile)
	})

	t.Run("a Release Update wins over a lagging usmvsn.pm", func(t *testing.T) {
		// Synthetic: a patched home whose storage management library was
		// left at the release the home was installed with; the 19c image
		// measured here has a usmvsn.pm without the USM VERSION FULL line.
		fs := afero.NewMemMapFs()
		writeFiles(t, fs, map[string]string{
			"/opt/oracle/product/19c/dbhome_1/inventory/ContentsXML/comps.xml":     measured19cComps,
			"/opt/oracle/product/19c/dbhome_1/inventory/ContentsXML/oui-patch.xml": measured19cPatches,
			"/opt/oracle/product/19c/dbhome_1/lib/usmvsn.pm":                       "# USM VERSION FULL: 19.3.0.0.0\n",
		})

		got, err := Detect(fs, []Detector{oracleDatabase})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "19.9.1.0.0", got[0].Version)
		assert.Equal(t, SourcePatchInventory, got[0].VersionSource)
	})

	t.Run("home found by its path when nothing registers it", func(t *testing.T) {
		// Synthetic: the documented /u01 layout, with no oraInst.loc or
		// oratab; no target showed this.
		fs := afero.NewMemMapFs()
		writeFiles(t, fs, map[string]string{
			"/u01/app/oracle/product/19.0.0.0/dbhome_1/inventory/ContentsXML/comps.xml": measured19cComps,
		})

		got, err := Detect(fs, []Detector{oracleDatabase})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "/u01/app/oracle/product/19.0.0.0/dbhome_1", got[0].Path)
		assert.Equal(t, LocatedByPath, got[0].LocatedBy)
	})

	t.Run("client and grid homes are not database homes", func(t *testing.T) {
		// Synthetic: no target showed these.
		fs := afero.NewMemMapFs()
		writeFiles(t, fs, map[string]string{
			"/etc/oraInst.loc": measuredOraInstLoc,
			"/opt/oracle/oraInventory/ContentsXML/inventory.xml": `<INVENTORY><HOME_LIST>
<HOME NAME="OraClient19Home1" LOC="/opt/oracle/product/19c/client_1" TYPE="O" IDX="1"/>
<HOME NAME="OraGI19Home1" LOC="/u01/app/19.0.0/grid" TYPE="O" IDX="2" CRS="true"/>
</HOME_LIST></INVENTORY>`,
			"/opt/oracle/product/19c/client_1/inventory/ContentsXML/comps.xml": `<PRD_LIST><TL_LIST><COMP NAME="oracle.client" VER="19.0.0.0.0"/></TL_LIST></PRD_LIST>`,
			"/u01/app/19.0.0/grid/inventory/ContentsXML/comps.xml":             `<PRD_LIST><TL_LIST><COMP NAME="oracle.crs" VER="19.0.0.0.0"/></TL_LIST></PRD_LIST>`,
		})

		got, err := Detect(fs, []Detector{oracleDatabase})
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}
