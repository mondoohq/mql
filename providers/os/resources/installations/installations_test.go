// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package installations

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deniedFs refuses every path below one of its prefixes, as a scan without
// the Oracle install group sees the 0770 central inventory.
type deniedFs struct {
	afero.Fs
	denied []string
}

func (d deniedFs) refuses(name string) bool {
	for _, p := range d.denied {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func (d deniedFs) Open(name string) (afero.File, error) {
	if d.refuses(name) {
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrPermission}
	}
	return d.Fs.Open(name)
}

func (d deniedFs) Stat(name string) (os.FileInfo, error) {
	if d.refuses(name) {
		return nil, &os.PathError{Op: "stat", Path: name, Err: os.ErrPermission}
	}
	return d.Fs.Stat(name)
}

func TestDetectSkipsUnreadableSourceWhenAnotherFindsTheHome(t *testing.T) {
	// Synthetic: the inventory is unreadable, the home under it is not; the
	// measured 19c files are used for the home.
	mem := afero.NewMemMapFs()
	writeFiles(t, mem, map[string]string{
		"/etc/oraInst.loc": measuredOraInstLoc,
		"/opt/oracle/oraInventory/ContentsXML/inventory.xml":                   measured19cInventory,
		"/opt/oracle/product/19c/dbhome_1/inventory/ContentsXML/comps.xml":     measured19cComps,
		"/opt/oracle/product/19c/dbhome_1/inventory/ContentsXML/oui-patch.xml": measured19cPatches,
	})
	fs := deniedFs{Fs: mem, denied: []string{"/opt/oracle/oraInventory"}}

	got, err := Detect(fs, []Detector{oracleDatabase})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, LocatedByPath, got[0].LocatedBy)
	assert.Equal(t, "19.9.1.0.0", got[0].Version)
}

func TestDetectReportsUnreadableSourceWhenNothingWasFound(t *testing.T) {
	// Synthetic: the inventory is unreadable and no home sits at a
	// documented path, so an empty list would claim there is no Oracle.
	mem := afero.NewMemMapFs()
	writeFiles(t, mem, map[string]string{
		"/etc/oraInst.loc": "inventory_loc=/u02/oraInventory\n",
		"/u02/oraInventory/ContentsXML/inventory.xml": measured19cInventory,
	})
	fs := deniedFs{Fs: mem, denied: []string{"/u02/oraInventory"}}

	got, err := Detect(fs, []Detector{oracleDatabase})
	assert.ErrorIs(t, err, os.ErrPermission)
	assert.Empty(t, got)
}

func TestDetectFindsEachRootOnce(t *testing.T) {
	// Synthetic: inventory, oratab and the documented path all name the same
	// home; the measured 19c files are used for it.
	fs := afero.NewMemMapFs()
	writeFiles(t, fs, map[string]string{
		"/etc/oraInst.loc": measuredOraInstLoc,
		"/etc/oratab":      "ORCLCDB:/opt/oracle/product/19c/dbhome_1/:Y\n",
		"/opt/oracle/oraInventory/ContentsXML/inventory.xml":               measured19cInventory,
		"/opt/oracle/product/19c/dbhome_1/inventory/ContentsXML/comps.xml": measured19cComps,
	})

	got, err := Detect(fs, []Detector{oracleDatabase})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, LocatedByRegistry, got[0].LocatedBy)
}

func TestDetectReportsHomeWithUnreadableVersion(t *testing.T) {
	// Synthetic: the patch inventory cannot be read, so the base release is
	// reported rather than nothing.
	mem := afero.NewMemMapFs()
	writeFiles(t, mem, map[string]string{
		"/opt/oracle/product/19c/dbhome_1/inventory/ContentsXML/comps.xml":     measured19cComps,
		"/opt/oracle/product/19c/dbhome_1/inventory/ContentsXML/oui-patch.xml": measured19cPatches,
	})
	fs := deniedFs{Fs: mem, denied: []string{"/opt/oracle/product/19c/dbhome_1/inventory/ContentsXML/oui-patch.xml"}}

	got, err := Detect(fs, []Detector{oracleDatabase})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "19.0.0.0.0", got[0].Version)
	assert.Equal(t, SourceInstallMetadata, got[0].VersionSource)
}

func TestDetectWithoutAnyOracleFiles(t *testing.T) {
	// Synthetic: a host without Oracle.
	got, err := Detect(afero.NewMemMapFs(), Detectors)
	require.NoError(t, err)
	assert.Empty(t, got)
}
