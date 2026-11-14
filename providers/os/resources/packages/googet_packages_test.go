// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: the shape of googet's client.PackageState as encoding/json writes
// it (exported Go field names, PkgSpec fields without omitempty always
// present), modelled on the guest environment packages of a Compute Engine
// Windows image. No target was measured for these values.
const googetAgentState = `{
  "SourceRepo": "https://packages.cloud.google.com/yuck/repos/google-compute-engine-stable",
  "DownloadURL": "https://packages.cloud.google.com/yuck/pool/google-compute-engine-windows.x86_64.20240109.00.0@1.goo",
  "Checksum": "aa11",
  "LocalPath": "C:\\ProgramData\\GooGet\\cache\\google-compute-engine-windows.x86_64.20240109.00.0@1.goo",
  "UnpackDir": "C:\\ProgramData\\GooGet\\cache\\google-compute-engine-windows.x86_64.20240109.00.0@1",
  "PackageSpec": {
    "Name": "google-compute-engine-windows",
    "Version": "20240109.00.0@1",
    "Arch": "x86_64",
    "Description": "Google Compute Engine Windows agent",
    "License": "http://www.apache.org/licenses/LICENSE-2.0",
    "Authors": "Google Inc.",
    "Replaces": null,
    "Conflicts": null,
    "Provides": null,
    "Install": {"Path": "install.ps1"},
    "Uninstall": {"Path": "uninstall.ps1"},
    "Verify": {"Path": ""},
    "ExternalProgramName": ""
  },
  "InstalledFiles": {
    "C:\\Program Files\\Google\\Compute Engine\\agent": "",
    "C:\\Program Files\\Google\\Compute Engine\\agent\\GCEWindowsAgent.exe": "0f3e",
    "C:\\Program Files\\Google\\Compute Engine\\agent\\GCEWindowsAgentManifest.json": "77ab"
  },
  "InstallDate": 1704844800,
  "InstalledApp": {"Name": "", "Reg": ""}
}`

// Synthetic: a package converted from a pre-database googet.state, which
// carries no InstallDate.
const googetNoDateState = `{
  "SourceRepo": "",
  "PackageSpec": {"Name": "googet", "Version": "2.18.3@0", "Arch": "x86_64"},
  "InstalledFiles": {"C:\\ProgramData\\GooGet\\googet.exe": "c0ffee"}
}`

func TestParseGooGetState(t *testing.T) {
	states, err := parseGooGetState([]byte("[" + googetAgentState + "," + googetNoDateState + "]"))
	require.NoError(t, err)
	require.Len(t, states, 2)

	s := states[0]
	require.NotNil(t, s.PackageSpec)
	assert.Equal(t, "https://packages.cloud.google.com/yuck/repos/google-compute-engine-stable", s.SourceRepo)
	assert.Equal(t, "google-compute-engine-windows", s.PackageSpec.Name)
	assert.Equal(t, "20240109.00.0@1", s.PackageSpec.Version)
	assert.Equal(t, "x86_64", s.PackageSpec.Arch)
	assert.Equal(t, "Google Compute Engine Windows agent", s.PackageSpec.Description)
	assert.Equal(t, "http://www.apache.org/licenses/LICENSE-2.0", s.PackageSpec.License)
	assert.Equal(t, "Google Inc.", s.PackageSpec.Authors)
	assert.Equal(t, int64(1704844800), s.InstallDate)
	assert.Len(t, s.InstalledFiles, 3)

	assert.Equal(t, int64(0), states[1].InstallDate)
}

func TestParseGooGetStateMalformed(t *testing.T) {
	_, err := parseGooGetState([]byte(`{"not": "an array"`))
	assert.Error(t, err)
}

func TestGooGetPackages(t *testing.T) {
	states, err := parseGooGetState([]byte("[" + googetAgentState + "," + googetNoDateState + `,{"SourceRepo":"x"}]`))
	require.NoError(t, err)

	pkgs := googetPackages(states)
	// The entry without a PackageSpec is skipped.
	require.Len(t, pkgs, 2)

	agent := pkgs[0]
	assert.Equal(t, "google-compute-engine-windows", agent.Name)
	assert.Equal(t, "20240109.00.0@1", agent.Version)
	assert.Equal(t, "x86_64", agent.Arch)
	assert.Equal(t, GooGetPkgFormat, agent.Format)
	assert.Equal(t, "Google Compute Engine Windows agent", agent.Description)
	assert.Equal(t, "http://www.apache.org/licenses/LICENSE-2.0", agent.License)
	assert.Equal(t, "Google Inc.", agent.Vendor)
	assert.Equal(t, time.Unix(1704844800, 0).UTC(), agent.InstallDate)
	assert.Equal(t,
		"pkg:googet/google-compute-engine-windows@20240109.00.0%401?arch=x86_64&repository_url=https:%2F%2Fpackages.cloud.google.com%2Fyuck%2Frepos%2Fgoogle-compute-engine-stable",
		agent.PUrl)
	assert.Equal(t, PkgFilesIncluded, agent.FilesAvailable)
	// The directory entry (empty checksum) is dropped; files are sorted.
	assert.Equal(t, []FileRecord{
		{Path: `C:\Program Files\Google\Compute Engine\agent\GCEWindowsAgent.exe`, Digest: PkgDigest{Value: "0f3e", Algorithm: "sha256"}},
		{Path: `C:\Program Files\Google\Compute Engine\agent\GCEWindowsAgentManifest.json`, Digest: PkgDigest{Value: "77ab", Algorithm: "sha256"}},
	}, agent.Files)

	noDate := pkgs[1]
	assert.True(t, noDate.InstallDate.IsZero(), "an absent InstallDate stays zero, not 1970")
	assert.Equal(t, "pkg:googet/googet@2.18.3%400?arch=x86_64", noDate.PUrl)
}

func TestNewGooGetPurl(t *testing.T) {
	assert.Equal(t, "pkg:googet/certgen@1.1.0%401", newGooGetPurl("certgen", "1.1.0@1", "", ""))
	assert.Equal(t, "pkg:googet/certgen@1.1.0%401?arch=noarch", newGooGetPurl("certgen", "1.1.0@1", "noarch", ""))
}

// writeGooGetDB creates a googet.db with the schema googetdb.createDB writes
// and the given pkg_json rows.
func writeGooGetDB(t *testing.T, rows ...string) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "googet.db")
	db, err := sql.Open("sqlite", p)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS InstalledPackages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pkg_name TEXT NOT NULL,
			pkg_arch TEXT NOT NULL,
			pkg_ver TEXT NOT NULL,
			pkg_json BLOB NOT NULL,
			UNIQUE(pkg_name, pkg_arch) ON CONFLICT REPLACE
		) STRICT;`)
	require.NoError(t, err)
	for i, r := range rows {
		_, err = db.Exec(`INSERT INTO InstalledPackages (pkg_name, pkg_ver, pkg_arch, pkg_json) VALUES (?, ?, ?, ?)`,
			string(rune('a'+i)), "1", "x86_64", []byte(r))
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())
	data, err := os.ReadFile(p)
	require.NoError(t, err)
	return data
}

func TestReadGooGetDB(t *testing.T) {
	// A row that is not JSON is skipped without hiding the others.
	data := writeGooGetDB(t, googetAgentState, "{broken", googetNoDateState)

	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, `C:\ProgramData\GooGet\googet.db`, data, 0o644))

	states, err := readGooGetDB(fs, `C:\ProgramData\GooGet\googet.db`)
	require.NoError(t, err)
	require.Len(t, states, 2)
	assert.Equal(t, "google-compute-engine-windows", states[0].PackageSpec.Name)
	assert.Equal(t, "googet", states[1].PackageSpec.Name)
}

func TestGooGetList(t *testing.T) {
	db := writeGooGetDB(t, googetAgentState)
	stale := []byte("[" + googetNoDateState + "]")

	t.Run("database wins over the stale state file", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, `C:\ProgramData\GooGet\googet.db`, db, 0o644))
		require.NoError(t, afero.WriteFile(fs, `C:\ProgramData\GooGet\googet.state`, stale, 0o644))

		pkgs, err := (&GooGetPkgManager{conn: &memFsConn{fs: fs}}).List()
		require.NoError(t, err)
		require.Len(t, pkgs, 1)
		assert.Equal(t, "google-compute-engine-windows", pkgs[0].Name)
	})

	t.Run("state file when there is no database", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, `C:\ProgramData\GooGet\googet.state`, stale, 0o644))

		pkgs, err := (&GooGetPkgManager{conn: &memFsConn{fs: fs}}).List()
		require.NoError(t, err)
		require.Len(t, pkgs, 1)
		assert.Equal(t, "googet", pkgs[0].Name)
	})

	t.Run("mounted system volume", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "ProgramData/GooGet/googet.db", db, 0o644))

		assert.True(t, hasGooGet(fs))
		pkgs, err := (&GooGetPkgManager{conn: &memFsConn{fs: fs}}).List()
		require.NoError(t, err)
		require.Len(t, pkgs, 1)
		assert.Equal(t, "google-compute-engine-windows", pkgs[0].Name)
	})

	t.Run("unreadable database does not fail the inventory", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, `C:\ProgramData\GooGet\googet.db`, []byte("not a sqlite file"), 0o644))

		pkgs, err := (&GooGetPkgManager{conn: &memFsConn{fs: fs}}).List()
		require.NoError(t, err)
		assert.Empty(t, pkgs)
	})
}

func TestHasGooGet(t *testing.T) {
	fs := afero.NewMemMapFs()
	assert.False(t, hasGooGet(fs))

	// A directory named like the database is not the database.
	require.NoError(t, fs.MkdirAll(`C:\ProgramData\GooGet\googet.db`, 0o755))
	assert.False(t, hasGooGet(fs))

	require.NoError(t, afero.WriteFile(fs, `C:\ProgramData\GooGet\googet.state`, []byte("[]"), 0o644))
	assert.True(t, hasGooGet(fs))
}

func TestDropGooGetRegistryDuplicates(t *testing.T) {
	pkgs := []Package{
		// Synthetic: the Add/Remove Programs rows googet writes (DisplayName
		// "GooGet - <name>", DisplayVersion the googet version).
		{Name: "GooGet - googet", Version: "2.18.5@0", Format: "windows/app"},
		{Name: "GooGet - google-compute-engine-windows", Version: "20240109.00.0@1", Format: "windows/app"},
		// googet has no state for this one, so its registry row stays.
		{Name: "GooGet - orphan", Version: "1.0.0@1", Format: "windows/app"},
		{Name: "Google Chrome", Version: "131.0.0.0", Format: "windows/app"},
		{Name: "googet", Version: "2.18.5@0", Format: GooGetPkgFormat},
		{Name: "google-compute-engine-windows", Version: "20240109.00.0@1", Format: GooGetPkgFormat},
		// Same name, but not a registry row: kept.
		{Name: "GooGet - googet", Version: "1", Format: "windows/appx"},
	}
	aligned := []int{0, 1, 2, 3, 4, 5, 6}

	gotPkgs, gotAligned := DropGooGetRegistryDuplicates(pkgs, aligned)

	names := make([]string, len(gotPkgs))
	for i := range gotPkgs {
		names[i] = gotPkgs[i].Format + ":" + gotPkgs[i].Name
	}
	assert.Equal(t, []string{
		"windows/app:GooGet - orphan",
		"windows/app:Google Chrome",
		"googet:googet",
		"googet:google-compute-engine-windows",
		"windows/appx:GooGet - googet",
	}, names)
	assert.Equal(t, []int{2, 3, 4, 5, 6}, gotAligned)
	// The input is not modified in place.
	assert.Equal(t, "GooGet - googet", pkgs[0].Name)
}

func TestDropGooGetRegistryDuplicatesWithoutGooGetState(t *testing.T) {
	pkgs := []Package{{Name: "GooGet - googet", Format: "windows/app"}}
	got, _ := DropGooGetRegistryDuplicates(pkgs, []int{0})
	assert.Equal(t, pkgs, got)
}
