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

// Measured: pkg_json rows of C:\ProgramData\GooGet\googet.db on a Compute
// Engine windows-2022 image (googet 20261003.00.0@1), 2026-11-14. Copied
// verbatim from the database with the sqlite3 CLI except ReleaseNotes, which
// is left out. `googet installed` on that VM listed the same name, arch and
// version for each.
//
// googet itself: InstalledFiles records directories with an empty checksum.
const googetMeasuredGooGet = `{"SourceRepo":"https://packages.cloud.google.com/yuck/repos/google-compute-engine-stable","DownloadURL":"https://packages.cloud.google.com/yuck/pool/google-compute-engine-stable/e1674fc9ea06609451ccc5726e585a660e298c47ed5fd4283c27ef382c2fe356-googet-x86_64-20261003.00.0@1.goo","Checksum":"e1674fc9ea06609451ccc5726e585a660e298c47ed5fd4283c27ef382c2fe356","LocalPath":"C:\\ProgramData\\GooGet\\cache\\googet.x86_64.20261003.00.0@1.goo","UnpackDir":"","PackageSpec":{"Name":"googet","Version":"20261003.00.0@1","Arch":"x86_64","Description":"GooGet Package Manager","License":"http://www.apache.org/licenses/LICENSE-2.0","Authors":"Google LLC","Replaces":null,"Conflicts":null,"Provides":null,"Install":{"Path":"install_googet.ps1"},"Uninstall":{},"Verify":{},"Files":{"LICENSE":"<ProgramData>/GooGet/LICENSE.txt","THIRD_PARTY_LICENSES":"<ProgramData>/GooGet/THIRD_PARTY_LICENSES/","googet.exe":"<ProgramData>/GooGet/googet.exe"},"ExternalProgramName":""},"InstalledFiles":{"C:\\ProgramData\\GooGet\\LICENSE.txt":"c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4","C:\\ProgramData\\GooGet\\THIRD_PARTY_LICENSES":"","C:\\ProgramData\\GooGet\\THIRD_PARTY_LICENSES\\PowerShell":"","C:\\ProgramData\\GooGet\\THIRD_PARTY_LICENSES\\PowerShell\\openssh-portable":"","C:\\ProgramData\\GooGet\\THIRD_PARTY_LICENSES\\PowerShell\\openssh-portable\\LICENCE":"d6807e99f3d159145c659060f57c3fa74e109faa39326dbfc38674cb550fd104","C:\\ProgramData\\GooGet\\googet.exe":"93f927526830d64dd9437b229c3ae1a2779f9a36596183e6b0a10e3066e36e74"},"InstallDate":1792986102,"InstalledApp":{"Name":"","Reg":""}}`

// A driver package installs through a script and records no files.
const googetMeasuredBalloon = `{"SourceRepo":"https://packages.cloud.google.com/yuck/repos/google-compute-engine-stable","DownloadURL":"https://packages.cloud.google.com/yuck/pool/google-compute-engine-stable/dfceaa8df80c5ba1fe5c839388d44f4efc7104cd332213063a9d95e783e753fd-google-compute-engine-driver-balloon-x86_64-16.1.8@9.goo","Checksum":"dfceaa8df80c5ba1fe5c839388d44f4efc7104cd332213063a9d95e783e753fd","LocalPath":"C:\\ProgramData\\GooGet\\cache\\google-compute-engine-driver-balloon.x86_64.16.1.8@9.goo","UnpackDir":"","PackageSpec":{"Name":"google-compute-engine-driver-balloon","Version":"16.1.8@9","Arch":"x86_64","Description":"Google Compute Engine Windows Memory Balloon Drive","License":"BSD-3-Clause","Authors":"Google Inc.","Replaces":null,"Conflicts":null,"Provides":null,"Install":{"Path":"script\\install-driver.ps1","Args":["-Target","balloon"]},"Uninstall":{"Path":"script\\remove-driver.ps1","Args":["-Target","balloon"]},"Verify":{},"ExternalProgramName":""},"InstalledFiles":{},"InstallDate":1792986477,"InstalledApp":{"Name":"","Reg":""}}`

// noarch package.
const googetMeasuredSysprepSpec = `{"SourceRepo":"https://packages.cloud.google.com/yuck/repos/google-compute-engine-stable","PackageSpec":{"Name":"google-compute-engine-sysprep","Version":"20260206.01@1","Arch":"noarch","Authors":"Google Inc."},"InstalledFiles":{},"InstallDate":1792988927}`

// Synthetic: a package converted from a pre-database googet.state, which
// carries no InstallDate and no SourceRepo; no target showed this.
const googetNoDateState = `{
  "SourceRepo": "",
  "PackageSpec": {"Name": "googet", "Version": "2.18.3@0", "Arch": "x86_64"},
  "InstalledFiles": {"C:\\ProgramData\\GooGet\\googet.exe": "c0ffee"}
}`

func TestParseGooGetState(t *testing.T) {
	states, err := parseGooGetState([]byte("[" + googetMeasuredGooGet + "," + googetNoDateState + "]"))
	require.NoError(t, err)
	require.Len(t, states, 2)

	s := states[0]
	require.NotNil(t, s.PackageSpec)
	assert.Equal(t, "https://packages.cloud.google.com/yuck/repos/google-compute-engine-stable", s.SourceRepo)
	assert.Equal(t, "googet", s.PackageSpec.Name)
	assert.Equal(t, "20261003.00.0@1", s.PackageSpec.Version)
	assert.Equal(t, "x86_64", s.PackageSpec.Arch)
	assert.Equal(t, "GooGet Package Manager", s.PackageSpec.Description)
	assert.Equal(t, "http://www.apache.org/licenses/LICENSE-2.0", s.PackageSpec.License)
	assert.Equal(t, "Google LLC", s.PackageSpec.Authors)
	assert.Equal(t, int64(1792986102), s.InstallDate)
	assert.Len(t, s.InstalledFiles, 6)

	assert.Equal(t, int64(0), states[1].InstallDate)
}

func TestParseGooGetStateMalformed(t *testing.T) {
	_, err := parseGooGetState([]byte(`{"not": "an array"`))
	assert.Error(t, err)
}

func TestGooGetPackages(t *testing.T) {
	states, err := parseGooGetState([]byte("[" + googetMeasuredGooGet + "," + googetMeasuredBalloon + "," +
		googetMeasuredSysprepSpec + "," + googetNoDateState + `,{"SourceRepo":"x"}]`))
	require.NoError(t, err)

	pkgs := googetPackages(states)
	// Synthetic: the entry without a PackageSpec is skipped.
	require.Len(t, pkgs, 4)

	// Measured: the live scan of the VM reported these values.
	g := pkgs[0]
	assert.Equal(t, "googet", g.Name)
	assert.Equal(t, "20261003.00.0@1", g.Version)
	assert.Equal(t, "x86_64", g.Arch)
	assert.Equal(t, GooGetPkgFormat, g.Format)
	assert.Equal(t, "GooGet Package Manager", g.Description)
	assert.Equal(t, "http://www.apache.org/licenses/LICENSE-2.0", g.License)
	assert.Equal(t, "Google LLC", g.Vendor)
	assert.Equal(t, time.Unix(1792986102, 0).UTC(), g.InstallDate)
	assert.Equal(t,
		"pkg:googet/googet@20261003.00.0%401?arch=x86_64&repository_url=https:%2F%2Fpackages.cloud.google.com%2Fyuck%2Frepos%2Fgoogle-compute-engine-stable",
		g.PUrl)
	assert.Equal(t, PkgFilesIncluded, g.FilesAvailable)
	// The three directory entries (empty checksum) are dropped; files are sorted.
	assert.Equal(t, []FileRecord{
		{Path: `C:\ProgramData\GooGet\LICENSE.txt`, Digest: PkgDigest{Value: "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4", Algorithm: "sha256"}},
		{Path: `C:\ProgramData\GooGet\THIRD_PARTY_LICENSES\PowerShell\openssh-portable\LICENCE`, Digest: PkgDigest{Value: "d6807e99f3d159145c659060f57c3fa74e109faa39326dbfc38674cb550fd104", Algorithm: "sha256"}},
		{Path: `C:\ProgramData\GooGet\googet.exe`, Digest: PkgDigest{Value: "93f927526830d64dd9437b229c3ae1a2779f9a36596183e6b0a10e3066e36e74", Algorithm: "sha256"}},
	}, g.Files)

	balloon := pkgs[1]
	assert.Equal(t, "BSD-3-Clause", balloon.License)
	assert.Empty(t, balloon.Files)

	sysprep := pkgs[2]
	assert.Equal(t, "noarch", sysprep.Arch)
	assert.Equal(t,
		"pkg:googet/google-compute-engine-sysprep@20260206.01%401?arch=noarch&repository_url=https:%2F%2Fpackages.cloud.google.com%2Fyuck%2Frepos%2Fgoogle-compute-engine-stable",
		sysprep.PUrl)

	// Synthetic: no install date stays zero, not 1970; no repo, no qualifier.
	noDate := pkgs[3]
	assert.True(t, noDate.InstallDate.IsZero())
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
	data := writeGooGetDB(t, googetMeasuredBalloon, "{broken", googetNoDateState)

	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, `C:\ProgramData\GooGet\googet.db`, data, 0o644))

	states, err := readGooGetDB(fs, `C:\ProgramData\GooGet\googet.db`)
	require.NoError(t, err)
	require.Len(t, states, 2)
	assert.Equal(t, "google-compute-engine-driver-balloon", states[0].PackageSpec.Name)
	assert.Equal(t, "googet", states[1].PackageSpec.Name)
}

func TestGooGetList(t *testing.T) {
	db := writeGooGetDB(t, googetMeasuredBalloon)
	stale := []byte("[" + googetNoDateState + "]")

	t.Run("database wins over the stale state file", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, `C:\ProgramData\GooGet\googet.db`, db, 0o644))
		require.NoError(t, afero.WriteFile(fs, `C:\ProgramData\GooGet\googet.state`, stale, 0o644))

		pkgs, err := (&GooGetPkgManager{conn: &memFsConn{fs: fs}}).List()
		require.NoError(t, err)
		require.Len(t, pkgs, 1)
		assert.Equal(t, "google-compute-engine-driver-balloon", pkgs[0].Name)
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
		assert.Equal(t, "google-compute-engine-driver-balloon", pkgs[0].Name)
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
