// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/registry"
)

// fakeCBS is an in-memory CBSReader. A package with no entry in mum has no
// manifest on disk.
type fakeCBS struct {
	names   []string
	values  map[string]CBSPackageValues
	mum     map[string]string
	listErr error
}

func newFakeCBS() *fakeCBS {
	return &fakeCBS{values: map[string]CBSPackageValues{}, mum: map[string]string{}}
}

func (f *fakeCBS) add(name string, state int64, mum string) {
	f.names = append(f.names, name)
	f.values[name] = CBSPackageValues{CurrentState: state}
	if mum != "" {
		f.mum[name] = mum
	}
}

func (f *fakeCBS) PackageNames() ([]string, error) { return f.names, f.listErr }

func (f *fakeCBS) PackageValues(name string) (CBSPackageValues, error) {
	v, ok := f.values[name]
	if !ok {
		return CBSPackageValues{}, errors.New("no values")
	}
	return v, nil
}

func (f *fakeCBS) OpenMUM(name string) (io.ReadCloser, error) {
	m, ok := f.mum[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(strings.NewReader(m)), nil
}

func mumFor(identifier, releaseType string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0">
  <assemblyIdentity name="x" version="1.0.0.0" />
  <package identifier=%q releaseType=%q restart="never">
    <update name="inner"><package integrate="hidden" identifier="KB1"/></update>
  </package>
</assembly>`, identifier, releaseType)
}

func kbs(updates []CBSUpdate) []string {
	res := []string{}
	for _, u := range updates {
		res = append(res, u.KB)
	}
	sort.Strings(res)
	return res
}

func TestInstalledCBSUpdates_StateFilter(t *testing.T) {
	f := newFakeCBS()
	f.add("Package_for_A~1", 112, mumFor("KB1000001", "Update"))
	f.add("Package_for_B~1", 64, mumFor("KB1000002", "Update"))
	f.add("Package_for_C~1", 32, mumFor("KB1000003", "Update"))
	f.add("Package_for_D~1", 0, mumFor("KB1000004", "Update"))

	got, err := InstalledCBSUpdates(f)
	require.NoError(t, err)
	assert.Equal(t, []string{"KB1000001"}, kbs(got))
}

func TestInstalledCBSUpdates_PackagePrefixFilter(t *testing.T) {
	f := newFakeCBS()
	// Shared-/Wrapper-/component packages carry identifiers too, but are
	// payload of an update, not an update.
	f.add("Shared-ABC~31bf3856ad364e35~amd64~~10.0.1", 112, mumFor("KB2000001", "Update"))
	f.add("Wrapper-ABC~31bf3856ad364e35~amd64~~10.0.1", 112, mumFor("KB2000002", "Update"))
	f.add("Microsoft-Windows-Foo-Package~31bf3856ad364e35~amd64~~10.0.1", 112, mumFor("KB2000003", "Update"))
	f.add("Package_for_KB2000004~31bf3856ad364e35~amd64~~10.0.1", 112, mumFor("KB2000004", "Update"))

	got, err := InstalledCBSUpdates(f)
	require.NoError(t, err)
	assert.Equal(t, []string{"KB2000004"}, kbs(got))
}

func TestInstalledCBSUpdates_KBComesFromManifestNotName(t *testing.T) {
	f := newFakeCBS()
	// the name says KB9999999, the manifest is authoritative
	f.add("Package_for_KB9999999~1", 112, mumFor("KB3000001", "Security Update"))
	// non-KB identifiers are not updates
	f.add("Package_for_Other~1", 112, mumFor("Microsoft-Windows-Something", "Feature Pack"))
	f.add("Package_for_Other2~1", 112, mumFor("", "Update"))
	f.add("Package_for_Lower~1", 112, mumFor("kb3000002", "Update"))
	f.add("Package_for_Partial~1", 112, mumFor("KB3000003-x", "Update"))

	got, err := InstalledCBSUpdates(f)
	require.NoError(t, err)
	assert.Equal(t, []string{"KB3000001", "KB3000002"}, kbs(got))
}

func TestInstalledCBSUpdates_BrokenManifestsAreSkipped(t *testing.T) {
	f := newFakeCBS()
	f.add("Package_for_Good~1", 112, mumFor("KB4000001", "Update"))
	f.add("Package_for_Missing~1", 112, "")
	f.add("Package_for_Truncated~1", 112, `<?xml version="1.0"?><assembly><package identifier="KB4000002" releaseType="Update"`)
	f.add("Package_for_NotXML~1", 112, "this is not xml at all")
	f.add("Package_for_NoPackage~1", 112, `<assembly><foo/></assembly>`)
	// values unreadable
	f.names = append(f.names, "Package_for_NoValues~1")

	got, err := InstalledCBSUpdates(f)
	require.NoError(t, err)
	assert.Equal(t, []string{"KB4000001"}, kbs(got))
}

func TestInstalledCBSUpdates_ListError(t *testing.T) {
	f := newFakeCBS()
	f.listErr = errors.New("hive not loaded")
	_, err := InstalledCBSUpdates(f)
	assert.Error(t, err)
}

func TestInstalledCBSUpdates_DedupesByKB(t *testing.T) {
	f := newFakeCBS()
	for i := 6; i <= 12; i++ {
		f.add(fmt.Sprintf("Package_%d_for_KB5120708~31bf3856ad364e35~amd64~~10.0.9344.1", i), 112, mumFor("KB5120708", "Update"))
	}
	// a superseded sibling must not add anything
	f.add("Package_17_for_KB5120708~31bf3856ad364e35~amd64~~10.0.9344.1", 64, mumFor("KB5120708", "Update"))

	got, err := InstalledCBSUpdates(f)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "KB5120708", got[0].KB)
	assert.Equal(t, "Update", got[0].ReleaseType)
}

func TestInstalledCBSUpdates_DedupKeepsAvailableInstallTime(t *testing.T) {
	f := newFakeCBS()
	f.add("Package_1_for_KB5000000~1", 112, mumFor("KB5000000", "Update"))
	f.add("Package_2_for_KB5000000~1", 112, mumFor("KB5000000", "Update"))
	f.values["Package_2_for_KB5000000~1"] = CBSPackageValues{CurrentState: 112, InstallTimeHigh: 0x01DA3C00, InstallTimeLow: 1}

	got, err := InstalledCBSUpdates(f)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.NotNil(t, got[0].InstalledOn)
}

// The manifests below were copied from a hotpatched Windows Server 2025 host.
// None of the three update packages has its KB in the key name.
func TestInstalledCBSUpdates_RealManifests(t *testing.T) {
	dir := filepath.Join("testdata", "cbs")
	cases := []struct {
		name        string
		kb          string
		releaseType string
	}{
		{"Package_for_HotpatchFix_33222~31bf3856ad364e35~amd64~~26100.33222.1.16", "KB5120228", "Security Update"},
		{"Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.33158.1.29", "KB5099536", "Security Update"},
		{"Package_for_ServicingStack_33288~31bf3856ad364e35~amd64~~26100.33288.1.4", "KB5120232", "Security Update"},
		{"Package_6_for_KB5120708~31bf3856ad364e35~amd64~~10.0.9344.1", "KB5120708", "Update"},
	}
	for _, tc := range cases {
		t.Run(tc.kb, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, tc.name+".mum"))
			require.NoError(t, err)
			f := newFakeCBS()
			f.add(tc.name, 112, string(data))

			got, err := InstalledCBSUpdates(f)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, tc.kb, got[0].KB)
			assert.Equal(t, tc.releaseType, got[0].ReleaseType)
			assert.Equal(t, tc.name, got[0].PackageName)
		})
	}
}

func TestInstalledCBSUpdates_HandlesBOM(t *testing.T) {
	withBOM := "\xEF\xBB\xBF" + mumFor("KB6000001", "Update")
	f := newFakeCBS()
	f.add("Package_for_Bom~1", 112, withBOM)
	got, err := InstalledCBSUpdates(f)
	require.NoError(t, err)
	assert.Equal(t, []string{"KB6000001"}, kbs(got))

	// the fixture copied from a real host starts with a BOM as well
	data, err := os.ReadFile(filepath.Join("testdata", "cbs", "Package_for_HotpatchFix_33222~31bf3856ad364e35~amd64~~26100.33222.1.16.mum"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(data), "\xEF\xBB\xBF"))
}

func TestFileTimeToTime(t *testing.T) {
	// 2024-01-01T00:00:00Z is 13348540800 s after 1601-01-01.
	var ticks uint64 = 133485408000000000
	got := FileTimeToTime(uint32(ticks>>32), uint32(ticks))
	require.NotNil(t, got)
	assert.Equal(t, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), *got)
	assert.Equal(t, time.UTC, got.Location())

	// sub-second part: 1234567 ticks = 123456700 ns
	withFraction := ticks + 1234567
	got = FileTimeToTime(uint32(withFraction>>32), uint32(withFraction))
	require.NotNil(t, got)
	assert.Equal(t, time.Date(2024, 1, 1, 0, 0, 0, 123456700, time.UTC), *got)

	assert.Nil(t, FileTimeToTime(0, 0), "an unset FILETIME is null, not 1601")
	assert.Nil(t, FileTimeToTime(0, 1), "a pre-1970 FILETIME is null")
}

// TestInstalledCBSUpdates_Parity feeds the CBS rows of a real hotpatched
// Windows Server 2025 host (testdata/cbs/packages.json: key name, state,
// manifest identifier and release type, install time) and expects exactly what
// Get-HotFix returned there.
func TestInstalledCBSUpdates_Parity(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "cbs", "packages.json"))
	require.NoError(t, err)
	var rows []struct {
		Name           string
		CurrentState   int64
		Identifier     string
		ReleaseType    string
		InstallTimeUtc *time.Time
	}
	require.NoError(t, json.Unmarshal(data, &rows))
	require.NotEmpty(t, rows)

	f := newFakeCBS()
	for _, r := range rows {
		f.add(r.Name, r.CurrentState, mumFor(r.Identifier, r.ReleaseType))
		if r.InstallTimeUtc != nil {
			ticks := uint64(r.InstallTimeUtc.Unix()+filetimeEpochDiff)*10_000_000 + uint64(r.InstallTimeUtc.Nanosecond()/100)
			v := f.values[r.Name]
			v.InstallTimeHigh, v.InstallTimeLow = uint32(ticks>>32), uint32(ticks)
			f.values[r.Name] = v
		}
	}

	got, err := InstalledCBSUpdates(f)
	require.NoError(t, err)
	assert.Equal(t, []string{"KB5099536", "KB5101372", "KB5120228", "KB5120232", "KB5120708"}, kbs(got))

	byKB := map[string]CBSUpdate{}
	for _, u := range got {
		byKB[u.KB] = u
	}
	assert.Equal(t, "Security Update", byKB["KB5120228"].ReleaseType)
	require.NotNil(t, byKB["KB5120228"].InstalledOn)
	assert.Equal(t, time.Date(2026, 8, 10, 15, 49, 51, 376640800, time.UTC), *byKB["KB5120228"].InstalledOn)
}

func TestCBSChildKeyPath(t *testing.T) {
	// GetNativeRegistryKeyChildren returns the parent's path on each child;
	// reading values from that path reads the Packages key itself.
	k := registry.RegistryKeyChild{
		Path: `HKEY_LOCAL_MACHINE\TmpReg_SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`,
		Name: "Package_for_HotpatchFix_33222~31bf3856ad364e35~amd64~~26100.33222.1.16",
	}
	assert.Equal(t,
		`HKEY_LOCAL_MACHINE\TmpReg_SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Package_for_HotpatchFix_33222~31bf3856ad364e35~amd64~~26100.33222.1.16`,
		cbsChildKeyPath(k))
}
