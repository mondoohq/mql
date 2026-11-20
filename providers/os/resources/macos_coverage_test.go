// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

// Measured: MacBook Pro Mac16,8, macOS 27.2 (26B123), 2026-11-19. The keys
// and values of the cache the AppleCare & Warranty pane wrote, read with
// python's json module; the serial number and hash are replaced.
const appleCarePlusCoverage = `{
  "serialNumber": "C02ABC123",
  "coverageLabel": "AppleCare+",
  "hasTheftAndLossBenefit": false,
  "settingsCoverageSection": {
    "coverageExpirationLabel": "Expires October 26, 2028",
    "offer": {"link": {}, "singularFooter": "", "pluralFooter": "", "expiration": 0}
  },
  "foregroundCacheTtl": 0,
  "coverageHash": "abc"
}`

// Synthetic: the limited warranty, in the measured file's shape; no target
// showed this.
const limitedWarrantyCoverage = `{
  "serialNumber": "C02ABC123",
  "coverageLabel": "Limited Warranty",
  "hasTheftAndLossBenefit": false,
  "settingsCoverageSection": {"coverageExpirationLabel": "Expires March 3, 2026"}
}`

func writeAppleCareCache(t *testing.T, fs afero.Fs, user, serial, content string, mod time.Time) {
	t.Helper()
	p := path.Join("/Users", user, appleCareCacheDir, serial+".json")
	require.NoError(t, afero.WriteFile(fs, p, []byte(content), 0o644))
	require.NoError(t, fs.Chtimes(p, mod, mod))
}

// Synthetic: two users and another device's file; the measured Mac had one
// user, with the cache also holding a second device's file.
func TestFindAppleCareCoverage(t *testing.T) {
	fs := afero.NewMemMapFs()
	older := time.Date(2026, 6, 4, 8, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 11, 2, 21, 0, 0, 0, time.UTC)
	writeAppleCareCache(t, fs, "alice", "C02ABC123", limitedWarrantyCoverage, older)
	writeAppleCareCache(t, fs, "bob", "C02ABC123", appleCarePlusCoverage, newer)
	// The cache also holds the account's other devices.
	writeAppleCareCache(t, fs, "bob", "OTHERPHONE", limitedWarrantyCoverage, newer.Add(time.Hour))

	c, updated, err := findAppleCareCoverage(fs, "C02ABC123")
	require.NoError(t, err)
	require.NotNil(t, c)
	// The most recently refreshed copy wins.
	assert.Equal(t, "AppleCare+", c.CoverageLabel)
	assert.Equal(t, "Expires October 26, 2028", c.SettingsCoverageSection.CoverageExpirationLabel)
	require.NotNil(t, c.HasTheftAndLossBenefit)
	assert.False(t, *c.HasTheftAndLossBenefit)
	require.NotNil(t, updated)
	assert.True(t, newer.Equal(*updated))
}

// Synthetic: no user opened the pane, and no serial number; no target showed this.
func TestFindAppleCareCoverageWithoutCache(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/Users/alice", 0o755))

	c, updated, err := findAppleCareCoverage(fs, "C02ABC123")
	require.NoError(t, err)
	assert.Nil(t, c)
	assert.Nil(t, updated)

	c, _, err = findAppleCareCoverage(fs, "")
	require.NoError(t, err)
	assert.Nil(t, c)
}

// Synthetic: a newer copy that is not JSON; no target showed this.
func TestFindAppleCareCoverageSkipsAnUnreadableCopy(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeAppleCareCache(t, fs, "alice", "C02ABC123", appleCarePlusCoverage, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	writeAppleCareCache(t, fs, "bob", "C02ABC123", "not json", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	c, _, err := findAppleCareCoverage(fs, "C02ABC123")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "AppleCare+", c.CoverageLabel)
}

// Synthetic: a symlink a user put in their home, where a root scan reads;
// no target showed this.
func TestFindAppleCareCoverageSkipsASymlink(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secret.json")
	require.NoError(t, os.WriteFile(secret, []byte(appleCarePlusCoverage), 0o600))
	dir := filepath.Join(root, "Users", "mallory", filepath.FromSlash(appleCareCacheDir))
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.Symlink(secret, filepath.Join(dir, "C02ABC123.json")))

	c, _, err := findAppleCareCoverage(afero.NewBasePathFs(afero.NewOsFs(), root), "C02ABC123")
	require.NoError(t, err)
	assert.Nil(t, c)
}

// Synthetic: the file swapped for another between lstat and open; no target
// showed this. readAtMost is handed the stat of one file and opens another.
func TestReadAtMostRejectsADifferentFile(t *testing.T) {
	root := t.TempDir()
	fs := afero.NewBasePathFs(afero.NewOsFs(), root)
	require.NoError(t, afero.WriteFile(fs, "/cache.json", []byte(appleCarePlusCoverage), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/other.json", []byte(appleCarePlusCoverage), 0o644))
	cache, err := lstat(fs, "/cache.json")
	require.NoError(t, err)

	_, err = readAtMost(fs, "/other.json", cache, appleCareMaxFileSize)
	assert.Error(t, err)

	data, err := readAtMost(fs, "/cache.json", cache, appleCareMaxFileSize)
	require.NoError(t, err)
	assert.Equal(t, appleCarePlusCoverage, string(data))
}

// Synthetic: a file far larger than a coverage cache; no target showed this.
func TestFindAppleCareCoverageSkipsAnOversizedFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	big := `{"coverageLabel":"AppleCare+","padding":"` + strings.Repeat("x", appleCareMaxFileSize) + `"}`
	writeAppleCareCache(t, fs, "mallory", "C02ABC123", big, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	c, _, err := findAppleCareCoverage(fs, "C02ABC123")
	require.NoError(t, err)
	assert.Nil(t, c)
}

func TestParseAppleCareExpiration(t *testing.T) {
	// Measured: MacBook Pro Mac16,8, macOS 27.2, 2026-11-19.
	got := parseAppleCareExpiration("Expires October 26, 2028")
	require.NotNil(t, got)
	assert.Equal(t, time.Date(2028, 10, 26, 0, 0, 0, 0, time.UTC), *got)

	// Synthetic: other English wording around the date; no target showed this.
	got = parseAppleCareExpiration("Coverage ends May 3, 2027")
	require.NotNil(t, got)
	assert.Equal(t, time.Date(2027, 5, 3, 0, 0, 0, 0, time.UTC), *got)

	// Synthetic: the label in another language, which is not parsed; no
	// target showed this.
	assert.Nil(t, parseAppleCareExpiration("2028年10月26日に期限切れ"))
	assert.Nil(t, parseAppleCareExpiration(""))
}

// Measured: MacBook Pro Mac16,8, macOS 27.2, 2026-11-20. The serial comes
// from system_profiler and the coverage file is read through a connection's
// filesystem, whose stats are not the os package's.
func TestInitMacosCoverage(t *testing.T) {
	coveragePath := path.Join("/Users/alice", appleCareCacheDir, "C02ABC123.json")
	mod := time.Date(2026, 11, 2, 21, 0, 57, 0, time.UTC)
	data := &mock.TomlData{
		Commands: map[string]*mock.Command{
			"system_profiler SPHardwareDataType -json": {
				Stdout: `{"SPHardwareDataType":[{"machine_model":"Mac16,8","serial_number":"C02ABC123"}]}`,
			},
		},
		Files: map[string]*mock.MockFileData{
			"/Users":       {Path: "/Users", StatData: mock.FileInfo{IsDir: true, Mode: os.ModeDir | 0o755}},
			"/Users/alice": {Path: "/Users/alice", StatData: mock.FileInfo{IsDir: true, Mode: os.ModeDir | 0o750}},
			coveragePath:   {Path: coveragePath, Content: appleCarePlusCoverage, StatData: mock.FileInfo{Mode: 0o644, ModTime: mod}},
		},
	}
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}},
	}, mock.WithData(data))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	args, _, err := initMacosCoverage(runtime, nil)
	require.NoError(t, err)
	assert.Equal(t, true, args["appleCare"].Value)
	assert.Equal(t, "AppleCare+", args["label"].Value)
	assert.Equal(t, "Expires October 26, 2028", args["expirationLabel"].Value)
	assert.Equal(t, false, args["theftAndLoss"].Value)
	assert.Equal(t, &mod, args["updated"].Value)
}

func TestSameFile(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	require.NoError(t, os.WriteFile(a, []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(b, []byte("x"), 0o644))
	mod := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, os.Chtimes(a, mod, mod))
	require.NoError(t, os.Chtimes(b, mod, mod))
	aInfo, err := os.Lstat(a)
	require.NoError(t, err)
	aAgain, err := os.Stat(a)
	require.NoError(t, err)
	bInfo, err := os.Lstat(b)
	require.NoError(t, err)

	// os stats compare by inode, so two files of equal size and time differ.
	assert.True(t, sameFile(aInfo, aAgain))
	assert.False(t, sameFile(aInfo, bInfo))

	// Other stat types compare by size and modification time.
	one := &shared.FileInfo{FName: "a", FSize: 1, FModTime: mod}
	assert.True(t, sameFile(one, &shared.FileInfo{FName: "a", FSize: 1, FModTime: mod}))
	assert.False(t, sameFile(one, &shared.FileInfo{FName: "a", FSize: 2, FModTime: mod}))
	assert.False(t, sameFile(one, &shared.FileInfo{FName: "a", FSize: 1, FModTime: mod.Add(time.Second)}))
}
