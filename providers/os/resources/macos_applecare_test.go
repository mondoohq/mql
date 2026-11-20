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
)

// The cache macOS writes when the AppleCare & Warranty pane loads.
const appleCarePlusCoverage = `{
  "serialNumber": "C02ABC123",
  "coverageLabel": "AppleCare+",
  "hasTheftAndLossBenefit": false,
  "settingsCoverageSection": {
    "coverageExpirationLabel": "Expires October 26, 2028",
    "offer": {"link": {}, "singularFooter": "", "pluralFooter": "", "expiration": "0"}
  },
  "foregroundCacheTtl": "0",
  "coverageHash": "abc"
}`

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

func TestFindAppleCareCoverageWithoutCache(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/Users/alice", 0o755))

	c, updated, err := findAppleCareCoverage(fs, "C02ABC123")
	require.NoError(t, err)
	assert.Nil(t, c)
	assert.Nil(t, updated)

	// No serial number: nothing to match.
	c, _, err = findAppleCareCoverage(fs, "")
	require.NoError(t, err)
	assert.Nil(t, c)
}

func TestFindAppleCareCoverageSkipsAnUnreadableCopy(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeAppleCareCache(t, fs, "alice", "C02ABC123", appleCarePlusCoverage, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	writeAppleCareCache(t, fs, "bob", "C02ABC123", "not json", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	c, _, err := findAppleCareCoverage(fs, "C02ABC123")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "AppleCare+", c.CoverageLabel)
}

// The file sits in a user's home and the scan usually runs as root: a symlink
// a user put there is not followed.
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

func TestFindAppleCareCoverageSkipsAnOversizedFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	big := `{"coverageLabel":"AppleCare+","padding":"` + strings.Repeat("x", appleCareMaxFileSize) + `"}`
	writeAppleCareCache(t, fs, "mallory", "C02ABC123", big, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	c, _, err := findAppleCareCoverage(fs, "C02ABC123")
	require.NoError(t, err)
	assert.Nil(t, c)
}

func TestParseAppleCareExpiration(t *testing.T) {
	got := parseAppleCareExpiration("Expires October 26, 2028")
	require.NotNil(t, got)
	assert.Equal(t, time.Date(2028, 10, 26, 0, 0, 0, 0, time.UTC), *got)

	got = parseAppleCareExpiration("Coverage ends May 3, 2027")
	require.NotNil(t, got)
	assert.Equal(t, time.Date(2027, 5, 3, 0, 0, 0, 0, time.UTC), *got)

	// The label follows the user's language; other languages are not parsed.
	assert.Nil(t, parseAppleCareExpiration("Läuft am 26. Oktober 2028 ab"))
	assert.Nil(t, parseAppleCareExpiration(""))
}
