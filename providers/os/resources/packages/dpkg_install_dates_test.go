// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDpkgInstallDates(t *testing.T) {
	f, err := os.Open("./testdata/dpkg.log")
	require.NoError(t, err)
	defer f.Close()

	dates, err := ParseDpkgInstallDates(f, time.UTC, nil)
	require.NoError(t, err)

	got, ok := dates.Get("curl", "amd64", "8.5.0-2ubuntu10.6")
	require.True(t, ok)
	// The install action is at 09:14:12 and the status line that confirms it at
	// 09:14:13; the later of the two is when the package was fully in place.
	assert.Equal(t, "2026-05-01T09:14:13Z", got.Format(time.RFC3339))

	got, ok = dates.Get("libpam-modules", "amd64", "1.5.3-5ubuntu5.5")
	require.True(t, ok)
	assert.Equal(t, "2026-05-04T03:22:08Z", got.Format(time.RFC3339))

	// The version it was upgraded away from never landed at that time.
	_, ok = dates.Get("libpam-modules", "amd64", "1.5.3-5ubuntu5")
	assert.False(t, ok, "the superseded version must not carry the upgrade's timestamp")

	// A removal is not an install, and neither is trigger processing.
	_, ok = dates.Get("telnet", "amd64", "0.17-44build1")
	assert.False(t, ok)
	_, ok = dates.Get("man-db", "amd64", "2.12.0-4build2")
	assert.False(t, ok)
}

func TestParseDpkgInstallDatesCases(t *testing.T) {
	tests := []struct {
		name    string
		log     string
		pkg     string
		arch    string
		version string
		want    string
	}{
		{
			name:    "install action",
			log:     "2026-05-01 09:14:12 install curl:amd64 <none> 8.5.0\n",
			pkg:     "curl",
			arch:    "amd64",
			version: "8.5.0",
			want:    "2026-05-01T09:14:12Z",
		},
		{
			name:    "upgrade records the new version",
			log:     "2026-05-04 03:22:07 upgrade openssl:amd64 3.0.13 3.0.14\n",
			pkg:     "openssl",
			arch:    "amd64",
			version: "3.0.14",
			want:    "2026-05-04T03:22:07Z",
		},
		{
			name:    "epoch in the version",
			log:     "2026-05-04 03:22:07 upgrade samba:amd64 2:4.17.11 2:4.17.12+dfsg-0+deb12u1\n",
			pkg:     "samba",
			arch:    "amd64",
			version: "2:4.17.12+dfsg-0+deb12u1",
			want:    "2026-05-04T03:22:07Z",
		},
		{
			// Older logs write the bare name, so lookup has to fall back to it.
			name:    "unqualified package token",
			log:     "2026-05-01 09:14:13 status installed curl 8.5.0\n",
			pkg:     "curl",
			arch:    "amd64",
			version: "8.5.0",
			want:    "2026-05-01T09:14:13Z",
		},
		{
			name:    "later entry wins",
			log:     "2026-05-01 09:14:13 status installed curl:amd64 8.5.0\n2026-06-01 10:00:00 status installed curl:amd64 8.5.0\n",
			pkg:     "curl",
			arch:    "amd64",
			version: "8.5.0",
			want:    "2026-06-01T10:00:00Z",
		},
		{
			name:    "removal is not an install",
			log:     "2026-05-09 14:17:19 remove telnet:amd64 0.17 <none>\n",
			pkg:     "telnet",
			arch:    "amd64",
			version: "0.17",
			want:    "",
		},
		{
			name:    "status not-installed is not an install",
			log:     "2026-05-09 14:17:20 status not-installed telnet:amd64 0.17\n",
			pkg:     "telnet",
			arch:    "amd64",
			version: "0.17",
			want:    "",
		},
		{
			name:    "startup lines are ignored",
			log:     "2026-05-01 09:14:11 startup archives unpack\n",
			pkg:     "archives",
			arch:    "",
			version: "unpack",
			want:    "",
		},
		{
			name:    "short line is ignored",
			log:     "2026-05-01 09:14:11 install curl:amd64\n",
			pkg:     "curl",
			arch:    "amd64",
			version: "8.5.0",
			want:    "",
		},
		{
			name:    "unparseable timestamp is ignored",
			log:     "not-a-date 09:14:12 install curl:amd64 <none> 8.5.0\n",
			pkg:     "curl",
			arch:    "amd64",
			version: "8.5.0",
			want:    "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dates, err := ParseDpkgInstallDates(strings.NewReader(test.log), time.UTC, nil)
			require.NoError(t, err)
			got, ok := dates.Get(test.pkg, test.arch, test.version)
			if test.want == "" {
				assert.False(t, ok)
				return
			}
			require.True(t, ok)
			assert.Equal(t, test.want, got.Format(time.RFC3339))
		})
	}
}

// dpkg writes local time with no offset. Reading it in the scanner's zone
// instead of the asset's shifts every install date by the difference, which on
// a mounted snapshot is the common case rather than the exotic one.
func TestParseDpkgInstallDatesUsesLocation(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	require.NoError(t, err)

	log := "2026-01-02 03:04:05 install curl:amd64 <none> 8.5.0\n"

	dates, err := ParseDpkgInstallDates(strings.NewReader(log), berlin, nil)
	require.NoError(t, err)
	got, ok := dates.Get("curl", "amd64", "8.5.0")
	require.True(t, ok)
	assert.Equal(t, "2026-01-02T02:04:05Z", got.Format(time.RFC3339))

	dates, err = ParseDpkgInstallDates(strings.NewReader(log), nil, nil)
	require.NoError(t, err)
	got, ok = dates.Get("curl", "amd64", "8.5.0")
	require.True(t, ok)
	assert.Equal(t, "2026-01-02T03:04:05Z", got.Format(time.RFC3339),
		"a nil location must fall back to UTC rather than panic")
}

// A multi-arch asset carries the same package name twice. Keying on the name
// alone would hand one architecture's install date to the other.
func TestDpkgInstallDatesMultiArch(t *testing.T) {
	log := "2026-05-01 09:00:00 status installed zlib1g:amd64 1.3\n" +
		"2026-06-01 09:00:00 status installed zlib1g:i386 1.3\n"

	dates, err := ParseDpkgInstallDates(strings.NewReader(log), time.UTC, nil)
	require.NoError(t, err)

	got, ok := dates.Get("zlib1g", "amd64", "1.3")
	require.True(t, ok)
	assert.Equal(t, "2026-05-01T09:00:00Z", got.Format(time.RFC3339))

	got, ok = dates.Get("zlib1g", "i386", "1.3")
	require.True(t, ok)
	assert.Equal(t, "2026-06-01T09:00:00Z", got.Format(time.RFC3339))
}

func TestDpkgInstallDatesGetOnEmpty(t *testing.T) {
	var dates DpkgInstallDates
	_, ok := dates.Get("curl", "amd64", "8.5.0")
	assert.False(t, ok, "a nil map must answer rather than panic")
}

// Coverage runs as far back as logrotate kept, so the walk has to read the
// rotated copies. Without it only the current month's installs carry a date.
func TestReadDpkgInstallDatesWalksRotations(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log",
		[]byte("2026-06-01 09:00:00 status installed curl:amd64 8.5.0\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log.1",
		[]byte("2026-05-01 09:00:00 status installed openssl:amd64 3.0.14\n"), 0o644))

	require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log.2.gz",
		gzipLog(t, "2026-04-01 09:00:00 status installed bash:amd64 5.2.21\n"), 0o644))

	dates := ReadDpkgInstallDates(fs, time.UTC)

	for _, want := range []struct{ name, version, at string }{
		{"curl", "8.5.0", "2026-06-01T09:00:00Z"},
		{"openssl", "3.0.14", "2026-05-01T09:00:00Z"},
		{"bash", "5.2.21", "2026-04-01T09:00:00Z"},
	} {
		got, ok := dates.Get(want.name, "amd64", want.version)
		require.True(t, ok, want.name)
		assert.Equal(t, want.at, got.Format(time.RFC3339), want.name)
	}
}

func TestReadDpkgInstallDatesWithoutLogs(t *testing.T) {
	assert.Empty(t, ReadDpkgInstallDates(afero.NewMemMapFs(), time.UTC),
		"an asset whose logs are gone yields no dates rather than an error")
	assert.Empty(t, ReadDpkgInstallDates(nil, time.UTC))
}

// A rotation that exists but cannot be read ends the walk: a package whose
// newest placement sat inside it would otherwise be dated by an older
// placement from a deeper rotation. What newer logs already supplied stays.
func TestReadDpkgInstallDatesStopsAtUnreadableRotation(t *testing.T) {
	t.Run("corrupt gzip", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log",
			[]byte("2026-06-01 09:00:00 status installed curl:amd64 8.5.0\n"), 0o644))
		require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log.1.gz", []byte("not gzip"), 0o644))
		require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log.2",
			[]byte("2026-04-01 09:00:00 status installed bash:amd64 5.2.21\n"), 0o644))

		dates := ReadDpkgInstallDates(fs, time.UTC)

		_, ok := dates.Get("curl", "amd64", "8.5.0")
		assert.True(t, ok, "dates from logs newer than the damage stay")
		_, ok = dates.Get("bash", "amd64", "5.2.21")
		assert.False(t, ok, "a rotation older than the damage must not supply dates")
	})

	t.Run("truncated gzip", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log",
			[]byte("2026-06-01 09:00:00 status installed curl:amd64 8.5.0\n"), 0o644))

		// The header stays intact so the open succeeds; the read fails midway.
		full := gzipLog(t, "2026-05-01 09:00:00 status installed openssl:amd64 3.0.14\n"+
			"2026-05-02 09:00:00 status installed libssl3:amd64 3.0.14\n")
		require.Greater(t, len(full), 40)
		require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log.1.gz", full[:len(full)/2], 0o644))

		require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log.2",
			[]byte("2026-04-01 09:00:00 status installed bash:amd64 5.2.21\n"), 0o644))

		dates := ReadDpkgInstallDates(fs, time.UTC)

		_, ok := dates.Get("curl", "amd64", "8.5.0")
		assert.True(t, ok, "dates from logs newer than the damage stay")
		_, ok = dates.Get("bash", "amd64", "5.2.21")
		assert.False(t, ok, "a rotation older than the damage must not supply dates")
	})
}

// A stream that stops early hands back what it read alongside the error:
// every entry parsed is a true placement event, and the error is what tells
// the walk to stop descending.
func TestParseDpkgInstallDatesScannerError(t *testing.T) {
	log := "2026-05-01 09:14:12 install curl:amd64 <none> 8.5.0\n" +
		strings.Repeat("x", dpkgMaxLine+1) + "\n" +
		"2026-06-01 09:14:12 install bash:amd64 <none> 5.2.21\n"

	dates, err := ParseDpkgInstallDates(strings.NewReader(log), time.UTC, nil)
	assert.Error(t, err)

	_, ok := dates.Get("curl", "amd64", "8.5.0")
	assert.True(t, ok, "entries read before the failure are kept")
	_, ok = dates.Get("bash", "amd64", "5.2.21")
	assert.False(t, ok)
}

func gzipLog(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return buf.Bytes()
}
