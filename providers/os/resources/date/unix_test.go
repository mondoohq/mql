// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package date

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUTCTime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Time
		wantErr bool
	}{
		{
			name:  "valid UTC time",
			input: "2026-03-17T14:30:00Z\n",
			want:  time.Date(2026, 3, 17, 14, 30, 0, 0, time.UTC),
		},
		{
			name:    "empty output",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid format",
			input:   "not a date",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUTCTime(strings.NewReader(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseTimezone(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "IANA timezone from readlink",
			input: "America/New_York\n",
			want:  "America/New_York",
		},
		{
			name:  "timezone from /etc/timezone",
			input: "Europe/London\n",
			want:  "Europe/London",
		},
		{
			name:  "abbreviated timezone fallback",
			input: "EST\n",
			want:  "EST",
		},
		{
			name:  "empty defaults to UTC",
			input: "",
			want:  "UTC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTimezone(strings.NewReader(tt.input))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractTZFromPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "standard Linux path",
			path: "/usr/share/zoneinfo/America/New_York",
			want: "America/New_York",
		},
		{
			name: "macOS path",
			path: "/var/db/timezone/zoneinfo/Europe/London",
			want: "Europe/London",
		},
		{
			name: "posix subdirectory path stripped",
			path: "/usr/share/zoneinfo/posix/Asia/Tokyo",
			want: "Asia/Tokyo",
		},
		{
			name: "right subdirectory path stripped",
			path: "/usr/share/zoneinfo/right/Europe/Berlin",
			want: "Europe/Berlin",
		},
		{
			name: "no zoneinfo marker",
			path: "/some/other/path",
			want: "",
		},
		{
			name: "zoneinfo at end with nothing after",
			path: "/usr/share/zoneinfo/",
			want: "",
		},
		{
			name: "localtime self-reference",
			path: "/usr/share/zoneinfo/localtime",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractTZFromPath(tt.path))
		})
	}
}

func TestTimezoneFromFS_EtcTimezone(t *testing.T) {
	// Simulate a Debian/Ubuntu system with /etc/timezone
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/timezone", []byte("Europe/Berlin\n"), 0o644))

	tz, err := timezoneFromFS(fs)
	require.NoError(t, err)
	assert.Equal(t, "Europe/Berlin", tz)
}

func TestTimezoneFromFS_EtcTIMEZONE(t *testing.T) {
	// Simulate a Solaris/AIX system with /etc/TIMEZONE
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/TIMEZONE", []byte("# timezone config\nTZ=US/Eastern\n"), 0o644))

	tz, err := timezoneFromFS(fs)
	require.NoError(t, err)
	assert.Equal(t, "US/Eastern", tz)
}

func TestTimezoneFromFS_LocaltimeBinaryMatch(t *testing.T) {
	// Simulate a Docker image where /etc/localtime is a copied TZif file
	fs := afero.NewMemMapFs()

	// Create a fake but valid TZif file
	tzifData := []byte("TZif" + strings.Repeat("\x00", 40) + "some timezone data here")

	// Write it as /etc/localtime (a regular file, not a symlink)
	require.NoError(t, afero.WriteFile(fs, "/etc/localtime", tzifData, 0o644))

	// Create a matching file in the zoneinfo tree
	require.NoError(t, afero.WriteFile(fs, "/usr/share/zoneinfo/America/Chicago", tzifData, 0o644))

	// Create a non-matching file to make sure we don't false-positive
	require.NoError(t, afero.WriteFile(fs, "/usr/share/zoneinfo/America/Denver", []byte("TZif"+strings.Repeat("\x00", 40)+"different data"), 0o644))

	tz, err := timezoneFromFS(fs)
	require.NoError(t, err)
	assert.Equal(t, "America/Chicago", tz)
}

func TestTimezoneFromFS_NoTimezoneInfo(t *testing.T) {
	// Empty filesystem - should fail
	fs := afero.NewMemMapFs()

	_, err := timezoneFromFS(fs)
	require.Error(t, err)
}

func TestTimezoneFromFS_SkipsPosixAndRight(t *testing.T) {
	fs := afero.NewMemMapFs()

	tzifData := []byte("TZif" + strings.Repeat("\x00", 40) + "unique tz data")
	require.NoError(t, afero.WriteFile(fs, "/etc/localtime", tzifData, 0o644))

	// Put matching file only under posix/ - should be skipped
	require.NoError(t, afero.WriteFile(fs, "/usr/share/zoneinfo/posix/America/Chicago", tzifData, 0o644))

	// Put real match under proper path
	require.NoError(t, afero.WriteFile(fs, "/usr/share/zoneinfo/America/Chicago", tzifData, 0o644))

	tz, err := timezoneFromFS(fs)
	require.NoError(t, err)
	assert.Equal(t, "America/Chicago", tz)
}

func TestTimezoneFromFS_InvalidLocaltime(t *testing.T) {
	fs := afero.NewMemMapFs()

	// /etc/localtime exists but isn't a valid TZif file
	require.NoError(t, afero.WriteFile(fs, "/etc/localtime", []byte("not a tzif file"), 0o644))

	_, err := timezoneFromFS(fs)
	require.Error(t, err)
}

// buildTZifV2 creates a minimal valid TZif v2 file with the given POSIX TZ
// footer string. The data section is minimal (no transitions) but structurally
// valid, so it can be used for both footer parsing and binary matching tests.
func buildTZifV2(posixTZ string) []byte {
	// V1 header (44 bytes) + V1 data section
	v1Header := make([]byte, 44)
	copy(v1Header[0:4], "TZif")
	v1Header[4] = '2' // version
	// All counts are zero → minimal v1 data section is just the header
	// plus the ttinfo (6 bytes) and the designation (\x00)
	// But the simplest valid v1 section: 0 transitions, 1 ttinfo, 1 char
	v1Header[32] = 0 // tzh_timecnt = 0 (big-endian uint32, high bytes)
	v1Header[35] = 0
	v1Header[36] = 0 // tzh_typecnt = 0
	v1Header[39] = 1 // need at least 1 for valid file
	v1Header[40] = 0 // tzh_charcnt = 0
	v1Header[43] = 4 // 4 chars ("UTC\0")

	// V1 data: 1 ttinfo (6 bytes: 4 offset + 1 dst + 1 idx) + 4 chars
	v1Data := []byte{0, 0, 0, 0, 0, 0, 'U', 'T', 'C', 0}

	// V2 header (same as v1 header)
	v2Header := make([]byte, 44)
	copy(v2Header, v1Header)

	// V2 data (same minimal structure)
	v2Data := make([]byte, len(v1Data))
	copy(v2Data, v1Data)

	// Footer: \n<posix-tz>\n
	footer := []byte("\n" + posixTZ + "\n")

	result := make([]byte, 0, len(v1Header)+len(v1Data)+len(v2Header)+len(v2Data)+len(footer))
	result = append(result, v1Header...)
	result = append(result, v1Data...)
	result = append(result, v2Header...)
	result = append(result, v2Data...)
	result = append(result, footer...)
	return result
}

func TestTzFromTZifFooter(t *testing.T) {
	tests := []struct {
		name    string
		posixTZ string
		want    string
		wantErr bool
	}{
		{name: "UTC0", posixTZ: "UTC0", want: "UTC"},
		{name: "empty string means UTC", posixTZ: "", want: "UTC"},
		{name: "UTC", posixTZ: "UTC", want: "UTC"},
		{name: "EST5EDT mapped", posixTZ: "EST5EDT,M3.2.0,M11.1.0", want: "America/New_York"},
		{name: "CST6CDT mapped", posixTZ: "CST6CDT,M3.2.0,M11.1.0", want: "America/Chicago"},
		{name: "PST8PDT mapped", posixTZ: "PST8PDT,M3.2.0,M11.1.0", want: "America/Los_Angeles"},
		{name: "JST-9 mapped", posixTZ: "JST-9", want: "Asia/Tokyo"},
		{name: "unmapped string", posixTZ: "WEIRD3", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildTZifV2(tt.posixTZ)
			got, err := tzFromTZifFooter(data)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTzFromTZifFooter_V1Only(t *testing.T) {
	// A v1 TZif file has no footer → should error
	v1 := make([]byte, 44+10) // header + minimal data
	copy(v1[0:4], "TZif")
	v1[4] = 0 // version 1 (no version byte)
	v1[39] = 1
	v1[43] = 4
	copy(v1[44:], []byte{0, 0, 0, 0, 0, 0, 'U', 'T', 'C', 0})

	_, err := tzFromTZifFooter(v1)
	require.Error(t, err)
}

func TestMatchLocaltimeByCommonPaths(t *testing.T) {
	fs := afero.NewMemMapFs()

	// Create a TZif file for /etc/localtime
	localtime := buildTZifV2("CST6CDT,M3.2.0,M11.1.0")
	require.NoError(t, afero.WriteFile(fs, "/etc/localtime", localtime, 0o644))

	// Put a matching file at America/Chicago (which is in commonTimezones)
	require.NoError(t, afero.WriteFile(fs, "/usr/share/zoneinfo/America/Chicago", localtime, 0o644))

	// Put a non-matching file at a different path
	other := buildTZifV2("PST8PDT,M3.2.0,M11.1.0")
	require.NoError(t, afero.WriteFile(fs, "/usr/share/zoneinfo/America/New_York", other, 0o644))

	tz, err := matchLocaltimeByCommonPaths(fs, localtime)
	require.NoError(t, err)
	assert.Equal(t, "America/Chicago", tz)
}

func TestMatchLocaltimeByCommonPaths_NoMatch(t *testing.T) {
	fs := afero.NewMemMapFs()
	localtime := buildTZifV2("WEIRD3")

	// No matching file in common paths
	_, err := matchLocaltimeByCommonPaths(fs, localtime)
	require.Error(t, err)
}

func TestTimezoneFromFS_UTCDockerImage(t *testing.T) {
	// Simulates a Docker image with UTC timezone: /etc/localtime is a
	// regular file (not symlink), no /etc/timezone. The TZif footer
	// should be parsed directly without walking the zoneinfo tree.
	fs := afero.NewMemMapFs()

	utcData := buildTZifV2("UTC0")
	require.NoError(t, afero.WriteFile(fs, "/etc/localtime", utcData, 0o644))

	tz, err := timezoneFromFS(fs)
	require.NoError(t, err)
	assert.Equal(t, "UTC", tz)
}

func TestTimezoneFromFS_NonUTCDockerImage(t *testing.T) {
	// Docker image with a non-UTC timezone, /etc/localtime is a copied
	// TZif file with a recognized POSIX TZ footer.
	fs := afero.NewMemMapFs()

	tokyoData := buildTZifV2("JST-9")
	require.NoError(t, afero.WriteFile(fs, "/etc/localtime", tokyoData, 0o644))

	tz, err := timezoneFromFS(fs)
	require.NoError(t, err)
	assert.Equal(t, "Asia/Tokyo", tz)
}

// LocationFromFS is what lets a timestamp written without an offset be read in
// the asset's own zone rather than the scanner's. A nil return is the signal to
// fall back, so it must not be confused with UTC.
func TestLocationFromFS(t *testing.T) {
	t.Run("zone from /etc/timezone", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/etc/timezone", []byte("Europe/Berlin\n"), 0o644))

		loc := LocationFromFS(fs)
		require.NotNil(t, loc)
		assert.Equal(t, "Europe/Berlin", loc.String())
	})

	t.Run("UTC container image", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/etc/timezone", []byte("Etc/UTC\n"), 0o644))

		loc := LocationFromFS(fs)
		require.NotNil(t, loc)

		// The point of resolving the asset's zone: the same naive timestamp must
		// name a different instant here than it would in the scanner's zone.
		parsed, err := time.ParseInLocation("2006-01-02 15:04:05", "2026-05-09 14:23:32", loc)
		require.NoError(t, err)
		assert.Equal(t, "2026-05-09T14:23:32Z", parsed.UTC().Format(time.RFC3339))
	})

	t.Run("no zone information", func(t *testing.T) {
		assert.Nil(t, LocationFromFS(afero.NewMemMapFs()),
			"an asset with no zone must report nil so the caller can fall back")
	})

	t.Run("unknown zone name", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/etc/timezone", []byte("Mars/Olympus_Mons\n"), 0o644))

		assert.Nil(t, LocationFromFS(fs), "a zone the scanner cannot load must report nil, not UTC")
	})
}
