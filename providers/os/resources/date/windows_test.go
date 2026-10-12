// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package date

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWindowsDate(t *testing.T) {
	w := &Windows{}

	tests := []struct {
		name      string
		input     string
		wantTZ    string
		wantWinTZ string
		wantYear  int
		wantErr   bool
	}{
		{
			name:      "Windows zone ID mapped to IANA",
			input:     `{"DateTime":"2026-03-17T14:30:00Z","Timezone":"Eastern Standard Time","UtcOffset":-14400}`,
			wantTZ:    "America/New_York",
			wantWinTZ: "Eastern Standard Time",
			wantYear:  2026,
		},
		{
			name:      "UTC",
			input:     `{"DateTime":"2026-03-17T14:30:00Z","Timezone":"UTC","UtcOffset":0}`,
			wantTZ:    "Etc/UTC",
			wantWinTZ: "UTC",
			wantYear:  2026,
		},
		{
			name:      "unmapped ID is kept",
			input:     `{"DateTime":"2026-03-17T14:30:00Z","Timezone":"Mars Standard Time","UtcOffset":3600}`,
			wantTZ:    "Mars Standard Time",
			wantWinTZ: "Mars Standard Time",
			wantYear:  2026,
		},
		{
			name:    "invalid json",
			input:   `not json`,
			wantErr: true,
		},
		{
			name:    "invalid datetime",
			input:   `{"DateTime":"not-a-date","Timezone":"UTC"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := w.parse(strings.NewReader(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantTZ, got.Timezone)
			require.NotNil(t, got.WindowsTimezone)
			assert.Equal(t, tt.wantWinTZ, *got.WindowsTimezone)
			assert.Equal(t, tt.wantYear, got.Time.Year())
		})
	}
}

// ConvertTo-Json output of windowsDateCmd on Windows Server 2022 set to
// "India Standard Time", pretty-printed the way PowerShell 5.1 writes it.
const windowsDateIndia = `{
    "UtcOffset":  19800,
    "Timezone":  "India Standard Time",
    "DateTime":  "2026-10-09T22:12:45Z"
}`

func TestParseWindowsDateOffset(t *testing.T) {
	got, err := (&Windows{}).parse(strings.NewReader(windowsDateIndia))
	require.NoError(t, err)

	assert.Equal(t, "Asia/Kolkata", got.Timezone)
	require.NotNil(t, got.UTCOffset)
	assert.Equal(t, int64(19800), *got.UTCOffset)

	// the instant is unchanged, and shown at the system's wall clock
	assert.Equal(t, "2026-10-09T22:12:45Z", got.Time.UTC().Format(time.RFC3339))
	assert.Equal(t, "2026-10-10T03:42:45+05:30", got.Time.Format(time.RFC3339))
}

func TestParseWindowsDateWithoutOffset(t *testing.T) {
	// Without UtcOffset in the output, the offset comes from the mapped zone
	// at the time that was read: CEST in July.
	got, err := (&Windows{}).parse(strings.NewReader(`{"DateTime":"2026-07-01T12:00:00Z","Timezone":"W. Europe Standard Time"}`))
	require.NoError(t, err)
	require.NotNil(t, got.UTCOffset)
	assert.Equal(t, int64(7200), *got.UTCOffset)
}

func TestParseWindowsDateUnmappedUsesReportedOffset(t *testing.T) {
	got, err := (&Windows{}).parse(strings.NewReader(`{"DateTime":"2026-07-01T12:00:00Z","Timezone":"Mars Standard Time","UtcOffset":-12600}`))
	require.NoError(t, err)
	assert.Equal(t, "2026-07-01T08:30:00-03:30", got.Time.Format(time.RFC3339))
	require.NotNil(t, got.UTCOffset)
	assert.Equal(t, int64(-12600), *got.UTCOffset)
}
