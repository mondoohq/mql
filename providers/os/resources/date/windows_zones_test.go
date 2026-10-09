// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package date

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "time/tzdata" // the offsets below, also where no Go installation provides them
)

func TestWindowsZoneToIANA(t *testing.T) {
	// Expected names and offsets are the IANA zones' own, not values read
	// from the table: winter and summer offsets in UTC seconds.
	winter := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	summer := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		windows      string
		iana         string
		winterOffset int
		summerOffset int
	}{
		{"UTC", "Etc/UTC", 0, 0},
		{"W. Europe Standard Time", "Europe/Berlin", 3600, 7200},
		{"GMT Standard Time", "Europe/London", 0, 3600},
		{"Eastern Standard Time", "America/New_York", -18000, -14400},
		{"Pacific Standard Time", "America/Los_Angeles", -28800, -25200},
		{"Tokyo Standard Time", "Asia/Tokyo", 32400, 32400},
		// half and quarter hour offsets
		{"India Standard Time", "Asia/Kolkata", 19800, 19800},
		{"Nepal Standard Time", "Asia/Kathmandu", 20700, 20700},
		{"Newfoundland Standard Time", "America/St_Johns", -12600, -9000},
		{"Cen. Australia Standard Time", "Australia/Adelaide", 37800, 34200},
		{"Chatham Islands Standard Time", "Pacific/Chatham", 49500, 45900},
		// a half hour DST shift
		{"Lord Howe Standard Time", "Australia/Lord_Howe", 39600, 37800},
		// CLDR names these Europe/Kiev and America/Indianapolis; the table
		// carries the names tzdata uses today
		{"FLE Standard Time", "Europe/Kyiv", 7200, 10800},
		{"US Eastern Standard Time", "America/Indiana/Indianapolis", -18000, -14400},
	}
	for _, tt := range tests {
		t.Run(tt.windows, func(t *testing.T) {
			iana, ok := WindowsZoneToIANA(tt.windows)
			require.True(t, ok)
			assert.Equal(t, tt.iana, iana)

			loc, err := time.LoadLocation(iana)
			require.NoError(t, err)
			_, off := winter.In(loc).Zone()
			assert.Equal(t, tt.winterOffset, off, "winter")
			_, off = summer.In(loc).Zone()
			assert.Equal(t, tt.summerOffset, off, "summer")
		})
	}
}

func TestWindowsZoneToIANAUnknown(t *testing.T) {
	_, ok := WindowsZoneToIANA("Mars Standard Time")
	assert.False(t, ok)
	_, ok = WindowsZoneToIANA("")
	assert.False(t, ok)
}

// Every name in the table must be one the Go zone database loads, so a
// mapped Windows zone always yields a usable location.
func TestWindowsZoneTableLoads(t *testing.T) {
	require.Greater(t, len(windowsZoneToIANA), 100)
	for windows, iana := range windowsZoneToIANA {
		_, err := time.LoadLocation(iana)
		assert.NoError(t, err, "%s -> %s", windows, iana)
	}
}
