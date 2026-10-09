// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package date

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// `w32tm /query /status` on a domain member synchronized to a domain controller.
const w32tmDomainMember = `Leap Indicator: 0(no warning)
Stratum: 4 (secondary reference - syncd by (S)NTP)
Precision: -23 (119.209ns per tick)
Root Delay: 0.0312500s
Root Dispersion: 7.8327898s
ReferenceId: 0xC0000204 (source IP:  192.0.2.4)
Last Successful Sync Time: 10/9/2026 8:12:45 PM
Source: dc01.corp.example.com
Poll Interval: 10 (1024s)
`

// A workgroup machine on the default server. The source carries its flags.
const w32tmWorkgroup = `Leap Indicator: 0(no warning)
Stratum: 3 (secondary reference - syncd by (S)NTP)
Precision: -23 (119.209ns per tick)
Root Delay: 0.0410767s
Root Dispersion: 7.7766471s
ReferenceId: 0xC6336414 (source IP:  198.51.100.20)
Last Successful Sync Time: 10/9/2026 7:58:02 PM
Source: time.windows.com,0x9
Poll Interval: 10 (1024s)
`

// The same status with German labels (an illustrative translation): w32tm
// localizes the labels and the date, not the values that are read.
const w32tmWorkgroupGerman = `Sprungindikator: 0(keine Warnung)
Stratum: 3 (Sekundärreferenz - synchr. über (S)NTP)
Präzision: -23 (119.209ns pro Tick)
Stammverzögerung: 0.0410767s
Stammabweichung: 7.7766471s
Referenz-ID: 0xC6336414 (Quell-IP:  198.51.100.20)
Letzte erfolgr. Synchronisierungszeit: 09.10.2026 19:58:02
Quelle: time.windows.com,0x9
Abrufintervall: 10 (1024s)
`

// Never synchronized: the source is the local CMOS clock.
const w32tmLocalCMOS = `Leap Indicator: 3(not synchronized)
Stratum: 0 (unspecified)
Precision: -23 (119.209ns per tick)
Root Delay: 0.0000000s
Root Dispersion: 0.0000000s
ReferenceId: 0x00000000 (unspecified)
Last Successful Sync Time: unspecified
Source: Local CMOS Clock
Poll Interval: 10 (1024s)
`

// Time service running with no time provider: the free-running clock
// reports stratum 1 and no warning, but its reference is LOCL.
const w32tmFreeRunning = `Leap Indicator: 0(no warning)
Stratum: 1 (primary reference - syncd by radio clock)
Precision: -23 (119.209ns per tick)
Root Delay: 0.0000000s
Root Dispersion: 10.0000000s
ReferenceId: 0x4C4F434C (source name:  "LOCL")
Last Successful Sync Time: 10/9/2026 8:01:13 PM
Source: Free-running System Clock
Poll Interval: 6 (64s)
`

// A Hyper-V guest synchronized through the integration services.
const w32tmHyperV = `Leap Indicator: 0(no warning)
Stratum: 2 (secondary reference - syncd by (S)NTP)
Precision: -23 (119.209ns per tick)
Root Delay: 0.0000000s
Root Dispersion: 10.0000000s
ReferenceId: 0x564D5450 (source name:  "VMTP")
Last Successful Sync Time: 10/9/2026 8:05:30 PM
Source: VM IC Time Synchronization Provider
Poll Interval: 6 (64s)
`

const w32tmNotStarted = `The following error occurred: The service has not been started. (0x80070426)`

func TestParseW32tm(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		source     string
		wantSynced *bool
		wantSource *string
	}{
		{"domain member", w32tmDomainMember, "dc01.corp.example.com\n", boolPtr(true), strPtr("dc01.corp.example.com")},
		{"workgroup, flags trimmed", w32tmWorkgroup, "time.windows.com,0x9\n", boolPtr(true), strPtr("time.windows.com")},
		{"German labels", w32tmWorkgroupGerman, "time.windows.com,0x9\n", boolPtr(true), strPtr("time.windows.com")},
		{"Hyper-V guest", w32tmHyperV, "VM IC Time Synchronization Provider\n", boolPtr(true), strPtr("VM IC Time Synchronization Provider")},
		{"local CMOS clock", w32tmLocalCMOS, "Local CMOS Clock\n", boolPtr(false), nil},
		{"free-running clock", w32tmFreeRunning, "Free-running System Clock\n", boolPtr(false), nil},
		{"service not started", w32tmNotStarted, w32tmNotStarted, boolPtr(false), nil},
		{"no output", "", "", nil, nil},
		{"unrelated text", "Access is denied.", "Access is denied.", nil, nil},
		{"status without reference ID", "Leap Indicator: 0(no warning)\nStratum: 3 (secondary reference - syncd by (S)NTP)\n", "", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseW32tm(tt.status, tt.source)
			assert.Equal(t, tt.wantSynced, got.Synchronized)
			assert.Equal(t, tt.wantSource, got.Source)
		})
	}
}

func TestParseW32tmCRLF(t *testing.T) {
	got := parseW32tm(strings.ReplaceAll(w32tmWorkgroup, "\n", "\r\n"), "time.windows.com,0x9\r\n")
	require.NotNil(t, got.Synchronized)
	assert.True(t, *got.Synchronized)
	assert.Equal(t, strPtr("time.windows.com"), got.Source)
}

func TestParseChronycTracking(t *testing.T) {
	tests := []struct {
		name       string
		stdout     string
		wantSynced *bool
		wantSource *string
	}{
		{
			name:       "synchronized to a server",
			stdout:     "C0000201,192.0.2.1,3,1760040765.402166235,-0.000004012,-0.000001789,0.000021553,-7.462,-0.001,0.026,0.000474853,0.000140421,1024.4,Normal\n",
			wantSynced: boolPtr(true),
			wantSource: strPtr("192.0.2.1"),
		},
		{
			name:       "synchronized to a reference clock",
			stdout:     "50484330,PHC0,1,1760040765.402166235,0.000000012,0.000000004,0.000000031,-2.104,0.000,0.003,0.000000001,0.000010210,8.0,Normal\n",
			wantSynced: boolPtr(true),
			wantSource: strPtr("PHC0"),
		},
		{
			name:       "not synchronized",
			stdout:     "00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,1.000000000,1.000000000,0.0,Not synchronised\n",
			wantSynced: boolPtr(false),
		},
		{
			name:   "daemon not reachable",
			stdout: "506 Cannot talk to daemon\n",
		},
		{
			name:   "unknown leap status",
			stdout: "C0000201,192.0.2.1,3,1760040765.402166235,-0.000004012,-0.000001789,0.000021553,-7.462,-0.001,0.026,0.000474853,0.000140421,1024.4,Something\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseChronycTracking(tt.stdout)
			assert.Equal(t, tt.wantSynced, got.Synchronized)
			assert.Equal(t, tt.wantSource, got.Source)
		})
	}
}

func TestMacOSTimeSource(t *testing.T) {
	t.Run("default server", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		// /etc/ntp.conf as macOS 15 writes it
		require.NoError(t, afero.WriteFile(fs, "/etc/ntp.conf", []byte("server time.apple.com\n"), 0o644))
		assert.Equal(t, strPtr("time.apple.com"), MacOSTimeSource(fs))
	})

	t.Run("custom server after comments", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/etc/ntp.conf", []byte("# set in System Settings\n\nserver ntp.corp.example.com iburst\nserver time.apple.com\n"), 0o644))
		assert.Equal(t, strPtr("ntp.corp.example.com"), MacOSTimeSource(fs))
	})

	t.Run("no file", func(t *testing.T) {
		assert.Nil(t, MacOSTimeSource(afero.NewMemMapFs()))
	})

	t.Run("no server", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/etc/ntp.conf", []byte("# nothing\ndriftfile /var/db/ntp.drift\n"), 0o644))
		assert.Nil(t, MacOSTimeSource(fs))
	})
}

func strPtr(s string) *string {
	return &s
}
