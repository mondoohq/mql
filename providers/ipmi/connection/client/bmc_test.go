// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeSELInfo(t *testing.T) {
	data := []byte{
		0x51,       // version 1.5, BCD with the major digit low
		0x2a, 0x00, // 42 entries, least significant byte first
		0x00, 0x10, // 4096 bytes free
		0x00, 0x00, 0x00, 0x60, // last add   1611662848
		0x00, 0x00, 0x00, 0x50, // last erase 1342177280
		0x0f, // overflow clear, all four operations supported
	}
	info, err := decodeSELInfo(data)
	require.NoError(t, err)
	assert.Equal(t, "1.5", info.Version)
	assert.Equal(t, int64(42), info.Entries)
	assert.Equal(t, int64(4096), info.FreeSpaceBytes)
	require.NotNil(t, info.LastAddTime)
	assert.Equal(t, time.Unix(0x60000000, 0).UTC(), *info.LastAddTime)
	require.NotNil(t, info.LastEraseTime)
	assert.Equal(t, time.Unix(0x50000000, 0).UTC(), *info.LastEraseTime)
	assert.False(t, info.Overflow)
	assert.True(t, info.SupportsDelete)
	assert.True(t, info.SupportsPartialAdd)
	assert.True(t, info.SupportsReserve)
	assert.True(t, info.SupportsGetAllocationInfo)
}

func TestDecodeSELInfoUnsetTimestamps(t *testing.T) {
	// A log that has never been written to reports both timestamps as the
	// reserved all-ones value. Passing that through time.Unix would report
	// a date in 2106 as the last time an event was recorded.
	data := []byte{
		0x51,
		0x00, 0x00,
		0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0x80, // overflow set, no operations supported
	}
	info, err := decodeSELInfo(data)
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Entries)
	assert.Nil(t, info.LastAddTime)
	assert.Nil(t, info.LastEraseTime)
	assert.True(t, info.Overflow)
	assert.False(t, info.SupportsDelete)
	assert.False(t, info.SupportsPartialAdd)
	assert.False(t, info.SupportsReserve)
	assert.False(t, info.SupportsGetAllocationInfo)
}

func TestDecodeSELInfoShort(t *testing.T) {
	_, err := decodeSELInfo(make([]byte, 13))
	require.Error(t, err)
}

func TestDecodeWatchdog(t *testing.T) {
	// Timer use 0xc4: don't log (bit 7), running (bit 6), SMS/OS (0x04).
	// Actions 0x21: NMI pre-timeout interrupt (bits 6:4 = 2), hard reset.
	// Pre-timeout 30 seconds, expiration flags for BIOS FRB2 and OS load,
	// initial countdown 600.0s and present countdown 76.7s.
	data := []byte{0xc4, 0x21, 0x1e, 0x0a, 0x70, 0x17, 0xff, 0x02}
	wd, err := decodeWatchdog(data)
	require.NoError(t, err)
	assert.True(t, wd.DontLog)
	assert.True(t, wd.Running)
	assert.Equal(t, "sms-os", wd.TimerUse)
	assert.Equal(t, "nmi", wd.PreTimeoutInterrupt)
	assert.Equal(t, "hard-reset", wd.TimeoutAction)
	assert.Equal(t, int64(30), wd.PreTimeoutIntervalSecs)
	assert.Equal(t, []string{"bios-frb2", "os-load"}, wd.ExpiredTimerUses)
	assert.InDelta(t, 600.0, wd.InitialCountdownSeconds, 0.001)
	assert.InDelta(t, 76.7, wd.PresentCountdownSeconds, 0.001)
}

func TestDecodeWatchdogStopped(t *testing.T) {
	// Bit 7 is don't-log and bit 6 is running. Reading them the other way
	// round would report a stopped timer as one whose resets are logged.
	wd, err := decodeWatchdog([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	require.NoError(t, err)
	assert.False(t, wd.DontLog)
	assert.False(t, wd.Running)
	assert.Equal(t, "os-load", wd.TimerUse)
	assert.Equal(t, "none", wd.TimeoutAction)
	assert.Equal(t, "none", wd.PreTimeoutInterrupt)
	assert.Equal(t, []string{}, wd.ExpiredTimerUses)
}

func TestDecodeWatchdogShort(t *testing.T) {
	_, err := decodeWatchdog(make([]byte, 7))
	require.Error(t, err)
}

func TestDecodeWatchdogExpirationFlags(t *testing.T) {
	// Bit 0 is reserved and must never turn into a timer use.
	assert.Equal(t, []string{}, decodeWatchdogExpirationFlags(0x01))
	assert.Equal(t, []string{"bios-frb2", "bios-post", "os-load", "sms-os", "oem"}, decodeWatchdogExpirationFlags(0xff))
}

func TestDecodeWatchdogEnums(t *testing.T) {
	assert.Equal(t, "bios-frb2", decodeWatchdogTimerUse(0x01))
	assert.Equal(t, "reserved", decodeWatchdogTimerUse(0x00))
	assert.Equal(t, "reserved", decodeWatchdogTimerUse(0x06))
	assert.Equal(t, "power-cycle", decodeWatchdogTimeoutAction(0x03))
	assert.Equal(t, "reserved", decodeWatchdogTimeoutAction(0x04))
	assert.Equal(t, "messaging", decodeWatchdogPreTimeoutInterrupt(0x03))
	assert.Equal(t, "reserved", decodeWatchdogPreTimeoutInterrupt(0x04))
}
