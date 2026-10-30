// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeManufacturerID(t *testing.T) {
	tests := []struct {
		name string
		id1  uint16
		id2  uint8
		want OemVendorID
	}{
		{"Dell (674)", 674, 0x00, OemDell},
		{"Supermicro (10876)", 10876, 0x00, OemSupermicro},
		{"Intel (343)", 343, 0x00, OemIntel},
		// 47488 = 0xB980 — fits in 16 bits, exercises ManufacturerID1 alone.
		{"Supermicro 47488", 0xB980, 0x00, OemSupermicro47488},
		// High-nibble bits: 0x10000 (65536) requires id2 bit 0 set.
		{"high nibble bit 0", 0x0000, 0x01, OemVendorID(0x10000)},
		// All 4 high-nibble bits set; high nibble of id2 must be ignored.
		{"high nibble masked to low 4 bits", 0xFFFF, 0xFF, OemVendorID(0xFFFFF)},
		{"zero", 0, 0, OemUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, decodeManufacturerID(tt.id1, tt.id2))
		})
	}
}

func TestDecodeFirmwareRevision(t *testing.T) {
	// Regression test for the bug where the BCD-encoded minor revision was
	// printed with %d, so firmware "1.10" rendered as "1.16".
	tests := []struct {
		name string
		rev1 uint8
		rev2 uint8
		want string
	}{
		{"single-digit minor", 9, 0x08, "9.08"},
		{"BCD minor 10", 1, 0x10, "1.10"},
		{"BCD minor 23", 2, 0x23, "2.23"},
		{"BCD minor 99", 3, 0x99, "3.99"},
		// The device-available bit (byte 1 bit 7) must not leak into the major.
		{"major masks bit 7", 0x89, 0x01, "9.01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, decodeFirmwareRevision(tt.rev1, tt.rev2))
		})
	}
}

func TestDecodeIPMIVersion(t *testing.T) {
	// Regression test for the bug where the raw BCD byte was cast to an int,
	// so IPMI 1.5 (0x51) reported as 81.
	tests := []struct {
		b    uint8
		want string
	}{
		{0x02, "2.0"},
		{0x51, "1.5"},
		{0x20, "0.2"},
		{0x00, "0.0"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, decodeIPMIVersion(tt.b), "b=0x%02X", tt.b)
	}
}

func TestDecodePowerRestorePolicy(t *testing.T) {
	tests := []struct {
		powerState uint8
		want       string
	}{
		{0x00, "always-off"},
		{0x20, "previous"},
		{0x40, "always-on"},
		{0x60, "unknown"},
		// Other bits in the power state byte must not influence the decode.
		{0xFF &^ 0x60, "always-off"},
		{0xFF, "unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, decodePowerRestorePolicy(tt.powerState),
			"powerState=0x%02X", tt.powerState)
	}
}

func TestDecodeLastPowerEvent(t *testing.T) {
	// Regression test for the bug where Command shared Fault's mask (0x8).
	t.Run("Fault and Command are distinct bits", func(t *testing.T) {
		fault := decodeLastPowerEvent(0x08)
		assert.True(t, fault.Fault)
		assert.False(t, fault.Command)

		cmd := decodeLastPowerEvent(0x10)
		assert.False(t, cmd.Fault)
		assert.True(t, cmd.Command)
	})

	t.Run("all bits set", func(t *testing.T) {
		got := decodeLastPowerEvent(0x1F)
		assert.Equal(t, ChassisLastPowerEvent{
			AcFailed:  true,
			Overload:  true,
			Interlock: true,
			Fault:     true,
			Command:   true,
		}, got)
	})

	t.Run("none set", func(t *testing.T) {
		assert.Equal(t, ChassisLastPowerEvent{}, decodeLastPowerEvent(0x00))
	})
}

func TestDecodeBIOSVerbosity(t *testing.T) {
	// Regression test for the bug where `& 0x3 >> 5` was always 0, so the
	// switch always landed on "default" regardless of input.
	tests := []struct {
		b    uint8
		want string
	}{
		{0x00, "default"},
		{0x20, "quiet"},    // bits 6:5 = 01
		{0x40, "verbose"},  // bits 6:5 = 10
		{0x60, "reserved"}, // bits 6:5 = 11
		// Other bits must not affect the decode.
		{0xFF, "reserved"},
		{0x1F, "default"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, decodeBIOSVerbosity(tt.b), "b=0x%02X", tt.b)
	}
}

func TestDecodeConsoleRedirection(t *testing.T) {
	tests := []struct {
		b    uint8
		want string
	}{
		{0x00, "bios"},
		{0x01, "skip"},
		{0x02, "redirected"},
		{0x03, "reserved"},
		{0xFC, "bios"}, // high bits don't leak in
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, decodeConsoleRedirection(tt.b), "b=0x%02X", tt.b)
	}
}

func TestDecodeBIOSMuxControlOverride(t *testing.T) {
	tests := []struct {
		b    uint8
		want string
	}{
		{0x00, "recommended"},
		{0x01, "force-bmc"},
		{0x02, "force-system"},
		{0x03, "reserved"},
		{0xFC, "recommended"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, decodeBIOSMuxControlOverride(tt.b), "b=0x%02X", tt.b)
	}
}

func TestOemVendorIDString(t *testing.T) {
	// Regression test for the "NEEC" typo.
	assert.Equal(t, "NEC", OemNEC.String())
	assert.Equal(t, "Dell Inc", OemDell.String())
	assert.Equal(t, "Unknown", OemVendorID(999999).String())
}
