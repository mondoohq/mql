// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import "fmt"

// Pure bit decoders for IPMI response bytes, kept separate so they can be
// unit tested without an IPMI transport. Bit layouts come from IPMI 2.0
// §20.1 (Get Device ID), §28.2 (Get Chassis Status), and §28.13 (Get System
// Boot Options).

// decodeManufacturerID assembles the 20-bit IANA Enterprise Number: low 16
// bits in id1, high 4 bits in the low nibble of id2.
func decodeManufacturerID(id1 uint16, id2 uint8) OemVendorID {
	return OemVendorID(uint32(id1) | (uint32(id2)&0x0F)<<16)
}

// decodeFirmwareRevision formats the BMC firmware revision per §20.1. The
// major revision is the low 7 bits of byte 1 (binary encoded); the minor
// revision (byte 2) is BCD encoded, so it is rendered with %x to print its
// decimal digits (BCD 0x10 -> "10", not the "16" that %d would produce).
func decodeFirmwareRevision(rev1, rev2 uint8) string {
	return fmt.Sprintf("%d.%02x", rev1&0x7F, rev2)
}

// decodeIPMIVersion decodes the BCD-encoded IPMI version byte (§20.1): the
// major version is the low nibble and the minor version the high nibble, so
// 0x02 -> "2.0" and 0x51 -> "1.5".
func decodeIPMIVersion(b uint8) string {
	return fmt.Sprintf("%d.%d", b&0x0F, (b>>4)&0x0F)
}

func decodePowerRestorePolicy(powerState uint8) string {
	switch (powerState & 0x60) >> 5 {
	case 0x0:
		return "always-off"
	case 0x1:
		return "previous"
	case 0x2:
		return "always-on"
	default:
		return "unknown"
	}
}

func decodeLastPowerEvent(b uint8) ChassisLastPowerEvent {
	return ChassisLastPowerEvent{
		AcFailed:  b&0x1 != 0,
		Overload:  b&0x2 != 0,
		Interlock: b&0x4 != 0,
		Fault:     b&0x8 != 0,
		Command:   b&0x10 != 0,
	}
}

func decodeBIOSVerbosity(b uint8) string {
	switch (b >> 5) & 0x3 {
	case 0x0:
		return "default"
	case 0x1:
		return "quiet"
	case 0x2:
		return "verbose"
	default:
		return "reserved"
	}
}

func decodeConsoleRedirection(b uint8) string {
	switch b & 0x3 {
	case 0x0:
		return "bios"
	case 0x1:
		return "skip"
	case 0x2:
		return "redirected"
	default:
		return "reserved"
	}
}

func decodeBIOSMuxControlOverride(b uint8) string {
	switch b & 0x3 {
	case 0x0:
		return "recommended"
	case 0x1:
		return "force-bmc"
	case 0x2:
		return "force-system"
	default:
		return "reserved"
	}
}
