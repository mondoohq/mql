// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"encoding/binary"
	"fmt"
	"time"

	ipmiTransport "github.com/vmware/goipmi"
)

// SELInfo is the state of the system event log, from Get SEL Info (§31.2).
type SELInfo struct {
	Version        string
	Entries        int64
	FreeSpaceBytes int64
	// LastAddTime and LastEraseTime are nil when the controller reports the
	// timestamp as unspecified, which is what an empty or never-erased log
	// returns. The zero timestamp would otherwise be reported as a real date.
	LastAddTime   *time.Time
	LastEraseTime *time.Time

	Overflow                  bool
	SupportsDelete            bool
	SupportsPartialAdd        bool
	SupportsReserve           bool
	SupportsGetAllocationInfo bool
}

// selTimestampUnspecified is the reserved value the specification uses for a
// timestamp that has never been set (§31.2).
const selTimestampUnspecified uint32 = 0xffffffff

// Watchdog is the state of the controller watchdog timer, from Get Watchdog
// Timer (§27.7).
type Watchdog struct {
	Running  bool
	DontLog  bool
	TimerUse string

	TimeoutAction           string
	PreTimeoutInterrupt     string
	PreTimeoutIntervalSecs  int64
	ExpiredTimerUses        []string
	InitialCountdownSeconds float64
	PresentCountdownSeconds float64
}

// watchdogCountdownUnitsPerSecond converts the raw countdown values, which
// the specification expresses in 100ms units, into seconds.
const watchdogCountdownUnitsPerSecond = 10.0

// SELInfo runs Get SEL Info (§31.2).
func (c *IpmiClient) SELInfo() (*SELInfo, error) {
	data, err := c.sendRaw(networkFunctionStorage, commandGetSELInfo, []byte{})
	if err != nil {
		return nil, err
	}
	return decodeSELInfo(data)
}

// SystemEventLoggingEnabled runs Get BMC Global Enables (§22.2) and reports
// whether the controller is writing events to the system event log at all.
func (c *IpmiClient) SystemEventLoggingEnabled() (bool, error) {
	data, err := c.sendRaw(ipmiTransport.NetworkFunctionApp, commandGetBMCGlobalEnables, []byte{})
	if err != nil {
		return false, err
	}
	if len(data) < 1 {
		return false, fmt.Errorf("ipmi: short global enables response, expected at least 1 byte, got %d", len(data))
	}
	return data[0]&0x08 != 0, nil
}

// Watchdog runs Get Watchdog Timer (§27.7).
func (c *IpmiClient) Watchdog() (*Watchdog, error) {
	data, err := c.sendRaw(ipmiTransport.NetworkFunctionApp, commandGetWatchdogTimer, []byte{})
	if err != nil {
		return nil, err
	}
	return decodeWatchdog(data)
}

func decodeSELInfo(data []byte) (*SELInfo, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("ipmi: short SEL info response, expected at least 14 bytes, got %d", len(data))
	}
	return &SELInfo{
		Version:                   decodeIPMIVersion(data[0]),
		Entries:                   int64(binary.LittleEndian.Uint16(data[1:3])),
		FreeSpaceBytes:            int64(binary.LittleEndian.Uint16(data[3:5])),
		LastAddTime:               decodeSELTimestamp(binary.LittleEndian.Uint32(data[5:9])),
		LastEraseTime:             decodeSELTimestamp(binary.LittleEndian.Uint32(data[9:13])),
		Overflow:                  data[13]&0x80 != 0,
		SupportsDelete:            data[13]&0x08 != 0,
		SupportsPartialAdd:        data[13]&0x04 != 0,
		SupportsReserve:           data[13]&0x02 != 0,
		SupportsGetAllocationInfo: data[13]&0x01 != 0,
	}, nil
}

func decodeSELTimestamp(ts uint32) *time.Time {
	if ts == selTimestampUnspecified {
		return nil
	}
	t := time.Unix(int64(ts), 0).UTC()
	return &t
}

func decodeWatchdog(data []byte) (*Watchdog, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("ipmi: short watchdog response, expected at least 8 bytes, got %d", len(data))
	}
	return &Watchdog{
		DontLog:                 data[0]&0x80 != 0,
		Running:                 data[0]&0x40 != 0,
		TimerUse:                decodeWatchdogTimerUse(data[0] & 0x07),
		PreTimeoutInterrupt:     decodeWatchdogPreTimeoutInterrupt((data[1] & 0x70) >> 4),
		TimeoutAction:           decodeWatchdogTimeoutAction(data[1] & 0x07),
		PreTimeoutIntervalSecs:  int64(data[2]),
		ExpiredTimerUses:        decodeWatchdogExpirationFlags(data[3]),
		InitialCountdownSeconds: float64(binary.LittleEndian.Uint16(data[4:6])) / watchdogCountdownUnitsPerSecond,
		PresentCountdownSeconds: float64(binary.LittleEndian.Uint16(data[6:8])) / watchdogCountdownUnitsPerSecond,
	}, nil
}

func decodeWatchdogTimerUse(b uint8) string {
	switch b {
	case 0x01:
		return "bios-frb2"
	case 0x02:
		return "bios-post"
	case 0x03:
		return "os-load"
	case 0x04:
		return "sms-os"
	case 0x05:
		return "oem"
	default:
		return "reserved"
	}
}

func decodeWatchdogTimeoutAction(b uint8) string {
	switch b {
	case 0x00:
		return "none"
	case 0x01:
		return "hard-reset"
	case 0x02:
		return "power-down"
	case 0x03:
		return "power-cycle"
	default:
		return "reserved"
	}
}

func decodeWatchdogPreTimeoutInterrupt(b uint8) string {
	switch b {
	case 0x00:
		return "none"
	case 0x01:
		return "smi"
	case 0x02:
		return "nmi"
	case 0x03:
		return "messaging"
	default:
		return "reserved"
	}
}

// decodeWatchdogExpirationFlags lists the timer uses whose expiration the
// controller still has recorded. Bit 0 is reserved (§27.7).
func decodeWatchdogExpirationFlags(b uint8) []string {
	ordered := []struct {
		bit uint8
		use string
	}{
		{0x02, "bios-frb2"},
		{0x04, "bios-post"},
		{0x08, "os-load"},
		{0x10, "sms-os"},
		{0x20, "oem"},
	}
	flags := []string{}
	for _, f := range ordered {
		if b&f.bit != 0 {
			flags = append(flags, f.use)
		}
	}
	return flags
}
