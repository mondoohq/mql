// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This test runs against an IPMI service. For example, an simulator can be used like the openipmi simulator
// a complete docker container is available at https://github.com/vapor-ware/ipmi-simulator
func TestIpmiDockerSimulator(t *testing.T) {
	c := &Connection{Hostname: "0.0.0.0", Port: 623, Username: "ADMIN", Password: "ADMIN", Interface: "lan"}
	client, err := NewIpmiClient(c)
	require.NoError(t, err)
	err = client.Open()

	id, err := client.DeviceID()
	expected := &DeviceID{
		DeviceID:           int64(0),
		DeviceRevision:     int64(3),
		ProvidesDeviceSDRs: false,
		DeviceAvailable:    true,
		FirmwareRevision:   "9.08",
		IpmiVersion:        "2.0",
		ManufacturerID:     int64(4753),
		ManufacturerName:   "Unknown",
		ProductID:          int64(3842),
		ProductName:        "Unknown",
		AdditionalDeviceSupport: AdditionalDeviceSupport{
			SensorDevice:        true,
			SDRRepositoryDevice: true,
			SELDevice:           true,
			FRUInventoryDevice:  true,
			IPMBEventReceiver:   true,
			ChassisDevice:       true,
		},
	}
	assert.Equal(t, expected, id)

	status, err := client.ChassisStatus()
	expectedStatus := &ChassisStatus{
		SystemPower:        true,
		PowerOverload:      false,
		PowerInterlock:     false,
		MainPowerFault:     false,
		PowerControlFault:  false,
		PowerRestorePolicy: "always-off",
		LastPowerEvent: ChassisLastPowerEvent{
			AcFailed:  false,
			Overload:  false,
			Fault:     false,
			Interlock: false,
			Command:   false,
		},
		ChassisIntrusion:  false,
		FrontPanelLockout: false,
		DriveFault:        false,
		CoolingFanFault:   false,
	}
	assert.Equal(t, expectedStatus, status)

	bootOptions, err := client.ChassisSystemBootOptions()
	expectedBootOptions := &ChassisSystemBootOptions{
		ParameterVersion:       1,
		ParameterValidUnlocked: true,
		BootFlags: ChassisSystemBootOptionsFlags{
			BootFlagsValid:         false,
			ApplyToNextBootOnly:    true,
			LegacyBootType:         true,
			BootDeviceSelector:     "pxe",
			CmosClear:              false,
			LockKeyboard:           false,
			LockOutResetButton:     false,
			ScreenBlank:            false,
			BIOSVerbosity:          "default",
			ConsoleRedirection:     "bios",
			BIOSMuxControlOverride: "recommended",
			BIOSSharedModeOverride: false,
		},
	}
	assert.Equal(t, expectedBootOptions, bootOptions)

	guid, err := client.DeviceGUID()
	require.NoError(t, err)
	assert.Equal(t, "A123456789AB", guid.GUID)
}
