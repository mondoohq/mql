// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package usb

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

func parseIORegFixture(t *testing.T, name string) []USBDevice {
	t.Helper()
	data, err := os.ReadFile(path.Join("testdata", name))
	require.NoError(t, err)

	plistData, err := plist.Decode(bytes.NewReader(data))
	require.NoError(t, err)

	var devices []USBDevice
	ParseMacosIORegData(plistData, &devices)
	return devices
}

// `ioreg -p IOUSB -l -w 0 -a` with a hub that has a USB 3 and a USB 2 half,
// and a microphone behind the USB 2 half, all below an AppleUSBXHCITR host
// controller. The controller is not a device.
func TestUsbPlist(t *testing.T) {
	devices := parseIORegFixture(t, "usb.plist.xml")
	got := byLocation(devices)
	require.Len(t, got, 3, "devices: %v", keys(got))

	hub3 := got["0x03300000"]
	assert.Equal(t, "USB3 Gen2 Hub", hub3.Name)
	assert.Equal(t, "Apple", hub3.Manufacturer)
	assert.Equal(t, "0x05ac", hub3.VendorID)
	assert.Equal(t, "0x101e", hub3.ProductID)
	assert.Equal(t, "123456", hub3.SerialNumber)
	assert.Equal(t, "0x09", hub3.DeviceClass)
	assert.Equal(t, "Hub", hub3.DeviceClassName)
	assert.Equal(t, "0x5212", hub3.BcdDevice)
	assert.Equal(t, "52.1.2", hub3.FormattedVersion)
	assert.Equal(t, "10 Gbps (Super Speed+)", hub3.USBSpeed)

	hub2 := got["0x03100000"]
	assert.Equal(t, "USB2 Hub", hub2.Name)
	assert.Equal(t, "0x101d", hub2.ProductID)
	assert.Equal(t, "480 Mbps (High Speed)", hub2.USBSpeed)

	mic := got["0x03130000"]
	assert.Equal(t, "RØDE PodMic USB", mic.Name)
	assert.Equal(t, "RØDE", mic.Manufacturer)
	assert.Equal(t, "0x19f7", mic.VendorID)
	assert.Equal(t, "0x004a", mic.ProductID)
	assert.Equal(t, "0xef", mic.DeviceClass)
	assert.Equal(t, "Miscellaneous", mic.DeviceClassName)
	assert.Equal(t, "1.1.7", mic.FormattedVersion)
	assert.Equal(t, "12 Mbps (Full Speed)", mic.USBSpeed)
}

// Captured on an Apple Silicon Mac with nothing plugged in, trimmed to the
// identifying keys: the IOUSB plane lists only the three xHCI host
// controllers, which are not devices.
func TestUsbPlist_AppleSiliconNoDevices(t *testing.T) {
	devices := parseIORegFixture(t, "usb_apple_silicon_no_devices.plist.xml")
	assert.Empty(t, devices)
}

func TestFormatUSBSpeed(t *testing.T) {
	cases := map[int]string{
		0: "",
		1: "12 Mbps (Full Speed)",
		2: "1.5 Mbps (Low Speed)",
		3: "480 Mbps (High Speed)",
		4: "5 Gbps (Super Speed)",
		5: "10 Gbps (Super Speed+)",
		6: "20 Gbps (Super Speed+ Gen 2x2)",
		7: "",
	}
	for in, want := range cases {
		assert.Equal(t, want, formatUSBSpeed(in), in)
	}
}

func TestFormatBcdVersion(t *testing.T) {
	cases := map[uint64]string{
		0x0000: "0.0",
		0x0117: "1.1.7",
		0x0200: "2.0",
		0x1000: "10.0",
		0x5212: "52.1.2",
	}
	for in, want := range cases {
		assert.Equal(t, want, formatBcdVersion(in), "0x%04x", in)
	}
}
