// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/resources/usb"
)

func TestUsbDevicesWithLocation(t *testing.T) {
	devices := []usb.USBDevice{
		// Composite device: empty DeviceClass but a valid LocationID — must be kept.
		{Name: "composite", LocationID: "0x14100000", DeviceClass: ""},
		// Has a class but no LocationID — must be dropped (blank __id otherwise).
		{Name: "no-location", LocationID: "", DeviceClass: "9"},
		{Name: "normal", LocationID: "0x14200000", DeviceClass: "0"},
	}

	got := usbDevicesWithLocation(devices)

	names := make([]string, 0, len(got))
	for _, d := range got {
		names = append(names, d.Name)
		assert.NotEmpty(t, d.LocationID)
	}
	assert.ElementsMatch(t, []string{"composite", "normal"}, names)
}

func TestUsbSourceFor(t *testing.T) {
	cases := []struct {
		name     string
		platform *inventory.Platform
		want     usbSource
	}{
		{"macos", &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}}, usbSourceMacos},
		{"ubuntu", &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}, usbSourceLinuxSysfs},
		{"redhat", &inventory.Platform{Name: "redhat", Family: []string{"redhat", "linux", "unix", "os"}}, usbSourceLinuxSysfs},
		{"windows", &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}}, usbSourceUnsupported},
		{"freebsd", &inventory.Platform{Name: "freebsd", Family: []string{"bsd", "unix", "os"}}, usbSourceUnsupported},
		{"nil", nil, usbSourceUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, usbSourceFor(tc.platform))
		})
	}
}

func TestErrUsbUnsupported(t *testing.T) {
	assert.EqualError(t, errUsbUnsupported(&inventory.Platform{Name: "windows"}), "could not detect usb: windows")
	assert.EqualError(t, errUsbUnsupported(nil), "could not detect usb: ")
}
